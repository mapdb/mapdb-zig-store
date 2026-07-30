//! `BTreeMap` — B-link tree over a Store4 store. Push-down
//! readers (acquire no node locks; the short pin mutex only for `left_edges`)
//! + Lehman-Yao concurrent writers, ported from `mapdb-rust-store/src/btree/map.rs`.
//!
//! The map is generic over `(S: Store, KF, VF: GroupFormat)`. Clones share one
//! ref-counted `Inner` = one open lease; every clone and derived iterator
//! observes the same writer state (node-lock table, `left_edges`, root cache).
//! The map owns ONE allocator; every materialized value/entry it returns is
//! owned by that allocator and freed by the caller.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const ser = @import("../ser/mod.zig");
const SearchResult = ser.SearchResult;
const serializers = @import("../ser/serializers.zig");
const value_mod = @import("../ser/value.zig");
const Value = value_mod.Value;
const storemod = @import("../store/mod.zig");
const RecordRead = storemod.RecordRead;
const TypeId = storemod.TypeId;
const typeToken = storemod.typeToken;
const shared = @import("../shared.zig");
const nodemod = @import("node.zig");
const Node = nodemod.Node;
const NodeSerializer = nodemod.NodeSerializer;
const DIR = nodemod.DIR;
const LEFT = nodemod.LEFT;
const RIGHT = nodemod.RIGHT;
const pumpmod = @import("pump.zig");
const viewmod = @import("view.zig");
const long_mod = @import("../ser/long.zig");
const listenermod = @import("../listener.zig");

/// i64 element serializer for the root-pointer / counter record (Java Long record).
const LONG = serializers.LongSer.instance;

/// Valid tree depth / move-right hops are tiny; anything past this is a cycle.
const CYCLE_DESCENT_SOFT: u64 = 4096;
/// Leaf-link scans can be long; only enormous chains begin tracking visited
/// recids so a crafted leaf-link cycle terminates at bounded extra memory.
const CYCLE_SCAN_SOFT: u64 = 1 << 16;

const LOCK_STRIPES: usize = 64;

/// The legal range of `maxNodeSize`, shared with the DB catalog validators so the
/// create and reopen bounds can never drift (review C2). A split needs ≥ 4 keys;
/// the upper bound matches Java's positive `int` domain.
pub const MIN_MAX_NODE_SIZE: usize = 4;
pub const MAX_MAX_NODE_SIZE: usize = std.math.maxInt(i32);

inline fn searchIdx(r: SearchResult) usize {
    return switch (r) {
        .found => |p| p,
        .insert => |i| i,
    };
}

fn insertLong(alloc: Allocator, arr: []const u64, pos: usize, val: u64) DbError![]u64 {
    const r = try alloc.alloc(u64, arr.len + 1);
    @memcpy(r[0..pos], arr[0..pos]);
    r[pos] = val;
    @memcpy(r[pos + 1 ..], arr[pos..]);
    return r;
}

// ---------------------------------------------------- cycle detector

/// Cheap cycle detector for traversals over persisted recid graphs. Below the
/// soft threshold it costs one increment; above it (never reached by a valid
/// tree) it records visited recids and reports corruption on repetition.
const CycleGuard = struct {
    steps: u64 = 0,
    soft: u64,
    seen: ?std.AutoHashMapUnmanaged(u64, void) = null,
    alloc: Allocator,

    fn init(alloc: Allocator, soft: u64) CycleGuard {
        return .{ .soft = soft, .alloc = alloc };
    }
    fn deinit(self: *CycleGuard) void {
        if (self.seen) |*s| s.deinit(self.alloc);
    }
    fn visit(self: *CycleGuard, recid: u64) DbError!void {
        self.steps += 1;
        if (self.steps > self.soft) {
            if (self.seen == null) self.seen = .empty;
            const gop = try self.seen.?.getOrPut(self.alloc, recid);
            if (gop.found_existing) return error.DataCorruption;
        }
    }
};

// ---------------------------------------------------- node lock table

/// Per-node write locks keyed by EXACT recid (mapdb1/2/3 lineage): distinct
/// recids are distinct set entries, sharded across `LOCK_STRIPES` mutexes to
/// reduce insert/remove contention; acquisition parks briefly on contention
/// via `Futex.timedWait` on the stripe's counter.
///
/// DEADLOCK-FREEDOM. Writers follow Sagiv 1986, not Lehman-Yao's 3-lock
/// discipline: every acquisition happens while holding NO node lock —
/// `lockCovering` releases before re-locking on move-right, a split releases
/// the child (map.zig split hand-off) before the parent is locked, root grow
/// holds only the root-pointer recid. Hold-and-wait never occurs, so no
/// waits-for cycle can form; no lock-ordering argument is needed (Sagiv
/// Thm 1). Conditional on: guard-based release on every exit, no
/// listener/codec re-entry and acyclic cross-map bindings, the store
/// no-upcall (A3) contract, and recid stability.
///
/// NON-REENTRANT by design; the Debug assert on self-relock is the tripwire.
/// Reentrancy would MASK the bug classes this table must surface: aliasing
/// (a fixed-size striped lock ARRAY sends parent+child to one lock — silently
/// absorbed by a reentrant lock single-threaded, cross-thread order inversion
/// under load; the historical mapdb store ran reentrant modulo stripes, and
/// mapdb3's CC.PARANOID SingleEntryLock existed to unmask re-entry) and any
/// future acquisition-while-holding in a forbidden direction. The assert
/// catches SELF-RELOCK only; the zero-held invariant is a protocol rule, and a
/// separate Debug-only threadlocal checker (`zeroHeldPreAcquire`/`zeroHeldRecord`
/// /`zeroHeldRelease`, scoped per table instance) asserts it directly — the
/// none-of-this-table check runs before any stripe lock, so a violation can
/// never deadlock ahead of the assert.
///
/// Reserved capacity: up to THREE overlapping locks for Sagiv compression
/// (parent → child → right sibling, TOP-DOWN then left-to-right) —
/// unexercised. Adopting it forbids child-held-while-locking-parent forever
/// (Sagiv p. 277: top-down compression deadlocks against bottom-up L&Y
/// inserters).
const NodeLockTable = struct {
    const Stripe = struct {
        mu: std.Thread.Mutex = .{},
        held: std.AutoHashMapUnmanaged(u64, std.Thread.Id) = .empty,
        seq: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    };

    stripes: []Stripe,
    enabled: bool,
    alloc: Allocator,

    fn init(alloc: Allocator, enabled: bool) DbError!NodeLockTable {
        const stripes = try alloc.alloc(Stripe, LOCK_STRIPES);
        for (stripes) |*s| s.* = .{};
        return .{ .stripes = stripes, .enabled = enabled, .alloc = alloc };
    }
    fn deinit(self: *NodeLockTable) void {
        for (self.stripes) |*s| s.held.deinit(self.alloc);
        self.alloc.free(self.stripes);
    }
    inline fn stripe(self: *NodeLockTable, recid: u64) *Stripe {
        // Reduce in the source (u64) width so the cast is provably bounded even
        // for a recid above maxInt(usize) on a 32-bit target.
        return &self.stripes[@as(usize, @intCast(recid % @as(u64, LOCK_STRIPES)))];
    }
    fn lock(self: *NodeLockTable, recid: u64) DbError!void {
        if (!self.enabled) return;
        // Debug zero-held PRE-check: assert BEFORE any stripe lock / futex wait,
        // so a violation surfaces at the assert rather than parking forever
        // holding an earlier lock (Java bc3695c: assertNoLockHeld before the loop).
        zeroHeldPreAcquire(self);
        const me = std.Thread.getCurrentId();
        const s = self.stripe(recid);
        while (true) {
            const seq = s.seq.load(.acquire);
            {
                s.mu.lock();
                defer s.mu.unlock();
                if (s.held.get(recid)) |owner| {
                    std.debug.assert(owner != me); // reentrant node lock
                } else {
                    try s.held.put(self.alloc, recid, me);
                    zeroHeldRecord(self, recid); // Debug: record (table, recid) on acquire
                    return;
                }
            }
            std.Thread.Futex.timedWait(&s.seq, seq, 50_000) catch {};
        }
    }
    fn unlock(self: *NodeLockTable, recid: u64) void {
        if (!self.enabled) return;
        zeroHeldRelease(self, recid); // Debug: assert this thread holds (table, recid) + remove
        const s = self.stripe(recid);
        s.mu.lock();
        const removed = s.held.fetchRemove(recid);
        s.mu.unlock();
        std.debug.assert(removed != null and removed.?.value == std.Thread.getCurrentId());
        _ = s.seq.fetchAdd(1, .release);
        std.Thread.Futex.wake(&s.seq, std.math.maxInt(u32));
    }
};

// -------------------------------------------- debug zero-held checker

/// Debug-only enforcement of the Sagiv zero-held rule: a writer
/// holds AT MOST ONE node lock, and every acquisition happens while holding
/// NONE. A threadlocal list records `(table, recid)` for each held lock,
/// scoped PER TABLE INSTANCE — a cross-map listener (Bind) holding a lock on a
/// DIFFERENT map does not trip it. Subsumes but does not replace the self-relock
/// assert, which also catches cross-instance stripe aliasing.
///
/// The list is UNBOUNDED: the deadlock-freedom contract permits acyclic synchronous Bind
/// chains of ANY depth (A→B→C→… each holding one lock in a DISTINCT table), so
/// a fixed cap would abort on legal input. Debug-only heap growth via
/// `page_allocator` (never freed — one small per-thread arena, like Java's
/// unbounded `ArrayDeque`; `page_allocator` so leak-checked test allocators do
/// not flag it). Every branch is behind a comptime `builtin.mode == .Debug`
/// gate, so release builds reference neither the list nor these functions.
const HeldLock = struct { table: *const NodeLockTable, recid: u64 };
threadlocal var held_locks: std.ArrayListUnmanaged(HeldLock) = .empty;

/// True iff this thread already holds a node lock of `table` (a zero-held
/// violation if it is about to acquire another of the same table). The
/// pre-acquire assert is built on this; also exposed for tests via `testHooks`.
fn zeroHeldViolation(table: *const NodeLockTable) bool {
    if (builtin.mode != .Debug) return false;
    for (held_locks.items) |h| {
        if (h.table == table) return true;
    }
    return false;
}

/// Pre-acquire check (Sagiv zero-held): assert this thread holds NO lock of
/// `table`. MUST run before any stripe lock / futex wait (see `lock`).
inline fn zeroHeldPreAcquire(table: *const NodeLockTable) void {
    if (builtin.mode != .Debug) return;
    std.debug.assert(!zeroHeldViolation(table)); // holds a lock of THIS table already
}

/// Record `(table, recid)` after a successful acquisition.
inline fn zeroHeldRecord(table: *const NodeLockTable, recid: u64) void {
    if (builtin.mode != .Debug) return;
    held_locks.append(std.heap.page_allocator, .{ .table = table, .recid = recid }) catch
        @panic("zero-held tracker OOM");
}

/// Assert this thread holds `(table, recid)`, then remove it.
inline fn zeroHeldRelease(table: *const NodeLockTable, recid: u64) void {
    if (builtin.mode != .Debug) return;
    for (held_locks.items, 0..) |h, i| {
        if (h.table == table and h.recid == recid) {
            _ = held_locks.swapRemove(i);
            return;
        }
    }
    unreachable; // released a (table, recid) this thread never acquired
}

/// Test-only: node locks this thread currently holds (Debug tracker). Always 0
/// outside Debug builds.
pub fn debugHeldLockCount() usize {
    if (builtin.mode != .Debug) return 0;
    return held_locks.items.len;
}

/// Test-only handles on the Debug zero-held checker (driven by btree_test.zig).
/// `pub` solely so the concurrency suite can create standalone lock tables and
/// exercise nesting / the pre-acquire predicate directly; not part of the map
/// API. In non-Debug builds the checker is inert, so these degrade accordingly.
pub const testHooks = struct {
    pub fn initTable(alloc: Allocator) DbError!NodeLockTable {
        return NodeLockTable.init(alloc, true);
    }
    pub fn deinitTable(t: *NodeLockTable) void {
        t.deinit();
    }
    pub fn lock(t: *NodeLockTable, recid: u64) DbError!void {
        return t.lock(recid);
    }
    pub fn unlock(t: *NodeLockTable, recid: u64) void {
        t.unlock(recid);
    }
    /// The pre-acquire predicate as a bool (the assert in `lock` is built on it).
    pub fn wouldViolate(t: *const NodeLockTable) bool {
        return zeroHeldViolation(t);
    }
    pub fn heldCount() usize {
        return debugHeldLockCount();
    }
};

/// Node-lock guard: created in its final stack location, passed by pointer.
/// `release` is idempotent so a `?`/error early-return never leaks the lock.
const NodeGuard = struct {
    table: *NodeLockTable,
    recid: u64,
    held: bool,

    fn release(self: *NodeGuard) void {
        if (self.held) {
            self.table.unlock(self.recid);
            self.held = false;
        }
    }
};

// ========================================================= the map

/// Inline-value BTreeMap (values live directly in leaf nodes) — the common case.
pub fn BTreeMap(comptime S: type, comptime KF: type, comptime VF: type) type {
    return BTreeMapG(S, KF, VF, true);
}

/// External-value BTreeMap (Java `createExternalValues`): each value is stored
/// as its own store record and the leaf node holds packed value recids
/// (`nodeValueFormat = LongFormat`). Bulk `createFromSorted` and columnar scans
/// are rejected on this type, matching Java.
pub fn BTreeMapExternal(comptime S: type, comptime KF: type, comptime VF: type) type {
    return BTreeMapG(S, KF, VF, false);
}

/// Generic BTreeMap monomorphized over the store, key/value formats, and the
/// `value_inline` flag. When `value_inline` is false the node's value slot holds
/// value recids (LongFormat) and the user's `VF` is used only to encode the
/// separate external value records.
pub fn BTreeMapG(comptime S: type, comptime KF: type, comptime VF: type, comptime value_inline: bool) type {
    return struct {
        const Self = @This();
        pub const Key = KF.Elem;
        pub const Val = VF.Elem;
        /// Node value format: the user format when inline, packed recids (Long)
        /// when external — this is what leaf nodes actually serialize.
        const NVF = if (value_inline) VF else long_mod.LongFormat;
        const NodeT = Node(KF, NVF);
        const NodeSer = NodeSerializer(KF, NVF);
        const Listeners = listenermod.ListenerRegistry(Key, Val);
        const Edges = shared.Shared([]u64);

        /// An owned key/value pair returned by iteration / navigation. Both
        /// fields are owned by the map's allocator; free with `deinitEntry`.
        pub const Entry = struct { key: Key, val: Val };

        const Inner = struct {
            alloc: Allocator,
            store: *S,
            kf: KF,
            vf: VF,
            max_node_size: usize,
            root_recid_recid: u64,
            /// Recid of the O(1) size-counter record (packed-long), or 0 when
            /// the counter is disabled (Feature A).
            counter_recid: u64,
            root_cacheable: bool,
            locks: NodeLockTable,
            /// Reader/writer barrier for external values (Java `externalValueLock`):
            /// a lock-free reader holds the read lock across descend+`store.get`, a
            /// remove holds the write lock across node-delete+`store.delete`, so a
            /// stale reader can never decode a deleted-then-reused value recid.
            /// Unused (never contended) for inline maps.
            ext_lock: std.Thread.RwLock,
            /// Runtime modification listeners (Feature B). Guarded by `listeners_mu`
            /// for add/remove; fired against a copied snapshot so a listener may
            /// run without holding the mutex. Listener CONTEXTS are borrowed: the
            /// caller must keep each registered context alive until it is removed
            /// or the map is deinitialized. `deinit` frees only the registry array
            /// and NEVER invokes a listener (so a freed context is never called).
            listeners: Listeners,
            listeners_mu: std.Thread.Mutex,
            /// Per-level left-edge recid, index 0 = leaf level, last = root.
            left_edges: Edges,
            /// Counter bumped (with a futex wake) whenever `left_edges` grows, so
            /// `leftEdge` waiters wake promptly.
            edges_seq: std.atomic.Value(u32),
            cached_root: std.atomic.Value(u64),
            poisoned: std.atomic.Value(bool),
            last_struct_gen: std.atomic.Value(u64),
            refcount: std.atomic.Value(usize),
        };

        inner: *Inner,

        // -------- small accessors --------
        pub inline fn a(self: Self) Allocator {
            return self.inner.alloc;
        }
        pub inline fn kf(self: Self) KF {
            return self.inner.kf;
        }
        pub inline fn vf(self: Self) VF {
            return self.inner.vf;
        }
        inline fn store(self: Self) *S {
            return self.inner.store;
        }
        /// Node value format instance (recids/Long when external, `vf` when inline).
        inline fn nvf(self: Self) NVF {
            return if (value_inline) self.inner.vf else NVF.instance;
        }
        inline fn nodeSer(self: Self) NodeSer {
            return NodeSer.init(self.inner.kf, self.nvf());
        }
        /// Element serializer for external value records (Java `valueFormat.element()`).
        inline fn velem(self: Self) VF.ElementSer {
            return self.inner.vf.element();
        }
        pub fn rootRecidRecid(self: Self) u64 {
            return self.inner.root_recid_recid;
        }
        /// Recid of the O(1) size-counter record, or 0 when disabled (Feature A).
        pub fn counterRecid(self: Self) u64 {
            return self.inner.counter_recid;
        }
        /// True when values live inline in leaf nodes; false for external values.
        pub fn valueInline(self: Self) bool {
            _ = self;
            return value_inline;
        }
        /// True iff the backing store is closed (Java `MapExtra.isClosed`).
        pub fn isClosed(self: Self) bool {
            return self.inner.store.isClosed();
        }
        /// Key group format (Java `MapExtra.keySerializer`).
        pub fn keySerializer(self: Self) KF {
            return self.inner.kf;
        }
        /// Value group format (Java `MapExtra.valueSerializer`).
        pub fn valueSerializer(self: Self) VF {
            return self.inner.vf;
        }
        pub fn maxNodeSize(self: Self) usize {
            return self.inner.max_node_size;
        }
        pub fn compareKeys(self: Self, x: Key, y: Key) Order {
            return self.kf().compare(x, y);
        }
        pub fn keyNaturalOrder(self: Self) bool {
            return self.kf().naturalOrder();
        }
        pub fn valueEquals(self: Self, x: Val, y: Val) bool {
            return self.vf().equalsElem(x, y);
        }

        // -------- external-value bridge (inline vs recid indirection) --------
        //
        // For an inline map `NVF == VF` and these are identities. For an external
        // map the leaf holds a value recid (`NVF.Elem == i64`) and each helper
        // bridges to a separate store record encoded with `VF.element()`.

        /// Materialize the USER value for a stored node value (`stored` is the
        /// value itself when inline, a recid when external). Returns an owned
        /// `Val`. For external maps this MUST be called while the external read
        /// barrier is held (the recid may otherwise be deleted+reused).
        fn expandStored(self: Self, stored: NVF.Elem) DbError!Val {
            if (value_inline) return stored; // already an owned Val from nvf.get
            const recid: u64 = @bitCast(stored);
            return (try self.store().get(Val, self.a(), recid, self.velem())) orelse error.DataCorruption;
        }

        /// The node value to insert for a fresh user `value` (borrowed): the value
        /// itself when inline (deep-cloned by `nvf.insert`), or a freshly allocated
        /// external value record's recid when external.
        fn storeNewStored(self: Self, value: Val) DbError!NVF.Elem {
            if (value_inline) return value;
            const recid = try self.store().put(Val, self.a(), value, self.velem());
            return @bitCast(recid);
        }

        /// Materialize the OWNED user value at leaf position `p`. Inline: the value
        /// itself. External: follows the recid to its value record (caller must
        /// hold the external read barrier).
        fn userValueGet(self: Self, values: *const NVF.Group, p: usize) DbError!Val {
            const alloc = self.a();
            if (value_inline) return self.nvf().get(alloc, values, p);
            const recid: u64 = @bitCast(try self.nvf().get(alloc, values, p));
            return (try self.store().get(Val, alloc, recid, self.velem())) orelse error.DataCorruption;
        }

        /// The external value recid stored at leaf position `p` (external only).
        fn recidAt(self: Self, values: *const NVF.Group, p: usize) DbError!u64 {
            return @bitCast(try self.nvf().get(self.a(), values, p));
        }

        // -------- persistent size counter (Feature A) --------

        /// Apply `delta` to the shared counter record via a CAS retry loop (Java
        /// `addToCounter`). Called AFTER the structural mutation commits. No-op when
        /// the counter is disabled. `delta` is always ±1 here.
        ///
        /// A persisted count that is negative, or that a decrement would drive below
        /// zero, is corruption: the map is POISONED (so `sizeLong` and every later op
        /// fail fast instead of "healing" to a bogus value) and `DataCorruption`
        /// returns. The normal update uses a WRAPPING add — Java `long` wraps at
        /// `maxInt`, and a ReleaseSafe overflow trap while holding the leaf lock would
        /// wedge the tree.
        fn addToCounter(self: Self, delta: i64) DbError!void {
            const recid = self.inner.counter_recid;
            if (recid == 0) return;
            // The mutation is already committed when this runs, so ANY counter
            // failure (corrupt count, store error) leaves an unrecoverably-wrong
            // O(1) size: poison the map so `sizeLong` and later ops fail fast.
            while (true) {
                const cur = self.getCounter(recid) catch |e| return self.poisonErr(e);
                if (cur < 0 or (delta < 0 and cur < -delta)) return self.poisonErr(error.DataCorruption);
                const swapped = self.store().compareAndSwap(i64, self.a(), recid, cur, cur +% delta, LONG) catch |e| return self.poisonErr(e);
                if (swapped) return;
            }
        }

        fn getCounter(self: Self, recid: u64) DbError!i64 {
            return (try self.store().get(i64, self.a(), recid, LONG)) orelse error.DataCorruption;
        }

        /// Poison the map and return `e` (a post-commit counter failure is fatal to
        /// the O(1) size — see `addToCounter`).
        fn poisonErr(self: Self, e: DbError) DbError {
            self.inner.poisoned.store(true, .release);
            return e;
        }

        // -------- modification listeners (Feature B) --------

        /// Register a modification listener (runtime-only, never persisted). A
        /// `synchronous` listener fires UNDER the covering leaf lock in per-key
        /// mutation order; an ordinary one fires after the lock is released and any
        /// split propagates. The listener's context is BORROWED (see `Inner`).
        ///
        /// LIFETIME: the context must outlive the map (or a caller-enforced
        /// quiesce point). `modificationListenerRemove` alone does NOT make the
        /// context safe to free: a concurrent mutation may already have copied the
        /// (ctx, fn) pair into an in-flight fire snapshot and will dereference it
        /// after remove returns. Removing a listener while mutations run and then
        /// freeing its context is undefined (v1 borrowed-context model; unlike
        /// Java's CopyOnWriteArrayList which retains the listener object). Quiesce
        /// the map before freeing a removed context.
        ///
        /// RE-ENTRY: a synchronous listener that calls back into THIS map is
        /// hazardous. On an inline map re-entrant reads are safe; on an external
        /// map the remove path holds `ext_lock` exclusively while firing, and
        /// `std.Thread.RwLock` is not reentrant (unlike Java's
        /// ReentrantReadWriteLock), so a listener calling `get`/iteration on the
        /// same external map self-deadlocks. Do not re-enter from a listener.
        pub fn modificationListenerAdd(self: Self, listener: Listeners.Listener) DbError!void {
            self.inner.listeners_mu.lock();
            defer self.inner.listeners_mu.unlock();
            // addIfAbsent parity: skip a duplicate (ctx+fn) registration.
            for (self.inner.listeners.listeners.items) |l| if (l.eql(listener)) return;
            try self.inner.listeners.add(self.a(), listener);
        }

        /// Remove a previously registered listener (by ctx+fn identity).
        pub fn modificationListenerRemove(self: Self, listener: Listeners.Listener) bool {
            self.inner.listeners_mu.lock();
            defer self.inner.listeners_mu.unlock();
            return self.inner.listeners.remove(listener);
        }

        /// Fire listeners whose `synchronous` flag matches `sync`, against a copied
        /// snapshot (so a listener never runs holding `listeners_mu`, and a
        /// concurrent register/remove is safe). Every matching listener is invoked
        /// even if one errors; the FIRST error is returned afterwards. Keys/values
        /// are borrowed for the call. Cheap fast-path when no listener is registered.
        fn fireListeners(self: Self, sync: bool, key: Key, old_value: ?Val, new_value: ?Val) DbError!void {
            const alloc = self.a();
            var snapshot: []Listeners.Listener = undefined;
            {
                self.inner.listeners_mu.lock();
                defer self.inner.listeners_mu.unlock();
                const items = self.inner.listeners.listeners.items;
                if (items.len == 0) return;
                snapshot = try alloc.dupe(Listeners.Listener, items);
            }
            defer alloc.free(snapshot);
            var first_err: ?DbError = null;
            for (snapshot) |l| {
                if (l.synchronous != sync) continue;
                l.modify(key, old_value, new_value, false) catch |e| {
                    if (first_err == null) first_err = e;
                };
            }
            if (first_err) |e| return e;
        }

        // -------- clone / deinit (lease shared via refcount) --------

        /// A new long-lived handle sharing this map's `Inner` (bumps the
        /// refcount). Each `clone` needs its own `deinit`. A plain by-value copy
        /// of a `BTreeMap` also shares `Inner` but does NOT bump — use that only
        /// for a scoped handoff (e.g. to a worker thread joined before `deinit`);
        /// use `clone` for a handle that outlives the original.
        pub fn clone(self: Self) Self {
            // CAS from a NONZERO count so a clone can never revive an `Inner` that a
            // concurrent last-ref release already transitioned to zero.
            // A zero count means the source handle was already fully
            // released — cloning it is a use-after-free bug in the caller.
            while (true) {
                const cur = self.inner.refcount.load(.monotonic);
                std.debug.assert(cur != 0);
                if (self.inner.refcount.cmpxchgWeak(cur, cur + 1, .acq_rel, .monotonic) == null)
                    return .{ .inner = self.inner };
            }
        }
        /// Number of live handles sharing this `Inner` (clones + the original).
        /// Advisory only — NOT a safe basis for a check-then-free (use
        /// [`closeIfLast`], which is atomic).
        pub fn refCount(self: Self) usize {
            return self.inner.refcount.load(.acquire);
        }
        fn freeInner(inner: *Inner) void {
            inner.store.leaseTable().release(inner.root_recid_recid);
            inner.left_edges.deinit();
            inner.locks.deinit();
            // Free only the registry's backing array — listener CONTEXTS are
            // caller-owned and are NEVER invoked from deinit (§5/§107): a freed
            // context can therefore never be called.
            inner.listeners.deinit(inner.alloc);
            inner.alloc.destroy(inner);
        }
        /// Atomically release THIS handle IFF it is the last reference: CAS the
        /// refcount 1→0 and, only on success, release the lease + free `Inner`,
        /// returning `true`. On failure (other live refs) returns `false` WITHOUT
        /// freeing — the handle stays valid. This linearizes the last-ref DECISION
        /// among independently-owned clones: if any other clone is
        /// live the CAS-from-1 fails, so `closeMap`/`closeSet` return HandlesOpen
        /// and free nothing. CONTRACT LIMIT: it does NOT make cloning a handle that
        /// is CONCURRENTLY undergoing its own final close safe — a `clone` that
        /// loads the refcount just before this frees `Inner` then CASes through a
        /// freed pointer (UAF). Never clone/copy-share a single handle across a
        /// thread that may be closing it; give each thread its own `clone` (see
        /// PORTING-GAPS "raw-handle lifetime contract").
        pub fn closeIfLast(self: Self) bool {
            if (self.inner.refcount.cmpxchgStrong(1, 0, .acq_rel, .monotonic) == null) {
                freeInner(self.inner);
                return true;
            }
            return false;
        }
        /// Drop this handle. The LAST handle (refcount → 0) releases the
        /// lease and frees `Inner`. Requires that no iterator/view derived from
        /// this handle is still live, and that the backing store outlives it.
        pub fn deinit(self: Self) void {
            if (self.inner.refcount.fetchSub(1, .acq_rel) == 1) freeInner(self.inner);
        }
        /// Release this (LAST-ref, never-shared) handle AND best-effort delete the
        /// fresh structural store records it allocated — the root node, the
        /// root-pointer record, and the counter record. Use ONLY on
        /// the error path of a fresh `create` that was never published (no clones,
        /// nothing else references the records). Captures the store + recids BEFORE
        /// `deinit` frees `Inner`.
        pub fn deinitAndDestroy(self: Self) void {
            const store_ = self.inner.store;
            const rrr = self.inner.root_recid_recid;
            const counter = self.inner.counter_recid;
            const root = self.loadRootRecid() catch 0;
            self.deinit();
            if (root != 0) store_.delete(root) catch {};
            store_.delete(rrr) catch {};
            if (counter != 0) store_.delete(counter) catch {};
        }

        /// Free both fields of an owned entry (from iteration/navigation).
        pub fn deinitEntry(self: Self, e: Entry) void {
            self.kf().deinitElem(self.a(), e.key);
            self.vf().deinitElem(self.a(), e.val);
        }
        /// Free a slice of owned entries and the slice itself (from `entries`).
        pub fn deinitEntries(self: Self, es: []Entry) void {
            for (es) |e| self.deinitEntry(e);
            self.a().free(es);
        }

        // -------- construction --------

        /// Create a fresh empty tree over `store`, allocating a new root-pointer
        /// recid and taking an RW lease on it (a second concurrent open of
        /// the same tree fails `AlreadyOpen`). `alloc` becomes the map's one
        /// allocator: every value/entry it later returns is owned by `alloc`.
        /// `key_format`/`value_format` are stored by value (borrowed schema
        /// slices, if any, must outlive the map). `max_node_size >= 4`. The
        /// caller owns the returned handle and must `deinit` it (which releases
        /// the lease). `store` must outlive the map.
        pub fn create(alloc: Allocator, store_: *S, key_format: KF, value_format: VF, max_node_size: usize) DbError!Self {
            return createCounter(alloc, store_, key_format, value_format, max_node_size, false);
        }

        /// `create` with an optional O(1) size counter (Feature A). When
        /// `counter_enable` is true a packed-long counter record (initially 0) is
        /// allocated; `sizeLong` then reads it in O(1). The counter recid is
        /// exposed via `counterRecid()` for reopening.
        pub fn createCounter(alloc: Allocator, store_: *S, key_format: KF, value_format: VF, max_node_size: usize, counter_enable: bool) DbError!Self {
            // Defense in depth: a persisted/configured value outside the legal
            // range is rejected (never a `reached unreachable code` panic).
            // The DB maker maps a create-time value to
            // `WrongConfiguration` before this.
            if (max_node_size < MIN_MAX_NODE_SIZE or max_node_size > MAX_MAX_NODE_SIZE) return error.DataCorruption;
            const nvf_inst: NVF = if (value_inline) value_format else NVF.instance;
            const ns = NodeSer.init(key_format, nvf_inst);
            const empty_keys = try key_format.empty(alloc);
            const empty_vals = nvf_inst.empty(alloc) catch |e| {
                key_format.deinitGroup(alloc, empty_keys);
                return e;
            };
            var leaf = NodeT{ .flags = LEFT | RIGHT, .link = 0, .keys = empty_keys, .body = .{ .leaf = .{ .values = empty_vals, .fence = null } } };
            const root_recid = store_.put(NodeT, alloc, leaf, ns) catch |e| {
                leaf.deinit(alloc, key_format, nvf_inst);
                return e;
            };
            leaf.deinit(alloc, key_format, nvf_inst);
            const counter_recid: u64 = if (counter_enable) try store_.put(i64, alloc, @as(i64, 0), LONG) else 0;
            const rrr = try store_.put(i64, alloc, @as(i64, @intCast(root_recid)), LONG);
            return openCounter(alloc, store_, rrr, key_format, value_format, max_node_size, counter_recid);
        }

        /// Reopen an existing tree given its root-pointer recid (the value
        /// `create` allocated). Takes the RW lease, then walks and validates the
        /// left spine — a structurally-broken root (not `LEFT|RIGHT`, zero
        /// root-pointer, an over-long spine) fails `DataCorruption` at open. Same
        /// ownership contract as `create`. On a tx store the root cache is
        /// disabled and the structural generation is snapshotted for
        /// rollback-aware left-edge rebuilds.
        pub fn open(alloc: Allocator, store_: *S, root_recid_recid: u64, key_format: KF, value_format: VF, max_node_size: usize) DbError!Self {
            return openCounter(alloc, store_, root_recid_recid, key_format, value_format, max_node_size, 0);
        }

        /// `open` wiring up an O(1) size counter when `counter_recid > 0` (the
        /// value returned by `counterRecid()` at create time); `counter_recid == 0`
        /// means no counter (Feature A). Same ownership/lease contract as `open`.
        pub fn openCounter(alloc: Allocator, store_: *S, root_recid_recid: u64, key_format: KF, value_format: VF, max_node_size: usize, counter_recid: u64) DbError!Self {
            // A corrupt persisted maxNodeSize must not panic.
            if (max_node_size < MIN_MAX_NODE_SIZE or max_node_size > MAX_MAX_NODE_SIZE) return error.DataCorruption;
            if (root_recid_recid == 0) return error.DataCorruption;
            // A read-only wrapper takes a READ-only lease so RO+RO opens are allowed
            // (mutation is still rejected by the wrapper — review C1). A writable
            // store takes the RW lease (second writable open → AlreadyOpen).
            const lease_kind: storemod.LeaseKind = if (storemod.isReadOnly(S, store_)) .read_only else .read_write;
            try store_.leaseTable().acquire(root_recid_recid, lease_kind);
            errdefer store_.leaseTable().release(root_recid_recid);

            const thread_safe = store_.isThreadSafe();
            const root_cacheable = !store_.isTx();
            const init_gen: u64 = if (comptime storemod.supportsTx(S)) store_.structuralGeneration() else 0;

            var locks = try NodeLockTable.init(alloc, thread_safe);
            errdefer locks.deinit();
            const empty0 = try alloc.alloc(u64, 0);
            // `Edges.init` takes ownership of `empty0` even on failure (its OOM
            // path frees it via `freeEdges`), so no extra free here.
            var edges = try Edges.init(alloc, empty0, freeEdges);
            errdefer edges.deinit();

            const inner = try alloc.create(Inner);
            errdefer alloc.destroy(inner);
            inner.* = .{
                .alloc = alloc,
                .store = store_,
                .kf = key_format,
                .vf = value_format,
                .max_node_size = max_node_size,
                .root_recid_recid = root_recid_recid,
                .counter_recid = counter_recid,
                .root_cacheable = root_cacheable,
                .locks = locks,
                .ext_lock = .{},
                .listeners = .{},
                .listeners_mu = .{},
                .left_edges = edges,
                .edges_seq = std.atomic.Value(u32).init(0),
                .cached_root = std.atomic.Value(u64).init(0),
                .poisoned = std.atomic.Value(bool).init(false),
                .last_struct_gen = std.atomic.Value(u64).init(init_gen),
                .refcount = std.atomic.Value(usize).init(1),
            };
            // `locks`/`edges` are bit-copied into `inner` but share their backing
            // allocations; the local errdefers above free that backing exactly
            // once on any failure below (inner itself is only `destroy`d, never
            // field-deinit'd, so there is no double free). The lease errdefer at
            // the top releases the lease.
            const map = Self{ .inner = inner };
            const built = try map.buildLeftEdges();
            try inner.left_edges.store(built); // frees `built` itself on OOM
            return map;
        }

        fn freeEdges(alloc: Allocator, v: *[]u64) void {
            alloc.free(v.*);
        }

        /// Walk the leftmost spine root→leaf; result index 0 = leaf level (owned).
        fn buildLeftEdges(self: Self) DbError![]u64 {
            const alloc = self.a();
            var cyc = CycleGuard.init(alloc, CYCLE_DESCENT_SOFT);
            defer cyc.deinit();
            var spine: std.ArrayListUnmanaged(u64) = .empty;
            errdefer spine.deinit(alloc);
            var current = try self.loadRootRecid();
            try spine.append(alloc, current);
            var n = try self.load(current);
            // A healthy root is ALWAYS both LEFT and RIGHT; anything else is an
            // incomplete root-grow (a damaged store) — reject at open.
            if ((n.flags & (LEFT | RIGHT)) != (LEFT | RIGHT)) {
                n.deinit(alloc, self.kf(), self.nvf());
                return error.DataCorruption;
            }
            while (n.isDir()) {
                cyc.visit(current) catch |e| {
                    n.deinit(alloc, self.kf(), self.nvf());
                    return e;
                };
                const child0 = n.children()[0];
                n.deinit(alloc, self.kf(), self.nvf());
                current = child0;
                try spine.append(alloc, current);
                n = try self.load(current);
            }
            n.deinit(alloc, self.kf(), self.nvf());
            std.mem.reverse(u64, spine.items);
            return spine.toOwnedSlice(alloc);
        }

        fn loadRootRecid(self: Self) DbError!u64 {
            const r = (try self.store().get(i64, self.a(), self.inner.root_recid_recid, LONG)) orelse return error.DataCorruption;
            if (r <= 0) return error.DataCorruption;
            return @intCast(r);
        }

        /// Resync `left_edges` with the tx-visible tree after a rollback shrank
        /// it. No-op (zero cost) for non-tx stores.
        fn refreshLeftEdgesIfTx(self: Self) DbError!void {
            if (comptime storemod.supportsTx(S)) {
                if (self.inner.root_cacheable) return;
                const gen = self.store().structuralGeneration();
                if (gen == self.inner.last_struct_gen.load(.acquire)) return;
                try self.checkPoison();
                const built = try self.buildLeftEdges();
                try self.inner.left_edges.store(built);
                self.bumpEdges();
                self.inner.last_struct_gen.store(gen, .release);
            }
        }

        fn bumpEdges(self: Self) void {
            _ = self.inner.edges_seq.fetchAdd(1, .release);
            std.Thread.Futex.wake(&self.inner.edges_seq, std.math.maxInt(u32));
        }

        inline fn checkPoison(self: Self) DbError!void {
            if (self.inner.poisoned.load(.acquire)) return error.DataCorruption;
        }

        fn isCurrentRoot(self: Self, recid: u64) DbError!bool {
            return (try self.loadRootRecid()) == recid;
        }

        fn rootRecid(self: Self) DbError!u64 {
            try self.checkPoison();
            const r = self.inner.cached_root.load(.acquire);
            if (r != 0) return r;
            const fresh = try self.loadRootRecid();
            if (self.inner.root_cacheable) self.inner.cached_root.store(fresh, .release);
            return fresh;
        }

        fn load(self: Self, recid: u64) DbError!NodeT {
            if (recid == 0) return error.DataCorruption;
            return (try self.store().get(NodeT, self.a(), recid, self.nodeSer())) orelse error.DataCorruption;
        }

        fn lockInto(self: Self, recid: u64, g: *NodeGuard) DbError!void {
            g.* = .{ .table = &self.inner.locks, .recid = recid, .held = false };
            try self.inner.locks.lock(recid);
            g.held = true;
        }

        fn storeUpdate(self: Self, recid: u64, node: *const NodeT) DbError!void {
            return self.store().update(NodeT, self.a(), recid, node.*, self.nodeSer());
        }
        fn storePut(self: Self, node: *const NodeT) DbError!u64 {
            return self.store().put(NodeT, self.a(), node.*, self.nodeSer());
        }

        // -------- read path (push-down) --------
        //
        // Readers descend via `store.read` push-down actions and acquire NO node
        // locks (only the short pin mutex for `left_edges`); safe to call
        // concurrently with writers and other readers on a thread-safe store.
        // `key` is borrowed. The returned `?Val` is OWNED by the map allocator
        // (free with `vf().deinitElem(map.a(), v)`).

        /// Look up `key`; owned value or `null` if absent. For an external-value
        /// map the whole descend + value-record read runs under the external read
        /// barrier so a concurrent remove cannot delete+reuse the value recid.
        pub fn get(self: Self, key: *const Key) DbError!?Val {
            if (!value_inline) self.inner.ext_lock.lockShared();
            defer if (!value_inline) self.inner.ext_lock.unlockShared();
            var action = GetAction(KF, NVF).init(self.a(), self.kf(), self.nvf(), key);
            defer action.deinitValue();
            try self.pushDown(key, &action);
            if (action.found) {
                const stored = action.value.?;
                action.value = null;
                // For inline `stored` IS the owned Val; for external it is the recid
                // — expand it (still under the read barrier), then free the recid.
                if (value_inline) return stored;
                defer self.nvf().deinitElem(self.a(), stored);
                return try self.expandStored(stored);
            }
            return null;
        }

        /// `true` iff `key` is present (no value materialized).
        pub fn containsKey(self: Self, key: *const Key) DbError!bool {
            var action = GetAction(KF, NVF).init(self.a(), self.kf(), self.nvf(), key);
            defer action.deinitValue();
            try self.pushDown(key, &action);
            return action.found;
        }

        fn pushDown(self: Self, key: *const Key, action: *GetAction(KF, NVF)) DbError!void {
            _ = key;
            var cyc = CycleGuard.init(self.a(), CYCLE_DESCENT_SOFT);
            defer cyc.deinit();
            var current = try self.rootRecid();
            while (current != 0) {
                try cyc.visit(current);
                const rr = action.recordRead();
                const next = try self.store().read(current, rr);
                current = @bitCast(next);
            }
        }

        // -------- writer helpers --------

        fn routeChild(self: Self, dir: *const NodeT, key: Key) ?usize {
            const child_idx = searchIdx(self.kf().search(&dir.keys, key));
            if (child_idx >= dir.children().len) return null;
            return child_idx;
        }
        fn beyondLeaf(self: Self, leaf: *const NodeT, key: Key) bool {
            if (leaf.isRight()) return false;
            switch (leaf.body) {
                .leaf => |l| {
                    if (l.fence) |f| {
                        return switch (self.kf().search(&f, key)) {
                            .insert => |x| x == 1,
                            .found => false,
                        };
                    }
                    return false;
                },
                .dir => return false,
            }
        }
        fn beyondDir(self: Self, dir: *const NodeT, key: Key) bool {
            return switch (self.kf().search(&dir.keys, key)) {
                .insert => |ins| ins == self.kf().size(&dir.keys),
                .found => false,
            };
        }

        /// Lock `recid`, load it, and move right (hand-over-hand, one lock held)
        /// until the node covers `key`. Returns the covering node (caller owns);
        /// its lock is HELD in `guard` on return.
        fn lockCovering(self: Self, recid: u64, key: Key, dir_level: bool, guard: *NodeGuard) DbError!NodeT {
            const alloc = self.a();
            var cyc = CycleGuard.init(alloc, CYCLE_DESCENT_SOFT);
            defer cyc.deinit();
            try self.lockInto(recid, guard);
            errdefer guard.release();
            var n = try self.load(guard.recid);
            while (true) {
                const beyond = if (dir_level) (!n.isRight() and self.beyondDir(&n, key)) else self.beyondLeaf(&n, key);
                if (!beyond) return n;
                const next = n.link;
                n.deinit(alloc, self.kf(), self.nvf());
                cyc.visit(next) catch |e| return e;
                guard.release();
                try self.lockInto(next, guard);
                n = try self.load(next);
            }
        }

        /// Unlocked descent to the leaf routing `key`, then `lockCovering` to the
        /// real owner. Returns that LOCKED leaf (in `guard`); `parent_stack`, when
        /// non-null, is filled with the covered parent path for split propagation.
        fn lockLeaf(self: Self, key: Key, parent_stack: ?*std.ArrayListUnmanaged(u64), guard: *NodeGuard) DbError!NodeT {
            const alloc = self.a();
            var cyc = CycleGuard.init(alloc, CYCLE_DESCENT_SOFT);
            defer cyc.deinit();
            var current = try self.rootRecid();
            var n = try self.load(current);
            while (n.isDir()) {
                cyc.visit(current) catch |e| {
                    n.deinit(alloc, self.kf(), self.nvf());
                    return e;
                };
                const routed = self.routeChild(&n, key);
                var next: u64 = undefined;
                if (routed) |child_idx| {
                    if (parent_stack) |stack| {
                        stack.append(alloc, current) catch |e| {
                            n.deinit(alloc, self.kf(), self.nvf());
                            return e;
                        };
                    }
                    next = n.children()[child_idx];
                } else {
                    next = n.link;
                }
                n.deinit(alloc, self.kf(), self.nvf());
                current = next;
                n = try self.load(current);
            }
            n.deinit(alloc, self.kf(), self.nvf());
            return self.lockCovering(current, key, false, guard);
        }

        // -------- put / putIfAbsent --------
        //
        // Writers are Lehman-Yao, holding ≤1 node lock at a time. On a
        // thread-safe non-tx store any number may run concurrently; a tx store
        // (StoreWAL) is single-writer. `key` and `value` are BORROWED — the map
        // deep-clones what it keeps, so the caller still owns (and must free) the
        // arguments it passed. Any returned displaced `?Val` is OWNED by the
        // caller.

        /// Insert/replace `key`; returns the OWNED previous value, or `null`.
        pub fn put(self: Self, key: Key, value: Val) DbError!?Val {
            return self.putInternal(key, value, false);
        }
        /// Insert only if absent; returns the OWNED existing value (unchanged) on
        /// a collision, else `null`.
        pub fn putIfAbsent(self: Self, key: Key, value: Val) DbError!?Val {
            return self.putInternal(key, value, true);
        }
        /// `put` discarding (freeing) any displaced value.
        pub fn putOnly(self: Self, key: Key, value: Val) DbError!void {
            const old = try self.putInternal(key, value, false);
            if (old) |o| self.vf().deinitElem(self.a(), o);
        }

        fn putInternal(self: Self, key: Key, value: Val, only_if_absent: bool) DbError!?Val {
            try self.refreshLeftEdgesIfTx();
            const alloc = self.a();
            const kformat = self.kf();
            const nvformat = self.nvf();
            var stack: std.ArrayListUnmanaged(u64) = .empty;
            defer stack.deinit(alloc);
            var guard: NodeGuard = undefined;
            var n = try self.lockLeaf(key, &stack, &guard);
            var released = false;
            var n_owned = true;
            defer if (!released) guard.release();
            defer if (n_owned) n.deinit(alloc, kformat, nvformat);
            const current = guard.recid;
            const pos = kformat.search(&n.keys, key);
            const leaf = switch (n.body) {
                .leaf => |*l| l,
                .dir => return error.DataCorruption,
            };
            switch (pos) {
                .found => |p| {
                    const old = try self.userValueGet(&leaf.values, p);
                    if (only_if_absent) return old; // putIfAbsent: no mutation, no fire
                    errdefer self.vf().deinitElem(alloc, old);
                    if (value_inline) {
                        const new_vals = try nvformat.set(alloc, &leaf.values, p, value);
                        var fence_clone: ?KF.Group = null;
                        if (leaf.fence) |f| {
                            fence_clone = kformat.cloneGroup(alloc, &f) catch |e| {
                                nvformat.deinitGroup(alloc, new_vals);
                                return e;
                            };
                        }
                        const keys_clone = kformat.cloneGroup(alloc, &n.keys) catch |e| {
                            if (fence_clone) |fc| kformat.deinitGroup(alloc, fc);
                            nvformat.deinitGroup(alloc, new_vals);
                            return e;
                        };
                        var updated = NodeT{ .flags = n.flags, .link = n.link, .keys = keys_clone, .body = .{ .leaf = .{ .values = new_vals, .fence = fence_clone } } };
                        defer updated.deinit(alloc, kformat, nvformat);
                        try self.storeUpdate(current, &updated);
                    } else {
                        // external: update the value record in place; node unchanged.
                        const recid = try self.recidAt(&leaf.values, p);
                        try self.store().update(Val, alloc, recid, value, self.velem());
                    }
                    // update of an existing key: counter unchanged. Fire sync under
                    // the leaf lock, unlock ALWAYS, then fire deferred (skipped on a
                    // sync-listener error — matches Java).
                    const sync_r = self.fireListeners(true, key, old, value);
                    guard.release();
                    released = true;
                    try sync_r;
                    try self.fireListeners(false, key, old, value);
                    return old;
                },
                .insert => |ip| {
                    // external: allocate the value record first; on any pre-publish
                    // failure delete it so the recid never leaks. `published` gates
                    // the cleanup and, being comptime-true for inline maps, elides
                    // the `store.delete` call entirely there.
                    const stored = try self.storeNewStored(value);
                    var published = value_inline;
                    errdefer if (!published) {
                        if (!value_inline) self.store().delete(@bitCast(stored)) catch {};
                    };
                    const new_keys = try kformat.insert(alloc, &n.keys, ip, key);
                    const new_vals = nvformat.insert(alloc, &leaf.values, ip, stored) catch |e| {
                        kformat.deinitGroup(alloc, new_keys);
                        return e;
                    };
                    if (kformat.size(&new_keys) <= self.inner.max_node_size) {
                        var fence_clone: ?KF.Group = null;
                        if (leaf.fence) |f| {
                            fence_clone = kformat.cloneGroup(alloc, &f) catch |e| {
                                kformat.deinitGroup(alloc, new_keys);
                                nvformat.deinitGroup(alloc, new_vals);
                                return e;
                            };
                        }
                        var updated = NodeT{ .flags = n.flags, .link = n.link, .keys = new_keys, .body = .{ .leaf = .{ .values = new_vals, .fence = fence_clone } } };
                        defer updated.deinit(alloc, kformat, nvformat);
                        try self.storeUpdate(current, &updated);
                        published = true; // the tree owns the value record now
                        // counter BEFORE listeners (mutation committed), unlock ALWAYS.
                        try self.addToCounter(1);
                        const sync_r = self.fireListeners(true, key, null, value);
                        guard.release();
                        released = true;
                        try sync_r;
                        try self.fireListeners(false, key, null, value);
                        return null;
                    }
                    // overfull: split publishes the value record; hand it over.
                    // ORPHAN NOTE (deliberate, Java-parity): `published` is set
                    // before the split so the caller's errdefer no longer deletes
                    // the new external value record. If the split then fails before
                    // republishing the left leaf (e.g. a store/alloc error), that
                    // value record — and sibling B if already written — are orphaned
                    // in the store. This is garbage, not corruption: the tree stays
                    // consistent and nothing references the orphan. Non-transactional
                    // stores cannot roll it back; WAL callers can. Gap-listed.
                    published = true;
                    released = true;
                    n_owned = false; // split reads `n`, we free it after
                    const result = self.splitLeafAndPropagate(&guard, &n, new_keys, new_vals, &stack, key, value);
                    n.deinit(alloc, kformat, nvformat);
                    guard.release();
                    try result; // structural (or listener) error → skip deferred fire
                    try self.fireListeners(false, key, null, value);
                    return null;
                },
            }
        }

        /// Split the (locked) overfull leaf and propagate separators upward. The
        /// right sibling B is written FIRST (referent before referrer), the left
        /// half republished with `link=q` (the insert's searchable commit point).
        /// Takes ownership of `keys`/`values` (frees them; `values` is the NODE
        /// value group — recids for an external map).
        ///
        /// SYNC-LISTENER FIRE POINT (Java 234e8ff/0f2e822): after A republishes but
        /// before its lock releases — ordering-safe even when the inserted key
        /// landed in B, because until the separator reaches the parent every locking
        /// path to B goes through A's link and `lockCovering` is hand-over-hand. The
        /// counter is bumped first, the unlock is unconditional, and a throwing
        /// listener must NOT skip propagation: its error is captured, separator/root
        /// propagation is COMPLETED, and only then rethrown (a structural propagation
        /// error is primary; the captured listener error is secondary and — since
        /// Zig errors carry no payload — dropped in favour of the structural one).
        fn splitLeafAndPropagate(self: Self, guard: *NodeGuard, orig: *const NodeT, keys: KF.Group, values: NVF.Group, stack: *std.ArrayListUnmanaged(u64), fire_key: Key, fire_value: Val) DbError!void {
            const alloc = self.a();
            const kformat = self.kf();
            const vformat = self.nvf();
            defer kformat.deinitGroup(alloc, keys);
            defer vformat.deinitGroup(alloc, values);
            const recid = guard.recid;
            const was_root = ((orig.flags & (LEFT | RIGHT)) == (LEFT | RIGHT)) and (try self.isCurrentRoot(recid));
            const total = kformat.size(&keys);
            const hh = total / 2;

            // right sibling B (keeps RIGHT status of the original)
            const b_keys = try kformat.copyRange(alloc, &keys, hh, total);
            const b_values = vformat.copyRange(alloc, &values, hh, total) catch |e| {
                kformat.deinitGroup(alloc, b_keys);
                return e;
            };
            var b_fence: ?KF.Group = null;
            if (orig.body.leaf.fence) |f| {
                b_fence = kformat.cloneGroup(alloc, &f) catch |e| {
                    kformat.deinitGroup(alloc, b_keys);
                    vformat.deinitGroup(alloc, b_values);
                    return e;
                };
            }
            var bnode = NodeT{ .flags = orig.flags & ~@as(i32, LEFT), .link = orig.link, .keys = b_keys, .body = .{ .leaf = .{ .values = b_values, .fence = b_fence } } };
            const q = self.storePut(&bnode) catch |e| {
                bnode.deinit(alloc, kformat, vformat);
                return e;
            };
            bnode.deinit(alloc, kformat, vformat);

            const sep = try kformat.get(alloc, &keys, hh - 1);
            defer kformat.deinitElem(alloc, sep);

            // left half A (link=q, drops RIGHT, fence=[sep])
            var afence_arr = [_]Key{sep};
            const a_fence = try kformat.fromSlice(alloc, &afence_arr);
            const a_keys = kformat.copyRange(alloc, &keys, 0, hh) catch |e| {
                kformat.deinitGroup(alloc, a_fence);
                return e;
            };
            const a_values = vformat.copyRange(alloc, &values, 0, hh) catch |e| {
                kformat.deinitGroup(alloc, a_fence);
                kformat.deinitGroup(alloc, a_keys);
                return e;
            };
            var anode = NodeT{ .flags = orig.flags & ~@as(i32, RIGHT), .link = q, .keys = a_keys, .body = .{ .leaf = .{ .values = a_values, .fence = a_fence } } };
            self.storeUpdate(recid, &anode) catch |e| {
                anode.deinit(alloc, kformat, vformat);
                return e;
            };
            anode.deinit(alloc, kformat, vformat);

            // Split published & searchable via A's link. Bump the counter (mutation
            // committed), fire sync listeners UNDER A's lock, then release it — a
            // throwing listener is captured, not rethrown yet.
            var pending_err: ?DbError = null;
            self.addToCounter(1) catch |e| {
                pending_err = e;
            };
            if (pending_err == null) {
                self.fireListeners(true, fire_key, null, fire_value) catch |e| {
                    pending_err = e;
                };
            }
            guard.release(); // drop child lock (always, before propagation)
            self.propagateSplit(recid, q, sep, was_root, stack, 1) catch |pe| {
                self.inner.poisoned.store(true, .release);
                return pe; // structural error is primary
            };
            if (pending_err) |e| return e; // rethrow captured listener/counter error
        }

        const Ascend = struct { old_child: u64, new_child: u64, sep: Key, child_was_root: bool, level: usize };
        const StepResult = union(enum) { done, ascend: Ascend };

        /// Insert (`sep` → `new_child` right of `old_child`) into the parent level,
        /// splitting upward as needed. No node lock held on entry.
        fn propagateSplit(self: Self, old_child: u64, new_child: u64, sep_in: Key, child_was_root: bool, stack: *std.ArrayListUnmanaged(u64), level: usize) DbError!void {
            const alloc = self.a();
            const kformat = self.kf();
            var cur = Ascend{
                .old_child = old_child,
                .new_child = new_child,
                .sep = try kformat.cloneElem(alloc, sep_in),
                .child_was_root = child_was_root,
                .level = level,
            };
            while (true) {
                const res = self.propagateStep(&cur, stack) catch |e| {
                    kformat.deinitElem(alloc, cur.sep);
                    return e;
                };
                kformat.deinitElem(alloc, cur.sep);
                switch (res) {
                    .done => return,
                    .ascend => |nx| cur = nx,
                }
            }
        }

        fn propagateStep(self: Self, cur: *const Ascend, stack: *std.ArrayListUnmanaged(u64)) DbError!StepResult {
            const alloc = self.a();
            const kformat = self.kf();
            // dir/interior nodes only: the "value" slot is child recids, so the
            // node value format is the same node format regardless of value_inline.
            const vformat = self.nvf();

            if (cur.child_was_root) {
                // grow the tree by one level
                var rk_arr = [_]Key{cur.sep};
                const root_keys = try kformat.fromSlice(alloc, &rk_arr);
                const kids = alloc.alloc(u64, 2) catch |e| {
                    kformat.deinitGroup(alloc, root_keys);
                    return e;
                };
                kids[0] = cur.old_child;
                kids[1] = cur.new_child;
                var new_root = NodeT{ .flags = DIR | LEFT | RIGHT, .link = 0, .keys = root_keys, .body = .{ .dir = kids } };
                const new_root_recid = self.storePut(&new_root) catch |e| {
                    new_root.deinit(alloc, kformat, vformat);
                    return e;
                };
                new_root.deinit(alloc, kformat, vformat);

                var rguard: NodeGuard = undefined;
                try self.lockInto(self.inner.root_recid_recid, &rguard);
                defer rguard.release();
                try self.store().update(i64, alloc, self.inner.root_recid_recid, @as(i64, @intCast(new_root_recid)), LONG);
                if (self.inner.root_cacheable) self.inner.cached_root.store(new_root_recid, .release);

                // append exactly one level; a mismatch is a stale structural cache.
                var eg: Edges.Guard = undefined;
                self.inner.left_edges.loadInto(&eg);
                const le = eg.get().*;
                if (le.len != cur.level) {
                    eg.release();
                    self.inner.poisoned.store(true, .release);
                    return error.DataCorruption;
                }
                const grown = alloc.alloc(u64, le.len + 1) catch |e| {
                    eg.release();
                    return e;
                };
                @memcpy(grown[0..le.len], le);
                grown[le.len] = new_root_recid;
                eg.release();
                try self.inner.left_edges.store(grown);
                self.bumpEdges();
                return .done;
            }

            const start = if (stack.items.len == 0) try self.leftEdge(cur.level) else stack.pop().?;
            var pguard: NodeGuard = undefined;
            var n = try self.lockCovering(start, cur.sep, true, &pguard);
            errdefer {
                n.deinit(alloc, kformat, vformat);
                pguard.release();
            }
            const current = pguard.recid;
            const current_is_root = ((n.flags & (LEFT | RIGHT)) == (LEFT | RIGHT)) and (try self.isCurrentRoot(current));
            const pos = kformat.search(&n.keys, cur.sep);
            const ip = switch (pos) {
                .insert => |x| x,
                .found => return error.DataCorruption, // duplicate parent separator
            };
            if (n.body != .dir) return error.DataCorruption;
            const children = n.body.dir;
            const new_keys = try kformat.insert(alloc, &n.keys, ip, cur.sep);
            const new_children = insertLong(alloc, children, ip + 1, cur.new_child) catch |e| {
                kformat.deinitGroup(alloc, new_keys);
                return e;
            };
            const keys_len = kformat.size(&new_keys);
            if (keys_len <= self.inner.max_node_size) {
                var updated = NodeT{ .flags = n.flags, .link = n.link, .keys = new_keys, .body = .{ .dir = new_children } };
                self.storeUpdate(current, &updated) catch |e| {
                    updated.deinit(alloc, kformat, vformat);
                    return e;
                };
                updated.deinit(alloc, kformat, vformat);
                n.deinit(alloc, kformat, vformat);
                pguard.release();
                return .done;
            }
            // split the dir node
            const hh = keys_len / 2;
            const b_keys = kformat.copyRange(alloc, &new_keys, hh, keys_len) catch |e| {
                kformat.deinitGroup(alloc, new_keys);
                alloc.free(new_children);
                return e;
            };
            const b_children = alloc.dupe(u64, new_children[hh..]) catch |e| {
                kformat.deinitGroup(alloc, new_keys);
                alloc.free(new_children);
                kformat.deinitGroup(alloc, b_keys);
                return e;
            };
            var bnode = NodeT{ .flags = n.flags & ~@as(i32, LEFT), .link = n.link, .keys = b_keys, .body = .{ .dir = b_children } };
            const q = self.storePut(&bnode) catch |e| {
                bnode.deinit(alloc, kformat, vformat);
                kformat.deinitGroup(alloc, new_keys);
                alloc.free(new_children);
                return e;
            };
            bnode.deinit(alloc, kformat, vformat);
            const parent_sep = kformat.get(alloc, &new_keys, hh - 1) catch |e| {
                kformat.deinitGroup(alloc, new_keys);
                alloc.free(new_children);
                return e;
            };
            const a_keys = kformat.copyRange(alloc, &new_keys, 0, hh) catch |e| {
                kformat.deinitElem(alloc, parent_sep);
                kformat.deinitGroup(alloc, new_keys);
                alloc.free(new_children);
                return e;
            };
            const a_children = alloc.dupe(u64, new_children[0..hh]) catch |e| {
                kformat.deinitElem(alloc, parent_sep);
                kformat.deinitGroup(alloc, a_keys);
                kformat.deinitGroup(alloc, new_keys);
                alloc.free(new_children);
                return e;
            };
            var anode = NodeT{ .flags = n.flags & ~@as(i32, RIGHT), .link = q, .keys = a_keys, .body = .{ .dir = a_children } };
            self.storeUpdate(current, &anode) catch |e| {
                kformat.deinitElem(alloc, parent_sep);
                anode.deinit(alloc, kformat, vformat);
                kformat.deinitGroup(alloc, new_keys);
                alloc.free(new_children);
                return e;
            };
            anode.deinit(alloc, kformat, vformat);
            kformat.deinitGroup(alloc, new_keys);
            alloc.free(new_children);
            n.deinit(alloc, kformat, vformat);
            pguard.release();
            return .{ .ascend = .{ .old_child = current, .new_child = q, .sep = parent_sep, .child_was_root = current_is_root, .level = cur.level + 1 } };
        }

        /// Left-edge recid of `level`; spins (parking on the edges counter) while a
        /// concurrent root split creating this level is between publishing the
        /// child and appending here. Bails if the map was poisoned.
        fn leftEdge(self: Self, level: usize) DbError!u64 {
            while (true) {
                const seq = self.inner.edges_seq.load(.acquire);
                var eg: Edges.Guard = undefined;
                self.inner.left_edges.loadInto(&eg);
                const le = eg.get().*;
                if (level < le.len) {
                    const r = le[level];
                    eg.release();
                    return r;
                }
                eg.release();
                try self.checkPoison();
                std.Thread.Futex.timedWait(&self.inner.edges_seq, seq, 100_000) catch {};
            }
        }

        // -------- remove / replace --------
        //
        // `key`/`value` args are BORROWED. `removeIf`/`replaceIf` compare with
        // the value format's LOGICAL `equalsElem` (D1), not byte equality.
        // Removal does not merge/rebalance nodes (mapdb lineage); it never
        // shrinks the tree height. Returned displaced values are OWNED.

        /// Remove `key`; returns the OWNED removed value, or `null` if absent.
        pub fn remove(self: Self, key: *const Key) DbError!?Val {
            return self.removeInternal(key, null);
        }
        /// Remove only if the current value logically equals `value`; frees the
        /// removed value. `true` iff a matching entry was removed.
        pub fn removeIf(self: Self, key: *const Key, value: *const Val) DbError!bool {
            const r = try self.removeInternal(key, value);
            if (r) |old| {
                self.vf().deinitElem(self.a(), old);
                return true;
            }
            return false;
        }
        /// Remove `key`, freeing any removed value; `true` iff it was present.
        pub fn removeOnly(self: Self, key: *const Key) DbError!bool {
            const r = try self.removeInternal(key, null);
            if (r) |old| {
                self.vf().deinitElem(self.a(), old);
                return true;
            }
            return false;
        }

        fn removeInternal(self: Self, key: *const Key, expected: ?*const Val) DbError!?Val {
            // External maps hold the write barrier across node-delete + record-delete
            // so a lock-free reader can never decode a deleted-then-reused value
            // recid. The counter/sync listeners run inside; the deferred listeners
            // run AFTER the barrier (and node lock) release — matching Java.
            var old: ?Val = null;
            if (!value_inline) {
                self.inner.ext_lock.lock();
                old = self.removeUnderBarrier(key, expected) catch |e| {
                    self.inner.ext_lock.unlock();
                    return e;
                };
                self.inner.ext_lock.unlock();
            } else {
                old = try self.removeUnderBarrier(key, expected);
            }
            if (old) |o| {
                self.fireListeners(false, key.*, o, null) catch |e| {
                    self.vf().deinitElem(self.a(), o);
                    return e;
                };
            }
            return old;
        }

        fn removeUnderBarrier(self: Self, key: *const Key, expected: ?*const Val) DbError!?Val {
            const alloc = self.a();
            const kformat = self.kf();
            const nvformat = self.nvf();
            var guard: NodeGuard = undefined;
            var n = try self.lockLeaf(key.*, null, &guard);
            var unlocked = false;
            defer if (!unlocked) guard.release();
            defer n.deinit(alloc, kformat, nvformat);
            const current = guard.recid;
            const pos = kformat.search(&n.keys, key.*);
            const leaf = switch (n.body) {
                .leaf => |*l| l,
                .dir => return error.DataCorruption,
            };
            const p = switch (pos) {
                .found => |x| x,
                .insert => return null,
            };
            const old = try self.userValueGet(&leaf.values, p);
            errdefer self.vf().deinitElem(alloc, old);
            if (expected) |exp| {
                if (!self.vf().equalsElem(old, exp.*)) {
                    self.vf().deinitElem(alloc, old);
                    return null;
                }
            }
            const ext_recid: u64 = if (value_inline) 0 else try self.recidAt(&leaf.values, p);
            const new_keys = try kformat.delete(alloc, &n.keys, p);
            const new_vals = nvformat.delete(alloc, &leaf.values, p) catch |e| {
                kformat.deinitGroup(alloc, new_keys);
                return e;
            };
            var fence_clone: ?KF.Group = null;
            if (leaf.fence) |f| {
                fence_clone = kformat.cloneGroup(alloc, &f) catch |e| {
                    kformat.deinitGroup(alloc, new_keys);
                    nvformat.deinitGroup(alloc, new_vals);
                    return e;
                };
            }
            var updated = NodeT{ .flags = n.flags, .link = n.link, .keys = new_keys, .body = .{ .leaf = .{ .values = new_vals, .fence = fence_clone } } };
            defer updated.deinit(alloc, kformat, nvformat);
            try self.storeUpdate(current, &updated);
            if (!value_inline) try self.store().delete(ext_recid); // free the value record
            // counter BEFORE listeners (mutation committed), unlock ALWAYS.
            try self.addToCounter(-1);
            const sync_r = self.fireListeners(true, key.*, old, null);
            guard.release();
            unlocked = true;
            try sync_r; // on error: errdefer frees old, skips deferred fire
            return old;
        }

        /// Replace an EXISTING key's value (`new_value` borrowed, cloned in);
        /// returns the OWNED previous value, or `null` if the key is absent (no
        /// insert). CAS-style: evaluated under the covering leaf lock.
        pub fn replace(self: Self, key: *const Key, value: Val) DbError!?Val {
            return self.replaceInternal(key, null, value);
        }
        /// Replace only if the current value logically equals `old_value`; frees
        /// the previous value. `true` iff the swap happened.
        pub fn replaceIf(self: Self, key: *const Key, old_value: *const Val, new_value: Val) DbError!bool {
            const r = try self.replaceInternal(key, old_value, new_value);
            if (r) |old| {
                self.vf().deinitElem(self.a(), old);
                return true;
            }
            return false;
        }

        fn replaceInternal(self: Self, key: *const Key, expected: ?*const Val, new_value: Val) DbError!?Val {
            const alloc = self.a();
            const kformat = self.kf();
            const nvformat = self.nvf();
            var guard: NodeGuard = undefined;
            var n = try self.lockLeaf(key.*, null, &guard);
            var unlocked = false;
            defer if (!unlocked) guard.release();
            defer n.deinit(alloc, kformat, nvformat);
            const current = guard.recid;
            const pos = kformat.search(&n.keys, key.*);
            const leaf = switch (n.body) {
                .leaf => |*l| l,
                .dir => return error.DataCorruption,
            };
            const p = switch (pos) {
                .found => |x| x,
                .insert => return null,
            };
            const old = try self.userValueGet(&leaf.values, p);
            errdefer self.vf().deinitElem(alloc, old);
            if (expected) |exp| {
                if (!self.vf().equalsElem(old, exp.*)) {
                    self.vf().deinitElem(alloc, old);
                    return null;
                }
            }
            if (value_inline) {
                const new_vals = try nvformat.set(alloc, &leaf.values, p, new_value);
                var fence_clone: ?KF.Group = null;
                if (leaf.fence) |f| {
                    fence_clone = kformat.cloneGroup(alloc, &f) catch |e| {
                        nvformat.deinitGroup(alloc, new_vals);
                        return e;
                    };
                }
                const keys_clone = kformat.cloneGroup(alloc, &n.keys) catch |e| {
                    if (fence_clone) |fc| kformat.deinitGroup(alloc, fc);
                    nvformat.deinitGroup(alloc, new_vals);
                    return e;
                };
                var updated = NodeT{ .flags = n.flags, .link = n.link, .keys = keys_clone, .body = .{ .leaf = .{ .values = new_vals, .fence = fence_clone } } };
                defer updated.deinit(alloc, kformat, nvformat);
                try self.storeUpdate(current, &updated);
            } else {
                // external: update the value record in place; node unchanged (no barrier
                // needed — the recid is neither deleted nor reused).
                const recid = try self.recidAt(&leaf.values, p);
                try self.store().update(Val, alloc, recid, new_value, self.velem());
            }
            // update of an existing key: counter unchanged. sync under lock, then deferred.
            const sync_r = self.fireListeners(true, key.*, old, new_value);
            guard.release();
            unlocked = true;
            try sync_r;
            try self.fireListeners(false, key.*, old, new_value);
            return old;
        }

        // -------- iteration --------

        fn firstLeafRecidForLowerBound(self: Self, lo: ?Key) DbError!u64 {
            const alloc = self.a();
            var cyc = CycleGuard.init(alloc, CYCLE_DESCENT_SOFT);
            defer cyc.deinit();
            var current = try self.rootRecid();
            var n = try self.load(current);
            while (n.isDir()) {
                cyc.visit(current) catch |e| {
                    n.deinit(alloc, self.kf(), self.nvf());
                    return e;
                };
                const child_idx: ?usize = if (lo) |k| self.routeChild(&n, k) else 0;
                const next = if (child_idx) |i| n.children()[i] else n.link;
                n.deinit(alloc, self.kf(), self.nvf());
                current = next;
                n = try self.load(current);
            }
            n.deinit(alloc, self.kf(), self.nvf());
            return current;
        }

        /// Ascending iterator over `[lo, hi]` (bounds borrowed; `null` =
        /// unbounded, `*_inc` = inclusive at equality). Follows leaf links — a
        /// lock-free scan that may observe concurrent writers. Each `next(alloc)`
        /// yields an OWNED `Entry`; abandoning the iterator mid-scan is fine
        /// (call `deinit`). See [`EntryIter`].
        pub fn entryIter(self: *const Self, lo: ?Key, lo_inc: bool, hi: ?Key, hi_inc: bool) DbError!EntryIter(S, KF, VF, value_inline) {
            if (value_inline) {
                const start_recid = try self.firstLeafRecidForLowerBound(lo);
                var leaf = try self.load(start_recid);
                const sp: usize = if (lo) |k| switch (self.kf().search(&leaf.keys, k)) {
                    .found => |p| if (lo_inc) p else p + 1,
                    .insert => |ins| ins,
                } else 0;
                return .{
                    .map = self,
                    .leaf = leaf,
                    .pos = sp,
                    .done = false,
                    .lo = lo,
                    .lo_inc = lo_inc,
                    .hi = hi,
                    .hi_inc = hi_inc,
                    .lo_pending = lo != null,
                    .cyc = CycleGuard.init(self.a(), CYCLE_SCAN_SOFT),
                };
            }
            // External values: no retained leaf snapshot — each step re-descends
            // under the external read barrier and expands the value record, so a
            // concurrent remove can never delete+reuse the recid mid-read.
            return .{
                .map = self,
                .leaf = null,
                .pos = 0,
                .done = false,
                .lo = lo,
                .lo_inc = lo_inc,
                .hi = hi,
                .hi_inc = hi_inc,
                .lo_pending = false,
                .cyc = CycleGuard.init(self.a(), CYCLE_SCAN_SOFT),
            };
        }

        /// Unbounded ascending iterator over the whole map.
        pub fn iter(self: *const Self) DbError!EntryIter(S, KF, VF, value_inline) {
            return self.entryIter(null, true, null, true);
        }

        /// Bounded descending entries — materialize the ascending range and
        /// reverse (parity stopgap). Returns owned `[]Entry`.
        pub fn descendingEntries(self: *const Self, lo: ?Key, lo_inc: bool, hi: ?Key, hi_inc: bool) DbError![]Entry {
            const buf = try self.collectRange(lo, lo_inc, hi, hi_inc);
            std.mem.reverse(Entry, buf);
            return buf;
        }

        fn collectRange(self: *const Self, lo: ?Key, lo_inc: bool, hi: ?Key, hi_inc: bool) DbError![]Entry {
            const alloc = self.a();
            var out: std.ArrayListUnmanaged(Entry) = .empty;
            errdefer {
                for (out.items) |e| self.deinitEntry(e);
                out.deinit(alloc);
            }
            var it = try self.entryIter(lo, lo_inc, hi, hi_inc);
            defer it.deinit();
            while (try it.next()) |e| out.append(alloc, e) catch |err| {
                self.deinitEntry(e);
                return err;
            };
            return out.toOwnedSlice(alloc);
        }

        /// All entries, ascending, as one OWNED `[]Entry` (free with
        /// `deinitEntries`). A convenience snapshot; use `iter` to stream.
        pub fn entries(self: *const Self) DbError![]Entry {
            return self.collectRange(null, true, null, true);
        }

        /// Remove and return the OWNED first (smallest) in-range entry, or
        /// `null` if the range is empty. Retries on a concurrent race.
        pub fn pollFirstEntry(self: Self, lo: ?Key, lo_inc: bool, hi: ?Key, hi_inc: bool) DbError!?Entry {
            const alloc = self.a();
            while (true) {
                var it = try self.entryIter(lo, lo_inc, hi, hi_inc);
                const first = blk: {
                    defer it.deinit();
                    break :blk try it.next();
                };
                if (first) |e| {
                    const removed = self.removeIf(&e.key, &e.val) catch |err| {
                        self.deinitEntry(e);
                        return err;
                    };
                    if (removed) return e;
                    self.deinitEntry(e);
                } else {
                    _ = alloc;
                    return null;
                }
            }
        }

        pub fn pollLastEntry(self: Self, lo: ?Key, lo_inc: bool, hi: ?Key, hi_inc: bool) DbError!?Entry {
            while (true) {
                var last: ?Entry = null;
                errdefer if (last) |l| self.deinitEntry(l); // free retained on iterator error
                {
                    var it = try self.entryIter(lo, lo_inc, hi, hi_inc);
                    defer it.deinit();
                    while (try it.next()) |e| {
                        if (last) |l| self.deinitEntry(l);
                        last = e;
                    }
                }
                if (last) |e| {
                    last = null; // disarm the errdefer; we own `e` explicitly now
                    const removed = self.removeIf(&e.key, &e.val) catch |err| {
                        self.deinitEntry(e);
                        return err;
                    };
                    if (removed) return e;
                    self.deinitEntry(e);
                } else {
                    return null;
                }
            }
        }

        /// Whole-map entry count. O(1) when the size counter is enabled (Feature A),
        /// else O(n) via a leaf-chain traversal.
        pub fn sizeLong(self: Self) DbError!u64 {
            if (self.inner.counter_recid != 0) {
                try self.checkPoison(); // a poisoned map must not report a size either
                const c = (try self.store().get(i64, self.a(), self.inner.counter_recid, LONG)) orelse return error.DataCorruption;
                if (c < 0) return error.DataCorruption;
                return @intCast(c);
            }
            return self.sizeLongRange(null, true, null, true);
        }
        /// Entry count within `[lo, hi]` (O(range)).
        pub fn sizeLongRange(self: Self, lo: ?Key, lo_inc: bool, hi: ?Key, hi_inc: bool) DbError!u64 {
            var it = try self.entryIter(lo, lo_inc, hi, hi_inc);
            defer it.deinit();
            var count: u64 = 0;
            while (try it.next()) |e| {
                self.deinitEntry(e);
                count += 1;
            }
            return count;
        }

        /// `true` iff the map has no entries. Propagates any iterator error
        /// (never silently reports non-empty on error).
        pub fn isEmpty(self: *const Self) DbError!bool {
            var it = try self.iter();
            defer it.deinit();
            if (try it.next()) |e| {
                self.deinitEntry(e);
                return false;
            }
            return true;
        }

        /// Remove every entry (snapshots keys, then removes one-by-one — not
        /// atomic vs concurrent writers). The snapshot is a KEY-ONLY leaf scan: an
        /// external-value map never dereferences its value records just to discover
        /// keys (each `remove` still reads the value once, to deliver it to
        /// listeners). `remove` fires a removal event per entry.
        pub fn clear(self: Self) DbError!void {
            const alloc = self.a();
            var keys: std.ArrayListUnmanaged(Key) = .empty;
            defer {
                for (keys.items) |k| self.kf().deinitElem(alloc, k);
                keys.deinit(alloc);
            }
            {
                var cyc = CycleGuard.init(alloc, CYCLE_SCAN_SOFT);
                defer cyc.deinit();
                var recid = try self.firstLeafRecidForLowerBound(null);
                while (recid != 0) {
                    try cyc.visit(recid);
                    var node = try self.load(recid);
                    defer node.deinit(alloc, self.kf(), self.nvf());
                    if (node.isDir()) return error.DataCorruption;
                    const size = self.kf().size(&node.keys);
                    var i: usize = 0;
                    while (i < size) : (i += 1) {
                        const k = try self.kf().get(alloc, &node.keys, i);
                        keys.append(alloc, k) catch |err| {
                            self.kf().deinitElem(alloc, k);
                            return err;
                        };
                    }
                    recid = node.link;
                }
            }
            for (keys.items) |*k| {
                if (try self.remove(k)) |old| self.vf().deinitElem(alloc, old);
            }
        }

        // -------- navigable view surface --------
        //
        // `view`/`range`/`subMap`/`headMap`/`tailMap`/`descending` return a
        // lightweight [`RangeView`] borrowing this map (no allocation, no lease
        // bump) — keep the map alive for the view's lifetime. The `*Entry`
        // navigators (`firstEntry`/`floorEntry`/…) return OWNED entries via the
        // full view. `popFirst`/`popLast` remove-and-return the extreme entry.

        /// A full navigable view over the whole map (borrows `self`).
        pub fn view(self: *const Self) viewmod.RangeView(Self) {
            return viewmod.RangeView(Self).full(self);
        }
        pub fn range(self: *const Self, from: Key, to: Key) viewmod.RangeView(Self) {
            return self.view().subMap(from, true, to, false);
        }
        pub fn subMap(self: *const Self, from: Key, from_inc: bool, to: Key, to_inc: bool) viewmod.RangeView(Self) {
            return self.view().subMap(from, from_inc, to, to_inc);
        }
        pub fn headMap(self: *const Self, to: Key, inc: bool) viewmod.RangeView(Self) {
            return self.view().headMap(to, inc);
        }
        pub fn tailMap(self: *const Self, from: Key, inc: bool) viewmod.RangeView(Self) {
            return self.view().tailMap(from, inc);
        }
        pub fn descending(self: *const Self) viewmod.RangeView(Self) {
            return self.view().descending();
        }
        pub fn firstEntry(self: *const Self) DbError!?Entry {
            return self.view().firstEntry();
        }
        pub fn lastEntry(self: *const Self) DbError!?Entry {
            return self.view().lastEntry();
        }
        pub fn floorEntry(self: *const Self, k: *const Key) DbError!?Entry {
            return self.view().floorEntry(k.*);
        }
        pub fn ceilingEntry(self: *const Self, k: *const Key) DbError!?Entry {
            return self.view().ceilingEntry(k.*);
        }
        pub fn lowerEntry(self: *const Self, k: *const Key) DbError!?Entry {
            return self.view().lowerEntry(k.*);
        }
        pub fn higherEntry(self: *const Self, k: *const Key) DbError!?Entry {
            return self.view().higherEntry(k.*);
        }
        pub fn popFirst(self: Self) DbError!?Entry {
            return self.pollFirstEntry(null, true, null, true);
        }
        pub fn popLast(self: Self) DbError!?Entry {
            return self.pollLastEntry(null, true, null, true);
        }

        // -------- columnar single-column scan --------

        /// Scan ONE value column over the ascending key range `[from, to]`
        /// (`null` bound = open), invoking `f(ctx, &key, &cell)` — WITHOUT
        /// materializing whole value rows on the byte path. The callback runs
        /// OUTSIDE the RecordRead (after validation). Requires `VF` to be a
        /// columnar value format (`columnCursor`).
        pub fn forEachValueColumn(
            self: Self,
            from: ?Key,
            from_inc: bool,
            to: ?Key,
            to_inc: bool,
            column: usize,
            ctx: anytype,
            comptime f: fn (@TypeOf(ctx), *const Key, *const Value) void,
        ) DbError!void {
            comptime std.debug.assert(@hasDecl(VF, "columnCursor"));
            // Runtime (not comptime) rejection so generic callers can invoke this on
            // any map and handle the error — external leaves hold recids, not columns.
            if (!value_inline) return error.Unsupported;
            const alloc = self.a();
            std.debug.assert(column < self.vf().columnCount());
            var action = LeafColumnScan(KF){
                .cf = self.vf(),
                .kf = self.kf(),
                .alloc = alloc,
                .column = column,
                .from = from,
                .from_inc = from_inc,
                .to = to,
                .to_inc = to_inc,
                .lo_pending_in = from != null,
            };
            defer action.deinit();
            var cyc = CycleGuard.init(alloc, CYCLE_SCAN_SOFT);
            defer cyc.deinit();
            var recid = try self.firstLeafRecidForLowerBound(action.from);
            while (recid != 0) {
                try cyc.visit(recid);
                const rr = action.recordRead();
                const next = try self.store().read(recid, rr);
                recid = @bitCast(next);
                for (action.keys.items, action.vals.items) |*k, *cell| f(ctx, k, cell);
                if (action.done) return;
                action.lo_pending_in = action.lo_pending_out;
            }
        }

        // -------- bulk build (TreePump) --------

        /// Bulk-build a fresh tree from strictly-ascending entries (default node
        /// fill). Far faster than a put loop; see [`createFromSortedFill`] for
        /// the ownership contract and `error.NotSorted` on misordered input.
        pub fn createFromSorted(alloc: Allocator, store_: *S, key_format: KF, value_format: VF, max_node_size: usize, entries_iter: anytype) DbError!Self {
            return createFromSortedCounter(alloc, store_, key_format, value_format, max_node_size, entries_iter, false);
        }

        /// `createFromSorted` with an optional O(1) size counter (initialized to the
        /// number of entries built). REJECTED for external-value maps (Java bulk
        /// builds are inline-only) with `error.Unsupported`.
        pub fn createFromSortedCounter(alloc: Allocator, store_: *S, key_format: KF, value_format: VF, max_node_size: usize, entries_iter: anytype, counter_enable: bool) DbError!Self {
            // Validate the FULL range BEFORE any `defaultFill` arithmetic (which
            // multiplies by 3 and would overflow `usize` for a hostile input).
            if (max_node_size < MIN_MAX_NODE_SIZE or max_node_size > MAX_MAX_NODE_SIZE) return error.WrongConfiguration;
            const fill = pumpmod.TreePump(S, BTreeSink(S, KF, VF)).defaultFill(max_node_size);
            return createFromSortedFill(alloc, store_, key_format, value_format, max_node_size, fill, entries_iter, counter_enable);
        }

        /// Bulk build from STRICTLY ascending entries. `entries_iter` is any value
        /// with `next(self) ?struct{ key: Key, val: Val }`; the pump TAKES
        /// OWNERSHIP of each yielded key/value (as the Rust oracle moves them).
        /// REJECTS external-value maps (`error.Unsupported`).
        pub fn createFromSortedFill(alloc: Allocator, store_: *S, key_format: KF, value_format: VF, max_node_size: usize, node_fill: usize, entries_iter: anytype, counter_enable: bool) DbError!Self {
            // Public API boundary: validate the full range instead of asserting.
            // `TreePump.init` validates `node_fill` vs this range.
            if (max_node_size < MIN_MAX_NODE_SIZE or max_node_size > MAX_MAX_NODE_SIZE) return error.WrongConfiguration;
            if (!value_inline) return error.Unsupported; // Java: bulk build is inline-only
            const Sink = BTreeSink(S, KF, VF);
            var sink = Sink{ .alloc = alloc, .store = store_, .kf = key_format, .vf = value_format };
            var count: i64 = 0;
            const root_recid = blk: {
                var pump = try pumpmod.TreePump(S, Sink).init(alloc, store_, &sink, max_node_size, node_fill);
                defer pump.deinit();
                var iter_ = entries_iter;
                while (iter_.next()) |kv| {
                    try pump.put(kv.key, kv.val);
                    count += 1;
                }
                break :blk try pump.finish();
            };
            const counter_recid: u64 = if (counter_enable) try store_.put(i64, alloc, count, LONG) else 0;
            const rrr = try store_.put(i64, alloc, @as(i64, @intCast(root_recid)), LONG);
            return openCounter(alloc, store_, rrr, key_format, value_format, max_node_size, counter_recid);
        }
    };
}

// ========================================================= GetAction

fn GetAction(comptime KF: type, comptime VF: type) type {
    return struct {
        const Self = @This();
        const NodeT = Node(KF, VF);

        alloc: Allocator,
        kf: KF,
        vf: VF,
        key: *const KF.Elem,
        value: ?VF.Elem = null,
        found: bool = false,

        fn init(alloc: Allocator, kf: KF, vf: VF, key: *const KF.Elem) Self {
            return .{ .alloc = alloc, .kf = kf, .vf = vf, .key = key };
        }
        fn deinitValue(self: *Self) void {
            if (self.value) |v| self.vf.deinitElem(self.alloc, v);
            self.value = null;
        }

        fn onBytes(self: *Self, input: *DataInput2, size: usize) DbError!i64 {
            self.deinitValue();
            self.found = false;
            const h = try input.unpackInt();
            const flags = h & 0xF;
            const keys_len: usize = @as(u32, @bitCast(h)) >> 4;
            if (keys_len > size) return error.DataCorruption;
            const link: u64 = if (flags & RIGHT != 0) 0 else blk: {
                const l = try input.unpackLong();
                if (l == 0) return error.DataCorruption;
                break :blk l;
            };
            const pos: SearchResult = if (self.kf.supportsBinary())
                try self.kf.binarySearch(self.alloc, self.key.*, input, keys_len)
            else blk: {
                const g = try self.kf.deserializeGroup(self.alloc, input, keys_len);
                defer self.kf.deinitGroup(self.alloc, g);
                break :blk self.kf.search(&g, self.key.*);
            };

            if (flags & DIR != 0) {
                const child_idx = searchIdx(pos);
                const child_count = keys_len + @as(usize, if (flags & RIGHT != 0) 1 else 0);
                if (child_count == 0) return error.DataCorruption;
                if (child_idx >= child_count) return @bitCast(link);
                try input.unpackLongSkip(child_idx);
                const child = try input.unpackLong();
                if (child == 0) return error.DataCorruption;
                return @bitCast(child);
            }
            // leaf
            switch (pos) {
                .found => |p| {
                    self.value = if (self.vf.supportsBinary())
                        try self.vf.binaryGet(self.alloc, input, keys_len, p)
                    else blk: {
                        const g = try self.vf.deserializeGroup(self.alloc, input, keys_len);
                        defer self.vf.deinitGroup(self.alloc, g);
                        break :blk try self.vf.get(self.alloc, &g, p);
                    };
                    self.found = true;
                    return 0;
                },
                .insert => |ip| {
                    if (ip >= keys_len and link != 0) return @bitCast(link);
                    return 0;
                },
            }
        }

        fn onObject(self: *Self, obj: *const anyopaque, token: TypeId) DbError!i64 {
            self.deinitValue();
            self.found = false;
            if (token != typeToken(NodeT)) return error.DataCorruption;
            const n: *const NodeT = @ptrCast(@alignCast(obj));
            const pos = self.kf.search(&n.keys, self.key.*);
            if (n.isDir()) {
                const child_idx = searchIdx(pos);
                const kids = n.children();
                if (child_idx >= kids.len) return @bitCast(n.link);
                return @bitCast(kids[child_idx]);
            }
            switch (pos) {
                .found => |p| {
                    const vals = n.body.leaf.values;
                    self.value = try self.vf.get(self.alloc, &vals, p);
                    self.found = true;
                    return 0;
                },
                .insert => |ip| {
                    if (ip >= self.kf.size(&n.keys) and n.link != 0) return @bitCast(n.link);
                    return 0;
                },
            }
        }

        // A dir child / leaf link / root recid resolving to null is a structurally
        // impossible tree — corrupt, not "key absent".
        fn onNull(_: *Self) DbError!i64 {
            return error.DataCorruption;
        }

        fn onBytesRaw(ctx: *anyopaque, input: *DataInput2, size: usize) DbError!i64 {
            return @as(*Self, @ptrCast(@alignCast(ctx))).onBytes(input, size);
        }
        fn onObjectRaw(ctx: *anyopaque, obj: *const anyopaque, token: TypeId) DbError!i64 {
            return @as(*Self, @ptrCast(@alignCast(ctx))).onObject(obj, token);
        }
        fn onNullRaw(ctx: *anyopaque) DbError!i64 {
            return @as(*Self, @ptrCast(@alignCast(ctx))).onNull();
        }
        const vtable = RecordRead.VTable{ .onBytes = onBytesRaw, .onObject = onObjectRaw, .onNull = onNullRaw };
        fn recordRead(self: *Self) RecordRead {
            return .{ .ptr = self, .vtable = &vtable };
        }
    };
}

// ========================================================= EntryIter

/// Ascending, weakly-consistent leaf-link iterator. `next` returns owned
/// `?Entry` (freed by the caller); fused after the first error. Borrows the map
/// and the bound keys (which must outlive iteration).
pub fn EntryIter(comptime S: type, comptime KF: type, comptime VF: type, comptime value_inline: bool) type {
    return struct {
        const Self = @This();
        const Map = BTreeMapG(S, KF, VF, value_inline);
        const NVF = if (value_inline) VF else long_mod.LongFormat;
        const NodeT = Node(KF, NVF);
        const Entry = Map.Entry;

        map: *const Map,
        /// Inline mode: the retained leaf snapshot being scanned (null in external
        /// mode, which re-descends each step).
        leaf: ?NodeT,
        pos: usize,
        done: bool,
        lo: ?KF.Elem,
        lo_inc: bool,
        hi: ?KF.Elem,
        hi_inc: bool,
        lo_pending: bool,
        cyc: CycleGuard,
        /// External mode: owned clone of the last emitted key (the exclusive lower
        /// bound of the next re-descent).
        resume_key: ?KF.Elem = null,
        resume_started: bool = false,

        /// Release the iterator's held leaf/resume key and scratch. Safe to call at
        /// any point, including after abandoning a partial scan.
        pub fn deinit(self: *Self) void {
            if (value_inline) {
                if (self.leaf) |*lf| lf.deinit(self.map.a(), self.map.kf(), self.map.nvf());
                self.leaf = null;
            } else if (self.resume_key) |rk| {
                self.map.kf().deinitElem(self.map.a(), rk);
                self.resume_key = null;
            }
            self.cyc.deinit();
        }

        /// Next OWNED entry, or `null` at end. On error the iterator fuses
        /// (subsequent calls return `null`). The caller frees the entry.
        pub fn next(self: *Self) DbError!?Entry {
            const r = self.advance();
            if (r) |v| {
                return v;
            } else |e| {
                self.done = true;
                return e;
            }
        }

        fn advance(self: *Self) DbError!?Entry {
            if (!value_inline) return self.advanceExternal();
            if (self.done) return null;
            const alloc = self.map.a();
            const kf = self.map.kf();
            const vf = self.map.vf();
            while (true) {
                // skip exhausted leaves, following links
                while (self.leaf != null and self.pos >= kf.size(&self.leaf.?.keys)) {
                    const link = self.leaf.?.link;
                    self.leaf.?.deinit(alloc, kf, self.map.nvf());
                    self.leaf = null;
                    if (link != 0) {
                        try self.cyc.visit(link);
                        self.leaf = try self.map.load(link);
                    }
                    self.pos = 0;
                }
                const leaf = if (self.leaf) |*l| l else {
                    self.done = true;
                    return null;
                };
                const k = try kf.get(alloc, &leaf.keys, self.pos);
                if (self.lo_pending) {
                    const lo = self.lo.?;
                    const c = kf.compare(k, lo);
                    if (c == .lt or (c == .eq and !self.lo_inc)) {
                        kf.deinitElem(alloc, k);
                        self.pos += 1;
                        continue;
                    }
                    self.lo_pending = false;
                }
                if (self.hi) |hi| {
                    const c = kf.compare(k, hi);
                    if (c == .gt or (c == .eq and !self.hi_inc)) {
                        kf.deinitElem(alloc, k);
                        self.done = true;
                        return null;
                    }
                }
                const v = switch (leaf.body) {
                    .leaf => |l| vf.get(alloc, &l.values, self.pos) catch |e| {
                        kf.deinitElem(alloc, k);
                        return e;
                    },
                    .dir => {
                        kf.deinitElem(alloc, k);
                        self.done = true;
                        return error.DataCorruption;
                    },
                };
                self.pos += 1;
                return Entry{ .key = k, .val = v };
            }
        }

        /// External-value step: descend afresh under the read barrier from the
        /// current lower bound (`lo` initially, then the last emitted key exclusive),
        /// find the first in-range key, and expand its value record — all while the
        /// barrier is held so the recid cannot be deleted+reused mid-read.
        fn advanceExternal(self: *Self) DbError!?Entry {
            if (self.done) return null;
            const map = self.map;
            const alloc = map.a();
            const kf = map.kf();
            const lo: ?KF.Elem = if (self.resume_started) self.resume_key else self.lo;
            const lo_inc: bool = if (self.resume_started) false else self.lo_inc;

            map.inner.ext_lock.lockShared();
            defer map.inner.ext_lock.unlockShared();

            // Fresh cycle guard PER advance: the hop count of one re-descent is tiny,
            // whereas a single guard shared across a whole scan would accumulate past
            // the soft cap and, under concurrent removes, spuriously flag a legitimately
            // revisited link recid as a cycle.
            var cyc = CycleGuard.init(alloc, CYCLE_SCAN_SOFT);
            defer cyc.deinit();
            var node = try map.load(try map.firstLeafRecidForLowerBound(lo));
            var node_live = true;
            // `defer` (not `errdefer`): the hi-bound / end exits below `return null`
            // successfully with the node still loaded, and that node (keys + recid
            // group + fence) must be freed on EVERY exit, not just error exits.
            defer if (node_live) node.deinit(alloc, kf, map.nvf());
            while (true) {
                if (node.isDir()) {
                    self.done = true;
                    return error.DataCorruption;
                }
                const size = kf.size(&node.keys);
                var pos: usize = if (lo) |lk| switch (kf.search(&node.keys, lk)) {
                    .found => |p| if (lo_inc) p else p + 1,
                    .insert => |ins| ins,
                } else 0;
                while (pos < size) : (pos += 1) {
                    const k = try kf.get(alloc, &node.keys, pos);
                    if (self.hi) |hi| {
                        const c = kf.compare(k, hi);
                        if (c == .gt or (c == .eq and !self.hi_inc)) {
                            kf.deinitElem(alloc, k);
                            self.done = true;
                            return null;
                        }
                    }
                    const val = map.userValueGet(&node.body.leaf.values, pos) catch |e| {
                        kf.deinitElem(alloc, k);
                        return e;
                    };
                    const rk = kf.cloneElem(alloc, k) catch |e| {
                        kf.deinitElem(alloc, k);
                        map.vf().deinitElem(alloc, val);
                        return e;
                    };
                    if (self.resume_key) |old| kf.deinitElem(alloc, old);
                    self.resume_key = rk;
                    self.resume_started = true;
                    node.deinit(alloc, kf, map.nvf());
                    node_live = false;
                    return Entry{ .key = k, .val = val };
                }
                const link = node.link;
                node.deinit(alloc, kf, map.nvf());
                node_live = false;
                if (link == 0) {
                    self.done = true;
                    return null;
                }
                try cyc.visit(link);
                node = try map.load(link);
                node_live = true;
            }
        }
    };
}

// ========================================================= LeafColumnScan

/// Per-leaf push-down action for `forEachValueColumn`: collects one leaf's
/// in-range `(key, column-cell)` pairs, reading only the requested column's
/// bytes on the byte path, returning the next leaf recid (or 0 to STOP).
fn LeafColumnScan(comptime KF: type) type {
    const columnar = @import("../ser/columnar.zig");
    const CF = columnar.ColumnarValueFormat;
    return struct {
        const Self = @This();
        const NodeT = Node(KF, CF);

        cf: CF,
        kf: KF,
        alloc: Allocator,
        column: usize,
        from: ?KF.Elem,
        from_inc: bool,
        to: ?KF.Elem,
        to_inc: bool,
        lo_pending_in: bool,
        keys: std.ArrayListUnmanaged(KF.Elem) = .empty,
        vals: std.ArrayListUnmanaged(Value) = .empty,
        lo_pending_out: bool = false,
        done: bool = false,

        fn deinit(self: *Self) void {
            for (self.keys.items) |k| self.kf.deinitElem(self.alloc, k);
            self.keys.deinit(self.alloc);
            self.vals.deinit(self.alloc);
        }

        fn resetOutputs(self: *Self) void {
            for (self.keys.items) |k| self.kf.deinitElem(self.alloc, k);
            self.keys.clearRetainingCapacity();
            self.vals.clearRetainingCapacity();
            self.lo_pending_out = self.lo_pending_in;
            self.done = false;
        }

        fn lowerPos(self: *Self, key_group: *const KF.Group) usize {
            const from = self.from.?;
            return switch (self.kf.search(key_group, from)) {
                .found => |p| if (self.from_inc) p else p + 1,
                .insert => |ins| ins,
            };
        }
        fn upperPos(self: *Self, key_group: *const KF.Group, keys_len: usize) usize {
            const to = self.to orelse return keys_len;
            const tp = switch (self.kf.search(key_group, to)) {
                .found => |p| blk: {
                    self.done = true;
                    break :blk if (self.to_inc) p + 1 else p;
                },
                .insert => |ins| blk: {
                    self.done = ins < keys_len;
                    break :blk ins;
                },
            };
            return @min(tp, keys_len);
        }

        fn onBytes(self: *Self, input: *DataInput2, size: usize) DbError!i64 {
            self.resetOutputs();
            const h = try input.unpackInt();
            const flags = h & 0xF;
            const keys_len: usize = @as(u32, @bitCast(h)) >> 4;
            if (flags & DIR != 0) return error.DataCorruption;
            if (keys_len > size) return error.DataCorruption;
            const link: u64 = if (flags & RIGHT != 0) 0 else blk: {
                const l = try input.unpackLong();
                if (l == 0) return error.DataCorruption;
                break :blk l;
            };
            const key_group = try self.kf.deserializeGroup(self.alloc, input, keys_len);
            defer self.kf.deinitGroup(self.alloc, key_group);
            const lo_pos = if (self.lo_pending_in and self.from != null) self.lowerPos(&key_group) else 0;
            const to_pos = self.upperPos(&key_group, keys_len);
            self.lo_pending_out = self.lo_pending_in and lo_pos >= keys_len;
            const from_pos = @min(lo_pos, to_pos);

            var vc = try self.cf.columnCursor(self.alloc, input, keys_len, self.column, from_pos, to_pos);
            defer vc.deinit();
            var i = from_pos;
            while (try vc.next()) {
                const k = try self.kf.get(self.alloc, &key_group, i);
                self.keys.append(self.alloc, k) catch |e| {
                    self.kf.deinitElem(self.alloc, k);
                    return e;
                };
                try self.vals.append(self.alloc, try vc.value(self.alloc));
                i += 1;
            }
            return if (self.done) 0 else @as(i64, @bitCast(link));
        }

        fn onObject(self: *Self, obj: *const anyopaque, token: TypeId) DbError!i64 {
            self.resetOutputs();
            if (token != typeToken(NodeT)) return error.DataCorruption;
            const n: *const NodeT = @ptrCast(@alignCast(obj));
            if (n.isDir()) return error.DataCorruption;
            const keys_len = self.kf.size(&n.keys);
            const lo_pos = if (self.lo_pending_in and self.from != null) self.lowerPos(&n.keys) else 0;
            const to_pos = self.upperPos(&n.keys, keys_len);
            self.lo_pending_out = self.lo_pending_in and lo_pos >= keys_len;
            const values = n.body.leaf.values;
            var i = @min(lo_pos, to_pos);
            while (i < to_pos) : (i += 1) {
                const k = try self.kf.get(self.alloc, &n.keys, i);
                self.keys.append(self.alloc, k) catch |e| {
                    self.kf.deinitElem(self.alloc, k);
                    return e;
                };
                const row = try self.cf.get(self.alloc, &values, i);
                defer self.cf.deinitElem(self.alloc, row);
                try self.vals.append(self.alloc, row[self.column]);
            }
            return if (self.done) 0 else @as(i64, @bitCast(n.link));
        }

        fn onNull(_: *Self) DbError!i64 {
            return error.DataCorruption;
        }
        fn onBytesRaw(ctx: *anyopaque, input: *DataInput2, size: usize) DbError!i64 {
            return @as(*Self, @ptrCast(@alignCast(ctx))).onBytes(input, size);
        }
        fn onObjectRaw(ctx: *anyopaque, obj: *const anyopaque, token: TypeId) DbError!i64 {
            return @as(*Self, @ptrCast(@alignCast(ctx))).onObject(obj, token);
        }
        fn onNullRaw(ctx: *anyopaque) DbError!i64 {
            return @as(*Self, @ptrCast(@alignCast(ctx))).onNull();
        }
        const vtable = RecordRead.VTable{ .onBytes = onBytesRaw, .onObject = onObjectRaw, .onNull = onNullRaw };
        fn recordRead(self: *Self) RecordRead {
            return .{ .ptr = self, .vtable = &vtable };
        }
    };
}

// ========================================================= TreePump sink

/// TreePump sink for a BTreeMap: materializes a node and writes it to its
/// preallocated recid.
fn BTreeSink(comptime S: type, comptime KF: type, comptime VF: type) type {
    return struct {
        const Self = @This();
        pub const Key = KF.Elem;
        pub const Val = VF.Elem;
        const NodeT = Node(KF, VF);
        const NodeSer = NodeSerializer(KF, VF);

        alloc: Allocator,
        store: *S,
        kf: KF,
        vf: VF,

        pub fn compareKeys(self: *const Self, x: Key, y: Key) Order {
            return self.kf.compare(x, y);
        }
        pub fn cloneKey(self: *const Self, alloc: Allocator, k: Key) DbError!Key {
            return self.kf.cloneElem(alloc, k);
        }
        pub fn deinitKey(self: *const Self, alloc: Allocator, k: Key) void {
            self.kf.deinitElem(alloc, k);
        }
        pub fn deinitVal(self: *const Self, alloc: Allocator, v: Val) void {
            self.vf.deinitElem(alloc, v);
        }

        pub fn writeLeaf(self: *const Self, recid: u64, flags: i32, link: u64, keys: []const Key, values: []const Val) DbError!void {
            // non-rightmost leaf: fence = last key (its inclusive high bound).
            var fence: ?KF.Group = null;
            if (flags & RIGHT == 0) {
                var fk = [_]Key{keys[keys.len - 1]};
                fence = try self.kf.fromSlice(self.alloc, &fk);
            }
            const keys_group = self.kf.fromSlice(self.alloc, keys) catch |e| {
                if (fence) |fc| self.kf.deinitGroup(self.alloc, fc);
                return e;
            };
            const vals_group = self.vf.fromSlice(self.alloc, values) catch |e| {
                if (fence) |fc| self.kf.deinitGroup(self.alloc, fc);
                self.kf.deinitGroup(self.alloc, keys_group);
                return e;
            };
            var node = NodeT{ .flags = flags, .link = link, .keys = keys_group, .body = .{ .leaf = .{ .values = vals_group, .fence = fence } } };
            defer node.deinit(self.alloc, self.kf, self.vf);
            try self.store.update(NodeT, self.alloc, recid, node, NodeSer.init(self.kf, self.vf));
        }

        pub fn writeDir(self: *const Self, recid: u64, flags: i32, link: u64, keys: []const Key, children: []const u64) DbError!void {
            const keys_group = try self.kf.fromSlice(self.alloc, keys);
            const kids = self.alloc.dupe(u64, children) catch |e| {
                self.kf.deinitGroup(self.alloc, keys_group);
                return e;
            };
            var node = NodeT{ .flags = flags, .link = link, .keys = keys_group, .body = .{ .dir = kids } };
            defer node.deinit(self.alloc, self.kf, self.vf);
            try self.store.update(NodeT, self.alloc, recid, node, NodeSer.init(self.kf, self.vf));
        }
    };
}
