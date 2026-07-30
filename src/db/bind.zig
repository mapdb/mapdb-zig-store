//! `Bind` — secondary indexes and derived views over a primary `BTreeMap`
//! (Java `org.mapdb.Bind`). Ported from `mapdb-rust-store/src/db/bind.rs` in the Zig
//! borrowed-context idiom.
//!
//! Two listener classes, exactly as Java:
//! - **Order-sensitive** (`secondaryValue`, `secondaryKey`, `secondaryKeys`,
//!   `secondaryValues`, `mapInverse`) install a SYNCHRONOUS listener, fired UNDER
//!   the covering leaf lock that serialized the mutation, so same-key events are
//!   totally ordered with the mutations (last writer wins in the index too).
//! - **Ordinary/deferred** (`size`, `histogram`, `mapPutAfterDelete`) install a
//!   plain listener, fired after the leaf lock is released and split propagation
//!   completes.
//!
//! ## Initial population
//! Every order-sensitive binding (and `histogram`) first checks whether its
//! secondary is empty and, if so, replays the primary's EXISTING entries through
//! the derive function, exactly as Java (`if (secondary.isEmpty()) for (Entry e :
//! primary.entrySet()) …`). The initial scan and the listener registration are
//! NOT atomic against concurrent writers, so install bindings while the primary
//! is quiescent.
//!
//! ## Secondary containers (in-memory & persistent)
//! Bindings target a container exposing the small duck-typed interface below.
//! Two implementations ship: the in-memory [`SecondaryMap`] / [`SecondarySet`]
//! (restricted to hashable, copy-managed key/value types — the Java Bind tests use
//! `Long`/`Integer`), and [`PersistentSecMap`] wrapping a real [`BTreeMap`] (Java
//! accepts any `Map`). `get`-returning containers pair with `freeVal` so an owned
//! persistent value is released after a unique-index comparison.
//!   Map:  isEmpty() !bool · get(K) !?V · freeVal(V) · put(K,V) !void ·
//!         remove(K) !void · removeIfValue(K,V) !void · secIdentity() ?*const anyopaque
//!   Set:  isEmpty() !bool · add(T) !void · remove(T) !void · secIdentity() ?*const anyopaque
//!
//! ## Listener-context lifetime (borrowed-context model)
//! Every binding registers a `(secondary_ptr, fn)` pair. The container is
//! BORROWED: it must outlive the registration (until the map is deinitialized).
//! `remove` alone does NOT make a container safe to free while mutations run.
//!
//! ## Self-binding and lock cycles
//! [`rejectSelfBind`] refuses a direct self-cycle (comparing shared `Inner`), and
//! every order-sensitive installer ALSO rejects a persistent secondary whose
//! identity IS the primary. Longer/transitive cycles are not detected; install
//! bindings while the primary is quiescent.
//!
//! PORTING-GAP: the in-memory containers are limited to hashable,
//! copy-managed key/value types (`std.AutoHashMap`); owned-slice keys/values in an
//! IN-MEMORY secondary are unsupported (use a `PersistentSecMap` for those).

const std = @import("std");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const listenermod = @import("../listener.zig");

// ============================================================ in-memory containers

/// A shareable in-memory secondary map (Java `ConcurrentMap`). `K`/`V` must be
/// hashable, copy-managed types (no heap ownership) — see the module gap note.
pub fn SecondaryMap(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        mu: std.Thread.Mutex = .{},
        map: std.AutoHashMapUnmanaged(K, V) = .empty,
        alloc: Allocator,

        pub fn init(alloc: Allocator) Self {
            return .{ .alloc = alloc };
        }
        pub fn deinit(self: *Self) void {
            self.map.deinit(self.alloc);
        }
        pub fn isEmpty(self: *Self) DbError!bool {
            self.mu.lock();
            defer self.mu.unlock();
            return self.map.count() == 0;
        }
        pub fn count(self: *Self) usize {
            self.mu.lock();
            defer self.mu.unlock();
            return self.map.count();
        }
        pub fn get(self: *Self, k: K) DbError!?V {
            self.mu.lock();
            defer self.mu.unlock();
            return self.map.get(k);
        }
        pub fn freeVal(_: *Self, _: V) void {}
        pub fn put(self: *Self, k: K, v: V) DbError!void {
            self.mu.lock();
            defer self.mu.unlock();
            self.map.put(self.alloc, k, v) catch return error.OutOfMemory;
        }
        /// Atomic Java `ConcurrentMap.putIfAbsent`: insert `v` iff `k` is absent;
        /// returns the EXISTING value when present (no insert), else null. One
        /// critical section, so two racing unique-index inserts can't both "win".
        pub fn putIfAbsent(self: *Self, k: K, v: V) DbError!?V {
            self.mu.lock();
            defer self.mu.unlock();
            const gop = self.map.getOrPut(self.alloc, k) catch return error.OutOfMemory;
            if (gop.found_existing) return gop.value_ptr.*;
            gop.value_ptr.* = v;
            return null;
        }
        /// Logical value equality (in-memory values are copy-managed, so bitwise
        /// equality IS logical equality — the container-provided equality the container contract asks
        /// for; NOT `std.meta.eql` at the call site, which would be pointer identity
        /// for a persistent owned value).
        pub fn valuesEqual(_: *Self, a: V, b: V) bool {
            return std.meta.eql(a, b);
        }
        pub fn remove(self: *Self, k: K) DbError!void {
            self.mu.lock();
            defer self.mu.unlock();
            _ = self.map.remove(k);
        }
        pub fn removeIfValue(self: *Self, k: K, v: V) DbError!void {
            self.mu.lock();
            defer self.mu.unlock();
            if (self.map.get(k)) |ex| if (std.meta.eql(ex, v)) {
                _ = self.map.remove(k);
            };
        }
        pub fn secIdentity(_: *Self) ?*const anyopaque {
            return null;
        }
        /// Atomic get+adjust+store used by [`histogram`]: apply `delta` (WRAPPING),
        /// removing the category at EXACTLY zero, keeping negatives. `V` must be an
        /// integer (only `histogram` instantiates this).
        pub fn addCount(self: *Self, k: K, delta: V) DbError!void {
            self.mu.lock();
            defer self.mu.unlock();
            const cur: V = self.map.get(k) orelse 0;
            const n = cur +% delta;
            if (n == 0) {
                _ = self.map.remove(k);
            } else {
                self.map.put(self.alloc, k, n) catch return error.OutOfMemory;
            }
        }
    };
}

/// A shareable in-memory secondary set (Java `Set`) of hashable tuples `T`.
pub fn SecondarySet(comptime T: type) type {
    return struct {
        const Self = @This();
        mu: std.Thread.Mutex = .{},
        set: std.AutoHashMapUnmanaged(T, void) = .empty,
        alloc: Allocator,

        pub fn init(alloc: Allocator) Self {
            return .{ .alloc = alloc };
        }
        pub fn deinit(self: *Self) void {
            self.set.deinit(self.alloc);
        }
        pub fn isEmpty(self: *Self) DbError!bool {
            self.mu.lock();
            defer self.mu.unlock();
            return self.set.count() == 0;
        }
        pub fn count(self: *Self) usize {
            self.mu.lock();
            defer self.mu.unlock();
            return self.set.count();
        }
        pub fn contains(self: *Self, t: T) bool {
            self.mu.lock();
            defer self.mu.unlock();
            return self.set.contains(t);
        }
        pub fn add(self: *Self, t: T) DbError!void {
            self.mu.lock();
            defer self.mu.unlock();
            self.set.put(self.alloc, t, {}) catch return error.OutOfMemory;
        }
        pub fn remove(self: *Self, t: T) DbError!void {
            self.mu.lock();
            defer self.mu.unlock();
            _ = self.set.remove(t);
        }
        pub fn secIdentity(_: *Self) ?*const anyopaque {
            return null;
        }
    };
}

/// A persistent [`BTreeMap`] used as a secondary map (Java accepts any `Map`).
/// `sec_identity` exposes the shared-state address so a self-bind is detected.
/// `get` returns an OWNED value; release it with `freeVal`.
pub fn PersistentSecMap(comptime M: type) type {
    return struct {
        const Self = @This();
        map: M,

        pub fn init(map: M) Self {
            return .{ .map = map };
        }
        pub fn isEmpty(self: *Self) DbError!bool {
            return self.map.isEmpty();
        }
        pub fn get(self: *Self, k: M.Key) DbError!?M.Val {
            return self.map.get(&k);
        }
        pub fn freeVal(self: *Self, v: M.Val) void {
            self.map.vf().deinitElem(self.map.a(), v);
        }
        pub fn put(self: *Self, k: M.Key, v: M.Val) DbError!void {
            return self.map.putOnly(k, v);
        }
        /// Atomic put-if-absent via the BTree's under-leaf-lock `putIfAbsent`:
        /// returns the OWNED existing value (free with `freeVal`)
        /// or null when it inserted.
        pub fn putIfAbsent(self: *Self, k: M.Key, v: M.Val) DbError!?M.Val {
            return self.map.putIfAbsent(k, v);
        }
        /// Format-aware value equality (a persistent value may be an owned slice —
        /// pointer identity would be wrong).
        pub fn valuesEqual(self: *Self, a: M.Val, b: M.Val) bool {
            return self.map.valueEquals(a, b);
        }
        pub fn remove(self: *Self, k: M.Key) DbError!void {
            _ = try self.map.removeOnly(&k);
        }
        pub fn removeIfValue(self: *Self, k: M.Key, v: M.Val) DbError!void {
            _ = try self.map.removeIf(&k, &v);
        }
        pub fn secIdentity(self: *Self) ?*const anyopaque {
            return @ptrCast(self.map.inner);
        }
    };
}

// ============================================================ Bind

/// Bind operations over a concrete `BTreeMap` type `Map`.
pub fn Bind(comptime Map: type) type {
    const K = Map.Key;
    const V = Map.Val;
    const Listener = listenermod.MapModificationListener(K, V);
    return struct {
        pub const ListenerT = Listener;

        /// Reject binding a map to a handle sharing its state (Java self-cycle guard).
        pub fn rejectSelfBind(primary: Map, secondary: Map) DbError!void {
            if (primary.inner == secondary.inner) return error.WrongConfiguration;
        }

        fn rejectSelfBindId(primary: Map, secondary: anytype) DbError!void {
            if (secondary.secIdentity()) |id| {
                if (id == @as(*const anyopaque, @ptrCast(primary.inner))) return error.WrongConfiguration;
            }
        }

        /// Register an order-sensitive SYNCHRONOUS listener over a borrowed `ctx`.
        pub fn addSync(primary: Map, ctx: *anyopaque, f: Listener.ModifyFn) DbError!void {
            try primary.modificationListenerAdd(Listener.initSynchronous(ctx, f));
        }
        /// Register an ordinary DEFERRED listener over a borrowed `ctx`.
        pub fn addDeferred(primary: Map, ctx: *anyopaque, f: Listener.ModifyFn) DbError!void {
            try primary.modificationListenerAdd(Listener.init(ctx, f));
        }
        /// Remove a previously registered binding (by ctx+fn identity).
        pub fn remove(primary: Map, ctx: *anyopaque, f: Listener.ModifyFn) bool {
            return primary.modificationListenerRemove(Listener.init(ctx, f));
        }

        // ---------------- order-sensitive bindings (synchronous) ----------------

        /// `secondary[key] = derive(key, value)`, removed when the primary key is
        /// removed (Java `secondaryValue`). `derive: fn(K, V) Dv`.
        pub fn secondaryValue(primary: Map, secondary: anytype, comptime derive: anytype) DbError!void {
            const Sec = @TypeOf(secondary);
            try rejectSelfBindId(primary, secondary);
            if (try secondary.isEmpty()) {
                const es = try primary.entries();
                defer primary.deinitEntries(es);
                for (es) |e| try secondary.put(e.key, derive(e.key, e.val));
            }
            const L = struct {
                fn modify(ctx: *anyopaque, key: K, _: ?V, new: ?V, _: bool) DbError!void {
                    const sec: Sec = @ptrCast(@alignCast(ctx));
                    if (new) |v| try sec.put(key, derive(key, v)) else try sec.remove(key);
                }
            };
            try addSync(primary, @ptrCast(secondary), L.modify);
        }

        /// A UNIQUE single-key secondary index: `secondary[derive(key,value)] = key`.
        /// A derived key already mapping to a DIFFERENT primary key is rejected
        /// (Java throws from the listener). `derive: fn(K, V) Dk`.
        pub fn secondaryKey(primary: Map, secondary: anytype, comptime derive: anytype) DbError!void {
            const Sec = @TypeOf(secondary);
            try rejectSelfBindId(primary, secondary);
            if (try secondary.isEmpty()) {
                const es = try primary.entries();
                defer primary.deinitEntries(es);
                for (es) |e| try putUnique(secondary, derive(e.key, e.val), e.key);
            }
            const L = struct {
                fn modify(ctx: *anyopaque, key: K, old: ?V, new: ?V, _: bool) DbError!void {
                    const sec: Sec = @ptrCast(@alignCast(ctx));
                    if (old) |ov| try sec.removeIfValue(derive(key, ov), key);
                    if (new) |nv| try putUnique(sec, derive(key, nv), key);
                }
            };
            try addSync(primary, @ptrCast(secondary), L.modify);
        }

        /// Inverse index: `inverse[value] = key`; values must be UNIQUE (Java
        /// `mapInverse`, `secondaryKey` with the identity value projection).
        pub fn mapInverse(primary: Map, inverse: anytype) DbError!void {
            const idV = struct {
                fn d(_: K, v: V) V {
                    return v;
                }
            }.d;
            return secondaryKey(primary, inverse, idV);
        }

        /// A multi-valued secondary SET index (Java `secondaryValues` /
        /// `secondaryKeys`): `derive` appends the set tuples of type `T` for
        /// `(key,value)` to `out`; every derived tuple is added on insert and
        /// removed on delete. `secondary: *SecondarySet(T)`; `derive:
        /// fn(K, V, *ArrayListUnmanaged(T), Allocator) DbError!void`.
        pub fn secondarySet(primary: Map, secondary: anytype, comptime T: type, comptime derive: anytype) DbError!void {
            const Sec = @TypeOf(secondary);
            try rejectSelfBindId(primary, secondary);
            if (try secondary.isEmpty()) {
                const alloc = primary.a();
                const es = try primary.entries();
                defer primary.deinitEntries(es);
                for (es) |e| {
                    var out: std.ArrayListUnmanaged(T) = .empty;
                    defer out.deinit(alloc);
                    try derive(e.key, e.val, &out, alloc);
                    for (out.items) |t| try secondary.add(t);
                }
            }
            const L = struct {
                fn modify(ctx: *anyopaque, key: K, old: ?V, new: ?V, _: bool) DbError!void {
                    const sec: Sec = @ptrCast(@alignCast(ctx));
                    const a = sec.alloc; // the container's own allocator (scratch)
                    if (old) |ov| {
                        var out: std.ArrayListUnmanaged(T) = .empty;
                        defer out.deinit(a);
                        try derive(key, ov, &out, a);
                        for (out.items) |t| try sec.remove(t);
                    }
                    if (new) |nv| {
                        var out: std.ArrayListUnmanaged(T) = .empty;
                        defer out.deinit(a);
                        try derive(key, nv, &out, a);
                        for (out.items) |t| try sec.add(t);
                    }
                }
            };
            try addSync(primary, @ptrCast(secondary), L.modify);
        }

        /// Java `secondaryValues` (tuple `(primaryKey, derivedValue)`) — the caller
        /// picks the tuple field order in `T` + `derive`. Alias of `secondarySet`.
        pub const secondaryValues = secondarySet;
        /// Java `secondaryKeys` (tuple `(derivedKey, primaryKey)`). Alias.
        pub const secondaryKeys = secondarySet;

        // ---------------- deferred bindings ----------------

        /// Maintain a running size in an `AtomicLong` (Java `Bind.size`). Seeds the
        /// counter from the primary's current size ONLY when it reads 0, then
        /// increments on insert / decrements on remove. `counter: *AtomicLong(S)`.
        pub fn size(primary: Map, counter: anytype) DbError!void {
            const Counter = @TypeOf(counter);
            if ((try counter.get()) == 0) {
                try counter.set(@intCast(try primary.sizeLong()));
            }
            const L = struct {
                fn modify(ctx: *anyopaque, _: K, old: ?V, new: ?V, _: bool) DbError!void {
                    const c: Counter = @ptrCast(@alignCast(ctx));
                    if (old == null and new != null) {
                        _ = try c.incrementAndGet();
                    } else if (old != null and new == null) {
                        _ = try c.decrementAndGet();
                    }
                }
            };
            try addDeferred(primary, @ptrCast(counter), L.modify);
        }

        /// A category histogram (Java `Bind.histogram`): counts values by
        /// `category`. A category reaching EXACTLY 0 is removed; negatives kept
        /// (wrapping). `hist: *SecondaryMap(C, i64)`; `category: fn(K, V) C`.
        pub fn histogram(primary: Map, hist: anytype, comptime category: anytype) DbError!void {
            const Hist = @TypeOf(hist);
            try rejectSelfBindId(primary, hist);
            if (try hist.isEmpty()) {
                const es = try primary.entries();
                defer primary.deinitEntries(es);
                for (es) |e| {
                    const c = category(e.key, e.val); // evaluate BEFORE the lock
                    try hist.addCount(c, 1);
                }
            }
            const L = struct {
                fn modify(ctx: *anyopaque, key: K, old: ?V, new: ?V, _: bool) DbError!void {
                    const h: Hist = @ptrCast(@alignCast(ctx));
                    if (old) |ov| {
                        const c = category(key, ov);
                        try h.addCount(c, -1);
                    }
                    if (new) |nv| {
                        const c = category(key, nv);
                        try h.addCount(c, 1);
                    }
                }
            };
            try addDeferred(primary, @ptrCast(hist), L.modify);
        }

        /// Capture the removed value of every deleted key (Java
        /// `Bind.mapPutAfterDelete`). `deleted: *SecondaryMap(K, V)`.
        pub fn mapPutAfterDelete(primary: Map, deleted: anytype) DbError!void {
            const Del = @TypeOf(deleted);
            const L = struct {
                fn modify(ctx: *anyopaque, key: K, old: ?V, new: ?V, _: bool) DbError!void {
                    const d: Del = @ptrCast(@alignCast(ctx));
                    if (new == null) if (old) |ov| try d.put(key, ov);
                }
            };
            try addDeferred(primary, @ptrCast(deleted), L.modify);
        }

        // ---------------- helpers ----------------

        /// Insert `derived -> primary_key`, tolerating a duplicate that already maps
        /// to the SAME primary key but rejecting one mapping to a different key. Uses
        /// the container's ATOMIC `putIfAbsent` so two racing synchronous listeners
        /// on different primary leaves cannot both insert the same derived key;
        /// the existing value is compared with the container's
        /// format-aware `valuesEqual` (not pointer identity) and freed via `freeVal`.
        fn putUnique(secondary: anytype, derived: anytype, primary_key: K) DbError!void {
            if (try secondary.putIfAbsent(derived, primary_key)) |existing| {
                defer secondary.freeVal(existing);
                if (!secondary.valuesEqual(existing, primary_key)) return error.WrongConfiguration;
            }
        }
    };
}

// ------------------------------------------------------------------- tests

const testing = std.testing;
const StoreByteArray = @import("../store/mod.zig").StoreByteArray;
const btree = @import("../btree/mod.zig");
const LongFormat = @import("../ser/long.zig").LongFormat;

test "bind: rejectSelfBind refuses a shared-state handle" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    const Map = btree.BTreeMap(StoreByteArray, LongFormat, LongFormat);
    const map = try Map.create(a, &s, LongFormat.instance, LongFormat.instance, 16);
    defer map.deinit();
    const shared = map; // shares Inner
    try testing.expectError(error.WrongConfiguration, Bind(Map).rejectSelfBind(map, shared));
}

test "bind: mapInverse tracks mutations + rejects a duplicate derived value" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    const Map = btree.BTreeMap(StoreByteArray, LongFormat, LongFormat);
    const map = try Map.create(a, &s, LongFormat.instance, LongFormat.instance, 16);
    defer map.deinit();

    var inv = SecondaryMap(i64, i64).init(a); // value -> key
    defer inv.deinit();
    try Bind(Map).mapInverse(map, &inv);

    try map.putOnly(1, 100);
    try map.putOnly(2, 200);
    try map.putOnly(1, 101); // update: 100 removed, 101 added
    try testing.expectEqual(@as(?i64, 1), try inv.get(101));
    try testing.expectEqual(@as(?i64, null), try inv.get(100));
    try testing.expectEqual(@as(?i64, 2), try inv.get(200));

    // A second primary key mapping to an existing value 200 → WrongConfiguration.
    try testing.expectError(error.WrongConfiguration, map.putOnly(3, 200));

    _ = try map.remove(&@as(i64, 2));
    try testing.expectEqual(@as(?i64, null), try inv.get(200));
}

test "bind: concurrent duplicate derived key → exactly one WrongConfiguration" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true); // thread-safe store
    defer s.deinit();
    const Map = btree.BTreeMap(StoreByteArray, LongFormat, LongFormat);
    // maxNodeSize(4) + many keys → multiple leaves, so the two colliding puts
    // fire their synchronous listeners on DIFFERENT leaves concurrently.
    const map = try Map.createCounter(a, &s, LongFormat.instance, LongFormat.instance, 4, true);
    defer map.deinit();
    for (0..20) |i| try map.putOnly(@intCast(i * 2), @intCast(i));

    var inv = SecondaryMap(i64, i64).init(a); // value -> key (unique)
    defer inv.deinit();
    try Bind(Map).mapInverse(map, &inv);

    // Two distinct primary keys, SAME value 999 → duplicate derived key.
    const Runner = struct {
        fn run(m: Map, key: i64, val: i64, out: *?DbError) void {
            m.putOnly(key, val) catch |e| {
                out.* = e;
            };
        }
    };
    var r1: ?DbError = null;
    var r2: ?DbError = null;
    const t1 = try std.Thread.spawn(.{}, Runner.run, .{ map, @as(i64, -1), @as(i64, 999), &r1 });
    const t2 = try std.Thread.spawn(.{}, Runner.run, .{ map, @as(i64, 1000), @as(i64, 999), &r2 });
    t1.join();
    t2.join();
    const errs = (@as(usize, if (r1 != null) 1 else 0)) + (@as(usize, if (r2 != null) 1 else 0));
    try testing.expectEqual(@as(usize, 1), errs); // exactly one loser
    if (r1) |e| try testing.expectEqual(@as(DbError, error.WrongConfiguration), e);
    if (r2) |e| try testing.expectEqual(@as(DbError, error.WrongConfiguration), e);
    try testing.expect((try inv.get(999)) != null); // exactly one mapping kept
}

test "bind: install on a POPULATED primary scans existing entries" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    const Map = btree.BTreeMap(StoreByteArray, LongFormat, LongFormat);
    // maxNodeSize(4) + >4 keys forces splits during population.
    const map = try Map.createCounter(a, &s, LongFormat.instance, LongFormat.instance, 4, true);
    defer map.deinit();
    for (0..8) |i| try map.putOnly(@intCast(i), @intCast(i * 10));

    var doubled = SecondaryMap(i64, i64).init(a); // key -> value*2
    defer doubled.deinit();
    const derive = struct {
        fn d(_: i64, v: i64) i64 {
            return v * 2;
        }
    }.d;
    try Bind(Map).secondaryValue(map, &doubled, derive);
    try testing.expectEqual(@as(usize, 8), doubled.count());
    try testing.expectEqual(@as(?i64, 140), try doubled.get(7)); // 70*2

    // live update flows through the sync listener
    try map.putOnly(7, 1);
    try testing.expectEqual(@as(?i64, 2), try doubled.get(7));
}

test "bind: size counter + histogram" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    const Map = btree.BTreeMap(StoreByteArray, LongFormat, LongFormat);
    const map = try Map.createCounter(a, &s, LongFormat.instance, LongFormat.instance, 8, true);
    defer map.deinit();

    const AtomicLong = @import("atomic.zig").AtomicLong(StoreByteArray);
    const crecid = try s.put(i64, a, @as(i64, 0), @import("../ser/serializers.zig").LongSer.instance);
    var counter = AtomicLong.init(&s, a, crecid);
    try Bind(Map).size(map, &counter);
    try map.putOnly(1, 10);
    try map.putOnly(2, 20);
    try map.putOnly(3, 30);
    _ = try map.remove(&@as(i64, 2));
    try testing.expectEqual(@as(i64, 2), try counter.get());

    // histogram by even/odd of the value
    var hist = SecondaryMap(i64, i64).init(a);
    defer hist.deinit();
    const cat = struct {
        fn c(_: i64, v: i64) i64 {
            return @mod(v, 2);
        }
    }.c;
    try Bind(Map).histogram(map, &hist, cat);
    // values now: {1:10, 3:30} → both even → category 0 count 2
    try testing.expectEqual(@as(?i64, 2), try hist.get(0));
    try map.putOnly(5, 55); // odd
    try testing.expectEqual(@as(?i64, 1), try hist.get(1));
    _ = try map.remove(&@as(i64, 5)); // odd count back to 0 → removed
    try testing.expectEqual(@as(?i64, null), try hist.get(1));
}

test "bind: persistent-map secondary (secondaryValue over a BTreeMap)" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    const Map = btree.BTreeMap(StoreByteArray, LongFormat, LongFormat);
    const primary = try Map.create(a, &s, LongFormat.instance, LongFormat.instance, 16);
    defer primary.deinit();
    const secmap = try Map.create(a, &s, LongFormat.instance, LongFormat.instance, 16);
    defer secmap.deinit();

    var sec = PersistentSecMap(Map).init(secmap);
    const derive = struct {
        fn d(_: i64, v: i64) i64 {
            return v + 1;
        }
    }.d;
    try Bind(Map).secondaryValue(primary, &sec, derive);
    try primary.putOnly(1, 100);
    try primary.putOnly(2, 200);
    try testing.expectEqual(@as(?i64, 101), try secmap.get(&@as(i64, 1)));
    _ = try primary.remove(&@as(i64, 1));
    try testing.expectEqual(@as(?i64, null), try secmap.get(&@as(i64, 1)));
}

test "bind: secondaryKeys multi-valued set index" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    const Map = btree.BTreeMap(StoreByteArray, LongFormat, LongFormat);
    const map = try Map.create(a, &s, LongFormat.instance, LongFormat.instance, 16);
    defer map.deinit();
    // Index each key under the two derived digits of its value.
    const Pair = struct { dk: i64, pk: i64 };
    var idx = SecondarySet(Pair).init(a);
    defer idx.deinit();
    const derive = struct {
        fn d(key: i64, value: i64, out: *std.ArrayListUnmanaged(Pair), alloc: Allocator) DbError!void {
            try out.append(alloc, .{ .dk = @mod(value, 10), .pk = key });
            try out.append(alloc, .{ .dk = @divTrunc(value, 10), .pk = key });
        }
    }.d;
    try Bind(Map).secondaryKeys(map, &idx, Pair, derive);
    try map.putOnly(1, 23); // → (3,1),(2,1)
    try testing.expect(idx.contains(.{ .dk = 3, .pk = 1 }));
    try testing.expect(idx.contains(.{ .dk = 2, .pk = 1 }));
    _ = try map.remove(&@as(i64, 1));
    try testing.expect(!idx.contains(.{ .dk = 3, .pk = 1 }));
    try testing.expectEqual(@as(usize, 0), idx.count());
}

test "bind: mapPutAfterDelete captures removed values" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    const Map = btree.BTreeMap(StoreByteArray, LongFormat, LongFormat);
    const map = try Map.create(a, &s, LongFormat.instance, LongFormat.instance, 16);
    defer map.deinit();
    var deleted = SecondaryMap(i64, i64).init(a);
    defer deleted.deinit();
    try Bind(Map).mapPutAfterDelete(map, &deleted);
    try map.putOnly(1, 111);
    try map.putOnly(2, 222);
    _ = try map.remove(&@as(i64, 1));
    try testing.expectEqual(@as(?i64, 111), try deleted.get(1));
    try testing.expectEqual(@as(?i64, null), try deleted.get(2));
}
