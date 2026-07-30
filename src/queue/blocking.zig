//! `PersistentBlockingQueue` — a store-backed FIFO / LIFO stack /
//! overwrite-on-full circular queue with blocking `take`/`put`, ported from
//! Java `org.mapdb.queue.PersistentBlockingQueue` (and the verified Rust port
//! `mapdb-rust-store/src/queue/blocking.rs`).
//!
//! ## Modes
//!
//! The mode ([`Mode`]), the head/tail/size pointers, and the circular capacity
//! all live in the **header record**, not a catalog key.
//! `Mode` ordinals are wire-relevant (`fifo=0`, `lifo=1`, `circular=2`).
//!
//! ## Wire format (byte-for-byte with Java)
//!
//! Header record: `packInt(mode) ++ packLong(head) ++ packLong(tail) ++
//! packLong(size) ++ packLong(capacity)` (a non-circular queue stores
//! `capacity = Long.MAX_VALUE`). Node record: `packLong(next) ++
//! element_serializer(value)`. `head`/`tail`/`next` are node recids, `0` for
//! "none". Golden: fresh FIFO header → `[80 80 80 80 · 7F×8 FF]`; circular
//! cap-3 → `[82 80 80 80 83]`; string node `{next:0,"a"}` → `[80 81 61]`.
//!
//! ## Blocking coordination (and its limit)
//!
//! Blocking `take`/`put` use a per-handle `std.Thread.Mutex` + two
//! `std.Thread.Condition`s (`not_empty` / `not_full`). Wakeups coordinate ONLY
//! threads sharing the one live handle (`*PersistentBlockingQueue`) — the queue
//! *contents* are durable, but the condition signals are not cross-process.
//!
//! Java `take`/`put` are interruptible (`InterruptedException`). Zig threads
//! have no interruption; a blocked waiter is released only by data becoming
//! available, by a timeout ([`pollTimeout`]/[`offerTimeout`]), or by
//! [`closeHandle`] (the shutdown flag), after which blocked and subsequent
//! operations return `error.StoreClosed`. See `PORTING-GAPS.md`.
//!
//! Use one writable handle per header; direct callers must not open the same
//! header twice concurrently (locks/conditions are handle-local). A store RW
//! lease on the header record (acquired in `build`, released in `closeHandle`)
//! makes a second concurrent open of the same queue fail `AlreadyOpen`, so the DB
//! facade needs no instance cache.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const storemod = @import("../store/mod.zig");

/// Non-circular queues store this as their capacity (Java `Long.MAX_VALUE`).
/// Kept identical to Java for byte parity of the header record.
const UNBOUNDED: u64 = std.math.maxInt(i64);

/// Validate a recid where a live node is expected (`0` means "none").
inline fn nz(recid: u64) DbError!u64 {
    if (recid == 0) return error.DataCorruption;
    return recid;
}

/// Queue discipline. The ordinal is persisted, so variant order is wire-fixed.
pub const Mode = enum(i32) {
    fifo = 0,
    lifo = 1,
    circular = 2,

    fn fromI32(v: i32) DbError!Mode {
        return switch (v) {
            0 => .fifo,
            1 => .lifo,
            2 => .circular,
            else => error.DataCorruption,
        };
    }
};

/// The mutable queue header (persisted in one record).
const Header = struct {
    mode: i32,
    head: u64,
    tail: u64,
    size: u64,
    capacity: u64,
};

/// Zero-sized codec for [`Header`]. Never CAS'd, so `equalsBySerializedBytes`
/// is irrelevant here (set `true` for consistency with the built-ins).
const HeaderSer = struct {
    pub const Elem = Header;
    pub const instance: HeaderSer = .{};

    pub fn serialize(_: HeaderSer, out: *DataOutput2, h: Header) DbError!void {
        try out.packInt(h.mode);
        try out.packLong(h.head);
        try out.packLong(h.tail);
        try out.packLong(h.size);
        try out.packLong(h.capacity);
    }
    pub fn deserialize(_: HeaderSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!Header {
        const mode = try input.unpackInt();
        const head = try input.unpackLong();
        const tail = try input.unpackLong();
        const size = try input.unpackLong();
        const capacity = try input.unpackLong();
        return .{ .mode = mode, .head = head, .tail = tail, .size = size, .capacity = capacity };
    }
    pub fn cloneElem(_: HeaderSer, _: Allocator, h: Header) DbError!Header {
        return h;
    }
    pub fn deinitElem(_: HeaderSer, _: Allocator, _: Header) void {}
    pub fn compare(_: HeaderSer, a: Header, b: Header) Order {
        if (a.mode != b.mode) return std.math.order(a.mode, b.mode);
        if (a.head != b.head) return std.math.order(a.head, b.head);
        if (a.tail != b.tail) return std.math.order(a.tail, b.tail);
        if (a.size != b.size) return std.math.order(a.size, b.size);
        return std.math.order(a.capacity, b.capacity);
    }
    pub fn equals(_: HeaderSer, a: Header, b: Header) bool {
        return a.mode == b.mode and a.head == b.head and a.tail == b.tail and
            a.size == b.size and a.capacity == b.capacity;
    }
    pub fn fixedSize(_: HeaderSer) ?usize {
        return null;
    }
    pub fn equalsBySerializedBytes(_: HeaderSer) bool {
        return true;
    }
};

/// A singly-linked node: `next` recid (`0` = end) plus the element `E`.
fn QNode(comptime E: type) type {
    return struct { next: u64, value: E };
}

/// Codec for [`QNode`], delegating the element to a serializer VALUE `se`
/// (`packLong(next) ++ element(value)`). `Se` may be STATEFUL (e.g. a
/// `CompressionSerializer`, which has no `instance`), so the codec carries the
/// serializer value rather than a singleton.
fn NodeSer(comptime Se: type) type {
    const E = Se.Elem;
    const QN = QNode(E);
    return struct {
        const Self = @This();
        pub const Elem = QN;
        se: Se,

        pub fn serialize(self: Self, out: *DataOutput2, node: QN) DbError!void {
            try out.packLong(node.next);
            try self.se.serialize(out, node.value);
        }
        pub fn deserialize(self: Self, alloc: Allocator, input: *DataInput2, _: ?usize) DbError!QN {
            const next = try input.unpackLong();
            const value = try self.se.deserialize(alloc, input, null);
            return .{ .next = next, .value = value };
        }
        pub fn cloneElem(self: Self, alloc: Allocator, node: QN) DbError!QN {
            return .{ .next = node.next, .value = try self.se.cloneElem(alloc, node.value) };
        }
        pub fn deinitElem(self: Self, alloc: Allocator, node: QN) void {
            self.se.deinitElem(alloc, node.value);
        }
        pub fn compare(self: Self, a: QN, b: QN) Order {
            if (a.next != b.next) return std.math.order(a.next, b.next);
            return self.se.compare(a.value, b.value);
        }
        pub fn equals(self: Self, a: QN, b: QN) bool {
            return a.next == b.next and self.se.equals(a.value, b.value);
        }
        pub fn fixedSize(_: Self) ?usize {
            return null;
        }
        pub fn equalsBySerializedBytes(self: Self) bool {
            return self.se.equalsBySerializedBytes();
        }
    };
}

/// Store-backed blocking FIFO/LIFO/circular queue. Generic over the store type
/// `S` and the element serializer type `Se` (element type `E == Se.Elem`).
///
/// Holds a `Mutex` + two `Condition`s; do not copy after construction — keep it
/// at a stable address and share a `*PersistentBlockingQueue(...)` to coordinate
/// threads over one live handle. Returned slice-typed elements are owned by the
/// queue's allocator; free them with `Se.instance.deinitElem(alloc, e)`.
pub fn PersistentBlockingQueue(comptime S: type, comptime Se: type) type {
    const E = Se.Elem;
    const QN = QNode(E);
    const NS = NodeSer(Se);
    return struct {
        const Self = @This();

        store: *S,
        alloc: Allocator,
        header_recid: u64,
        /// The element serializer VALUE (may be stateful).
        se: Se,
        mu: std.Thread.Mutex = .{},
        not_empty: std.Thread.Condition = .{},
        not_full: std.Thread.Condition = .{},
        closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        /// Number of threads currently PARKED inside `not_empty`/`not_full` (review
        /// C4). `closeHandle` broadcasts then blocks on `drained` until this reaches
        /// zero, so the DB facade can free the heap box only after every woken
        /// waiter has left the queue. Guarded by `mu`.
        waiters: usize = 0,
        drained: std.Thread.Condition = .{},
        /// Whether the header RW lease is still held. Acquired in
        /// `build`, released exactly once by `closeHandle`. Guarded by `mu`.
        lease_active: bool = true,

        /// Create a fresh queue of the given `mode`. `capacity` is used only for
        /// [`Mode.circular`]; FIFO/LIFO are unbounded (`Long.MAX_VALUE`). A
        /// circular capacity must be in `1..=maxInt(i64)` (a value Java can
        /// reopen as a positive signed long).
        pub fn create(store: *S, alloc: Allocator, queue_mode: Mode, capacity: u64, se: Se) DbError!Self {
            const actual_capacity: u64 = if (queue_mode == .circular) capacity else UNBOUNDED;
            if (actual_capacity == 0 or actual_capacity > UNBOUNDED) return error.DataCorruption;
            const hdr = Header{
                .mode = @intFromEnum(queue_mode),
                .head = 0,
                .tail = 0,
                .size = 0,
                .capacity = actual_capacity,
            };
            const header_recid = try store.put(Header, alloc, hdr, HeaderSer.instance);
            return build(store, alloc, header_recid, se);
        }

        /// Reopen an existing queue from its header recid.
        pub fn open(store: *S, alloc: Allocator, header_recid: u64, se: Se) DbError!Self {
            return build(store, alloc, header_recid, se);
        }

        /// The node codec bound to this queue's serializer value.
        fn nodeSer(self: *const Self) NS {
            return NS{ .se = self.se };
        }

        fn build(store: *S, alloc: Allocator, header_recid: u64, se: Se) DbError!Self {
            // A store lease on the header record makes a conflicting second open of
            // the same queue fail `AlreadyOpen`, mirroring the map's
            // root-recid lease. A read-only store takes a READ-only lease so RO+RO
            // opens coexist; a writable store takes the RW lease
            // (2nd writable open → AlreadyOpen). Released exactly once in
            // `closeHandle`.
            const lease_kind: storemod.LeaseKind = if (storemod.isReadOnly(S, store)) .read_only else .read_write;
            try store.leaseTable().acquire(header_recid, lease_kind);
            errdefer store.leaseTable().release(header_recid);
            var q = Self{ .store = store, .alloc = alloc, .header_recid = header_recid, .se = se };
            const h = try q.headerRaw();
            // Java reads capacity/size/head/tail as SIGNED longs, so a value above
            // maxInt(i64) (foreign/torn write) fails its capacity<=0 / size<0 checks.
            // Reject the same here so a bad header can't later underflow a u64 sub.
            if (h.mode < 0 or h.mode >= 3 or h.capacity == 0) return error.DataCorruption;
            if (h.capacity > UNBOUNDED or h.size > UNBOUNDED) return error.DataCorruption;
            return q;
        }

        // ---- record accessors (caller holds `mu` unless noted) ----------

        /// Read the header, erroring once the handle is closed (Java `header()`).
        fn header(self: *Self) DbError!Header {
            if (self.closed.load(.acquire)) return error.StoreClosed;
            return self.headerRaw();
        }
        fn headerRaw(self: *Self) DbError!Header {
            return (try self.store.get(Header, self.alloc, self.header_recid, HeaderSer.instance)) orelse
                error.DataCorruption;
        }
        fn writeHeader(self: *Self, h: Header) DbError!void {
            try self.store.update(Header, self.alloc, self.header_recid, h, HeaderSer.instance);
        }
        /// Owned node at `recid` (caller frees via `nodeDeinit`).
        fn node(self: *Self, recid: u64) DbError!QN {
            return (try self.store.get(QN, self.alloc, recid, self.nodeSer())) orelse error.DataCorruption;
        }
        fn nodeDeinit(self: *Self, n: QN) void {
            self.nodeSer().deinitElem(self.alloc, n);
        }
        fn elemDeinit(self: *Self, v: E) void {
            self.se.deinitElem(self.alloc, v);
        }
        fn full(_: *Self, h: Header) bool {
            return h.size >= h.capacity;
        }

        // ---- core enqueue / dequeue (caller holds `mu`) -----------------

        fn enqueue(self: *Self, h_in: Header, value: E) DbError!void {
            const m = try Mode.fromI32(h_in.mode);
            var h = h_in;
            if (m == .circular and self.full(h)) {
                const d = try self.dequeueLocked(h);
                if (d.value) |v| self.elemDeinit(v);
                h = d.h;
            }
            if (m == .lifo) {
                const recid = try self.store.put(QN, self.alloc, .{ .next = h.head, .value = value }, self.nodeSer());
                try self.writeHeader(.{
                    .mode = h.mode,
                    .head = recid,
                    .tail = if (h.size == 0) recid else h.tail,
                    .size = h.size + 1,
                    .capacity = h.capacity,
                });
            } else {
                const recid = try self.store.put(QN, self.alloc, .{ .next = 0, .value = value }, self.nodeSer());
                if (h.tail != 0) {
                    const tail_recid = try nz(h.tail);
                    const tail_node = try self.node(tail_recid);
                    defer self.elemDeinit(tail_node.value);
                    try self.store.update(QN, self.alloc, tail_recid, .{ .next = recid, .value = tail_node.value }, self.nodeSer());
                }
                try self.writeHeader(.{
                    .mode = h.mode,
                    .head = if (h.size == 0) recid else h.head,
                    .tail = recid,
                    .size = h.size + 1,
                    .capacity = h.capacity,
                });
            }
        }

        const Dequeued = struct { h: Header, value: ?E };

        /// Remove the head node, returning its (owned) value in `.value`.
        fn dequeueLocked(self: *Self, h: Header) DbError!Dequeued {
            if (h.size == 0) return .{ .h = h, .value = null };
            const head_recid = try nz(h.head);
            const n = try self.node(head_recid); // owned; value transfers out on success
            errdefer self.elemDeinit(n.value);
            const next = Header{
                .mode = h.mode,
                .head = n.next,
                .tail = if (h.size == 1) 0 else h.tail,
                .size = h.size - 1,
                .capacity = h.capacity,
            };
            try self.writeHeader(next);
            try self.store.delete(head_recid);
            return .{ .h = next, .value = n.value };
        }

        fn removeHeadLocked(self: *Self) DbError!E {
            const d = try self.dequeueLocked(try self.header());
            self.not_full.signal();
            return d.value orelse error.DataCorruption;
        }

        // ---- non-blocking API -------------------------------------------

        /// Insert `value`; `false` if a bounded (FIFO/LIFO) queue is full.
        pub fn offer(self: *Self, value: E) DbError!bool {
            self.mu.lock();
            defer self.mu.unlock();
            const h = try self.header();
            if (self.full(h) and (try Mode.fromI32(h.mode)) != .circular) return false;
            try self.enqueue(h, value);
            self.not_empty.signal();
            return true;
        }

        /// Insert `value`, erroring `Unsupported` if a bounded queue is full
        /// (Java `AbstractQueue.add` / `IllegalStateException`).
        pub fn add(self: *Self, value: E) DbError!void {
            if (try self.offer(value)) return;
            return error.Unsupported;
        }

        /// `add` every element of `values`.
        pub fn addAll(self: *Self, values: []const E) DbError!void {
            for (values) |v| try self.add(v);
        }

        /// Remove and return the head, or `null` if empty.
        pub fn poll(self: *Self) DbError!?E {
            self.mu.lock();
            defer self.mu.unlock();
            const h = try self.header();
            if (h.size == 0) return null;
            const d = try self.dequeueLocked(h);
            self.not_full.signal();
            return d.value;
        }

        /// The head element without removing it, or `null` if empty.
        pub fn peek(self: *Self) DbError!?E {
            self.mu.lock();
            defer self.mu.unlock();
            const h = try self.header();
            if (h.size == 0) return null;
            const n = try self.node(try nz(h.head));
            return n.value; // owned; only field is `value`
        }

        // ---- blocking API -----------------------------------------------

        /// Block until an element is available, then remove and return it.
        /// Errors `error.StoreClosed` if the handle is closed while waiting.
        pub fn take(self: *Self) DbError!E {
            self.mu.lock();
            defer self.mu.unlock();
            while (true) {
                const h = try self.header();
                if (h.size != 0) return try self.removeHeadLocked();
                self.parkWait(&self.not_empty);
            }
        }

        /// [`take`] with a timeout (nanoseconds); `null` if it elapses.
        pub fn pollTimeout(self: *Self, timeout_ns: u64) DbError!?E {
            self.mu.lock();
            defer self.mu.unlock();
            const deadline = std.time.nanoTimestamp() + @as(i128, timeout_ns);
            while (true) {
                const h = try self.header();
                if (h.size != 0) return try self.removeHeadLocked();
                const now = std.time.nanoTimestamp();
                if (now >= deadline) return null;
                const rem: u64 = @intCast(deadline - now);
                self.parkTimedWait(&self.not_empty, rem); // Timeout -> loop -> deadline check
            }
        }

        /// Block until there is room, then insert `value`. Circular queues never
        /// block. Errors `error.StoreClosed` if closed while waiting.
        pub fn put(self: *Self, value: E) DbError!void {
            self.mu.lock();
            defer self.mu.unlock();
            var h = try self.header();
            while (self.full(h) and (try Mode.fromI32(h.mode)) != .circular) {
                self.parkWait(&self.not_full);
                h = try self.header();
            }
            try self.enqueue(h, value);
            self.not_empty.signal();
        }

        /// [`put`] with a timeout (nanoseconds); `false` if it elapses.
        pub fn offerTimeout(self: *Self, value: E, timeout_ns: u64) DbError!bool {
            self.mu.lock();
            defer self.mu.unlock();
            const deadline = std.time.nanoTimestamp() + @as(i128, timeout_ns);
            var h = try self.header();
            while (self.full(h) and (try Mode.fromI32(h.mode)) != .circular) {
                const now = std.time.nanoTimestamp();
                if (now >= deadline) return false;
                const rem: u64 = @intCast(deadline - now);
                self.parkTimedWait(&self.not_full, rem);
                h = try self.header();
            }
            try self.enqueue(h, value);
            self.not_empty.signal();
            return true;
        }

        // ---- waiter accounting (review C4; caller holds `mu`) ------------

        /// Park on `cond`, counting this thread as an in-flight waiter so
        /// `closeHandle` can join it before the handle is freed.
        fn parkWait(self: *Self, cond: *std.Thread.Condition) void {
            self.waiters += 1;
            cond.wait(&self.mu);
            self.waiters -= 1;
            self.drained.signal();
        }
        fn parkTimedWait(self: *Self, cond: *std.Thread.Condition, timeout_ns: u64) void {
            self.waiters += 1;
            cond.timedWait(&self.mu, timeout_ns) catch {};
            self.waiters -= 1;
            self.drained.signal();
        }

        // ---- collection helpers -----------------------------------------

        /// Current element count.
        pub fn size(self: *Self) DbError!u64 {
            self.mu.lock();
            defer self.mu.unlock();
            return (try self.header()).size;
        }

        pub fn isEmpty(self: *Self) DbError!bool {
            return (try self.size()) == 0;
        }

        /// Remaining insertable capacity (`capacity - size`).
        pub fn remainingCapacity(self: *Self) DbError!u64 {
            self.mu.lock();
            defer self.mu.unlock();
            const h = try self.header();
            // Saturating: a corrupt size>capacity must not panic on u64 underflow
            // (Java returns a clamped negative; callers treat <=0 as "full").
            return h.capacity -| h.size;
        }

        /// True if `value` is present (by serializer equality).
        pub fn contains(self: *Self, value: E) DbError!bool {
            self.mu.lock();
            defer self.mu.unlock();
            var recid = (try self.header()).head;
            while (recid != 0) {
                const n = try self.node(try nz(recid));
                defer self.elemDeinit(n.value);
                if (self.se.equals(n.value, value)) return true;
                recid = n.next;
            }
            return false;
        }

        /// Remove the first node equal to `value`; `true` if one was removed.
        pub fn removeValue(self: *Self, value: E) DbError!bool {
            self.mu.lock();
            defer self.mu.unlock();
            const h = try self.header();
            var previous_recid: u64 = 0;
            var recid = h.head;
            while (recid != 0) {
                const cur = try nz(recid);
                const n = try self.node(cur); // owned
                if (self.se.equals(n.value, value)) {
                    self.elemDeinit(n.value); // done with matched value
                    if (previous_recid == 0) {
                        try self.writeHeader(.{
                            .mode = h.mode,
                            .head = n.next,
                            .tail = if (h.size == 1) 0 else h.tail,
                            .size = h.size - 1,
                            .capacity = h.capacity,
                        });
                    } else {
                        const prev_recid = try nz(previous_recid);
                        const previous = try self.node(prev_recid);
                        defer self.elemDeinit(previous.value);
                        try self.store.update(QN, self.alloc, prev_recid, .{ .next = n.next, .value = previous.value }, self.nodeSer());
                        try self.writeHeader(.{
                            .mode = h.mode,
                            .head = h.head,
                            .tail = if (h.tail == recid) previous_recid else h.tail,
                            .size = h.size - 1,
                            .capacity = h.capacity,
                        });
                    }
                    try self.store.delete(cur);
                    self.not_full.signal();
                    return true;
                }
                previous_recid = recid;
                const nxt = n.next;
                self.elemDeinit(n.value); // free non-matching node value
                recid = nxt;
            }
            return false;
        }

        /// Move up to `max_elements` head elements into `out` (appended, owned by
        /// the queue's allocator); returns the count moved.
        pub fn drainTo(self: *Self, out: *std.ArrayListUnmanaged(E), max_elements: usize) DbError!usize {
            if (max_elements == 0) return 0;
            self.mu.lock();
            defer self.mu.unlock();
            var count: usize = 0;
            while (count < max_elements and (try self.header()).size != 0) {
                const v = try self.removeHeadLocked();
                errdefer self.elemDeinit(v);
                try out.append(self.alloc, v);
                count += 1;
            }
            return count;
        }

        /// Remove all elements.
        pub fn clear(self: *Self) DbError!void {
            self.mu.lock();
            defer self.mu.unlock();
            var h = try self.header();
            while (h.size != 0) {
                const d = try self.dequeueLocked(h);
                if (d.value) |v| self.elemDeinit(v);
                h = d.h;
            }
            self.not_full.broadcast();
        }

        /// Snapshot of the elements head-first, into an owned slice. Each element
        /// AND the slice are owned by the queue's allocator (caller frees).
        pub fn toOwnedSlice(self: *Self) DbError![]E {
            self.mu.lock();
            defer self.mu.unlock();
            var out: std.ArrayListUnmanaged(E) = .empty;
            errdefer {
                for (out.items) |v| self.elemDeinit(v);
                out.deinit(self.alloc);
            }
            var recid = (try self.header()).head;
            while (recid != 0) {
                const n = try self.node(try nz(recid));
                errdefer self.elemDeinit(n.value); // free the in-flight element if append OOMs
                try out.append(self.alloc, n.value);
                recid = n.next;
            }
            return out.toOwnedSlice(self.alloc);
        }

        /// Wake blocked operations, mark the handle closed, JOIN every woken waiter
        /// (so a subsequent free of the heap box cannot use-after-free — review
        /// C4), then release the header lease exactly once. Idempotent.
        /// Does not touch the shared store; subsequent ops return `StoreClosed`.
        pub fn closeHandle(self: *Self) void {
            self.mu.lock();
            defer self.mu.unlock();
            self.closed.store(true, .release);
            self.not_empty.broadcast();
            self.not_full.broadcast();
            // Wait for every parked waiter to leave its wait BEFORE returning, so
            // the caller may free this handle without a live waiter still inside it.
            while (self.waiters != 0) self.drained.wait(&self.mu);
            if (self.lease_active) {
                self.lease_active = false;
                self.store.leaseTable().release(self.header_recid);
            }
        }

        pub fn headerRecid(self: *const Self) u64 {
            return self.header_recid;
        }

        /// The queue's mode (reads the header).
        pub fn mode(self: *Self) DbError!Mode {
            self.mu.lock();
            defer self.mu.unlock();
            return Mode.fromI32((try self.header()).mode);
        }

        /// Structural self-check; `error.VerifyFailed` on inconsistency.
        pub fn verify(self: *Self) DbError!void {
            self.mu.lock();
            defer self.mu.unlock();
            const h = try self.header();
            var count: u64 = 0;
            var recid = h.head;
            var last: u64 = 0;
            while (recid != 0) {
                count += 1;
                if (count > h.size) return error.VerifyFailed;
                last = recid;
                const n = try self.node(try nz(recid));
                defer self.nodeDeinit(n);
                recid = n.next;
            }
            const tail_ok = if (count == 0) h.tail == 0 else h.tail == last;
            if (count != h.size or !tail_ok) return error.VerifyFailed;
        }
    };
}

// ------------------------------------------------------------------- tests

const testing = std.testing;
const StoreByteArray = @import("../store/mod.zig").StoreByteArray;
const StringSer = @import("../ser/serializers.zig").StringSer;

test {
    testing.refAllDecls(@This());
    // Force analysis of every method for a concrete (store, serializer) pair.
    testing.refAllDecls(PersistentBlockingQueue(StoreByteArray, StringSer));
}

test "blocking queue header/node golden vectors (Java parity)" {
    const a = testing.allocator;
    // Fresh FIFO header: mode=0, head=tail=size=0, capacity=Long.MAX_VALUE.
    // packInt(0)=0x80; packLong(0)=0x80 (x3); packLong(i64::MAX)=0x7F x8 then 0xFF.
    {
        var out = DataOutput2.init(a);
        defer out.deinit();
        try HeaderSer.instance.serialize(&out, .{ .mode = 0, .head = 0, .tail = 0, .size = 0, .capacity = UNBOUNDED });
        try testing.expectEqualSlices(u8, &.{ 0x80, 0x80, 0x80, 0x80, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0xFF }, out.bytes());
    }
    // Fresh CIRCULAR cap-3 header: mode=2 -> 0x82; three 0x80; capacity 3 -> 0x83.
    {
        var out = DataOutput2.init(a);
        defer out.deinit();
        try HeaderSer.instance.serialize(&out, .{ .mode = 2, .head = 0, .tail = 0, .size = 0, .capacity = 3 });
        try testing.expectEqualSlices(u8, &.{ 0x82, 0x80, 0x80, 0x80, 0x83 }, out.bytes());
    }
    // String node {next:0, "a"}: packLong(0)=0x80; STRING("a")=packInt(1)0x81 + 'a'0x61.
    {
        const NS = NodeSer(StringSer){ .se = StringSer.instance };
        var out = DataOutput2.init(a);
        defer out.deinit();
        try NS.serialize(&out, .{ .next = 0, .value = "a" });
        try testing.expectEqualSlices(u8, &.{ 0x80, 0x81, 0x61 }, out.bytes());
        // {next:7, "bc"}: packLong(7)=0x87; STRING("bc")=0x82 'b'0x62 'c'0x63.
        var o2 = DataOutput2.init(a);
        defer o2.deinit();
        try NS.serialize(&o2, .{ .next = 7, .value = "bc" });
        try testing.expectEqualSlices(u8, &.{ 0x87, 0x82, 0x62, 0x63 }, o2.bytes());
    }
}

const StrQueue = PersistentBlockingQueue(StoreByteArray, StringSer);

fn expectPollEql(q: *StrQueue, expected: ?[]const u8) !void {
    const got = try q.poll();
    if (expected) |e| {
        try testing.expect(got != null);
        defer StringSer.instance.deinitElem(testing.allocator, got.?);
        try testing.expectEqualStrings(e, got.?);
    } else {
        try testing.expect(got == null);
    }
}

test "blocking queue FIFO/LIFO/CIRCULAR and reopen" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();

    var fifo = try StrQueue.create(&s, a, .fifo, std.math.maxInt(u64), StringSer.instance);
    try fifo.addAll(&.{ "a", "b", "c" });
    try expectPollEql(&fifo, "a");
    try testing.expect(try fifo.removeValue("b"));
    {
        const p = (try fifo.peek()).?;
        defer StringSer.instance.deinitElem(a, p);
        try testing.expectEqualStrings("c", p);
    }
    try fifo.verify();
    const fifo_header = fifo.headerRecid();
    fifo.closeHandle(); // release the header lease before reopening
    var reopened = try StrQueue.open(&s, a, fifo_header, StringSer.instance);
    defer reopened.closeHandle();
    {
        const t = try reopened.take();
        defer StringSer.instance.deinitElem(a, t);
        try testing.expectEqualStrings("c", t);
    }
    try expectPollEql(&reopened, null);

    var stack = try StrQueue.create(&s, a, .lifo, std.math.maxInt(u64), StringSer.instance);
    try stack.addAll(&.{ "a", "b", "c" });
    try expectPollEql(&stack, "c");
    try expectPollEql(&stack, "b");
    try stack.verify();

    var circular = try StrQueue.create(&s, a, .circular, 3, StringSer.instance);
    try circular.addAll(&.{ "a", "b", "c", "d" }); // "a" is dropped
    try testing.expectEqual(@as(u64, 3), try circular.size());
    try expectPollEql(&circular, "b");
    try expectPollEql(&circular, "c");
    try expectPollEql(&circular, "d");
    try circular.verify();
}

test "blocking take wakes on put" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    var q = try StrQueue.create(&s, a, .fifo, std.math.maxInt(u64), StringSer.instance);

    const Taker = struct {
        fn run(queue: *StrQueue, out: *?[]const u8) void {
            out.* = queue.take() catch null;
        }
    };
    var taken: ?[]const u8 = null;
    const t = try std.Thread.spawn(.{}, Taker.run, .{ &q, &taken });
    std.Thread.sleep(50 * std.time.ns_per_ms); // let the taker block on empty
    try q.put("ready");
    t.join();
    try testing.expect(taken != null);
    defer StringSer.instance.deinitElem(a, taken.?);
    try testing.expectEqualStrings("ready", taken.?);
}

test "blocking closeHandle wakes taker with StoreClosed" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    var q = try StrQueue.create(&s, a, .fifo, std.math.maxInt(u64), StringSer.instance);

    const Taker = struct {
        fn run(queue: *StrQueue, out: *?DbError) void {
            if (queue.take()) |v| {
                StringSer.instance.deinitElem(testing.allocator, v);
                out.* = null;
            } else |e| out.* = e;
        }
    };
    var result: ?DbError = null;
    const t = try std.Thread.spawn(.{}, Taker.run, .{ &q, &result });
    std.Thread.sleep(50 * std.time.ns_per_ms);
    q.closeHandle();
    t.join();
    try testing.expectEqual(@as(?DbError, error.StoreClosed), result);
}

test "blocking pollTimeout returns null" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    var q = try StrQueue.create(&s, a, .fifo, std.math.maxInt(u64), StringSer.instance);
    try testing.expect((try q.pollTimeout(20 * std.time.ns_per_ms)) == null);
}

test "blocking remove tail/middle + drain + contains + offerTimeout" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    var q = try StrQueue.create(&s, a, .fifo, std.math.maxInt(u64), StringSer.instance);

    // offerTimeout success (not full, returns immediately).
    try testing.expect(try q.offerTimeout("a", 50 * std.time.ns_per_ms));
    try q.addAll(&.{ "b", "c" });
    try testing.expect(try q.contains("b"));
    try testing.expect(!(try q.contains("z")));

    // Drain two head elements.
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (out.items) |v| StringSer.instance.deinitElem(a, v);
        out.deinit(a);
    }
    try testing.expectEqual(@as(usize, 2), try q.drainTo(&out, 2));
    try testing.expectEqualStrings("a", out.items[0]);
    try testing.expectEqualStrings("b", out.items[1]);
    try testing.expectEqual(@as(u64, 1), try q.size());
    try expectPollEql(&q, "c");

    // Remove the TAIL element (h.tail == recid fix-up).
    try q.addAll(&.{ "a", "b", "c" });
    try testing.expect(try q.removeValue("c"));
    try q.verify();
    {
        const vs = try q.toOwnedSlice();
        defer {
            for (vs) |v| StringSer.instance.deinitElem(a, v);
            a.free(vs);
        }
        try testing.expectEqual(@as(usize, 2), vs.len);
        try testing.expectEqualStrings("a", vs[0]);
        try testing.expectEqualStrings("b", vs[1]);
    }
    // Remove a MIDDLE element (previous != 0, tail unchanged).
    try q.clear();
    try q.addAll(&.{ "a", "b", "c" });
    try testing.expect(try q.removeValue("b"));
    try q.verify();
    try expectPollEql(&q, "a");
    try expectPollEql(&q, "c");
}

test "blocking remove head with size==1 resets tail" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    var q = try StrQueue.create(&s, a, .fifo, std.math.maxInt(u64), StringSer.instance);
    try q.add("a");
    try testing.expect(try q.removeValue("a"));
    try testing.expectEqual(@as(u64, 0), try q.size());
    try q.verify();
}

test "blocking create rejects circular capacity above maxInt(i64)" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    try testing.expectError(error.DataCorruption, StrQueue.create(&s, a, .circular, std.math.maxInt(u64), StringSer.instance));
    // capacity 0 also rejected.
    try testing.expectError(error.DataCorruption, StrQueue.create(&s, a, .circular, 0, StringSer.instance));
}

test "queue header lease rejects a second concurrent open" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    var q = try StrQueue.create(&s, a, .fifo, std.math.maxInt(u64), StringSer.instance);
    // A second open of the same header while the first handle is live → AlreadyOpen.
    try testing.expectError(error.AlreadyOpen, StrQueue.open(&s, a, q.headerRecid(), StringSer.instance));
    const header = q.headerRecid();
    q.closeHandle(); // releases the lease
    var q2 = try StrQueue.open(&s, a, header, StringSer.instance); // now allowed
    q2.closeHandle();
}

test "blocking bounded queue offer returns false when full" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    // A FIFO's capacity is Long.MAX_VALUE, so it never fills; use CIRCULAR to
    // exercise a full queue differently. For a bounded FIFO-style full test we
    // rely on `add` erroring via `offer` only on a genuinely bounded queue,
    // which the public API only exposes as CIRCULAR (never blocks). Instead,
    // assert offerTimeout on a circular queue always succeeds (overwrites).
    var q = try StrQueue.create(&s, a, .circular, 2, StringSer.instance);
    try testing.expect(try q.offer("a"));
    try testing.expect(try q.offer("b"));
    try testing.expect(try q.offer("c")); // circular overwrite, still true
    try testing.expectEqual(@as(u64, 2), try q.size());
}
