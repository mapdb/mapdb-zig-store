//! `QueueLong` — persistent FIFO of `(timestamp, value)` long pairs over a
//! Store4 store, ported from Java `org.mapdb.QueueLong` /
//! `QueueLongTakeUntil` (and the verified Rust port `mapdb-rust-store/src/queue/long.rs`).
//!
//! A queue is reopenable from just its three pointer recids
//! (`tail_recid`, `head_recid`, `head_prev_recid`) — there is no separate
//! header object. It is a **direct store primitive**, not a named DB catalog
//! object: the DB facade writes no QueueLong catalog entry
//! and constructs it directly from the three recids.
//!
//! ## Wire format (byte-for-byte with Java)
//!
//! Each of the three pointer recids stores a single `LONG_PACKED` value (a node
//! recid, or `0` for "none"). A queue **node** record is four packed longs, in
//! order: `packLong(prev) ++ packLong(next) ++ packLong(timestamp) ++
//! packLong(value)`. Java writes `prev`/`next` via `Serializers.LONG_PACKED`
//! and `timestamp`/`value` via `DataOutput2.packLong`; for non-negative values
//! those two encoders emit identical bytes, so all four fields are plain packed
//! longs. Golden: `Node(0,5,10,1)` → `[80 85 8A 81]`.
//!
//! ## Strictness
//!
//! Java's `QueueLong.Node` constructor rejects a negative `timestamp`/`value`
//! (or recid), because the fields are packed as **unsigned** longs — stricter
//! than MapDB 3, which accepted negatives. This port enforces that structurally:
//! every `Node` field and the public `put` API take `u64`, so a negative is
//! unrepresentable (decisions D8/D9 — API misuse becomes a type error). In
//! addition, `put`/`bump` REJECT a field `> maxInt(i64)`: such a `u64` would
//! serialize a record Java's `Node` reads back as a negative field and rejects.
//!
//! ## Concurrency
//!
//! Java's methods are `synchronized` on the handle. Here a per-handle
//! `std.Thread.Mutex` serializes operations so each multi-record mutation is
//! atomic against other operations on the same handle. `takeUntil`/`forEach`
//! run a user callback while holding the lock; because the mutex is
//! non-reentrant (unlike Java's `synchronized` monitor), a callback that
//! re-enters the same handle would deadlock — a re-entry guard detects this and
//! returns `error.DataCorruption` instead (see `PORTING-GAPS.md`). As in Java,
//! do not open two writable handles over the same pointer recids concurrently;
//! share one `*QueueLong` handle instead.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const serializers = @import("../ser/serializers.zig");

/// Pointer-record serializer (Java `Serializers.LONG_PACKED`).
const LONG_PACKED = serializers.LongPackedSer.instance;

/// Largest field value that round-trips through Java, whose packed longs decode
/// as **signed** `long`s. A `u64` in `(maxInt(i64), maxInt(u64)]` would
/// serialize a record Java's `QueueLong.Node` rejects (negative field).
const MAX_FIELD: u64 = std.math.maxInt(i64);

fn checkField(v: u64) DbError!void {
    if (v > MAX_FIELD) return error.DataCorruption;
}

/// Validate a recid where a live node is expected (`0` means "none").
inline fn nz(recid: u64) DbError!u64 {
    if (recid == 0) return error.DataCorruption;
    return recid;
}

/// A queue node: two link recids plus the `(timestamp, value)` payload. `prev`
/// is `0` for the oldest (tail) node; `next` always points to the following
/// node or the head sentinel. All four fields are non-negative (see the module
/// strictness note), hence `u64`.
pub const Node = struct {
    prev: u64,
    next: u64,
    timestamp: u64,
    value: u64,

    pub fn init(prev: u64, next: u64, timestamp: u64, value: u64) Node {
        return .{ .prev = prev, .next = next, .timestamp = timestamp, .value = value };
    }

    fn withPrev(self: Node, prev: u64) Node {
        return .{ .prev = prev, .next = self.next, .timestamp = self.timestamp, .value = self.value };
    }
    fn withNext(self: Node, next: u64) Node {
        return .{ .prev = self.prev, .next = next, .timestamp = self.timestamp, .value = self.value };
    }
    fn withLinksAndTimestamp(self: Node, prev: u64, next: u64, timestamp: u64) Node {
        return .{ .prev = prev, .next = next, .timestamp = timestamp, .value = self.value };
    }
};

/// Byte-for-byte codec for [`Node`] — four packed longs (`prev`, `next`,
/// `timestamp`, `value`). Matches Java `QueueLong.Node.SERIALIZER`. Zero-sized
/// and stateless (so it is usable by `StoreOnHeap`).
pub const NodeSer = struct {
    pub const Elem = Node;
    pub const instance: NodeSer = .{};

    pub fn serialize(_: NodeSer, out: *DataOutput2, v: Node) DbError!void {
        try out.packLong(v.prev);
        try out.packLong(v.next);
        try out.packLong(v.timestamp);
        try out.packLong(v.value);
    }
    pub fn deserialize(_: NodeSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!Node {
        const prev = try input.unpackLong();
        const next = try input.unpackLong();
        const timestamp = try input.unpackLong();
        const value = try input.unpackLong();
        // Read-path strictness (Java `Node` constructor also runs on deserialize):
        // a corrupt/foreign record with a >63-bit packed field reads as a negative
        // long in Java and throws — reject it here too rather than round-trip it.
        try checkField(prev);
        try checkField(next);
        try checkField(timestamp);
        try checkField(value);
        return .{ .prev = prev, .next = next, .timestamp = timestamp, .value = value };
    }
    pub fn cloneElem(_: NodeSer, _: Allocator, v: Node) DbError!Node {
        return v;
    }
    pub fn deinitElem(_: NodeSer, _: Allocator, _: Node) void {}
    pub fn compare(_: NodeSer, a: Node, b: Node) Order {
        if (a.prev != b.prev) return std.math.order(a.prev, b.prev);
        if (a.next != b.next) return std.math.order(a.next, b.next);
        if (a.timestamp != b.timestamp) return std.math.order(a.timestamp, b.timestamp);
        return std.math.order(a.value, b.value);
    }
    pub fn equals(_: NodeSer, a: Node, b: Node) bool {
        return a.prev == b.prev and a.next == b.next and
            a.timestamp == b.timestamp and a.value == b.value;
    }
    pub fn fixedSize(_: NodeSer) ?usize {
        return null;
    }
    pub fn equalsBySerializedBytes(_: NodeSer) bool {
        return true;
    }
};

/// Callback signature for [`QueueLong.takeUntil`] (Java `QueueLongTakeUntil`):
/// `f(ctx, node_recid, node) -> bool`. Return `true` to consume the node and
/// continue. The callback runs while the handle lock is held and MUST NOT
/// re-enter the same queue handle (a re-entry returns `error.DataCorruption`).
pub fn TakeUntilFn(comptime Ctx: type) type {
    return *const fn (Ctx, u64, Node) bool;
}

/// Callback signature for [`QueueLong.forEach`] (Java `NodeConsumer`):
/// `f(ctx, node_recid, value, timestamp)`.
pub fn NodeConsumerFn(comptime Ctx: type) type {
    return *const fn (Ctx, u64, u64, u64) void;
}

/// Persistent FIFO of `(timestamp, value)` long pairs with O(1) removal / bump
/// by node recid. Generic over the concrete `Store` type `S`. See the module
/// docs for the format and strictness contract.
///
/// The handle holds a `std.Thread.Mutex`; do not copy it after construction —
/// keep it at a stable address and call methods through a `*QueueLong(S)`
/// pointer (share that pointer to coordinate threads over one live handle).
pub fn QueueLong(comptime S: type) type {
    return struct {
        const Self = @This();

        store: *S,
        alloc: Allocator,
        tail_recid: u64,
        head_recid: u64,
        head_prev_recid: u64,
        mu: std.Thread.Mutex = .{},
        /// Guards `cb_owner`.
        cb_mu: std.Thread.Mutex = .{},
        /// Thread currently running a `takeUntil`/`forEach` callback while
        /// holding `mu`. `enter` consults this to reject same-thread re-entry
        /// loudly instead of deadlocking on the non-reentrant `mu`.
        cb_owner: ?std.Thread.Id = null,

        /// Reopen a queue from its three pointer recids. Fails if
        /// `tail_recid == head_recid` (Java `IllegalArgumentException`).
        pub fn open(
            store: *S,
            alloc: Allocator,
            tail_recid: u64,
            head_recid: u64,
            head_prev_recid: u64,
        ) DbError!Self {
            if (tail_recid == head_recid) return error.DataCorruption;
            return .{
                .store = store,
                .alloc = alloc,
                .tail_recid = tail_recid,
                .head_recid = head_recid,
                .head_prev_recid = head_prev_recid,
            };
        }

        /// Allocate a fresh empty queue (sentinel + three pointer records) in
        /// `store`. Mirrors Java `QueueLong.make(store)`.
        pub fn make(store: *S, alloc: Allocator) DbError!Self {
            const sentinel = try store.preallocate();
            const s: i64 = @bitCast(sentinel);
            const tail_r = try store.put(i64, alloc, s, LONG_PACKED);
            const head_r = try store.put(i64, alloc, s, LONG_PACKED);
            const head_prev_r = try store.put(i64, alloc, @as(i64, 0), LONG_PACKED);
            return open(store, alloc, tail_r, head_r, head_prev_r);
        }

        pub fn tailRecid(self: *const Self) u64 {
            return self.tail_recid;
        }
        pub fn headRecid(self: *const Self) u64 {
            return self.head_recid;
        }
        pub fn headPrevRecid(self: *const Self) u64 {
            return self.head_prev_recid;
        }

        // ---- lock / re-entry guard --------------------------------------

        fn enter(self: *Self) DbError!void {
            self.cb_mu.lock();
            const owner = self.cb_owner;
            self.cb_mu.unlock();
            if (owner) |o| {
                if (o == std.Thread.getCurrentId()) return error.DataCorruption;
            }
            self.mu.lock();
        }
        fn exit(self: *Self) void {
            self.mu.unlock();
        }
        fn setCbOwner(self: *Self, owner: ?std.Thread.Id) void {
            self.cb_mu.lock();
            self.cb_owner = owner;
            self.cb_mu.unlock();
        }

        // ---- pointer-record accessors -----------------------------------

        fn readPtr(self: *Self, recid: u64) DbError!u64 {
            const v = (try self.store.get(i64, self.alloc, recid, LONG_PACKED)) orelse
                return error.DataCorruption;
            return @bitCast(v);
        }
        fn writePtr(self: *Self, recid: u64, value: u64) DbError!void {
            try self.store.update(i64, self.alloc, recid, @as(i64, @bitCast(value)), LONG_PACKED);
        }

        /// Recid of the oldest node (or the head sentinel when empty).
        pub fn tail(self: *Self) DbError!u64 {
            try self.enter();
            defer self.exit();
            return self.readPtr(self.tail_recid);
        }
        /// Recid of the head sentinel (the preallocated append slot).
        pub fn head(self: *Self) DbError!u64 {
            try self.enter();
            defer self.exit();
            return self.readPtr(self.head_recid);
        }
        /// Recid of the newest node (or `0` when empty).
        pub fn headPrev(self: *Self) DbError!u64 {
            try self.enter();
            defer self.exit();
            return self.readPtr(self.head_prev_recid);
        }

        fn tailLocked(self: *Self) DbError!u64 {
            return self.readPtr(self.tail_recid);
        }
        fn headLocked(self: *Self) DbError!u64 {
            return self.readPtr(self.head_recid);
        }
        fn headPrevLocked(self: *Self) DbError!u64 {
            return self.readPtr(self.head_prev_recid);
        }

        fn getNode(self: *Self, recid: u64) DbError!?Node {
            return self.store.get(Node, self.alloc, recid, NodeSer.instance);
        }

        // ---- mutations --------------------------------------------------

        /// Append `(timestamp, value)` at the head and return the new node's
        /// recid. `timestamp`/`value` must be `<= maxInt(i64)`.
        pub fn put(self: *Self, timestamp: u64, value: u64) DbError!u64 {
            try checkField(timestamp);
            try checkField(value);
            try self.enter();
            defer self.exit();
            const next = try self.store.preallocate();
            const old_head = try nz(try self.headLocked());
            const old_prev = try self.headPrevLocked();
            try self.store.update(Node, self.alloc, old_head, Node.init(old_prev, next, timestamp, value), NodeSer.instance);
            try self.writePtr(self.head_recid, next);
            try self.writePtr(self.head_prev_recid, old_head);
            return old_head;
        }

        /// Insert a caller-preallocated node at the head. Mirrors Java
        /// `put(timestamp, value, nodeRecid)`.
        pub fn putPreallocated(self: *Self, timestamp: u64, value: u64, node_recid: u64) DbError!void {
            try checkField(timestamp);
            try checkField(value);
            try self.enter();
            defer self.exit();
            return self.putPreallocatedLocked(timestamp, value, node_recid);
        }

        fn putPreallocatedLocked(self: *Self, timestamp: u64, value: u64, node_recid: u64) DbError!void {
            const prev = try self.headPrevLocked();
            const sentinel = try self.headLocked();
            try self.store.update(Node, self.alloc, node_recid, Node.init(prev, sentinel, timestamp, value), NodeSer.instance);
            try self.writePtr(self.head_prev_recid, node_recid);
            if (prev != 0) {
                const prev_recid = try nz(prev);
                const previous = (try self.getNode(prev_recid)) orelse return error.DataCorruption;
                try self.store.update(Node, self.alloc, prev_recid, previous.withNext(node_recid), NodeSer.instance);
            }
            if ((try self.tailLocked()) == sentinel) try self.writePtr(self.tail_recid, node_recid);
        }

        /// Remove and return the oldest node, or `null` when empty.
        pub fn take(self: *Self) DbError!?Node {
            try self.enter();
            defer self.exit();
            return self.takeLocked();
        }

        fn takeLocked(self: *Self) DbError!?Node {
            const old_tail = try nz(try self.tailLocked());
            const node = (try self.getNode(old_tail)) orelse {
                try self.writePtr(self.head_prev_recid, 0);
                return null;
            };
            try self.store.delete(old_tail);
            try self.writePtr(self.tail_recid, node.next);
            // Reset headPrev to 0 iff it still points at the node we just
            // removed (the single-element case). Ignore the CAS result (Java).
            _ = try self.store.compareAndSwap(i64, self.alloc, self.head_prev_recid, @as(i64, @bitCast(old_tail)), @as(i64, 0), LONG_PACKED);
            const next_recid = try nz(node.next);
            if (try self.getNode(next_recid)) |next| {
                try self.store.update(Node, self.alloc, next_recid, next.withPrev(0), NodeSer.instance);
            }
            return node;
        }

        /// Consume oldest nodes while `callback` returns `true`. The callback
        /// runs while the handle lock is held and MUST NOT re-enter this same
        /// handle (a re-entry returns `error.DataCorruption`).
        pub fn takeUntil(self: *Self, ctx: anytype, callback: TakeUntilFn(@TypeOf(ctx))) DbError!void {
            try self.enter();
            defer self.exit();
            self.setCbOwner(std.Thread.getCurrentId());
            defer self.setCbOwner(null);
            while (true) {
                const recid = try nz(try self.tailLocked());
                const node = (try self.getNode(recid)) orelse return;
                if (!callback(ctx, recid, node)) return;
                _ = try self.takeLocked();
            }
        }

        /// Unlink a node. When `remove_node` is false its record is left intact
        /// for the caller (used by [`bump`]).
        pub fn remove(self: *Self, node_recid: u64, remove_node: bool) DbError!Node {
            try self.enter();
            defer self.exit();
            return self.removeLocked(node_recid, remove_node);
        }

        fn removeLocked(self: *Self, node_recid: u64, remove_node: bool) DbError!Node {
            const node = (try self.getNode(node_recid)) orelse return error.DataCorruption;
            if (remove_node) try self.store.delete(node_recid);

            const next_recid = try nz(node.next);
            if (try self.getNode(next_recid)) |next| {
                if (next.prev != node_recid) return error.DataCorruption;
                try self.store.update(Node, self.alloc, next_recid, next.withPrev(node.prev), NodeSer.instance);
            } else {
                if ((try self.headPrevLocked()) != node_recid) return error.DataCorruption;
                try self.writePtr(self.head_prev_recid, node.prev);
            }
            if (node.prev != 0) {
                const prev_recid = try nz(node.prev);
                const previous = (try self.getNode(prev_recid)) orelse return error.DataCorruption;
                if (previous.next != node_recid) return error.DataCorruption;
                try self.store.update(Node, self.alloc, prev_recid, previous.withNext(node.next), NodeSer.instance);
            } else {
                if ((try self.tailLocked()) != node_recid) return error.DataCorruption;
                try self.writePtr(self.tail_recid, node.next);
            }
            return node;
        }

        /// Move a node to the newest position and replace its timestamp.
        pub fn bump(self: *Self, node_recid: u64, new_timestamp: u64) DbError!void {
            try checkField(new_timestamp);
            try self.enter();
            defer self.exit();
            const newest = try self.headPrevLocked();
            const node = (try self.getNode(node_recid)) orelse return error.DataCorruption;
            if (newest == node_recid) {
                try self.store.update(Node, self.alloc, node_recid, node.withLinksAndTimestamp(node.prev, node.next, new_timestamp), NodeSer.instance);
                return;
            }
            _ = try self.removeLocked(node_recid, false);
            try self.putPreallocatedLocked(new_timestamp, node.value, node_recid);
        }

        /// Remove every node.
        pub fn clear(self: *Self) DbError!void {
            const Always = struct {
                fn f(_: void, _: u64, _: Node) bool {
                    return true;
                }
            };
            return self.takeUntil({}, Always.f);
        }

        /// Number of nodes currently in the queue (O(n) walk, like Java).
        pub fn size(self: *Self) DbError!u64 {
            try self.enter();
            defer self.exit();
            const sentinel = try self.headLocked();
            var recid = try self.tailLocked();
            var count: u64 = 0;
            while (recid != sentinel) {
                const node = (try self.getNode(try nz(recid))) orelse return error.DataCorruption;
                recid = node.next;
                count += 1;
            }
            return count;
        }

        /// Values from oldest to newest, into an owned slice (caller frees).
        pub fn valuesArray(self: *Self, alloc: Allocator) DbError![]u64 {
            try self.enter();
            defer self.exit();
            var out: std.ArrayListUnmanaged(u64) = .empty;
            errdefer out.deinit(alloc);
            var recid = try self.tailLocked();
            while (true) {
                const node = (try self.getNode(try nz(recid))) orelse
                    return out.toOwnedSlice(alloc);
                try out.append(alloc, node.value);
                recid = node.next;
            }
        }

        /// Visit every node oldest-first: `f(ctx, node_recid, value, timestamp)`.
        /// `f` runs under the handle lock and MUST NOT re-enter this same handle.
        pub fn forEach(self: *Self, ctx: anytype, consumer: NodeConsumerFn(@TypeOf(ctx))) DbError!void {
            try self.enter();
            defer self.exit();
            self.setCbOwner(std.Thread.getCurrentId());
            defer self.setCbOwner(null);
            var recid = try self.tailLocked();
            while (true) {
                const r = try nz(recid);
                const node = (try self.getNode(r)) orelse return;
                consumer(ctx, r, node.value, node.timestamp);
                recid = node.next;
            }
        }

        /// Structural self-check; `error.VerifyFailed` on inconsistency.
        pub fn verify(self: *Self) DbError!void {
            try self.enter();
            defer self.exit();
            const sentinel = try self.headLocked();
            const first = try self.tailLocked();
            const newest = try self.headPrevLocked();
            if (sentinel == first) {
                if (newest != 0) return error.VerifyFailed;
                return;
            }
            var previous: u64 = 0;
            var recid = first;
            while (recid != sentinel) {
                const node = (try self.getNode(try nz(recid))) orelse return error.VerifyFailed;
                if (node.prev != previous) return error.VerifyFailed;
                previous = recid;
                recid = node.next;
            }
            if ((try self.getNode(try nz(sentinel))) != null) return error.VerifyFailed;
            if (previous != newest) return error.VerifyFailed;
        }
    };
}

// ------------------------------------------------------------------- tests

const testing = std.testing;
const StoreOnHeap = @import("../store/mod.zig").StoreOnHeap;
const StoreByteArray = @import("../store/mod.zig").StoreByteArray;
const StoreDirect = @import("../store/mod.zig").StoreDirect;

test {
    testing.refAllDecls(@This());
    // Force analysis of every method for the concrete store types used.
    testing.refAllDecls(QueueLong(StoreOnHeap));
    testing.refAllDecls(QueueLong(StoreByteArray));
    testing.refAllDecls(QueueLong(StoreDirect));
}

test "QueueLong node golden vectors (Java parity)" {
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    // Node(prev=0, next=5, ts=10, value=1):
    // packLong(0)=0x80, packLong(5)=0x85, packLong(10)=0x8A, packLong(1)=0x81.
    try NodeSer.instance.serialize(&out, Node.init(0, 5, 10, 1));
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x85, 0x8A, 0x81 }, out.bytes());

    // Multi-byte round-trip: prev=200 -> [0x01,0xC8], next=1 -> [0x81],
    // ts=128 -> [0x01,0x80], value=300 -> [0x02,0xAC].
    var o2 = DataOutput2.init(a);
    defer o2.deinit();
    const n = Node.init(200, 1, 128, 300);
    try NodeSer.instance.serialize(&o2, n);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0xC8, 0x81, 0x01, 0x80, 0x02, 0xAC }, o2.bytes());
    var inp = DataInput2.init(o2.bytes());
    const back = try NodeSer.instance.deserialize(a, &inp, null);
    try testing.expect(NodeSer.instance.equals(n, back));
}

fn collectValue(ctx: *std.ArrayListUnmanaged(u64), _: u64, value: u64, timestamp: u64) void {
    ctx.append(testing.allocator, value) catch unreachable;
    ctx.append(testing.allocator, timestamp) catch unreachable;
}

fn tsLeq20(_: void, _: u64, node: Node) bool {
    return node.timestamp <= 20;
}

fn fifoRemoveBumpReopen(comptime S: type, store: *S) !void {
    const a = testing.allocator;
    var queue = try QueueLong(S).make(store, a);
    const na = try queue.put(10, 1);
    const nb = try queue.put(20, 2);
    const nc = try queue.put(30, 3);
    {
        const vs = try queue.valuesArray(a);
        defer a.free(vs);
        try testing.expectEqualSlices(u64, &.{ 1, 2, 3 }, vs);
    }
    try testing.expectEqual(@as(u64, 2), (try queue.remove(nb, true)).value);
    {
        const vs = try queue.valuesArray(a);
        defer a.free(vs);
        try testing.expectEqualSlices(u64, &.{ 1, 3 }, vs);
    }
    try queue.bump(na, 40);
    {
        const vs = try queue.valuesArray(a);
        defer a.free(vs);
        try testing.expectEqualSlices(u64, &.{ 3, 1 }, vs);
    }
    try queue.verify();

    var reopened = try QueueLong(S).open(store, a, queue.tailRecid(), queue.headRecid(), queue.headPrevRecid());
    try testing.expectEqual(nc, try reopened.tail());
    try testing.expectEqual(@as(u64, 3), (try reopened.take()).?.value);
    try testing.expectEqual(@as(u64, 1), (try reopened.take()).?.value);
    try testing.expect((try reopened.take()) == null);
    try reopened.verify();
}

test "QueueLong fifo/remove/bump/reopen over heap+bytearray+direct" {
    const a = testing.allocator;
    {
        var s = try StoreOnHeap.init(a, true);
        defer s.deinit();
        try fifoRemoveBumpReopen(StoreOnHeap, &s);
    }
    {
        var s = try StoreByteArray.init(a, true);
        defer s.deinit();
        try fifoRemoveBumpReopen(StoreByteArray, &s);
    }
    {
        var s = try StoreDirect.init(a, true);
        defer s.deinit();
        try fifoRemoveBumpReopen(StoreDirect, &s);
    }
}

test "QueueLong takeUntil + forEach + clear" {
    const a = testing.allocator;
    var s = try StoreOnHeap.init(a, true);
    defer s.deinit();
    var queue = try QueueLong(StoreOnHeap).make(&s, a);
    _ = try queue.put(10, 1);
    _ = try queue.put(20, 2);
    _ = try queue.put(30, 3);
    try queue.takeUntil({}, tsLeq20);
    {
        const vs = try queue.valuesArray(a);
        defer a.free(vs);
        try testing.expectEqualSlices(u64, &.{3}, vs);
    }
    var seen: std.ArrayListUnmanaged(u64) = .empty;
    defer seen.deinit(a);
    try queue.forEach(&seen, collectValue);
    try testing.expectEqualSlices(u64, &.{ 3, 30 }, seen.items);
    try queue.clear();
    try testing.expectEqual(@as(u64, 0), try queue.size());
    try queue.verify();
}

test "QueueLong insert preallocated node" {
    const a = testing.allocator;
    var s = try StoreOnHeap.init(a, true);
    defer s.deinit();
    var queue = try QueueLong(StoreOnHeap).make(&s, a);
    const recid = try s.preallocate();
    try queue.putPreallocated(7, 9, recid);
    try testing.expectEqual(recid, try queue.tail());
    const vs = try queue.valuesArray(a);
    defer a.free(vs);
    try testing.expectEqualSlices(u64, &.{9}, vs);
    try queue.verify();
}

test "QueueLong bump newest is in-place (timestamp rewrite, order unchanged)" {
    const a = testing.allocator;
    var s = try StoreOnHeap.init(a, true);
    defer s.deinit();
    var queue = try QueueLong(StoreOnHeap).make(&s, a);
    _ = try queue.put(10, 1);
    const nb = try queue.put(20, 2); // newest == headPrev
    try queue.bump(nb, 99);
    const vs = try queue.valuesArray(a);
    defer a.free(vs);
    try testing.expectEqualSlices(u64, &.{ 1, 2 }, vs);
    var ts: std.ArrayListUnmanaged(u64) = .empty;
    defer ts.deinit(a);
    try queue.forEach(&ts, struct {
        fn f(ctx: *std.ArrayListUnmanaged(u64), _: u64, _: u64, timestamp: u64) void {
            ctx.append(testing.allocator, timestamp) catch unreachable;
        }
    }.f);
    try testing.expectEqualSlices(u64, &.{ 10, 99 }, ts.items);
    try queue.verify();
}

test "QueueLong rejects fields above maxInt(i64)" {
    const a = testing.allocator;
    var s = try StoreOnHeap.init(a, true);
    defer s.deinit();
    var queue = try QueueLong(StoreOnHeap).make(&s, a);
    try testing.expectError(error.DataCorruption, queue.put(0, @as(u64, std.math.maxInt(i64)) + 1));
    try testing.expectError(error.DataCorruption, queue.put(@as(u64, std.math.maxInt(i64)) + 1, 0));
    // The boundary value is accepted.
    _ = try queue.put(std.math.maxInt(i64), std.math.maxInt(i64));
    try queue.verify();
}

test "QueueLong deserialize rejects a field above maxInt(i64)" {
    // Read-path strictness parity: a foreign/torn node record whose packed field
    // exceeds maxInt(i64) reads as a negative long in Java and throws; reject here.
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try out.packLong(0); // prev
    try out.packLong(0); // next
    try out.packLong(std.math.maxInt(u64)); // timestamp: > maxInt(i64)
    try out.packLong(1); // value
    var inp = DataInput2.init(out.bytes());
    try testing.expectError(error.DataCorruption, NodeSer.instance.deserialize(a, &inp, null));
}

test "QueueLong reentrant callback errors, not deadlock" {
    const a = testing.allocator;
    var s = try StoreOnHeap.init(a, true);
    defer s.deinit();
    var queue = try QueueLong(StoreOnHeap).make(&s, a);
    _ = try queue.put(10, 1);
    const Ctx = struct {
        q: *QueueLong(StoreOnHeap),
        reentry_errored: bool = false,
        fn cb(ctx: *@This(), _: u64, _: Node) bool {
            // size() re-enters the same handle -> must error, not hang.
            ctx.reentry_errored = if (ctx.q.size()) |_| false else |_| true;
            return false;
        }
    };
    var ctx = Ctx{ .q = &queue };
    try queue.takeUntil(&ctx, Ctx.cb);
    try testing.expect(ctx.reentry_errored);
}

test "QueueLong open rejects tail==head" {
    const a = testing.allocator;
    var s = try StoreOnHeap.init(a, true);
    defer s.deinit();
    try testing.expectError(error.DataCorruption, QueueLong(StoreOnHeap).open(&s, a, 5, 5, 6));
}
