//! `StoreReadOnlyWrapper` (Java `org.mapdb.store.StoreReadOnlyWrapper`): a
//! comptime-generic `Store` decorator that rejects every mutating operation and
//! passes reads/inspection straight through to a delegate store `*S`.
//!
//! Mutators (`preallocate`/`put`/`update`/`compareAndSwap`/`delete`/`compact`/
//! `append`/`updateWithHeadroom`) return `error.ReadOnly` (Java
//! `UnsupportedOperationException`). Reads (`get`/`read`/`getAllRecids`/
//! `verify`/`isClosed`/`isThreadSafe`/`getCurrentSize`/`capacityRemaining`)
//! delegate. `commit()` is a harmless no-op (a read-only DB may still call it);
//! `close()` closes the delegate. `isReadOnly()` returns `true`; `isTx()` is
//! `false` (a read-only view has nothing to roll back).
//!
//! ## Logical guard, not an OS-level mode (Java parity)
//! This rejects mutations at the `Store` API. It does not change how the
//! underlying store maps its backing file; a file store still opens the volume
//! read/write at the OS level. Use it to forbid writes THROUGH the API on an
//! existing DB, not as a filesystem-level protection.
//!
//! Fits the port's comptime-generic store model (D1): monomorphized over the
//! concrete delegate `S`, so `store.checkStore(StoreReadOnlyWrapper(S))` holds
//! and any collection generic over a `Store` accepts the wrapper unchanged.

const std = @import("std");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const mod = @import("mod.zig");
const RecordRead = mod.RecordRead;
const AppendResult = mod.AppendResult;

pub fn StoreReadOnlyWrapper(comptime S: type) type {
    return struct {
        const Self = @This();
        delegate: *S,

        pub fn init(delegate: *S) Self {
            return .{ .delegate = delegate };
        }

        // ---- mutators: rejected -------------------------------------------

        pub fn preallocate(_: *Self) DbError!u64 {
            return error.ReadOnly;
        }
        pub fn put(_: *Self, comptime R: type, alloc: Allocator, value: R, ser: anytype) DbError!u64 {
            _ = alloc;
            _ = value;
            _ = ser;
            return error.ReadOnly;
        }
        pub fn update(_: *Self, comptime R: type, alloc: Allocator, recid: u64, value: ?R, ser: anytype) DbError!void {
            _ = alloc;
            _ = recid;
            _ = value;
            _ = ser;
            return error.ReadOnly;
        }
        pub fn compareAndSwap(_: *Self, comptime R: type, alloc: Allocator, recid: u64, expect: ?R, new: ?R, ser: anytype) DbError!bool {
            _ = alloc;
            _ = recid;
            _ = expect;
            _ = new;
            _ = ser;
            return error.ReadOnly;
        }
        pub fn delete(_: *Self, recid: u64) DbError!void {
            _ = recid;
            return error.ReadOnly;
        }
        pub fn compact(_: *Self) DbError!void {
            return error.ReadOnly;
        }
        pub fn append(_: *Self, recid: u64, data: []const u8) DbError!AppendResult {
            _ = recid;
            _ = data;
            return error.ReadOnly;
        }
        pub fn updateWithHeadroom(_: *Self, comptime R: type, alloc: Allocator, recid: u64, value: R, ser: anytype, headroom: usize) DbError!void {
            _ = alloc;
            _ = recid;
            _ = value;
            _ = ser;
            _ = headroom;
            return error.ReadOnly;
        }

        // ---- reads / inspection: delegated --------------------------------

        pub fn get(self: *Self, comptime R: type, alloc: Allocator, recid: u64, ser: anytype) DbError!?R {
            return self.delegate.get(R, alloc, recid, ser);
        }
        pub fn read(self: *Self, recid: u64, action: RecordRead) DbError!i64 {
            return self.delegate.read(recid, action);
        }
        pub fn getAllRecids(self: *Self, alloc: Allocator) DbError![]u64 {
            return self.delegate.getAllRecids(alloc);
        }
        pub fn verify(self: *Self) DbError!void {
            return self.delegate.verify();
        }
        pub fn isClosed(self: *Self) bool {
            return self.delegate.isClosed();
        }
        pub fn isThreadSafe(self: *Self) bool {
            return self.delegate.isThreadSafe();
        }
        pub fn getCurrentSize(self: *Self) u64 {
            return self.delegate.getCurrentSize();
        }
        pub fn capacityRemaining(self: *Self, recid: u64) DbError!usize {
            if (comptime mod.supportsDelta(S)) return self.delegate.capacityRemaining(recid);
            return 0;
        }

        // ---- capability / lifecycle ---------------------------------------

        pub fn isReadOnly(_: *const Self) bool {
            return true;
        }
        pub fn isTx(_: *Self) bool {
            return false;
        }
        /// No-op: a read-only view has nothing to make durable (Java parity).
        pub fn commit(_: *Self) DbError!void {}
        /// Closes the underlying store so its resources are released.
        pub fn close(self: *Self) DbError!void {
            return self.delegate.close();
        }

        /// The delegate's open-lease table (review C1): a BTree opened THROUGH the
        /// wrapper leases the same underlying recid, and a read-only wrapper takes
        /// a READ-only lease so RO+RO opens coexist.
        pub fn leaseTable(self: *Self) *mod.LeaseTable {
            return self.delegate.leaseTable();
        }

        /// The wrapper owns only a BORROWED delegate pointer, so `deinit` frees
        /// nothing here — the DB frees the delegate via its `ro_backing` hook
        /// (review C1). Present so `Db(StoreReadOnlyWrapper(S)).deinit()` compiles
        /// (it unconditionally calls `store.deinit()` for an owned store).
        pub fn deinit(_: *Self) void {}
    };
}

// ------------------------------------------------------------------- tests

const testing = std.testing;
const heap = @import("heap.zig");
const bytearray = @import("bytearray.zig");
const serializers = @import("../ser/serializers.zig");
const LongSer = serializers.LongSer;

comptime {
    mod.checkStore(StoreReadOnlyWrapper(heap.StoreOnHeap));
    mod.checkStore(StoreReadOnlyWrapper(bytearray.StoreByteArray));
}

test "read-only wrapper: reads pass through, mutators rejected" {
    const a = testing.allocator;
    var inner = try heap.StoreOnHeap.init(a, false);
    defer inner.deinit();

    // seed a record through the writable store
    const recid = try inner.put(i64, a, 42, LongSer.instance);

    var ro = StoreReadOnlyWrapper(heap.StoreOnHeap).init(&inner);

    // reads delegate
    try testing.expectEqual(@as(?i64, 42), try ro.get(i64, a, recid, LongSer.instance));
    try testing.expect(!ro.isClosed());
    try testing.expect(ro.isReadOnly());
    try testing.expect(!ro.isTx());
    try testing.expect(!mod.isReadOnly(heap.StoreOnHeap, &inner)); // base default false
    try testing.expect(mod.isReadOnly(StoreReadOnlyWrapper(heap.StoreOnHeap), &ro));

    // mutators rejected
    try testing.expectError(error.ReadOnly, ro.preallocate());
    try testing.expectError(error.ReadOnly, ro.put(i64, a, 7, LongSer.instance));
    try testing.expectError(error.ReadOnly, ro.update(i64, a, recid, 9, LongSer.instance));
    try testing.expectError(error.ReadOnly, ro.compareAndSwap(i64, a, recid, 42, 9, LongSer.instance));
    try testing.expectError(error.ReadOnly, ro.delete(recid));
    try testing.expectError(error.ReadOnly, ro.compact());

    // commit is a tolerated no-op; record still intact afterwards
    try ro.commit();
    try testing.expectEqual(@as(?i64, 42), try ro.get(i64, a, recid, LongSer.instance));

    getAllRecidsCheck(&ro, a) catch |e| return e;
}

fn getAllRecidsCheck(ro: anytype, a: Allocator) !void {
    const recids = try ro.getAllRecids(a);
    defer a.free(recids);
    try testing.expectEqual(@as(usize, 1), recids.len);
}

test "read-only wrapper over delta store: append rejected, capacity delegates" {
    const a = testing.allocator;
    var inner = try bytearray.StoreByteArray.init(a, false);
    defer inner.deinit();
    const recid = try inner.put(i64, a, 5, LongSer.instance);

    var ro = StoreReadOnlyWrapper(bytearray.StoreByteArray).init(&inner);
    try testing.expect(mod.supportsDelta(StoreByteArrayWrapper()));
    try testing.expectError(error.ReadOnly, ro.append(recid, "xx"));
    // capacityRemaining delegates without error
    _ = try ro.capacityRemaining(recid);
}

fn StoreByteArrayWrapper() type {
    return StoreReadOnlyWrapper(bytearray.StoreByteArray);
}
