//! `store` layer — the comptime `Store` interface contract chain and shared
//! store-layer types. Ported from `mapdb-rust-store/src/store/mod.rs`.
//!
//! The `Store` interface is **comptime duck-typed**: consumers are
//! `fn X(comptime S: type, ...)` and monomorphize over the concrete store.
//! `StoreOnHeap` keeps live objects and dispatches the object dialect;
//! byte stores preserve serializer-defined *logical* CAS equality.
//!
//! Interface chain `Store ← StoreDelta ← StoreTx`; impls: [`heap.StoreOnHeap`],
//! [`bytearray.StoreByteArray`] (the reference oracle), later StoreDirect / WAL.
//!
//! ## Store method set (comptime contract, per store `self: *S`)
//! ```
//! preallocate(self)                                    DbError!u64
//! put(self, comptime R, alloc, value: R, ser)          DbError!u64
//! get(self, comptime R, alloc, recid: u64, ser)        DbError!?R
//! read(self, recid: u64, action: RecordRead)           DbError!i64   // locked
//! update(self, comptime R, alloc, recid, value: ?R, ser) DbError!void
//! compareAndSwap(self, comptime R, alloc, recid, expect: ?R, new: ?R, ser) DbError!bool
//! delete(self, recid: u64)                             DbError!void
//! commit(self)                                         DbError!void
//! compact(self)                                        DbError!void
//! close(self)                                          DbError!void
//! isClosed(self)                                       bool
//! verify(self)                                         DbError!void
//! getAllRecids(self, alloc)                            DbError![]u64  // sorted, owned
//! isThreadSafe(self)                                   bool
//! getCurrentSize(self)                                 u64
//! isTx(self)                                           bool
//! // StoreDelta adds:
//! append(self, recid, data: []const u8)                DbError!AppendResult
//! capacityRemaining(self, recid)                       DbError!usize
//! updateWithHeadroom(self, comptime R, alloc, recid, value: R, ser, headroom) DbError!void
//! // StoreTx adds:
//! rollback(self)                                       DbError!void
//! structuralGeneration(self)                           u64
//! ```
//! Serialization for byte stores happens OUTSIDE store locks (Java/Rust). CAS
//! deserializes under the record lock and uses `ser.equals` (logical equality).

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const DataInput2 = @import("../io.zig").DataInput2;
const ser_contracts = @import("../ser/mod.zig");

pub const segment_locks = @import("segment_locks.zig");
pub const heap = @import("heap.zig");
pub const bytearray = @import("bytearray.zig");
pub const parity = @import("parity.zig");
pub const index_val = @import("index_val.zig");
pub const volume = @import("volume.zig");
pub const direct = @import("direct.zig");
pub const wal = @import("wal.zig");
/// WAL format v3 (slice B0+): the durability-event seam and the segment-set
/// namespace layer. Not reachable from any public open until the B2 cutover.
pub const wal_io = @import("wal_io.zig");
pub const wal_segments = @import("wal_segments.zig");
pub const wal_segments_test = @import("wal_segments_test.zig");
pub const tck = @import("tck.zig");
pub const read_only = @import("read_only.zig");
pub const store_direct_test = @import("store_direct_test.zig");
pub const store_wal_test = @import("store_wal_test.zig");

pub const StoreReadOnlyWrapper = read_only.StoreReadOnlyWrapper;

pub const SegmentLocks = segment_locks.SegmentLocks;
pub const StoreOnHeap = heap.StoreOnHeap;
pub const StoreByteArray = bytearray.StoreByteArray;
pub const Volume = volume.Volume;
pub const StoreDirect = direct.StoreDirect;
pub const StoreWAL = wal.StoreWAL;

comptime {
    // v1 targets 64-bit only: recid/size math assumes usize == u64.
    std.debug.assert(@bitSizeOf(usize) == 64);
}

// ------------------------------------------------------------- record states

/// Semantic record states (Java/Rust). Not every state is a stored map entry:
/// `void`/`deleted` are absent from a store's map (deleted recids may be
/// reused); `preallocated`/`null_rec`/`live` are the persisted contents.
///
/// TCK semantics (port verbatim): `get` of a preallocated record → null;
/// `read`/`get` of a void or deleted recid → `error.GetVoid`; `getAllRecids`
/// excludes preallocated records.
pub const RecState = enum {
    /// Never allocated (absent from the map).
    void,
    /// Recid reserved with null content; `get` → null; excluded from getAllRecids.
    preallocated,
    /// Record exists with explicit null content; `get` → null.
    null_rec,
    /// Record exists with live content.
    live,
    /// Recid was deleted (absent from the map; may be reused).
    deleted,
};

/// Result of [`StoreDelta.append`]: the new content size, or a capacity refusal
/// (Java `REFUSED = -1`). `enum{refused}/usize` → tagged union.
pub const AppendResult = union(enum) {
    new_size: usize,
    refused,

    pub fn eql(a: AppendResult, b: AppendResult) bool {
        return switch (a) {
            .refused => b == .refused,
            .new_size => |x| switch (b) {
                .new_size => |y| x == y,
                .refused => false,
            },
        };
    }
};

// -------------------------------------------------------------- type tokens

/// A per-type identity token: the address of a per-type static byte.
/// Unique per `T`, stable across calls. Compared at runtime BEFORE any
/// `@ptrCast`+`@alignCast` of a boxed heap record.
pub const TypeId = usize;

/// Address of a per-type static → a unique, stable `TypeId` for `T`. The
/// `Holder` struct references `T` so distinct types get distinct instantiations
/// (hence distinct static addresses); identical `T` memoizes to the same static.
pub fn typeToken(comptime T: type) TypeId {
    const Holder = struct {
        // Reference T so the struct type depends on it (distinct per T).
        const marker = T;
        var token: u8 = 0;
    };
    return @intFromPtr(&Holder.token);
}

// -------------------------------------------------------------- RecordRead

/// Push-down read action. The store resolves the recid under
/// its own locks and dispatches exactly one method. Return values are opaque
/// `i64`s passed through bit-exactly.
///
/// Contract (load-bearing): re-invocable; resets ALL output state per
/// invocation; bounds-clamps every decoded length; never calls back into the
/// store; never runs user callbacks. In v1 (locked baseline) actions never
/// actually see torn bytes. `ptr`+`vtable` in the `std.mem.Allocator` style.
pub const RecordRead = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Record is byte-resident. `input` at content start; `size` = length.
        onBytes: *const fn (*anyopaque, input: *DataInput2, size: usize) DbError!i64,
        /// Record is object-resident (heap store). `obj` valid only for the call
        /// (never retained); `token` names its runtime type (compare before cast).
        onObject: *const fn (*anyopaque, obj: *const anyopaque, token: TypeId) DbError!i64,
        /// Record exists but is null (preallocated or explicit null).
        onNull: *const fn (*anyopaque) DbError!i64,
    };

    pub fn callOnBytes(self: RecordRead, input: *DataInput2, size: usize) DbError!i64 {
        return self.vtable.onBytes(self.ptr, input, size);
    }
    pub fn callOnObject(self: RecordRead, obj: *const anyopaque, token: TypeId) DbError!i64 {
        return self.vtable.onObject(self.ptr, obj, token);
    }
    pub fn callOnNull(self: RecordRead) DbError!i64 {
        return self.vtable.onNull(self.ptr);
    }
};

/// Default `onObject` for byte-only actions: object handles are unsupported.
pub fn defaultOnObjectErr(_: *anyopaque, _: *const anyopaque, _: TypeId) DbError!i64 {
    return error.DataCorruption;
}

/// Default `onNull`: null content decodes to 0 (Java/Rust `on_null` default).
pub fn defaultOnNullZero(_: *anyopaque) DbError!i64 {
    return 0;
}

// ----------------------------------------------- capability + shape probes

/// `true` if `S` implements the `StoreDelta` capability (append/headroom).
pub fn supportsDelta(comptime S: type) bool {
    return @hasDecl(S, "append") and @hasDecl(S, "capacityRemaining") and
        @hasDecl(S, "updateWithHeadroom");
}

/// `true` if `S` implements the `StoreTx` capability (rollback).
pub fn supportsTx(comptime S: type) bool {
    return @hasDecl(S, "rollback");
}

/// Java `Store.isReadOnly()` default (`false`): a store is writable unless it
/// declares otherwise (only [`read_only.StoreReadOnlyWrapper`] does). Free
/// function because Zig has no interface-default methods.
pub fn isReadOnly(comptime S: type, s: *const S) bool {
    if (@hasDecl(S, "isReadOnly")) return s.isReadOnly();
    return false;
}

/// Validate that `S` presents the `Store` decl set (names only; generic
/// signatures are checked by instantiation — the TCK compile-probes them).
pub fn checkStore(comptime S: type) void {
    comptime {
        const decls = [_][]const u8{
            "preallocate",  "put",            "get",            "read",
            "update",       "compareAndSwap", "delete",         "commit",
            "compact",      "close",          "isClosed",       "verify",
            "getAllRecids", "isThreadSafe",   "getCurrentSize", "isTx",
        };
        for (decls) |name| {
            if (!@hasDecl(S, name))
                @compileError("store " ++ @typeName(S) ++ " missing decl `" ++ name ++ "`");
        }
    }
}

// ----------------------------------------------- serializer boundary checks

/// Comptime check that `Ser` is a Serializer for `R` — called at the top of
/// every typed store method (put/get/update/CAS/updateWithHeadroom), per the store contract.
/// Readable `@compileError` via `ser.checkSerializer` on violation.
pub inline fn checkSer(comptime R: type, comptime Ser: type) void {
    comptime ser_contracts.checkSerializer(Ser, R);
}

/// Non-erroring probe of the same association (testable form of [`checkSer`]:
/// same decl set + `Elem == R`, returning `false` instead of `@compileError`).
pub fn serIsFor(comptime Ser: type, comptime R: type) bool {
    if (comptime !@hasDecl(Ser, "Elem")) return false;
    if (comptime Ser.Elem != R) return false;
    const decls = [_][]const u8{
        "serialize", "deserialize", "cloneElem", "deinitElem",
        "compare",   "equals",      "fixedSize", "equalsBySerializedBytes",
    };
    inline for (decls) |name| {
        if (comptime !@hasDecl(Ser, name)) return false;
    }
    return true;
}

/// True if `Ser` is stateless (zero-sized). `StoreOnHeap` requires this: its
/// box clone/deinit vtables are comptime-baked from the (R, Ser) pair and
/// cannot retain per-instance state. heap.zig rejects stateful serializers via
/// this predicate BEFORE consulting any `instance` decl (a
/// stateful serializer with a default `instance` must not silently compile
/// with its state discarded).
pub fn isStatelessSer(comptime Ser: type) bool {
    return @sizeOf(Ser) == 0;
}

// -------------------------------------------------- action reentrancy guard

/// Depth of the current push-down action / serializer callback. A store op
/// invoked while this is non-zero is an A3 violation ("an action/serializer
/// callback must never call back into the store").
///
/// Coverage: stores enter the guard around read-action dispatch
/// AND around every serializer callback made while holding a record lock
/// (deserialize/equals/cloneElem in get/CAS paths; the CAS-side serialize). A
/// same-thread reentry then trips the Debug assert instead of deadlocking.
///
/// Honest Release-build contract: the tracker compiles away outside Debug. In
/// ReleaseSafe/ReleaseFast a serializer or action that calls back into the
/// store DEADLOCKS on the record lock (or creates lock-order cycles); the A3
/// contract is enforced by Debug testing, not at runtime in release builds.
threadlocal var action_depth: u32 = 0;

/// Assert we are not inside a read action (called at the top of every store op).
pub inline fn assertNotInAction(comptime op: []const u8) void {
    if (builtin.mode == .Debug) {
        std.debug.assert(action_depth == 0); // op re-entered from inside an action (A3)
        _ = op;
    }
}

/// RAII-ish marker: entered around a read-action dispatch. `exit` via `defer`.
pub const ActionGuard = struct {
    pub fn enter() ActionGuard {
        if (builtin.mode == .Debug) action_depth += 1;
        return .{};
    }
    pub fn exit(_: ActionGuard) void {
        if (builtin.mode == .Debug) action_depth -= 1;
    }
};

/// Test-only (Debug): the current action depth. A reentrant store op invoked
/// while this is > 0 trips `assertNotInAction`. Tests probe it from inside a
/// serializer/action callback to prove the callback runs under a published
/// guard — i.e. that reentry would assert rather than silently deadlock on a
/// record lock (the actual assert panic is uncatchable in a Zig test).
pub fn actionDepthForTest() u32 {
    return action_depth;
}

// --------------------------------------------------------------- lease table

/// Requested access mode for a lease.
pub const LeaseKind = enum { read_write, read_only };

/// Per-store lease registry keyed by header/root recid. Hard exclusion,
/// release builds included:
/// - `read_write` fails `AlreadyOpen` if ANY lease exists on the recid;
/// - `read_only` fails if an RW lease exists; RO+RO is allowed.
///
/// Zig has no `Drop`: collections call `acquire` in open() and `release` in
/// deinit() (paired with `errdefer` over the init window).
pub const LeaseTable = struct {
    const Entry = union(enum) { rw, ro: usize };

    mu: std.Thread.Mutex = .{},
    map: std.AutoHashMapUnmanaged(u64, Entry) = .empty,
    alloc: Allocator,

    pub fn init(alloc: Allocator) LeaseTable {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *LeaseTable) void {
        self.map.deinit(self.alloc);
    }

    /// Acquire a lease. `error.AlreadyOpen` on a conflicting existing lease.
    pub fn acquire(self: *LeaseTable, header_recid: u64, kind: LeaseKind) DbError!void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.map.getPtr(header_recid)) |entry| {
            switch (entry.*) {
                .ro => |*n| {
                    if (kind == .read_only) {
                        n.* += 1;
                        return;
                    }
                    return error.AlreadyOpen; // RW-while-RO
                },
                .rw => return error.AlreadyOpen, // anything-while-RW
            }
        }
        // No existing lease.
        const e: Entry = switch (kind) {
            .read_write => .rw,
            .read_only => .{ .ro = 1 },
        };
        try self.map.put(self.alloc, header_recid, e);
    }

    /// Release one lease on `header_recid`. Last RO or the RW removes the entry.
    pub fn release(self: *LeaseTable, header_recid: u64) void {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.map.getPtr(header_recid)) |entry| {
            switch (entry.*) {
                .ro => |*n| {
                    if (n.* > 1) {
                        n.* -= 1;
                        return;
                    }
                },
                .rw => {},
            }
            _ = self.map.remove(header_recid);
        }
    }
};

// ------------------------------------------------------------ recid allocator

/// Shared monotonic recid allocator with a free list (used by heap/bytearray).
/// Recid 0 is never handed out. Guarded by its own mutex.
///
/// Failure-atomicity protocol: recycling must never
/// fail AFTER a state transition committed (a deleted record must not report
/// an error once destroyed, and an OOM during `put`/`preallocate` must not
/// permanently consume the recid). Callers therefore `reserve()` free-list
/// slack up front (the only fallible step), then use the infallible
/// `recycleReserved`/`cancelReserve` to settle it. Invariant:
/// `free.capacity ≥ free.items.len + reserved` at all times, so every
/// outstanding reservation has a guaranteed `appendAssumeCapacity` slot.
///
/// Lock-order invariant: store `verify()` holds
/// `mu` across its ENTIRE scan (matching the Rust oracle — an unlocked
/// free-list slice races concurrent recycles, and an unlocked `max_recid`
/// makes concurrent allocation look like corruption). Consequently no caller
/// may invoke ANY RecidAlloc method while holding a shard/segment lock —
/// stores settle reservations after releasing the record lock.
pub const RecidAlloc = struct {
    mu: std.Thread.Mutex = .{},
    max_recid: u64 = 0,
    free: std.ArrayListUnmanaged(u64) = .empty,
    /// Outstanding `reserve()`s not yet settled.
    reserved: usize = 0,
    alloc: Allocator,

    pub fn init(alloc: Allocator) RecidAlloc {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *RecidAlloc) void {
        self.free.deinit(self.alloc);
    }

    pub fn next(self: *RecidAlloc) u64 {
        self.mu.lock();
        defer self.mu.unlock();
        if (self.free.pop()) |r| return r;
        self.max_recid += 1;
        return self.max_recid;
    }

    /// Reserve slack so ONE later [`recycleReserved`] cannot fail. Pair every
    /// reserve with exactly one `recycleReserved` or `cancelReserve`.
    pub fn reserve(self: *RecidAlloc) DbError!void {
        self.mu.lock();
        defer self.mu.unlock();
        try self.free.ensureTotalCapacity(self.alloc, self.free.items.len + self.reserved + 1);
        self.reserved += 1;
    }

    /// Settle a [`reserve`] without recycling (the recid stayed allocated).
    pub fn cancelReserve(self: *RecidAlloc) void {
        self.mu.lock();
        defer self.mu.unlock();
        std.debug.assert(self.reserved > 0);
        self.reserved -= 1;
    }

    /// Infallible recycle consuming a prior [`reserve`].
    pub fn recycleReserved(self: *RecidAlloc, recid: u64) void {
        self.mu.lock();
        defer self.mu.unlock();
        std.debug.assert(self.reserved > 0);
        self.free.appendAssumeCapacity(recid);
        self.reserved -= 1;
    }

    pub fn clearFree(self: *RecidAlloc) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.free.clearRetainingCapacity();
    }
};

// ------------------------------------------------------------------- tests

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}

test "typeToken: stable per type, distinct across types" {
    const a1 = typeToken(i64);
    const a2 = typeToken(i64);
    const b = typeToken(i32);
    const c = typeToken([]const u8);
    try testing.expectEqual(a1, a2); // stable
    try testing.expect(a1 != b);
    try testing.expect(a1 != c);
    try testing.expect(b != c);
}

test "AppendResult eql" {
    try testing.expect((AppendResult{ .new_size = 5 }).eql(.{ .new_size = 5 }));
    try testing.expect(!(AppendResult{ .new_size = 5 }).eql(.refused));
    try testing.expect((@as(AppendResult, .refused)).eql(.refused));
}

test "LeaseTable exclusion rules (port of lease.rs)" {
    var t = LeaseTable.init(testing.allocator);
    defer t.deinit();
    // double RW rejected
    try t.acquire(1, .read_write);
    try testing.expectError(error.AlreadyOpen, t.acquire(1, .read_write));
    // RO-while-RW rejected
    try testing.expectError(error.AlreadyOpen, t.acquire(1, .read_only));
    t.release(1);
    // after release, RO succeeds; RO+RO ok
    try t.acquire(1, .read_only);
    try t.acquire(1, .read_only);
    // RW-while-RO rejected
    try testing.expectError(error.AlreadyOpen, t.acquire(1, .read_write));
    t.release(1);
    // still one RO live → RW still rejected
    try testing.expectError(error.AlreadyOpen, t.acquire(1, .read_write));
    t.release(1);
    // all released → RW ok
    try t.acquire(1, .read_write);
    t.release(1);
    // different header independent
    try t.acquire(2, .read_write);
    t.release(2);
}

test "serIsFor probe: association enforced at typed boundaries" {
    const sers = @import("../ser/serializers.zig");
    try testing.expect(serIsFor(sers.LongSer, i64));
    try testing.expect(serIsFor(sers.ByteArraySer, []const u8));
    try testing.expect(!serIsFor(sers.LongSer, i32)); // Elem mismatch rejected
    try testing.expect(!serIsFor(struct {}, i64)); // no decls rejected
    checkSer(i64, sers.LongSer); // compile probe of the erroring form
}

test "isStatelessSer probe: stateful serializer rejected even with `instance`" {
    const sers = @import("../ser/serializers.zig");
    const StatefulWithInstance = struct {
        pub const Elem = i64;
        mode: u8,
        pub const instance: @This() = .{ .mode = 0 };
    };
    try testing.expect(isStatelessSer(sers.LongSer));
    try testing.expect(!isStatelessSer(StatefulWithInstance));
}

test "RecidAlloc reserve/recycleReserved/cancelReserve invariants" {
    var ra = RecidAlloc.init(testing.allocator);
    defer ra.deinit();
    const r1 = ra.next();
    const r2 = ra.next();
    try testing.expectEqual(@as(u64, 1), r1);
    try testing.expectEqual(@as(u64, 2), r2);
    // reserve → recycle is infallible; recid comes back
    try ra.reserve();
    ra.recycleReserved(r1);
    try testing.expectEqual(r1, ra.next());
    // reserve → cancel keeps the list untouched
    try ra.reserve();
    ra.cancelReserve();
    try testing.expectEqual(@as(u64, 3), ra.next());
    // multiple outstanding reservations each have a guaranteed slot
    try ra.reserve();
    try ra.reserve();
    try ra.reserve();
    ra.recycleReserved(1);
    ra.recycleReserved(2);
    ra.recycleReserved(3);
    try testing.expectEqual(@as(usize, 3), ra.free.items.len);
    try testing.expectEqual(@as(usize, 0), ra.reserved);
}

test "checkStore/supportsDelta/supportsTx over impls" {
    checkStore(StoreOnHeap);
    checkStore(StoreByteArray);
    try testing.expect(!supportsDelta(StoreOnHeap));
    try testing.expect(supportsDelta(StoreByteArray));
    try testing.expect(!supportsTx(StoreOnHeap));
    try testing.expect(!supportsTx(StoreByteArray));
}
