//! `StoreOnHeap` — records are live objects, never serialized.
//! `read` dispatches `onObject`/`onNull`, never `onBytes`. Sharded
//! `RwLock + AutoHashMap` for records (concurrent, not lock-free — accepted for
//! a test-oriented store), a global mutex for recid allocation.
//!
//! A live record is a **boxed** value `{ ptr, token, vtable }`: `ptr` is a
//! `self.alloc`-owned deep clone of the record `R`; `token = typeToken(R)` is
//! compared BEFORE any cast; `vtable.clone`/`vtable.deinit` are comptime-
//! generated from the serializer's `cloneElem`/`deinitElem` so the store
//! can free/duplicate the box without re-presenting the serializer.
//!
//! Allocator domains: boxes are cloned + freed with the STORE's
//! `self.alloc`; the per-call allocator is used only for values returned to the
//! caller (`get`). Serializers here must be stateless (zero-sized); a stateful
//! serializer would need to be captured in the box — out of scope.

const std = @import("std");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const mod = @import("mod.zig");
const RecordRead = mod.RecordRead;
const TypeId = mod.TypeId;
const typeToken = mod.typeToken;
const LeaseTable = mod.LeaseTable;
const RecidAlloc = mod.RecidAlloc;

const SHARDS: usize = 64;

/// Reconstruct a stateless serializer instance for comptime-baked box vtables.
/// The zero-size check runs FIRST: a stateful
/// serializer that happens to declare a default `instance` is rejected rather
/// than silently used with its per-call state discarded.
inline fn serInstance(comptime Ser: type) Ser {
    comptime {
        if (!mod.isStatelessSer(Ser))
            @compileError("StoreOnHeap requires a stateless (zero-sized) serializer, got " ++ @typeName(Ser));
    }
    if (@hasDecl(Ser, "instance")) return Ser.instance;
    return .{};
}

/// Per-box clone/deinit, generated from the (R, Serializer) pair.
const RecordVTable = struct {
    /// Deep-clone the boxed value into `alloc`, returning a new box pointer.
    clone: *const fn (Allocator, *const anyopaque) DbError!*const anyopaque,
    /// Free the boxed value + its allocation (via `alloc`).
    deinit: *const fn (Allocator, *const anyopaque) void,
};

fn boxVTable(comptime R: type, comptime Ser: type) *const RecordVTable {
    const Gen = struct {
        fn clone(alloc: Allocator, p: *const anyopaque) DbError!*const anyopaque {
            const src: *const R = @ptrCast(@alignCast(p));
            const cloned = try serInstance(Ser).cloneElem(alloc, src.*);
            errdefer serInstance(Ser).deinitElem(alloc, cloned);
            const box = try alloc.create(R);
            box.* = cloned;
            return @ptrCast(box);
        }
        fn deinit(alloc: Allocator, p: *const anyopaque) void {
            const src: *R = @ptrCast(@alignCast(@constCast(p)));
            serInstance(Ser).deinitElem(alloc, src.*);
            alloc.destroy(src);
        }
        const vtable = RecordVTable{ .clone = clone, .deinit = deinit };
    };
    return &Gen.vtable;
}

/// A live heap record: a `self.alloc`-owned deep clone + its type identity.
const Boxed = struct {
    ptr: *const anyopaque,
    token: TypeId,
    vtable: *const RecordVTable,

    fn deinit(self: Boxed, alloc: Allocator) void {
        self.vtable.deinit(alloc, self.ptr);
    }
};

const HeapRec = union(enum) {
    null_rec,
    prealloc,
    live: Boxed,

    fn deinit(self: HeapRec, alloc: Allocator) void {
        switch (self) {
            .live => |b| b.deinit(alloc),
            else => {},
        }
    }
};

const Shard = struct {
    lock: std.Thread.RwLock = .{},
    map: std.AutoHashMapUnmanaged(u64, HeapRec) = .empty,
};

pub const StoreOnHeap = struct {
    const Self = @This();

    shards: []Shard,
    recids: RecidAlloc,
    leases: LeaseTable,
    thread_safe: bool,
    closed: std.atomic.Value(bool),
    alloc: Allocator,

    /// New empty in-memory store. `alloc` owns all internal boxes/structures
    /// and every record clone; the caller must `deinit`. `thread_safe` selects
    /// real vs no-op sharded locks.
    pub fn init(alloc: Allocator, thread_safe: bool) DbError!Self {
        const shards = try alloc.alloc(Shard, SHARDS);
        for (shards) |*s| s.* = .{};
        return .{
            .shards = shards,
            .recids = RecidAlloc.init(alloc),
            .leases = LeaseTable.init(alloc),
            .thread_safe = thread_safe,
            .closed = std.atomic.Value(bool).init(false),
            .alloc = alloc,
        };
    }

    /// Frees every boxed record + all internal structures. Safe after `close`
    /// (which already emptied the shards).
    pub fn deinit(self: *Self) void {
        for (self.shards) |*s| {
            var it = s.map.iterator();
            while (it.next()) |e| e.value_ptr.deinit(self.alloc);
            s.map.deinit(self.alloc);
        }
        self.alloc.free(self.shards);
        self.recids.deinit();
        self.leases.deinit();
    }

    inline fn shard(self: *Self, recid: u64) *Shard {
        return &self.shards[@as(usize, @intCast(recid)) & (SHARDS - 1)];
    }

    fn checkClosed(self: *Self) DbError!void {
        if (self.closed.load(.acquire)) return error.StoreClosed;
    }

    fn makeBox(self: *Self, comptime R: type, comptime Ser: type, value: R) DbError!Boxed {
        const cloned = try serInstance(Ser).cloneElem(self.alloc, value);
        errdefer serInstance(Ser).deinitElem(self.alloc, cloned);
        const box = try self.alloc.create(R);
        box.* = cloned;
        return .{ .ptr = @ptrCast(box), .token = typeToken(R), .vtable = boxVTable(R, Ser) };
    }

    // ------------------------------------------------------------- Store API

    pub fn preallocate(self: *Self) DbError!u64 {
        mod.assertNotInAction("preallocate");
        try self.checkClosed();
        // reserve first: an insert failure then rolls the recid back infallibly
        try self.recids.reserve();
        const recid = self.recids.next();
        errdefer self.recids.recycleReserved(recid);
        {
            const s = self.shard(recid);
            s.lock.lock();
            defer s.lock.unlock();
            try s.map.put(self.alloc, recid, .prealloc);
        }
        // settle after unlocking: RecidAlloc.mu is never taken under a shard lock
        self.recids.cancelReserve();
        return recid;
    }

    pub fn put(self: *Self, comptime R: type, alloc: Allocator, value: R, ser: anytype) DbError!u64 {
        comptime mod.checkSer(R, @TypeOf(ser));
        _ = alloc;
        mod.assertNotInAction("put");
        try self.checkClosed();
        const box = try self.makeBox(R, @TypeOf(ser), value);
        errdefer box.deinit(self.alloc);
        try self.recids.reserve();
        const recid = self.recids.next();
        errdefer self.recids.recycleReserved(recid);
        {
            const s = self.shard(recid);
            s.lock.lock();
            defer s.lock.unlock();
            try s.map.put(self.alloc, recid, .{ .live = box });
        }
        // settle after unlocking: RecidAlloc.mu is never taken under a shard lock
        self.recids.cancelReserve();
        return recid;
    }

    pub fn get(self: *Self, comptime R: type, alloc: Allocator, recid: u64, ser: anytype) DbError!?R {
        comptime mod.checkSer(R, @TypeOf(ser));
        mod.assertNotInAction("get");
        try self.checkClosed();
        const s = self.shard(recid);
        s.lock.lockShared();
        defer s.lock.unlockShared();
        var ag = mod.ActionGuard.enter();
        defer ag.exit();
        const rec = s.map.get(recid) orelse return error.GetVoid;
        return switch (rec) {
            .null_rec, .prealloc => null,
            .live => |b| blk: {
                if (b.token != typeToken(R)) return error.DataCorruption; // heap record type mismatch
                const r: *const R = @ptrCast(@alignCast(b.ptr));
                break :blk try serInstance(@TypeOf(ser)).cloneElem(alloc, r.*);
            },
        };
    }

    pub fn read(self: *Self, recid: u64, action: RecordRead) DbError!i64 {
        mod.assertNotInAction("read");
        try self.checkClosed();
        const s = self.shard(recid);
        s.lock.lockShared();
        defer s.lock.unlockShared();
        var ag = mod.ActionGuard.enter();
        defer ag.exit();
        const rec = s.map.get(recid) orelse return error.GetVoid;
        return switch (rec) {
            .null_rec, .prealloc => action.callOnNull(),
            .live => |b| action.callOnObject(b.ptr, b.token),
        };
    }

    pub fn update(self: *Self, comptime R: type, alloc: Allocator, recid: u64, value: ?R, ser: anytype) DbError!void {
        comptime mod.checkSer(R, @TypeOf(ser));
        _ = alloc;
        mod.assertNotInAction("update");
        try self.checkClosed();
        var new_rec: HeapRec = undefined;
        if (value) |v| {
            new_rec = .{ .live = try self.makeBox(R, @TypeOf(ser), v) };
        } else {
            new_rec = .null_rec;
        }
        errdefer new_rec.deinit(self.alloc);
        const s = self.shard(recid);
        s.lock.lock();
        defer s.lock.unlock();
        const entry = s.map.getPtr(recid) orelse return error.GetVoid;
        entry.deinit(self.alloc);
        entry.* = new_rec;
    }

    pub fn compareAndSwap(
        self: *Self,
        comptime R: type,
        alloc: Allocator,
        recid: u64,
        expect: ?R,
        new: ?R,
        ser: anytype,
    ) DbError!bool {
        comptime mod.checkSer(R, @TypeOf(ser));
        _ = alloc;
        mod.assertNotInAction("compareAndSwap");
        try self.checkClosed();
        const s = self.shard(recid);
        s.lock.lock();
        defer s.lock.unlock();
        // Serializer callbacks (equals/cloneElem) run under the shard write
        // lock: guard them so same-thread reentry into the store trips the A3
        // Debug assert instead of deadlocking.
        var ag = mod.ActionGuard.enter();
        defer ag.exit();
        const entry = s.map.getPtr(recid) orelse return error.GetVoid;

        // Compare current (logical) against `expect`.
        const eq = switch (entry.*) {
            .null_rec, .prealloc => expect == null,
            .live => |b| blk: {
                if (expect == null) break :blk false;
                if (b.token != typeToken(R)) return error.DataCorruption;
                const cur: *const R = @ptrCast(@alignCast(b.ptr));
                break :blk serInstance(@TypeOf(ser)).equals(cur.*, expect.?);
            },
        };
        if (!eq) return false;

        var new_rec: HeapRec = undefined;
        if (new) |v| {
            new_rec = .{ .live = try self.makeBox(R, @TypeOf(ser), v) };
        } else {
            new_rec = .null_rec;
        }
        entry.deinit(self.alloc);
        entry.* = new_rec;
        return true;
    }

    pub fn delete(self: *Self, recid: u64) DbError!void {
        mod.assertNotInAction("delete");
        try self.checkClosed();
        // reserve BEFORE the removal commits, so recycling can't fail after
        // the record is destroyed
        try self.recids.reserve();
        const s = self.shard(recid);
        s.lock.lock();
        const removed = s.map.fetchRemove(recid);
        s.lock.unlock();
        if (removed) |kv| {
            kv.value.deinit(self.alloc);
            self.recids.recycleReserved(recid);
            return;
        }
        self.recids.cancelReserve();
        return error.GetVoid;
    }

    pub fn commit(self: *Self) DbError!void {
        return self.checkClosed();
    }

    pub fn compact(self: *Self) DbError!void {
        return self.checkClosed();
    }

    pub fn close(self: *Self) DbError!void {
        self.closed.store(true, .release);
        for (self.shards) |*s| {
            s.lock.lock();
            var it = s.map.iterator();
            while (it.next()) |e| e.value_ptr.deinit(self.alloc);
            s.map.clearRetainingCapacity();
            s.lock.unlock();
        }
        self.recids.clearFree();
    }

    pub fn isClosed(self: *Self) bool {
        return self.closed.load(.acquire);
    }

    pub fn isThreadSafe(self: *Self) bool {
        return self.thread_safe;
    }

    pub fn getCurrentSize(_: *Self) u64 {
        return 0;
    }

    pub fn isTx(_: *Self) bool {
        return false;
    }

    /// lease registry accessor (the StoreLease capability). Collections
    /// acquire in open() and release in deinit() against this table.
    pub fn leaseTable(self: *Self) *LeaseTable {
        return &self.leases;
    }

    pub fn verify(self: *Self) DbError!void {
        try self.checkClosed();
        // Concurrency-correct with only SHORT lock holds; the mutex is
        // released via scoped defers on every error path.
        // Same design as StoreByteArray.verify — see the comment there for
        // the soundness argument (monotonic-max re-check after the shard
        // lock is released; per-candidate mu+shard-read combined hold).
        const max_snap = self.currentMax();
        for (self.shards) |*s| {
            var suspicious: u64 = 0;
            {
                s.lock.lockShared();
                defer s.lock.unlockShared();
                var it = s.map.keyIterator();
                while (it.next()) |k| {
                    if (k.* < 1) return error.VerifyFailed;
                    if (k.* > max_snap) suspicious = @max(suspicious, k.*);
                }
            }
            if (suspicious > 0 and suspicious > self.currentMax()) return error.VerifyFailed;
        }
        // free recids must be in range and not live
        const free_snap = blk: {
            self.recids.mu.lock();
            defer self.recids.mu.unlock();
            break :blk try self.alloc.dupe(u64, self.recids.free.items);
        };
        defer self.alloc.free(free_snap);
        for (free_snap) |f| {
            self.recids.mu.lock();
            const still_free = std.mem.indexOfScalar(u64, self.recids.free.items, f) != null;
            var bad = false;
            if (still_free) {
                if (f > self.recids.max_recid) {
                    bad = true;
                } else {
                    const s = self.shard(f);
                    s.lock.lockShared();
                    bad = s.map.contains(f);
                    s.lock.unlockShared();
                }
            }
            self.recids.mu.unlock();
            if (bad) return error.VerifyFailed;
        }
    }

    /// Current `max_recid` under a brief mutex hold (verify re-check path).
    fn currentMax(self: *Self) u64 {
        self.recids.mu.lock();
        defer self.recids.mu.unlock();
        return self.recids.max_recid;
    }

    /// Sorted live recids (excluding preallocated), owned by `alloc`.
    pub fn getAllRecids(self: *Self, alloc: Allocator) DbError![]u64 {
        try self.checkClosed();
        var out: std.ArrayListUnmanaged(u64) = .empty;
        errdefer out.deinit(alloc);
        for (self.shards) |*s| {
            s.lock.lockShared();
            defer s.lock.unlockShared();
            var it = s.map.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.* != .prealloc) try out.append(alloc, e.key_ptr.*);
            }
        }
        const slice = try out.toOwnedSlice(alloc);
        std.mem.sort(u64, slice, {}, std.sort.asc(u64));
        return slice;
    }
};

// ------------------------------------------------------------------- tests

test {
    std.testing.refAllDecls(@This());
}
