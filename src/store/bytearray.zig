//! `StoreByteArray` — the reference `StoreDelta` oracle: one
//! `buf: []u8` per record, `buf.len` is capacity, `used` is content length.
//! Everything explicit — this store doubles as the differential-fuzz oracle.
//! Kept dumb; its value is being obviously correct. Ported from
//! `mapdb-rust-store/src/store/bytearray.rs`.
//!
//! Locking: [`SegmentLocks`] (64, cache-line padded; a no-op bank when
//! `thread_safe == false`) over a parallel array of per-segment maps — lock `i`
//! guards map `i` (same recid low bits). Serialization happens OUTSIDE the
//! record lock (D-rule); the CAS path deserializes the current image under the
//! lock and compares with `ser.equals` (logical equality). Serializer callbacks
//! that DO run under a record lock (get's deserialize, the whole CAS compare +
//! rebuild) are wrapped in the A3 [`mod.ActionGuard`] so same-thread reentry
//! into the store trips the Debug assert instead of deadlocking.
//! Record buffers are owned by `self.alloc`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const mod = @import("mod.zig");
const RecordRead = mod.RecordRead;
const RecState = mod.RecState;
const AppendResult = mod.AppendResult;
const LeaseTable = mod.LeaseTable;
const RecidAlloc = mod.RecidAlloc;
const SegmentLocks = mod.SegmentLocks;
const SegReadGuard = mod.segment_locks.SegReadGuard;
const SegWriteGuard = mod.segment_locks.SegWriteGuard;

const SHARDS: usize = 64;

const Rec = struct {
    buf: []u8, // capacity == buf.len
    used: usize,
    state: RecState, // one of .preallocated / .null_rec / .live

    fn deinit(self: Rec, alloc: Allocator) void {
        alloc.free(self.buf);
    }
};

pub const StoreByteArray = struct {
    const Self = @This();
    const Map = std.AutoHashMapUnmanaged(u64, Rec);

    maps: []Map, // one per segment; maps[i] guarded by locks segment i
    locks: SegmentLocks,
    recids: RecidAlloc,
    leases: LeaseTable,
    thread_safe: bool,
    closed: std.atomic.Value(bool),
    alloc: Allocator,

    /// New empty in-memory byte store. `alloc` owns all record buffers and
    /// internal structures; the caller must `deinit`. `thread_safe` selects the
    /// real vs no-op segment-lock bank.
    pub fn init(alloc: Allocator, thread_safe: bool) DbError!Self {
        const maps = try alloc.alloc(Map, SHARDS);
        for (maps) |*m| m.* = .empty;
        errdefer alloc.free(maps);
        var locks = try SegmentLocks.init(alloc, SHARDS, thread_safe);
        errdefer locks.deinit();
        return .{
            .maps = maps,
            .locks = locks,
            .recids = RecidAlloc.init(alloc),
            .leases = LeaseTable.init(alloc),
            .thread_safe = thread_safe,
            .closed = std.atomic.Value(bool).init(false),
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.maps) |*m| {
            var it = m.iterator();
            while (it.next()) |e| e.value_ptr.deinit(self.alloc);
            m.deinit(self.alloc);
        }
        self.alloc.free(self.maps);
        self.locks.deinit();
        self.recids.deinit();
        self.leases.deinit();
    }

    inline fn mapFor(self: *Self, recid: u64) *Map {
        return &self.maps[self.locks.index(recid)];
    }

    fn checkClosed(self: *Self) DbError!void {
        if (self.closed.load(.acquire)) return error.StoreClosed;
    }

    /// Serialize `value` (or build a null record) reserving `headroom` trailing
    /// bytes. Runs OUTSIDE any record lock (except the CAS rebuild, which
    /// guards it). Buffer owned by `self.alloc`.
    fn newRec(self: *Self, comptime R: type, value: ?R, ser: anytype, headroom: usize) DbError!Rec {
        if (value) |v| {
            var out = DataOutput2.init(self.alloc);
            defer out.deinit();
            try ser.serialize(&out, v);
            const used = out.pos();
            const total = try mod_ckAdd(used, headroom);
            const buf = try self.alloc.alloc(u8, total);
            @memcpy(buf[0..used], out.bytes());
            @memset(buf[used..], 0);
            return .{ .buf = buf, .used = used, .state = .live };
        }
        const buf = try self.alloc.alloc(u8, headroom);
        @memset(buf, 0);
        return .{ .buf = buf, .used = 0, .state = .null_rec };
    }

    // ------------------------------------------------------------- Store API

    pub fn preallocate(self: *Self) DbError!u64 {
        mod.assertNotInAction("preallocate");
        try self.checkClosed();
        const empty = try self.alloc.alloc(u8, 0);
        errdefer self.alloc.free(empty);
        // reserve first: an insert failure then rolls the recid back infallibly
        try self.recids.reserve();
        const recid = self.recids.next();
        errdefer self.recids.recycleReserved(recid);
        {
            var g: SegWriteGuard = undefined;
            self.locks.write(recid, &g);
            defer g.unlock();
            try self.mapFor(recid).put(self.alloc, recid, .{ .buf = empty, .used = 0, .state = .preallocated });
        }
        // settle after unlocking: RecidAlloc.mu is never taken under a segment lock
        self.recids.cancelReserve();
        return recid;
    }

    pub fn put(self: *Self, comptime R: type, alloc: Allocator, value: R, ser: anytype) DbError!u64 {
        comptime mod.checkSer(R, @TypeOf(ser));
        _ = alloc;
        mod.assertNotInAction("put");
        try self.checkClosed();
        const rec = try self.newRec(R, value, ser, 0);
        errdefer rec.deinit(self.alloc);
        try self.recids.reserve();
        const recid = self.recids.next();
        errdefer self.recids.recycleReserved(recid);
        {
            var g: SegWriteGuard = undefined;
            self.locks.write(recid, &g);
            defer g.unlock();
            try self.mapFor(recid).put(self.alloc, recid, rec);
        }
        // settle after unlocking: RecidAlloc.mu is never taken under a segment lock
        self.recids.cancelReserve();
        return recid;
    }

    pub fn get(self: *Self, comptime R: type, alloc: Allocator, recid: u64, ser: anytype) DbError!?R {
        comptime mod.checkSer(R, @TypeOf(ser));
        mod.assertNotInAction("get");
        try self.checkClosed();
        var g: SegReadGuard = undefined;
        self.locks.read(recid, &g);
        defer g.unlock();
        var ag = mod.ActionGuard.enter(); // deserialize runs under the read lock
        defer ag.exit();
        const rec = self.mapFor(recid).getPtr(recid) orelse return error.GetVoid;
        if (rec.state != .live) return null;
        var input = DataInput2.init(rec.buf[0..rec.used]);
        return try ser.deserialize(alloc, &input, rec.used);
    }

    pub fn read(self: *Self, recid: u64, action: RecordRead) DbError!i64 {
        mod.assertNotInAction("read");
        try self.checkClosed();
        var g: SegReadGuard = undefined;
        self.locks.read(recid, &g);
        defer g.unlock();
        var ag = mod.ActionGuard.enter();
        defer ag.exit();
        const rec = self.mapFor(recid).getPtr(recid) orelse return error.GetVoid;
        if (rec.state != .live) return action.callOnNull();
        var input = DataInput2.init(rec.buf[0..rec.used]);
        return action.callOnBytes(&input, rec.used);
    }

    pub fn update(self: *Self, comptime R: type, alloc: Allocator, recid: u64, value: ?R, ser: anytype) DbError!void {
        comptime mod.checkSer(R, @TypeOf(ser));
        _ = alloc;
        return self.updateHeadroomOpt(R, recid, value, ser, 0);
    }

    fn updateHeadroomOpt(self: *Self, comptime R: type, recid: u64, value: ?R, ser: anytype, headroom: usize) DbError!void {
        mod.assertNotInAction("update");
        try self.checkClosed();
        const rec = try self.newRec(R, value, ser, headroom); // outside the lock
        errdefer rec.deinit(self.alloc);
        var g: SegWriteGuard = undefined;
        self.locks.write(recid, &g);
        defer g.unlock();
        const entry = self.mapFor(recid).getPtr(recid) orelse return error.GetVoid;
        entry.deinit(self.alloc);
        entry.* = rec;
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
        mod.assertNotInAction("compareAndSwap");
        try self.checkClosed();
        var g: SegWriteGuard = undefined;
        self.locks.write(recid, &g);
        defer g.unlock();
        // Serializer callbacks (deserialize/equals/deinitElem + the rebuild's
        // serialize) run under the write lock: A3-guard them.
        var ag = mod.ActionGuard.enter();
        defer ag.exit();
        const entry = self.mapFor(recid).getPtr(recid) orelse return error.GetVoid;

        // Deserialize the current logical image under the lock (temp, caller alloc).
        var eq: bool = undefined;
        if (entry.state != .live) {
            eq = expect == null;
        } else if (expect == null) {
            eq = false;
        } else {
            var input = DataInput2.init(entry.buf[0..entry.used]);
            const cur = try ser.deserialize(alloc, &input, entry.used);
            defer ser.deinitElem(alloc, cur);
            eq = ser.equals(cur, expect.?);
        }
        if (!eq) return false;

        const rec = try self.newRec(R, new, ser, 0);
        entry.deinit(self.alloc);
        entry.* = rec;
        return true;
    }

    pub fn delete(self: *Self, recid: u64) DbError!void {
        mod.assertNotInAction("delete");
        try self.checkClosed();
        // reserve BEFORE the removal commits, so recycling can't fail after
        // the record is destroyed
        try self.recids.reserve();
        var g: SegWriteGuard = undefined;
        self.locks.write(recid, &g);
        const removed = self.mapFor(recid).fetchRemove(recid);
        g.unlock();
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
        for (self.maps, 0..) |*m, i| {
            var g: SegWriteGuard = undefined;
            self.locks.write(@intCast(i), &g);
            var it = m.iterator();
            while (it.next()) |e| e.value_ptr.deinit(self.alloc);
            m.clearRetainingCapacity();
            g.unlock();
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

    /// lease registry accessor (the StoreLease capability).
    pub fn leaseTable(self: *Self) *LeaseTable {
        return &self.leases;
    }

    pub fn verify(self: *Self) DbError!void {
        try self.checkClosed();
        // Concurrency-correct with only SHORT lock holds (and its fix must not
        // hold `recids.mu` across the whole
        // scan either: `std.Thread.Mutex` is unfair, so a looping verifier
        // then starves every allocator user, livelocking the store):
        // - key range: `max_recid` is monotonic, so any allocated k satisfies
        //   k ≤ max at any later read. Suspicious keys (> the pre-scan
        //   snapshot) are re-checked against a FRESH max AFTER the segment
        //   lock is released (never mu-under-segment).
        // - free-vs-live: per candidate recid, hold mu (freezes the free
        //   list) + that recid's segment read lock together, briefly. Under
        //   both, "f free AND f in map" is a genuine violation: put pops f
        //   from free BEFORE inserting, delete removes from the map BEFORE
        //   recycling. mu→segment is the only combined order anywhere (no
        //   store path takes mu while holding a segment lock; RecidAlloc doc).
        const max_snap = self.currentMax();
        for (self.maps, 0..) |*m, i| {
            var suspicious: u64 = 0;
            {
                var g: SegReadGuard = undefined;
                self.locks.read(@intCast(i), &g);
                defer g.unlock();
                var it = m.iterator();
                while (it.next()) |e| {
                    const k = e.key_ptr.*;
                    if (k < 1) return error.VerifyFailed;
                    if (k > max_snap) suspicious = @max(suspicious, k);
                    if (e.value_ptr.used > e.value_ptr.buf.len) return error.VerifyFailed;
                }
            }
            if (suspicious > 0 and suspicious > self.currentMax()) return error.VerifyFailed;
        }
        // Candidate free recids (owned snapshot under mu; each candidate is
        // re-validated under mu below, so staleness cannot mis-fire).
        const free_snap = blk: {
            self.recids.mu.lock();
            defer self.recids.mu.unlock();
            break :blk try self.alloc.dupe(u64, self.recids.free.items);
        };
        defer self.alloc.free(free_snap);
        for (free_snap) |f| {
            self.recids.mu.lock();
            const still_free = std.mem.indexOfScalar(u64, self.recids.free.items, f) != null;
            var live = false;
            if (still_free) {
                var g: SegReadGuard = undefined;
                self.locks.read(f, &g);
                live = self.mapFor(f).contains(f);
                g.unlock();
            }
            self.recids.mu.unlock();
            if (still_free and live) return error.VerifyFailed;
        }
    }

    /// Current `max_recid` under a brief mutex hold (verify re-check path).
    fn currentMax(self: *Self) u64 {
        self.recids.mu.lock();
        defer self.recids.mu.unlock();
        return self.recids.max_recid;
    }

    pub fn getAllRecids(self: *Self, alloc: Allocator) DbError![]u64 {
        try self.checkClosed();
        var out: std.ArrayListUnmanaged(u64) = .empty;
        errdefer out.deinit(alloc);
        for (self.maps, 0..) |*m, i| {
            var g: SegReadGuard = undefined;
            self.locks.read(@intCast(i), &g);
            defer g.unlock();
            var it = m.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.state != .preallocated) try out.append(alloc, e.key_ptr.*);
            }
        }
        const slice = try out.toOwnedSlice(alloc);
        std.mem.sort(u64, slice, {}, std.sort.asc(u64));
        return slice;
    }

    // ------------------------------------------------------------ StoreDelta

    pub fn append(self: *Self, recid: u64, data: []const u8) DbError!AppendResult {
        mod.assertNotInAction("append");
        try self.checkClosed();
        var g: SegWriteGuard = undefined;
        self.locks.write(recid, &g);
        defer g.unlock();
        const r = self.mapFor(recid).getPtr(recid) orelse return error.GetVoid;
        const new_used = try mod_ckAdd(r.used, data.len);
        if (new_used > r.buf.len) {
            const never_provisioned = r.state != .live and r.buf.len == 0;
            if (!never_provisioned) return .refused;
            // First append establishes the record: capacity == len.
            const nbuf = try self.alloc.alloc(u8, data.len);
            self.alloc.free(r.buf);
            r.buf = nbuf;
        }
        @memcpy(r.buf[r.used .. r.used + data.len], data);
        r.used = new_used;
        r.state = .live;
        return .{ .new_size = r.used };
    }

    pub fn capacityRemaining(self: *Self, recid: u64) DbError!usize {
        mod.assertNotInAction("capacityRemaining");
        try self.checkClosed();
        var g: SegReadGuard = undefined;
        self.locks.read(recid, &g);
        defer g.unlock();
        const r = self.mapFor(recid).getPtr(recid) orelse return error.GetVoid;
        return r.buf.len - r.used;
    }

    pub fn updateWithHeadroom(self: *Self, comptime R: type, alloc: Allocator, recid: u64, value: R, ser: anytype, headroom: usize) DbError!void {
        comptime mod.checkSer(R, @TypeOf(ser));
        _ = alloc;
        return self.updateHeadroomOpt(R, recid, value, ser, headroom);
    }
};

/// Local checked-add (torn/oversize lengths must fail fast, not wrap — D4).
fn mod_ckAdd(a: usize, b: usize) DbError!usize {
    return std.math.add(usize, a, b) catch return error.DataCorruption;
}

// ------------------------------------------------------------------- tests

test {
    std.testing.refAllDecls(@This());
}
