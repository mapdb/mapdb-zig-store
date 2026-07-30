//! `SegmentLocks` — a fixed bank of cache-line-padded reader/writer locks keyed
//! by recid low bits (Java `SegmentLocks`). In single-threaded
//! mode the bank is a no-op (resolved at construction — a runtime `?[]Cell`).
//!
//! The `align(cache_line)` goes on the padded element type so the array *stride*
//! is a whole number of cache lines → no false sharing between adjacent locks.
//!
//! Guard discipline: guards are initialized IN their final
//! stack location via out-param `read`/`write` and passed by pointer only. In
//! Debug builds each guard records its own address at init; `unlock` asserts
//! the guard still lives there and was not already released, so an aliased
//! copy trips an assert instead of double-unlocking the RwLock.
//!
//! Debug lock tracker: a `threadlocal` counter enforces ≤1 segment lock
//! held per thread and rejects reentrancy. Cheap; caught real bugs in Java.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;

/// Default number of segments (Java `SegmentLocks.DEFAULT_COUNT`).
pub const DEFAULT_COUNT: usize = 64;

const cache_line = std.atomic.cache_line;
const guard_debug = builtin.mode == .Debug;

/// One RW lock padded to a whole cache line. Alignment on the element type pads
/// the array stride (`@sizeOf(Cell)` is a multiple of `cache_line`).
const Cell = struct {
    lock: std.Thread.RwLock align(cache_line) = .{},
};

comptime {
    std.debug.assert(@alignOf(Cell) == cache_line);
    std.debug.assert(@sizeOf(Cell) % cache_line == 0);
}

// -------------------------------------------------- debug held-lock tracker

/// Depth of segment locks held by the current thread (Debug only).
threadlocal var seg_held: u32 = 0;

inline fn trackAcquire() void {
    if (builtin.mode == .Debug) {
        std.debug.assert(seg_held == 0); // ≤1 segment lock per thread, no reentrancy
        seg_held += 1;
    }
}
inline fn trackRelease() void {
    if (builtin.mode == .Debug) {
        std.debug.assert(seg_held == 1);
        seg_held -= 1;
    }
}

// ------------------------------------------------------------------- guards

/// Read guard; `lock == null` in single-threaded (no-op) mode or after unlock
/// (`released` disambiguates in Debug). Out-param init only; see module doc.
pub const SegReadGuard = struct {
    lock: ?*std.Thread.RwLock,
    home: if (guard_debug) ?*const SegReadGuard else void,
    released: if (guard_debug) bool else void,

    pub fn unlock(self: *SegReadGuard) void {
        if (guard_debug) {
            // copied/moved guard (lock-discipline violation) or double unlock
            std.debug.assert(self.home == self);
            std.debug.assert(!self.released);
            self.released = true;
        }
        if (self.lock) |l| {
            trackRelease();
            l.unlockShared();
        }
        self.lock = null;
    }
};

/// Write guard; same discipline as [`SegReadGuard`].
pub const SegWriteGuard = struct {
    lock: ?*std.Thread.RwLock,
    home: if (guard_debug) ?*const SegWriteGuard else void,
    released: if (guard_debug) bool else void,

    pub fn unlock(self: *SegWriteGuard) void {
        if (guard_debug) {
            // copied/moved guard (lock-discipline violation) or double unlock
            std.debug.assert(self.home == self);
            std.debug.assert(!self.released);
            self.released = true;
        }
        if (self.lock) |l| {
            trackRelease();
            l.unlock();
        }
        self.lock = null;
    }
};

// --------------------------------------------------------------- the bank

pub const SegmentLocks = struct {
    cells: ?[]Cell,
    mask: usize,
    count: usize,
    alloc: Allocator,

    /// `count` must be a power of two. `thread_safe == false` builds a no-op bank.
    pub fn init(alloc: Allocator, count: usize, thread_safe: bool) DbError!SegmentLocks {
        std.debug.assert(std.math.isPowerOfTwo(count));
        if (!thread_safe) {
            return .{ .cells = null, .mask = count - 1, .count = count, .alloc = alloc };
        }
        const cells = try alloc.alloc(Cell, count);
        for (cells) |*c| c.* = .{};
        return .{ .cells = cells, .mask = count - 1, .count = count, .alloc = alloc };
    }

    /// Convenience constructor with the default segment count.
    pub fn defaultFor(alloc: Allocator, thread_safe: bool) DbError!SegmentLocks {
        return init(alloc, DEFAULT_COUNT, thread_safe);
    }

    pub fn deinit(self: *SegmentLocks) void {
        if (self.cells) |c| self.alloc.free(c);
        self.cells = null;
    }

    /// The segment index for `recid` (also selects the store's parallel map).
    pub inline fn index(self: *const SegmentLocks, recid: u64) usize {
        return @as(usize, @intCast(recid)) & self.mask;
    }

    /// Acquire the read lock for `recid`'s segment into `g` (out-param — `g`
    /// must already be in its final location).
    pub fn read(self: *SegmentLocks, recid: u64, g: *SegReadGuard) void {
        var lock: ?*std.Thread.RwLock = null;
        if (self.cells) |cells| {
            const l = &cells[self.index(recid)].lock;
            trackAcquire();
            l.lockShared();
            lock = l;
        }
        g.* = .{
            .lock = lock,
            .home = if (guard_debug) g else {},
            .released = if (guard_debug) false else {},
        };
    }

    /// Acquire the write lock for `recid`'s segment into `g` (out-param — `g`
    /// must already be in its final location).
    pub fn write(self: *SegmentLocks, recid: u64, g: *SegWriteGuard) void {
        var lock: ?*std.Thread.RwLock = null;
        if (self.cells) |cells| {
            const l = &cells[self.index(recid)].lock;
            trackAcquire();
            l.lock();
            lock = l;
        }
        g.* = .{
            .lock = lock,
            .home = if (guard_debug) g else {},
            .released = if (guard_debug) false else {},
        };
    }
};

// ------------------------------------------------------------------- tests

const testing = std.testing;

test "segment locks: stride is cache-line padded" {
    try testing.expect(@sizeOf(Cell) >= cache_line);
    try testing.expectEqual(@as(usize, 0), @sizeOf(Cell) % cache_line);
}

test "real bank: read/write acquire+release; index selection" {
    var sl = try SegmentLocks.defaultFor(testing.allocator, true);
    defer sl.deinit();
    try testing.expectEqual(@as(usize, 5), sl.index(5));
    try testing.expectEqual(@as(usize, 5), sl.index(64 + 5)); // low bits
    {
        var g: SegWriteGuard = undefined;
        sl.write(5, &g);
        defer g.unlock();
    }
    {
        var g: SegReadGuard = undefined;
        sl.read(5, &g);
        defer g.unlock();
    }
    // sequential (non-nested) acquisitions do not trip the tracker
    {
        var g: SegWriteGuard = undefined;
        sl.write(1, &g);
        g.unlock();
        var g2: SegReadGuard = undefined;
        sl.read(2, &g2);
        g2.unlock();
    }
}

test "no-op bank: guards are inert" {
    var sl = try SegmentLocks.defaultFor(testing.allocator, false);
    defer sl.deinit();
    try testing.expect(sl.cells == null);
    var w: SegWriteGuard = undefined;
    sl.write(7, &w);
    try testing.expect(w.lock == null);
    w.unlock();
    var r: SegReadGuard = undefined;
    sl.read(7, &r);
    try testing.expect(r.lock == null);
    r.unlock();
}
