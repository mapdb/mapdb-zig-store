//! Paged volume: 1 MiB slices, heap or file-backed mmap (Java `ByteBufferVol`,
//! ported from `mapdb-rust-store/src/store/volume.rs`. Records never
//! cross a slice boundary (allocator invariant).
//!
//! # Lock discipline (the raw-memory projection soundness invariant)
//! This is the ONLY module that projects the volume's raw bytes. Soundness rests
//! on the store's lock discipline (enforced by the caller): a byte range is
//! WRITTEN only while its record's segment write lock (or the structural lock,
//! for allocator/header words) is held, and READ only under the matching read
//! lock — so no plain read ever races a write to the same range. In v1 there is
//! no optimistic mode: every access is under a lock.
//!
//! Slices are addressed through owned `[]align(page_size_min) u8` regions
//! (heap or mmap). 1 MiB (`SLICE_SHIFT = 20`) is a LOGICAL length/offset
//! invariant only — mmap gives no 1 MiB pointer-alignment guarantee, and
//! promising more than `page_size_min` is illegal behavior. The slice *table*
//! is published via `Shared`(mutex-pin): growth republishes a new table;
//! the mapped slices themselves are never retired before close.
//!
//! Every raw accessor bounds-checks UNCONDITIONALLY (`error.DataCorruption`, not
//! `debug_assert`): ReleaseFast has no implicit checks, so these explicit guards
//! are the only line of defense — a corrupt index-derived offset must never
//! produce an out-of-bounds access.

const std = @import("std");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const Shared = @import("../shared.zig").Shared;
const tainted = @import("../tainted.zig");

pub const SLICE_SHIFT: u6 = 20;
pub const SLICE_SIZE: u64 = 1 << SLICE_SHIFT; // 1 MiB
pub const SLICE_MASK: u64 = SLICE_SIZE - 1;

const page_align = std.heap.page_size_min;
const PageBytes = []align(page_align) u8;

/// One 1 MiB slice; `mem` is the whole (logical) region, `is_mmap` selects the
/// teardown/flush path.
const Slice = struct {
    mem: PageBytes,
    is_mmap: bool,

    fn flush(self: *const Slice) DbError!void {
        if (self.is_mmap) {
            std.posix.msync(self.mem, std.os.linux.MSF.SYNC) catch return error.Io;
        }
    }
};

/// The published slice table: an owned array of owned slice pointers.
const Table = []*Slice;

/// `deinitFn` for the `Shared(Table)` — frees ONLY the table array, never the
/// slices it points at (slices outlive republication; they are reclaimed at
/// close/deinit). The outer table needs sound reclamation, the mapped
/// slices do not yet.
fn freeTable(alloc: Allocator, t: *Table) void {
    alloc.free(t.*);
}

pub const Volume = struct {
    const Self = @This();
    const SharedTable = Shared(Table);

    table: SharedTable,
    file: ?std.fs.File,
    grow_lock: std.Thread.Mutex = .{},
    alloc: Allocator,

    /// Anonymous heap-backed volume.
    pub fn initHeap(alloc: Allocator) DbError!Self {
        const empty = try alloc.alloc(*Slice, 0);
        return .{
            .table = try SharedTable.init(alloc, empty, freeTable),
            .file = null,
            .alloc = alloc,
        };
    }

    /// File-backed mmap volume (created if absent). `path` relative to cwd.
    pub fn openFile(alloc: Allocator, path: []const u8) DbError!Self {
        const file = std.fs.cwd().createFile(path, .{ .read = true, .truncate = false }) catch return error.Io;
        // a subsequent allocation / init failure must not
        // strand the descriptor.
        errdefer file.close();
        const empty = try alloc.alloc(*Slice, 0);
        errdefer alloc.free(empty);
        return .{
            .table = try SharedTable.init(alloc, empty, freeTable),
            .file = file,
            .alloc = alloc,
        };
    }

    /// fsync the directory holding `path` so a freshly-created file's directory
    /// ENTRY is itself durable. No-op for a heap volume. Linux-scoped —
    /// mirrors the WAL checkpoint dir-fsync (`.iterate` forces a real O_RDONLY
    /// dir fd; a default O_PATH fd cannot be fsync'd → EBADF).
    pub fn syncParentDir(self: *Self, path: []const u8) DbError!void {
        if (self.file == null) return;
        const parent = std.fs.path.dirname(path) orelse ".";
        const dir_path = if (parent.len == 0) "." else parent;
        var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch return error.Io;
        defer dir.close();
        std.posix.fsync(dir.fd) catch return error.Io;
    }

    /// Free every remaining slice and the table; close the file handle. Assumes
    /// quiescence (no outstanding guards) — the store calls this at teardown.
    pub fn deinit(self: *Self) void {
        {
            var g: Pin = undefined;
            self.table.loadInto(&g);
            defer g.release();
            for (g.get().*) |s| self.freeSlice(s);
        }
        self.table.deinit();
        if (self.file) |f| f.close();
        self.file = null;
    }

    fn freeSlice(self: *Self, s: *Slice) void {
        if (s.is_mmap) {
            std.posix.munmap(s.mem);
        } else {
            self.alloc.free(s.mem);
        }
        self.alloc.destroy(s);
    }

    pub fn isFileBacked(self: *const Self) bool {
        return self.file != null;
    }

    /// Physical file length (file mode) or addressable mapped length (memory mode).
    pub fn length(self: *Self) DbError!u64 {
        if (self.file) |f| {
            return f.getEndPos() catch error.Io;
        }
        var g: Pin = undefined;
        self.table.loadInto(&g);
        defer g.release();
        return @as(u64, g.get().len) << SLICE_SHIFT;
    }

    // ---- pinned table access ----

    const Pin = SharedTable.Guard;

    /// Pin the slice table into `g` (out-param; guards are
    /// initialized in their final stack location and passed by pointer only).
    inline fn pinInto(self: *Self, g: *Pin) void {
        self.table.loadInto(g);
    }

    /// Validate that `[offset, offset+len)` is addressable and lies within a
    /// single slice, returning `DataCorruption` otherwise. Callers reading at an
    /// offset derived from a (possibly corrupt) index/link value MUST call this
    /// before the raw accessors, so corruption yields a graceful error rather
    /// than the `bound` backstop.
    pub fn checkRange(self: *Self, offset: u64, len: u64) DbError!void {
        const end = try tainted.checkedAdd(u64, offset, len);
        var g: Pin = undefined;
        self.pinInto(&g);
        defer g.release();
        const addressable = @as(u64, g.get().len) << SLICE_SHIFT;
        if (end > addressable) return error.DataCorruption; // past addressable end
        if ((offset & SLICE_MASK) + len > SLICE_SIZE) return error.DataCorruption; // crosses a slice
    }

    /// Bounds backstop for the raw path (mirrors Rust `Slice::bound`): unmapped
    /// or out-of-slice access is corruption, never an OOB.
    inline fn sliceBytes(slices: Table, offset: u64, len: usize) DbError![]u8 {
        const idx: usize = @intCast(offset >> SLICE_SHIFT);
        if (idx >= slices.len) return error.DataCorruption;
        const off: usize = @intCast(offset & SLICE_MASK);
        return tainted.checkedSliceMut(slices[idx].mem, off, len);
    }

    /// Grow so bytes `[0, end_offset)` are addressable. For file mode, the file
    /// is extended (`setEndPos`) to cover a slice BEFORE it is mapped writable —
    /// access beyond EOF SIGBUSes (spec note).
    pub fn ensureAvailable(self: *Self, end_offset: u64) DbError!void {
        const needed_u = try tainted.checkedAdd(u64, end_offset, SLICE_MASK) >> SLICE_SHIFT;
        const needed: usize = @intCast(needed_u);
        self.grow_lock.lock();
        defer self.grow_lock.unlock();

        const cur_len = blk: {
            var g: Pin = undefined;
            self.pinInto(&g);
            defer g.release();
            break :blk g.get().len;
        };
        if (cur_len >= needed) return;

        const grown = try self.alloc.alloc(*Slice, needed);
        var built: usize = cur_len;
        var published = false;
        // publication is via prepare()+publish() so the
        // final step is INFALLIBLE. `Shared.store` consumes its argument even on
        // OOM (freeing the array), so the previous errdefer double-freed the
        // array and read freed slice pointers. Now the errdefer only runs while
        // we still own everything (prepare failed or an earlier step failed).
        errdefer if (!published) {
            // free only the NEW slices created in this call (indices cur_len..built)
            var j: usize = cur_len;
            while (j < built) : (j += 1) self.freeSlice(grown[j]);
            self.alloc.free(grown);
        };
        // copy the existing slice pointers (shared with the old table)
        {
            var g: Pin = undefined;
            self.pinInto(&g);
            defer g.release();
            @memcpy(grown[0..cur_len], g.get().*);
        }
        var i: usize = cur_len;
        while (i < needed) : (i += 1) {
            grown[i] = try self.makeSlice(i);
            built = i + 1;
        }
        // prepare (fallible; does NOT consume `grown` on failure) then publish
        // (infallible; old table array freed once all pins drop).
        const prepared = try self.table.prepare(grown);
        self.table.publish(prepared);
        published = true;
    }

    fn makeSlice(self: *Self, index: usize) DbError!*Slice {
        const s = try self.alloc.create(Slice);
        errdefer self.alloc.destroy(s);
        if (self.file) |f| {
            const end = (@as(u64, index) + 1) << SLICE_SHIFT;
            const cur = f.getEndPos() catch return error.Io;
            if (cur < end) {
                f.setEndPos(end) catch return error.Io;
            }
            const mem = std.posix.mmap(
                null,
                SLICE_SIZE,
                std.posix.PROT.READ | std.posix.PROT.WRITE,
                .{ .TYPE = .SHARED },
                f.handle,
                @as(u64, index) << SLICE_SHIFT,
            ) catch return error.Io;
            s.* = .{ .mem = mem, .is_mmap = true };
        } else {
            const mem = try self.alloc.alignedAlloc(u8, .fromByteUnits(page_align), @intCast(SLICE_SIZE));
            @memset(mem, 0);
            s.* = .{ .mem = mem, .is_mmap = false };
        }
        return s;
    }

    // ---- scalar accessors (value copies out; no borrow escapes) ----

    pub fn putI32(self: *Self, offset: u64, v: i32) DbError!void {
        var g: Pin = undefined;
        self.pinInto(&g);
        defer g.release();
        const dst = try sliceBytes(g.get().*, offset, 4);
        std.mem.writeInt(i32, dst[0..4], v, .big);
    }
    pub fn getI32(self: *Self, offset: u64) DbError!i32 {
        var g: Pin = undefined;
        self.pinInto(&g);
        defer g.release();
        const src = try sliceBytes(g.get().*, offset, 4);
        return std.mem.readInt(i32, src[0..4], .big);
    }
    pub fn putU64(self: *Self, offset: u64, v: u64) DbError!void {
        var g: Pin = undefined;
        self.pinInto(&g);
        defer g.release();
        const dst = try sliceBytes(g.get().*, offset, 8);
        std.mem.writeInt(u64, dst[0..8], v, .big);
    }
    pub fn getU64(self: *Self, offset: u64) DbError!u64 {
        var g: Pin = undefined;
        self.pinInto(&g);
        defer g.release();
        const src = try sliceBytes(g.get().*, offset, 8);
        return std.mem.readInt(u64, src[0..8], .big);
    }
    pub fn putByte(self: *Self, offset: u64, v: u8) DbError!void {
        var g: Pin = undefined;
        self.pinInto(&g);
        defer g.release();
        const dst = try sliceBytes(g.get().*, offset, 1);
        dst[0] = v;
    }
    pub fn getU8(self: *Self, offset: u64) DbError!u8 {
        var g: Pin = undefined;
        self.pinInto(&g);
        defer g.release();
        const src = try sliceBytes(g.get().*, offset, 1);
        return src[0];
    }

    /// Absolute put of `src` at `offset`; must not cross a slice boundary.
    pub fn putData(self: *Self, offset: u64, src: []const u8) DbError!void {
        var g: Pin = undefined;
        self.pinInto(&g);
        defer g.release();
        const dst = try sliceBytes(g.get().*, offset, src.len);
        @memcpy(dst, src);
    }

    /// Absolute get into `dst`; must not cross a slice boundary.
    pub fn getData(self: *Self, offset: u64, dst: []u8) DbError!void {
        var g: Pin = undefined;
        self.pinInto(&g);
        defer g.release();
        const src = try sliceBytes(g.get().*, offset, dst.len);
        @memcpy(dst, src);
    }

    /// Zero `[from, to)`; may span slices.
    pub fn clear(self: *Self, from: u64, to: u64) DbError!void {
        var p = from;
        while (p < to) {
            var g: Pin = undefined;
            self.pinInto(&g);
            const off = p & SLICE_MASK;
            const n = @min(to - p, SLICE_SIZE - off);
            const dst = sliceBytes(g.get().*, p, @intCast(n)) catch {
                g.release();
                return error.DataCorruption;
            };
            @memset(dst, 0);
            g.release();
            p += n;
        }
    }

    /// A pinned borrow of record content `[offset, offset+len)` as a const slice.
    /// The pin keeps the slice table alive for the borrow's lifetime; the caller
    /// MUST `deinit` it. Must not cross a slice boundary (validate first).
    ///
    /// Out-param initialized by [`borrowInto`] (the embedded
    /// guard records its final address at init; a Borrow must never be copied
    /// or moved afterwards).
    pub const Borrow = struct {
        guard: Pin,
        bytes: []const u8,
        pub fn deinit(self: *Borrow) void {
            self.guard.release();
        }
    };

    /// Initialize `out` (in its final location) with a pinned borrow.
    pub fn borrowInto(self: *Self, offset: u64, len: usize, out: *Borrow) DbError!void {
        self.table.loadInto(&out.guard);
        errdefer out.guard.release();
        out.bytes = try sliceBytes(out.guard.get().*, offset, len);
    }

    // ---- durability ----

    /// Full durability point: flush every mapped slice, then fsync. No-op in memory mode.
    pub fn sync(self: *Self) DbError!void {
        const f = self.file orelse return;
        {
            var g: Pin = undefined;
            self.pinInto(&g);
            defer g.release();
            for (g.get().*) |s| try s.flush();
        }
        std.posix.fsync(f.handle) catch return error.Io;
    }

    /// Header-page-only durability (slice 0), for the second phase of commit.
    pub fn syncHeader(self: *Self) DbError!void {
        const f = self.file orelse return;
        {
            var g: Pin = undefined;
            self.pinInto(&g);
            defer g.release();
            const t = g.get().*;
            if (t.len > 0) try t[0].flush();
        }
        std.posix.fsync(f.handle) catch return error.Io;
    }

    /// Shrink the addressable volume to `truncate_to` (page-aligned).
    pub fn truncate(self: *Self, truncate_to: u64) DbError!void {
        if (truncate_to & SLICE_MASK != 0) return error.DataCorruption; // not page-aligned
        self.grow_lock.lock();
        defer self.grow_lock.unlock();
        const needed: usize = @intCast(truncate_to >> SLICE_SHIFT);
        try self.shrinkTo(needed);
        if (self.file) |f| {
            const cur = f.getEndPos() catch return error.Io;
            if (truncate_to < cur) f.setEndPos(truncate_to) catch return error.Io;
            std.posix.fsync(f.handle) catch return error.Io;
        }
    }

    /// Release all slices; in file mode optionally shrink to `truncate_to`.
    pub fn close(self: *Self, truncate_to: ?u64) DbError!void {
        self.grow_lock.lock();
        defer self.grow_lock.unlock();
        try self.shrinkTo(0);
        if (self.file) |f| {
            if (truncate_to) |t| {
                const cur = f.getEndPos() catch return error.Io;
                if (t < cur) f.setEndPos(t) catch return error.Io;
            }
            std.posix.fsync(f.handle) catch return error.Io;
        }
    }

    /// grow_lock held. Publish a table of the first `needed` slices, freeing the
    /// slices dropped off the tail. (Slices are only reclaimed here and in
    /// `deinit`, both at store quiescence — never while a reader can hold them.)
    fn shrinkTo(self: *Self, needed: usize) DbError!void {
        // PUBLISH the shortened table before reclaiming
        // the dropped slices. The old code freed slices first, then called the
        // fallible `Shared.store`; on OOM the still-published old table held
        // pointers to freed slices → UAF/double-free at deinit. Now every
        // fallible allocation is staged while the live table is untouched, the
        // dropped pointers are copied out (the old array is freed by publish),
        // publication is infallible, and only then are the slices reclaimed.
        var g: Pin = undefined;
        self.pinInto(&g);
        const old_len = g.get().len;
        if (old_len <= needed) {
            g.release();
            return;
        }
        const shrunk = self.alloc.alloc(*Slice, needed) catch {
            g.release();
            return error.OutOfMemory;
        };
        const dropped = self.alloc.alloc(*Slice, old_len - needed) catch {
            self.alloc.free(shrunk);
            g.release();
            return error.OutOfMemory;
        };
        @memcpy(shrunk, g.get().*[0..needed]);
        @memcpy(dropped, g.get().*[needed..]);
        g.release();
        const prepared = self.table.prepare(shrunk) catch |e| {
            self.alloc.free(shrunk);
            self.alloc.free(dropped);
            return e;
        };
        self.table.publish(prepared); // infallible; old array freed once pins drop
        for (dropped) |s| self.freeSlice(s);
        self.alloc.free(dropped);
    }
};

// ------------------------------------------------------------------- tests

const testing = std.testing;

test "heap volume: grow, scalar round-trips, bounds, clear" {
    var v = try Volume.initHeap(testing.allocator);
    defer v.deinit();
    try testing.expectEqual(@as(u64, 0), try v.length());
    try v.ensureAvailable(SLICE_SIZE);
    try testing.expectEqual(SLICE_SIZE, try v.length());

    try v.putU64(0, 0xDEAD_BEEF_CAFE_F00D);
    try testing.expectEqual(@as(u64, 0xDEAD_BEEF_CAFE_F00D), try v.getU64(0));
    try v.putI32(16, -12345);
    try testing.expectEqual(@as(i32, -12345), try v.getI32(16));
    try v.putByte(100, 0xAB);
    try testing.expectEqual(@as(u8, 0xAB), try v.getU8(100));

    // bounds: cross a slice boundary / past end → DataCorruption
    try testing.expectError(error.DataCorruption, v.checkRange(SLICE_SIZE - 4, 8));
    try testing.expectError(error.DataCorruption, v.checkRange(SLICE_SIZE, 1));
    try v.checkRange(0, SLICE_SIZE);

    // clear then verify zeroed
    try v.putU64(200, 0x1111_2222_3333_4444);
    try v.clear(200, 208);
    try testing.expectEqual(@as(u64, 0), try v.getU64(200));
}

test "heap volume: putData/getData/borrow" {
    var v = try Volume.initHeap(testing.allocator);
    defer v.deinit();
    try v.ensureAvailable(SLICE_SIZE);
    const src = [_]u8{ 1, 2, 3, 4, 5, 6, 7 };
    try v.putData(300, &src);
    var dst: [7]u8 = undefined;
    try v.getData(300, &dst);
    try testing.expectEqualSlices(u8, &src, &dst);
    var b: Volume.Borrow = undefined;
    try v.borrowInto(300, 7, &b);
    defer b.deinit();
    try testing.expectEqualSlices(u8, &src, b.bytes);
}

test "heap volume: multi-slice grow keeps earlier bytes" {
    var v = try Volume.initHeap(testing.allocator);
    defer v.deinit();
    try v.ensureAvailable(SLICE_SIZE);
    try v.putU64(8, 0xAAAA);
    try v.ensureAvailable(3 * SLICE_SIZE);
    try testing.expectEqual(@as(u64, 0xAAAA), try v.getU64(8)); // survived republish
    try v.putU64(2 * SLICE_SIZE + 8, 0xBBBB);
    try testing.expectEqual(@as(u64, 0xBBBB), try v.getU64(2 * SLICE_SIZE + 8));
    try testing.expectEqual(3 * SLICE_SIZE, try v.length());
}

test "file volume: create, write, reopen, truncate" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmp.dir.realpath(".", &buf);
    const full = try std.fs.path.join(testing.allocator, &.{ path, "vol.bin" });
    defer testing.allocator.free(full);

    {
        var v = try Volume.openFile(testing.allocator, full);
        defer v.deinit();
        try v.ensureAvailable(2 * SLICE_SIZE);
        try v.putU64(0, 0x0102_0304_0506_0708);
        try v.putU64(SLICE_SIZE + 16, 0x1122_3344);
        try v.sync();
        try v.close(2 * SLICE_SIZE);
    }
    {
        var v = try Volume.openFile(testing.allocator, full);
        defer v.deinit();
        try testing.expectEqual(2 * SLICE_SIZE, try v.length());
        try v.ensureAvailable(2 * SLICE_SIZE);
        try testing.expectEqual(@as(u64, 0x0102_0304_0506_0708), try v.getU64(0));
        try testing.expectEqual(@as(u64, 0x1122_3344), try v.getU64(SLICE_SIZE + 16));
    }
}

// allocation-failure robustness at the table
// publication (ensureAvailable), the shrink/close reclamation, and file open.
// std.testing.allocator fails the build on any leak or double-free.

test "FailingAllocator sweep: ensureAvailable + shrink/close publication" {
    var idx: usize = 0;
    while (idx < 400) : (idx += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = idx });
        const a = failing.allocator();
        var v = Volume.initHeap(a) catch continue;
        defer v.deinit();
        // grow (publish a bigger table), grow again (republish), then reclaim.
        v.ensureAvailable(4 * SLICE_SIZE) catch continue;
        v.ensureAvailable(8 * SLICE_SIZE) catch {};
        v.truncate(2 * SLICE_SIZE) catch {}; // shrinkTo: publish-before-reclaim
        v.close(SLICE_SIZE) catch {};
        // survivors (if any) round-trip; deinit reclaims the rest with no leak.
        if ((v.length() catch 0) > 0) v.putU64(0, 0xABCD) catch {};
    }
}

test "FailingAllocator sweep: Volume.openFile no fd/alloc leak" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmp.dir.realpath(".", &buf);
    const full = try std.fs.path.join(testing.allocator, &.{ path, "openleak.bin" });
    defer testing.allocator.free(full);
    var idx: usize = 0;
    while (idx < 8) : (idx += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = idx });
        if (Volume.openFile(failing.allocator(), full)) |vc| {
            var v = vc;
            v.deinit();
        } else |_| {}
    }
}
