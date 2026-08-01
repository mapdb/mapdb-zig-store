//! The **durability-event seam** — the writer obligations W1-W5, W7 and W9 are
//! ordering claims about operations that leave no trace in the resulting bytes,
//! and this is where a test observes them.
//!
//! Port of the seam Rust declares in `mapdb-rust-store/src/store/wal_write.rs`
//! (slice A2) and Java exposes as its `WalIo` interface. **File-layout
//! deviation, deliberate:** Rust introduced the seam with the writer, so it
//! lives beside it; the Zig port needs it one slice EARLIER, because the
//! namespace layer (`wal_segments.zig`, slice B0) already emits five of the nine
//! kinds — create, segment header, full force, unlink and directory fsync — and
//! having `wal_segments.zig` import the writer for them would invert the
//! dependency the split exists to express. A file of its own says the seam
//! belongs to neither.
//!
//! What it does NOT model: this is an I/O-FAILURE seam, not a power-loss one.
//! Returning an error here makes a syscall fail; it does not make written bytes
//! vanish. Power-loss images — torn tails at every offset, non-prefix unlink
//! subsets, create-crash residue — are the recovery suite's and the crash
//! harness's subject and stay there.
//!
//! **Per store, not per process.** Java installs its `WalIo` in a static and
//! serializes the tests that use it; a test binary that runs tests
//! concurrently in one process would leak fault injection from one test into
//! another through a global. The seam is therefore a field on the store and on
//! the segment set, handed in at open. This is a test-harness difference, not a
//! format one.

const std = @import("std");
const DbError = @import("../errors.zig").DbError;

/// The durability-relevant file operations. `sec_header` and `sec_body` are
/// separate kinds deliberately: a failure between them is a *partial section
/// write*, and that is precisely the state W9 exists to forbid appending after.
pub const WalOpKind = enum {
    create,
    seg_header,
    sec_header,
    sec_body,
    force_data,
    force_full,
    truncate,
    unlink,
    dir_sync,
};

/// One reported operation. `seq` is the segment's sequence number (0 for
/// `dir_sync`), `off` the byte offset it starts at — for a force, the file
/// length it makes durable — `len` the bytes it writes (0 where it writes none),
/// and `tag` the section tag for section events, else 0.
pub const WalIoEvent = struct {
    kind: WalOpKind,
    seq: i64,
    off: u64,
    len: u64,
    tag: u8,
};

/// Writer fault-injection and trace seam, called immediately **before** each
/// operation; returning an error makes that operation fail exactly as the
/// platform would.
///
/// A hand-rolled vtable rather than an allocated interface object: the seam is
/// installed at open and BORROWED for the whole life of the segment set, and it
/// is never freed through this handle.
///
/// That lifetime is a **requirement on the installer, not a guarantee this type
/// provides**. Nothing here couples the two: `openWithIo` stores a raw pointer,
/// and a seam that dies first leaves the set calling into freed memory on its
/// next durability event. B2 installs the store's seam as a field of the store
/// that owns the set, which is what makes the requirement hold there.
pub const WalIo = struct {
    ctx: *anyopaque,
    beforeFn: *const fn (ctx: *anyopaque, e: *const WalIoEvent) DbError!void,

    pub fn before(self: *const WalIo, e: *const WalIoEvent) DbError!void {
        return self.beforeFn(self.ctx, e);
    }
};

/// Reports one operation, if a seam is installed.
pub fn walIoEvent(
    io: ?*const WalIo,
    kind: WalOpKind,
    seq: i64,
    off: u64,
    len: u64,
    tag: u8,
) DbError!void {
    const seam = io orelse return;
    return seam.before(&.{ .kind = kind, .seq = seq, .off = off, .len = len, .tag = tag });
}

// ------------------------------------------------------------------- tests

const testing = std.testing;

/// A recording seam: every event in order, plus an optional failure injected at
/// the n-th call. Shared by the `wal_segments` and (from B2) `wal_write` suites.
pub const RecordingIo = struct {
    events: std.ArrayListUnmanaged(WalIoEvent) = .empty,
    alloc: std.mem.Allocator,
    /// Index of the call that fails, or null. Counted over ALL calls.
    fail_at: ?usize = null,
    calls: usize = 0,

    pub fn init(alloc: std.mem.Allocator) RecordingIo {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *RecordingIo) void {
        self.events.deinit(self.alloc);
    }

    pub fn io(self: *RecordingIo) WalIo {
        return .{ .ctx = @ptrCast(self), .beforeFn = beforeImpl };
    }

    fn beforeImpl(ctx: *anyopaque, e: *const WalIoEvent) DbError!void {
        const self: *RecordingIo = @ptrCast(@alignCast(ctx));
        defer self.calls += 1;
        if (self.fail_at) |n| if (self.calls == n) return error.Io;
        self.events.append(self.alloc, e.*) catch return error.OutOfMemory;
    }

    /// How many events of `kind` were recorded.
    pub fn count(self: *const RecordingIo, kind: WalOpKind) usize {
        var n: usize = 0;
        for (self.events.items) |e| {
            if (e.kind == kind) n += 1;
        }
        return n;
    }

    /// The recorded kinds, in order — what an ordering assertion compares.
    pub fn kinds(self: *const RecordingIo, alloc: std.mem.Allocator) ![]WalOpKind {
        const out = try alloc.alloc(WalOpKind, self.events.items.len);
        for (self.events.items, 0..) |e, i| out[i] = e.kind;
        return out;
    }
};

test "walIoEvent is a no-op without a seam" {
    try walIoEvent(null, .dir_sync, 0, 0, 0, 0);
}

test "RecordingIo records in order and injects at the n-th call" {
    var rec = RecordingIo.init(testing.allocator);
    defer rec.deinit();
    const seam = rec.io();

    try walIoEvent(&seam, .create, 7, 0, 0, 0);
    try walIoEvent(&seam, .seg_header, 7, 0, 36, 0);
    try testing.expectEqual(@as(usize, 2), rec.events.items.len);
    try testing.expectEqual(WalOpKind.create, rec.events.items[0].kind);
    try testing.expectEqual(@as(i64, 7), rec.events.items[1].seq);
    try testing.expectEqual(@as(u64, 36), rec.events.items[1].len);
    try testing.expectEqual(@as(usize, 1), rec.count(.create));

    rec.fail_at = rec.calls; // the very next call
    try testing.expectError(error.Io, walIoEvent(&seam, .force_full, 7, 36, 0, 0));
    // A failed call is NOT recorded: the operation it precedes never ran.
    try testing.expectEqual(@as(usize, 2), rec.events.items.len);
    try walIoEvent(&seam, .dir_sync, 0, 0, 0, 0);
    try testing.expectEqual(@as(usize, 3), rec.events.items.len);
}
