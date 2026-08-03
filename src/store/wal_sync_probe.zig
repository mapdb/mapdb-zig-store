//! The gate's **real-syscall probe** — run under `strace` by `ci/check.sh`.
//!
//! The writer's W1/W3 durability claims are stated over seam EVENTS, and the
//! unit suite observes those; but an event is declared intent, not evidence
//! that the syscall behind it still happens. This probe is the discriminator:
//! it drives a fixed scenario through the section writer and the gate counts
//! the actual `fdatasync`/`fsync` calls the kernel saw. A mutant that deletes
//! either sync, or swaps one flavour for the other, changes the counts and
//! fails the gate — which no assertion inside the process can do.
//!
//! The scenario is exact, so the expected counts are too (they are pinned in
//! `ci/check.sh`, with the arithmetic in a comment there):
//!
//!   1. open a fresh namespace and create segment 1
//!   2. three appends that do not roll over  → 3× fdatasync, nothing else
//!   3. one append with the limit at 1 byte  → the rollover seal's fsync, the
//!      successor create's fsync + directory fsync, then the section's
//!      fdatasync
//!   4. close
//!
//! `fdatasync` is called by NOTHING but the writer's data force, so its count
//! equals the number of appends; every full force in the scenario is an fsync.

const std = @import("std");
const mapdb = @import("mapdb_zig_store");

const ws = mapdb.store.wal_segments;
const ww = mapdb.store.wal_write;
const TAG_SECTION = mapdb.store.wal_recover.TAG_SECTION;

const Ctx = struct { body: []const u8 };

fn emitBody(ctx: *const Ctx, sink: *ww.BodySink) mapdb.DbError!void {
    return sink.write(ctx.body);
}

fn append(set: *ws.WalSegmentSet, segment_bytes: u64, lsn: i64, alloc: std.mem.Allocator) !void {
    // The body is opaque: nothing recovers this image, the probe only counts
    // syscalls.
    const ctx = Ctx{ .body = "probe" };
    try ww.appendSection(set, segment_bytes, null, TAG_SECTION, lsn, alloc, &ctx, emitBody);
}

pub fn main() !void {
    const alloc = std.heap.page_allocator;
    const dir = try std.fmt.allocPrint(alloc, "/tmp/mapdb5_syncprobe_{d}", .{std.os.linux.getpid()});
    defer alloc.free(dir);
    std.fs.cwd().deleteTree(dir) catch {};
    try std.fs.cwd().makePath(dir);
    defer std.fs.cwd().deleteTree(dir) catch {};
    const base = try std.fmt.allocPrint(alloc, "{s}/store.db", .{dir});
    defer alloc.free(base);

    var set = try ws.WalSegmentSet.open(alloc, base, false);
    defer set.deinit();
    _ = try set.createSegment(1);

    var lsn: i64 = 1;
    while (lsn <= 3) : (lsn += 1) try append(&set, 1 << 20, lsn, alloc);
    try append(&set, 1, 4, alloc);
}
