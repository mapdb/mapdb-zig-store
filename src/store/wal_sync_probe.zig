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
//!   4. one `'K'` mark append              → 1× fdatasync
//!   5. close
//!
//! Step 4 exists because the mark's force is W5's whole content and a
//! TAG-conditional skip of it is invisible to a section-only scenario: the
//! B3 review ran exactly that mutant (`if (tag != 'K') forceData`) and the
//! prior scenario passed. With a mark in the trace, deleting the `'K'` force
//! changes the kernel-observed counts and fails the gate.
//!
//! `fdatasync` is called by NOTHING but the writer's data force, so its count
//! equals the number of appends (marks included); every full force in the
//! scenario is an fsync.

const std = @import("std");
const mapdb = @import("mapdb_zig_store");

const ws = mapdb.store.wal_segments;
const ww = mapdb.store.wal_write;
const wr = mapdb.store.wal_recover;
const TAG_SECTION = wr.TAG_SECTION;

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

fn appendMark(set: *ws.WalSegmentSet, lsn: i64, alloc: std.mem.Allocator) !void {
    // A genuine mark body, exactly as the cleaner writes one (its content is
    // irrelevant to the syscall counts; its TAG is the point).
    const body = wr.buildMarkBody(1, lsn);
    const ctx = Ctx{ .body = &body };
    try ww.appendSection(set, 1 << 20, null, wr.TAG_MARK, lsn, alloc, &ctx, emitBody);
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
    try appendMark(&set, 5, alloc);
}
