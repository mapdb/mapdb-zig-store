//! StoreWAL public-surface tests, ported from
//! `mapdb-rust-store/tests/store_wal.rs` (the black-box suite) and the
//! non-cleaner half of `wal.rs`'s in-module seam tests: D1's legacy boundary,
//! commit durability across reopen, multi-section replay, delete/append
//! replay, rollback, torn-tail truncation vs mid-log corruption, rollover,
//! the store lock, close linearization and D2's delete-on-close, the
//! zero-length/refused append no-ops, D8's config surface, W9 fail-closed
//! through the event seam, and the zig-only crash shapes (allocator failure
//! at every index, a partial raw write). The inner StoreDirect is heap-backed,
//! so *all* durability is carried by the segment namespace.
//!
//! Byte-level codec and recovery tests live with their owning modules
//! (`wal_recover_test.zig`, `wal_write_test.zig`); two of rust's in-module
//! tests (pass divergence refused before the force; the two passes produce
//! the length and CRC the reader verifies) are already pinned there and are
//! deliberately not re-ported here.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const iv = @import("index_val.zig");
const mod = @import("mod.zig");
const wal = @import("wal.zig");
const StoreWAL = wal.StoreWAL;
const segments = @import("wal_segments.zig");
const SEG_HDR = segments.SEG_HDR;
const wr = @import("wal_recover.zig");
const SEC_HDR = wr.SEC_HDR;
const wal_io = @import("wal_io.zig");
const RecordingIo = wal_io.RecordingIo;
const WalOpKind = wal_io.WalOpKind;
const wal_write = @import("wal_write.zig");
const FailingAllocator = @import("wal_recover_test.zig").FailingAllocator;
const sers = @import("../ser/serializers.zig");
const LongSer = sers.LongSer;

const L = LongSer.instance;

// ---------------------------------------------------------------- fixtures

/// Raw-bytes serializer: content == value, so large/linked records round-trip
/// byte-exactly through the log.
const RawSer = struct {
    pub const Elem = []const u8;
    pub const instance: RawSer = .{};
    pub fn serialize(_: RawSer, out: *DataOutput2, v: []const u8) DbError!void {
        try out.writeAll(v);
    }
    pub fn deserialize(_: RawSer, alloc: Allocator, input: *DataInput2, size: ?usize) DbError![]const u8 {
        const n = size orelse return error.DataCorruption;
        const b = try alloc.alloc(u8, n);
        errdefer alloc.free(b);
        try input.readFully(b);
        return b;
    }
    pub fn cloneElem(_: RawSer, alloc: Allocator, v: []const u8) DbError![]const u8 {
        return alloc.dupe(u8, v);
    }
    pub fn deinitElem(_: RawSer, alloc: Allocator, v: []const u8) void {
        alloc.free(v);
    }
    pub fn equals(_: RawSer, a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
    pub fn compare(_: RawSer, a: []const u8, b: []const u8) std.math.Order {
        return std.mem.order(u8, a, b);
    }
    pub fn fixedSize(_: @This()) ?usize {
        return null;
    }
    pub fn equalsBySerializedBytes(_: @This()) bool {
        return true;
    }
};
const R = RawSer.instance;

/// Deterministic LCG-filled buffer (owned; caller frees). Matches rust `bytes`.
fn bytes(alloc: Allocator, seed: u64, len: usize) ![]u8 {
    var x = seed *% 0x9E37_79B9_7F4A_7C15 +% 1;
    const out = try alloc.alloc(u8, len);
    for (out) |*b| {
        x = x *% 6364136223846793005 +% 1442695040888963407;
        b.* = @truncate(x >> 33);
    }
    return out;
}

var scratch_n: std.atomic.Value(u64) = .init(0);

/// A unique scratch dir with a base path inside it. Absolute, so segment
/// paths survive any cwd games.
const Scratch = struct {
    alloc: Allocator,
    dir: []u8,
    base: []u8,

    fn init(alloc: Allocator, tag: []const u8) !Scratch {
        const n = scratch_n.fetchAdd(1, .monotonic);
        const dir = try std.fmt.allocPrint(
            alloc,
            "/tmp/mapdb5_storewal_{d}_{s}_{d}",
            .{ std.os.linux.getpid(), tag, n },
        );
        errdefer alloc.free(dir);
        std.fs.cwd().deleteTree(dir) catch {};
        try std.fs.cwd().makePath(dir);
        const base = try std.fmt.allocPrint(alloc, "{s}/store.db", .{dir});
        return .{ .alloc = alloc, .dir = dir, .base = base };
    }

    fn deinit(self: *Scratch) void {
        std.fs.cwd().deleteTree(self.dir) catch {};
        self.alloc.free(self.base);
        self.alloc.free(self.dir);
    }

    /// `<base>.wal.<16 hex>` for `seq` (owned; caller frees).
    fn segPath(self: *const Scratch, seq: i64) ![]u8 {
        return std.fmt.allocPrint(self.alloc, "{s}.wal.{x:0>16}", .{ self.base, @as(u64, @intCast(seq)) });
    }

    /// Names in the scratch dir, sorted (owned; caller frees each + slice).
    fn dirNames(self: *const Scratch, alloc: Allocator) ![][]u8 {
        var d = try std.fs.cwd().openDir(self.dir, .{ .iterate = true });
        defer d.close();
        var out: std.ArrayListUnmanaged([]u8) = .empty;
        errdefer {
            for (out.items) |s| alloc.free(s);
            out.deinit(alloc);
        }
        var it = d.iterate();
        while (try it.next()) |e| try out.append(alloc, try alloc.dupe(u8, e.name));
        std.mem.sort([]u8, out.items, {}, struct {
            fn lt(_: void, a: []u8, b: []u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lt);
        return out.toOwnedSlice(alloc);
    }
};

fn freeNames(alloc: Allocator, names: [][]u8) void {
    for (names) |s| alloc.free(s);
    alloc.free(names);
}

fn pathExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn fileLen(path: []const u8) !u64 {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    return (try f.stat()).size;
}

fn getLong(s: *StoreWAL, alloc: Allocator, recid: u64) !?i64 {
    return s.get(i64, alloc, recid, L);
}

fn getRaw(s: *StoreWAL, alloc: Allocator, recid: u64) !?[]const u8 {
    return s.get([]const u8, alloc, recid, R);
}

fn putLong(s: *StoreWAL, alloc: Allocator, v: i64) !u64 {
    return s.put(i64, alloc, v, L);
}

/// The number of live segments and their total on-device bytes.
fn segCount(sc: *const Scratch) !usize {
    const names = try sc.dirNames(sc.alloc);
    defer freeNames(sc.alloc, names);
    var n: usize = 0;
    for (names) |name| {
        if (std.mem.indexOf(u8, name, ".wal.") != null) n += 1;
    }
    return n;
}

/// The smallest legal segment size — one segment header plus one section
/// header, the floor D8's config surface enforces.
const TINY: u64 = SEG_HDR + SEC_HDR;

// ------------------------------------------------------------- D1: legacy

test "wal3 D1: a v1 artifact at any of the three names refuses the open and is not touched" {
    const a = testing.allocator;
    // (suffix, bytes) — content is irrelevant: the rows are name+kind tests,
    // because headerless legacy files have no magic to sniff.
    const rows = [_][]const u8{ ".wal", "", ".ckpt" };
    for (rows) |suffix| {
        var sc = try Scratch.init(a, "d1");
        defer sc.deinit();
        const artifact = try std.fmt.allocPrint(a, "{s}{s}", .{ sc.base, suffix });
        defer a.free(artifact);
        const payload = "v1 bytes, precious";
        try std.fs.cwd().writeFile(.{ .sub_path = artifact, .data = payload });

        try testing.expectError(error.DataCorruption, StoreWAL.open(a, sc.base, true));

        // Refused, DELETED NOTHING, and created no v3 segment.
        const f = try std.fs.cwd().openFile(artifact, .{});
        defer f.close();
        var buf: [64]u8 = undefined;
        const n = try f.readAll(&buf);
        try testing.expectEqualStrings(payload, buf[0..n]);
        try testing.expectEqual(@as(usize, 0), try segCount(&sc));
    }
}

test "wal3 D1: a directory or symlink at a legacy name is not a legacy artifact" {
    const a = testing.allocator;
    // Both regular-file rows (`<base>.wal` and bare `<base>`) are no-follow
    // REGULAR-FILE tests: a directory is an ordinary acceptable layout (the
    // namespace lives in `<base>.wal.<hex>` sibling names), and a symlink —
    // even one pointing at a regular file — is not a legacy log either.
    const Kind = enum { dir, symlink };
    for ([_][]const u8{ ".wal", "" }) |suffix| {
        for ([_]Kind{ .dir, .symlink }) |kind| {
            var sc = try Scratch.init(a, "d1dir");
            defer sc.deinit();
            const at = try std.fmt.allocPrint(a, "{s}{s}", .{ sc.base, suffix });
            defer a.free(at);
            switch (kind) {
                .dir => try std.fs.cwd().makePath(at),
                .symlink => {
                    const target = try std.fmt.allocPrint(a, "{s}/target.file", .{sc.dir});
                    defer a.free(target);
                    try std.fs.cwd().writeFile(.{ .sub_path = target, .data = "regular" });
                    try std.fs.cwd().symLink("target.file", at, .{});
                },
            }
            var s = try StoreWAL.open(a, sc.base, true);
            _ = try putLong(&s, a, 1);
            try s.commit();
            try s.close();
            s.deinit();
        }
    }
}

test "wal3 D1: anything at all at the ckpt name refuses (existence sentinel, not a file test)" {
    const a = testing.allocator;
    const Kind = enum { file, dir, symlink };
    for ([_]Kind{ .file, .dir, .symlink }) |kind| {
        var sc = try Scratch.init(a, "d1ck");
        defer sc.deinit();
        const ck = try std.fmt.allocPrint(a, "{s}.ckpt", .{sc.base});
        defer a.free(ck);
        switch (kind) {
            .file => try std.fs.cwd().writeFile(.{ .sub_path = ck, .data = "x" }),
            .dir => try std.fs.cwd().makePath(ck),
            // Dangling target on purpose: `.ckpt` is an EXISTENCE sentinel
            // (the one recoverable v1 copy may be BEHIND the link), so even a
            // link to nowhere must refuse.
            .symlink => try std.fs.cwd().symLink("does-not-exist", ck, .{}),
        }
        try testing.expectError(error.DataCorruption, StoreWAL.open(a, sc.base, true));
        try testing.expectEqual(@as(usize, 0), try segCount(&sc));
    }
}

// ---------------------------------------------------------- durability

test "wal3: a fresh store creates one segment at sequence one" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "fresh");
    defer sc.deinit();
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    const seg1 = try sc.segPath(1);
    defer a.free(seg1);
    try testing.expect(pathExists(seg1));
    try testing.expectEqual(@as(u64, SEG_HDR), try fileLen(seg1));
    try testing.expectEqual(@as(i64, 1), s.nextLsn());
    const seqs = try s.segmentSeqs(a);
    defer a.free(seqs);
    try testing.expectEqualSlices(i64, &.{1}, seqs);
}

test "wal3: committed state survives reopen, uncommitted is lost" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "reopen");
    defer sc.deinit();
    var committed: u64 = 0;
    var lost: u64 = 0;
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        committed = try putLong(&s, a, 41);
        try s.commit();
        try s.update(i64, a, committed, 42, L);
        try s.commit();
        lost = try putLong(&s, a, 7); // staged, never committed
        try s.close();
    }
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        try testing.expectEqual(@as(?i64, 42), try getLong(&s, a, committed));
        try testing.expectError(error.GetVoid, getLong(&s, a, lost));
        try s.verify();
    }
}

test "wal3: multi-section replay and last-write-wins" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "multi");
    defer sc.deinit();
    var r1: u64 = 0;
    var r2: u64 = 0;
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        r1 = try putLong(&s, a, 1);
        r2 = try putLong(&s, a, 2);
        try s.commit();
        try s.update(i64, a, r1, 11, L);
        try s.commit();
        try s.update(i64, a, r1, 111, L);
        try s.update(i64, a, r2, 222, L);
        try s.commit();
    }
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    try testing.expectEqual(@as(?i64, 111), try getLong(&s, a, r1));
    try testing.expectEqual(@as(?i64, 222), try getLong(&s, a, r2));
}

test "wal3: delete, explicit null and prealloc replay" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "shapes");
    defer sc.deinit();
    var dead: u64 = 0;
    var nulled: u64 = 0;
    var pre: u64 = 0;
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        dead = try putLong(&s, a, 1);
        nulled = try putLong(&s, a, 2);
        try s.commit();
        try s.delete(dead);
        try s.update(i64, a, nulled, null, L);
        pre = try s.preallocate();
        try s.commit();
    }
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    try testing.expectError(error.GetVoid, getLong(&s, a, dead));
    try testing.expectEqual(@as(?i64, null), try getLong(&s, a, nulled));
    // The preallocated recid is durable and writable after reopen.
    try s.update(i64, a, pre, 9, L);
    try s.commit();
    try testing.expectEqual(@as(?i64, 9), try getLong(&s, a, pre));
}

test "wal3: an append replays across a segment boundary" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "xseg");
    defer sc.deinit();
    var rec: u64 = 0;
    {
        var s = try StoreWAL.openSegmentBytes(a, sc.base, TINY);
        defer s.deinit();
        rec = try s.put([]const u8, a, "base", R);
        try s.commit();
        // Each commit lands in its own tiny segment; the delta cites a base
        // in a STRICTLY earlier one.
        try testing.expectEqual(AppendNewSize(9), try s.append(rec, "-tail"));
        try s.commit();
    }
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    const got = (try getRaw(&s, a, rec)).?;
    defer a.free(@constCast(got));
    try testing.expectEqualStrings("base-tail", got);
}

/// `AppendResult.new_size` shorthand — the staged size after the append.
fn AppendNewSize(n: usize) mod.AppendResult {
    return .{ .new_size = n };
}

test "wal3: a linked oversize record replays" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "linked");
    defer sc.deinit();
    const big = try bytes(a, 5, @as(usize, iv.MAX_CAPACITY) + 4096);
    defer a.free(big);
    var rec: u64 = 0;
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        rec = try s.put([]const u8, a, big, R);
        try s.commit();
    }
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    const got = (try getRaw(&s, a, rec)).?;
    defer a.free(@constCast(got));
    try testing.expectEqualSlices(u8, big, got);
}

test "wal3: rollback discards staged, keeps committed, and burns no LSN" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "rollback");
    defer sc.deinit();
    var keep: u64 = 0;
    var rolled: u64 = 0;
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        keep = try putLong(&s, a, 5);
        try s.commit();
        const before = s.nextLsn();
        rolled = try putLong(&s, a, 6);
        try s.update(i64, a, keep, 55, L);
        try s.rollback();
        // Rollback writes NOTHING: the reservation never advanced anything.
        try testing.expectEqual(before, s.nextLsn());
        try testing.expectEqual(@as(?i64, 5), try getLong(&s, a, keep));
        try testing.expectError(error.GetVoid, getLong(&s, a, rolled));
    }
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    try testing.expectEqual(@as(?i64, 5), try getLong(&s, a, keep));
    try testing.expectError(error.GetVoid, getLong(&s, a, rolled));
}

test "wal3: an empty commit writes nothing and burns no LSN" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "emptyc");
    defer sc.deinit();
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    const lsn = s.nextLsn();
    const len0 = try s.logBytes();
    try s.commit();
    try testing.expectEqual(lsn, s.nextLsn());
    try testing.expectEqual(len0, try s.logBytes());
}

// ------------------------------------------------------------- rollover

test "wal3: the log rolls over at the segment threshold" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "roll");
    defer sc.deinit();
    var s = try StoreWAL.openSegmentBytes(a, sc.base, 512);
    defer s.deinit();
    var recs: [8]u64 = undefined;
    for (&recs, 0..) |*r, i| {
        const payload = try bytes(a, i, 200);
        defer a.free(payload);
        r.* = try s.put([]const u8, a, payload, R);
        try s.commit();
    }
    const seqs = try s.segmentSeqs(a);
    defer a.free(seqs);
    try testing.expect(seqs.len >= 2);
    for (seqs[1..], 1..) |q, i| try testing.expect(q > seqs[i - 1]);
    // O(1) descriptors: the steady state holds at most the active segment open.
    try testing.expect(s.openSegmentFiles() <= 1);
    // Every sealed segment ends exactly at a section boundary (W3): nonzero,
    // and recovery accepts the image whole.
    try s.close();
    var s2 = try StoreWAL.open(a, sc.base, true);
    defer s2.deinit();
    for (recs, 0..) |r, i| {
        const want = try bytes(a, i, 200);
        defer a.free(want);
        const got = (try getRaw(&s2, a, r)).?;
        defer a.free(@constCast(got));
        try testing.expectEqualSlices(u8, want, got);
    }
}

test "wal3: a section larger than a segment gets a segment of its own" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "ownseg");
    defer sc.deinit();
    var s = try StoreWAL.openSegmentBytes(a, sc.base, TINY);
    defer s.deinit();
    const big = try bytes(a, 9, 4096);
    defer a.free(big);
    const r1 = try s.put([]const u8, a, big, R);
    try s.commit();
    const r2 = try putLong(&s, a, 2);
    try s.commit();
    try s.close();
    var s2 = try StoreWAL.open(a, sc.base, true);
    defer s2.deinit();
    const got = (try getRaw(&s2, a, r1)).?;
    defer a.free(@constCast(got));
    try testing.expectEqualSlices(u8, big, got);
    try testing.expectEqual(@as(?i64, 2), try getLong(&s2, a, r2));
}

test "wal3 D8: a segment size below the minimum is refused, at open and at the setter" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "floor");
    defer sc.deinit();
    try testing.expectError(error.WrongConfiguration, StoreWAL.openSegmentBytes(a, sc.base, TINY - 1));
    // The refusal fired before ANY namespace I/O: no segment, no lock file.
    const names = try sc.dirNames(a);
    defer freeNames(a, names);
    try testing.expectEqual(@as(usize, 0), names.len);
    var s = try StoreWAL.openSegmentBytes(a, sc.base, TINY);
    defer s.deinit();
    try testing.expectError(error.WrongConfiguration, s.setSegmentBytes(TINY - 1));
    try s.setSegmentBytes(TINY);
}

test "wal3 D8: set_segment_bytes rolls the writer over at the new size" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "setseg");
    defer sc.deinit();
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    // At the 64 MiB default nothing here would ever roll.
    try s.setSegmentBytes(TINY);
    _ = try putLong(&s, a, 1);
    try s.commit();
    _ = try putLong(&s, a, 2);
    try s.commit();
    const seqs = try s.segmentSeqs(a);
    defer a.free(seqs);
    try testing.expect(seqs.len >= 2);
}

// ------------------------------------------------------------ store lock

test "wal3: a second open of the same store is refused and close releases it" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "lock");
    defer sc.deinit();
    var s = try StoreWAL.open(a, sc.base, true);
    try testing.expectError(error.Locked, StoreWAL.open(a, sc.base, true));
    try s.close();
    s.deinit();
    var s2 = try StoreWAL.open(a, sc.base, true);
    s2.deinit();
}

// ------------------------------------------------------------- lifecycle

test "wal3: ops after close return StoreClosed; double close is a no-op" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "closed");
    defer sc.deinit();
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    const rec = try putLong(&s, a, 1);
    try s.commit();
    try s.close();
    try s.close(); // double close is ok
    try testing.expectError(error.StoreClosed, putLong(&s, a, 2));
    try testing.expectError(error.StoreClosed, s.update(i64, a, rec, 3, L));
    try testing.expectError(error.StoreClosed, s.delete(rec));
    try testing.expectError(error.StoreClosed, s.commit());
    try testing.expectError(error.StoreClosed, s.rollback());
    try testing.expectError(error.StoreClosed, s.preallocate());
    try testing.expectError(error.StoreClosed, s.append(rec, "x"));
    try testing.expectError(error.StoreClosed, getLong(&s, a, rec));
    try testing.expectError(error.StoreClosed, s.capacityRemaining(rec));
    try testing.expectError(error.StoreClosed, s.verify());
    try testing.expectError(error.StoreClosed, s.getAllRecids(a));
    try testing.expectError(error.StoreClosed, s.logBytes());
    // `segs.close` cleared the segment list: an ungated answer here would be
    // an allocated EMPTY namespace, which is a lie, not a snapshot.
    try testing.expectError(error.StoreClosed, s.segmentSeqs(a));
    try testing.expect(s.isClosed());
}

test "wal3 D2: delete on close removes the whole namespace and nothing else" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "d2");
    defer sc.deinit();
    // An unrelated file and a foreign segment-shaped name (uppercase hex is
    // NOT this namespace) must survive.
    const foreign = try std.fmt.allocPrint(a, "{s}.wal.00000000000000AB", .{sc.base});
    defer a.free(foreign);
    try std.fs.cwd().writeFile(.{ .sub_path = foreign, .data = "not ours" });
    const unrelated = try std.fmt.allocPrint(a, "{s}/other.txt", .{sc.dir});
    defer a.free(unrelated);
    try std.fs.cwd().writeFile(.{ .sub_path = unrelated, .data = "keep" });

    var s = try StoreWAL.openSegmentBytes(a, sc.base, TINY);
    defer s.deinit();
    _ = try putLong(&s, a, 1);
    try s.commit();
    _ = try putLong(&s, a, 2);
    try s.commit();
    s.setDeleteOnClose(true);
    try s.close();

    const names = try sc.dirNames(a);
    defer freeNames(a, names);
    // Exactly the survivors: no segments of OUR grammar, no `.lock`.
    try testing.expectEqual(@as(usize, 2), names.len);
    for (names) |name| {
        try testing.expect(std.mem.endsWith(u8, foreign, name) or std.mem.eql(u8, name, "other.txt"));
    }
}

test "wal3 D2: a read-only handle never deletes, whatever the flag says" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "d2ro");
    defer sc.deinit();
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        _ = try putLong(&s, a, 1);
        try s.commit();
    }
    var s = try StoreWAL.openCfg(a, sc.base, .{ .read_only = true });
    defer s.deinit();
    s.setDeleteOnClose(true);
    try s.close();
    try testing.expectEqual(@as(usize, 1), try segCount(&sc));
}

// ---------------------------------------------------------- torn vs midlog

/// Truncates the segment at `seq` to `len` bytes.
fn truncateSeg(sc: *const Scratch, seq: i64, len: u64) !void {
    const p = try sc.segPath(seq);
    defer sc.alloc.free(p);
    const f = try std.fs.cwd().openFile(p, .{ .mode = .read_write });
    defer f.close();
    try f.setEndPos(len);
}

/// Flips one byte of the segment at `seq`, at `off`.
fn flipByte(sc: *const Scratch, seq: i64, off: u64) !void {
    const p = try sc.segPath(seq);
    defer sc.alloc.free(p);
    const f = try std.fs.cwd().openFile(p, .{ .mode = .read_write });
    defer f.close();
    var b: [1]u8 = undefined;
    _ = try f.preadAll(&b, off);
    b[0] ^= 0xFF;
    try f.pwriteAll(&b, off);
}

test "wal3: a torn tail is truncated, not fatal — mid-body and mid-header" {
    const a = testing.allocator;
    // Cut the ACTIVE segment's last section mid-body, then mid-header.
    for ([_]u64{ 3, SEC_HDR + 1 }) |keep_past_hdr| {
        var sc = try Scratch.init(a, "torn");
        defer sc.deinit();
        var keep: u64 = 0;
        var torn: u64 = 0;
        var second_end: u64 = 0;
        {
            var s = try StoreWAL.open(a, sc.base, true);
            defer s.deinit();
            keep = try putLong(&s, a, 1);
            try s.commit();
            second_end = try s.logBytes();
            torn = try putLong(&s, a, 2);
            try s.commit();
            try s.close();
        }
        // Cut inside the LAST section (header is SEC_HDR; keep_past_hdr < SEC_HDR
        // cuts inside the trailing section's header, more cuts into its body).
        try truncateSeg(&sc, 1, second_end + keep_past_hdr);
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        try testing.expectEqual(@as(?i64, 1), try getLong(&s, a, keep));
        try testing.expectError(error.GetVoid, getLong(&s, a, torn));
        // The tail was truncated away and the store accepts new commits.
        _ = try putLong(&s, a, 3);
        try s.commit();
    }
}

test "wal3: mid-log corruption is fatal — body and header" {
    const a = testing.allocator;
    // Flip a byte in the FIRST section while a later valid section exists:
    // in its body, then in its header.
    for ([_]bool{ true, false }) |in_body| {
        var sc = try Scratch.init(a, "midlog");
        defer sc.deinit();
        var first_end: u64 = 0;
        {
            var s = try StoreWAL.open(a, sc.base, true);
            defer s.deinit();
            _ = try putLong(&s, a, 1);
            try s.commit();
            first_end = try s.logBytes();
            _ = try putLong(&s, a, 2);
            try s.commit();
            try s.close();
        }
        const off = if (in_body) first_end - 2 else SEG_HDR + 2;
        try flipByte(&sc, 1, off);
        var d: wr.Diag = .{};
        try testing.expectError(error.DataCorruption, StoreWAL.openCfg(a, sc.base, .{ .diag = &d }));
        // The refusal carries a reason (the Diag protocol): never empty.
        try testing.expect(d.reason.len > 0);
    }
}

test "wal3: a damaged segment header below the highest name refuses the open" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "hdrlow");
    defer sc.deinit();
    {
        var s = try StoreWAL.openSegmentBytes(a, sc.base, TINY);
        defer s.deinit();
        _ = try putLong(&s, a, 1);
        try s.commit();
        _ = try putLong(&s, a, 2);
        try s.commit();
        try s.close();
    }
    try testing.expect(try segCount(&sc) >= 2);
    try flipByte(&sc, 1, 8); // inside the 36-byte segment header
    try testing.expectError(error.DataCorruption, StoreWAL.open(a, sc.base, true));
}

// ------------------------------------------------------ records and framing

test "wal3: headroom past max capacity is rejected at update and the log stays reopenable" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "headroom");
    defer sc.deinit();
    var rec: u64 = 0;
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        rec = try s.put([]const u8, a, "content", R);
        try s.commit();
        // Plain-sized content whose headroom rounds past MAX_CAPACITY refuses
        // AT UPDATE TIME (not commit time), with the transaction untouched.
        try testing.expectError(
            error.RecordTooLarge,
            s.updateWithHeadroom([]const u8, a, rec, "content", R, iv.MAX_CAPACITY),
        );
        try s.commit();
    }
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    const got = (try getRaw(&s, a, rec)).?;
    defer a.free(@constCast(got));
    try testing.expectEqualStrings("content", got);
}

test "wal3: an append that overflows the headroom clamps rather than going linked" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "clamp");
    defer sc.deinit();
    // Staged base + headroom that still fits, then an append that pushes the
    // merged content to the plain maximum: the headroom now overflows the
    // ceiling, and the capacity CLAMPS to MAX_CAPACITY (the content itself
    // fits), keeping the record plain with an exact capacity — falling to 0
    // would acknowledge a commit the decoder rejects as garbage capacity.
    const tail_len: usize = 100;
    const base_len: usize = iv.MAX_CAPACITY - 4 - tail_len;
    const base = try bytes(a, 3, base_len);
    defer a.free(base);
    const tail = try bytes(a, 4, tail_len);
    defer a.free(tail);
    var rec: u64 = 0;
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        rec = try s.put([]const u8, a, base, R);
        try s.updateWithHeadroom([]const u8, a, rec, base, R, 64);
        try testing.expectEqual(AppendNewSize(base_len + tail_len), try s.append(rec, tail));
        try s.commit();
        // Exactly full: plain with capacity MAX_CAPACITY, zero headroom left.
        try testing.expectEqual(@as(usize, 0), try s.capacityRemaining(rec));
    }
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    const got = (try getRaw(&s, a, rec)).?;
    defer a.free(@constCast(got));
    try testing.expectEqual(base_len + tail_len, got.len);
    try testing.expectEqualSlices(u8, tail, got[base_len..]);
    try testing.expectEqual(@as(usize, 0), try s.capacityRemaining(rec));
}

test "wal3: a refused append stages nothing" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "refused");
    defer sc.deinit();
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    const rec = try s.put([]const u8, a, "tiny", R);
    try s.commit();
    const cap_rem = try s.capacityRemaining(rec);
    const too_big = try bytes(a, 6, cap_rem + 1);
    defer a.free(too_big);
    const lsn = s.nextLsn();
    try testing.expectEqual(mod.AppendResult.refused, try s.append(rec, too_big));
    // REFUSED is a no-op: nothing staged, so the commit writes nothing — the
    // empty `Staged` the refusal used to leave behind classified as
    // T_PREALLOC over a content-live record, which §4.2 rejects on replay.
    try s.commit();
    try testing.expectEqual(lsn, s.nextLsn());
}

test "wal3: a zero-length append is a no-op on every record shape" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "zlen");
    defer sc.deinit();
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();

    // Committed plain record.
    const plain = try s.put([]const u8, a, "abcd", R);
    // Committed LINKED record — the shape whose zero-length append v1-style
    // staging turned into a post-durability refusal that failed the store.
    const big = try bytes(a, 7, @as(usize, iv.MAX_CAPACITY) + 4096);
    defer a.free(big);
    const linked = try s.put([]const u8, a, big, R);
    try s.commit();

    const lsn = s.nextLsn();
    try testing.expectEqual(AppendNewSize(4), try s.append(plain, ""));
    try testing.expectEqual(AppendNewSize(big.len), try s.append(linked, ""));
    try s.commit();
    // No section was written for either: the no-op staged nothing.
    try testing.expectEqual(lsn, s.nextLsn());
    try testing.expect(!s.isClosed());

    // Fresh preallocation: the zero-length append must not reclassify it as
    // content-bearing; the commit logs it as the prealloc it is.
    const pre = try s.preallocate();
    try testing.expectEqual(AppendNewSize(0), try s.append(pre, ""));
    try s.commit();
    try s.close();
    var s2 = try StoreWAL.open(a, sc.base, true);
    defer s2.deinit();
    // Still preallocated (writable, no content), and the others intact.
    try s2.update(i64, a, pre, 5, L);
    try s2.commit();
    try testing.expectEqual(@as(?i64, 5), try getLong(&s2, a, pre));

    // Staged-deleted recid: the validation half still fires.
    const doomed = try putLong(&s2, a, 1);
    try s2.commit();
    try s2.delete(doomed);
    try testing.expectError(error.GetVoid, s2.append(doomed, ""));
}

test "wal3: a zero-length append on an already staged record keeps the staging" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "zkeep");
    defer sc.deinit();
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    const rec = try s.put([]const u8, a, "base", R);
    try s.commit();
    try testing.expectEqual(AppendNewSize(6), try s.append(rec, "-x"));
    // The zero-length call reports the staged size and disturbs nothing.
    try testing.expectEqual(AppendNewSize(6), try s.append(rec, ""));
    try s.commit();
    const got = (try getRaw(&s, a, rec)).?;
    defer a.free(@constCast(got));
    try testing.expectEqualStrings("base-x", got);
}

// ---------------------------------------------------------------- config

test "wal3 D8: the config setters refuse after close, but a bad argument wins" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "setters");
    defer sc.deinit();
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    try s.setMinLogBytes(1 << 20);
    try s.setSpaceAmplification(1);
    try s.close();
    try testing.expectError(error.StoreClosed, s.setMinLogBytes(1));
    try testing.expectError(error.StoreClosed, s.setSegmentBytes(TINY));
    try testing.expectError(error.StoreClosed, s.setSpaceAmplification(2));
    // Argument validation runs BEFORE the lock (Java's precedence): a bad
    // argument is refused identically on an open and on a closed store.
    try testing.expectError(error.WrongConfiguration, s.setSegmentBytes(TINY - 1));
    try testing.expectError(error.WrongConfiguration, s.setSpaceAmplification(0));
}

test "wal3: streaming replay with a tiny window" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "stream");
    defer sc.deinit();
    var recs: [3]u64 = undefined;
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        for (&recs, 0..) |*r, i| {
            const payload = try bytes(a, i + 20, 300 + i * 100);
            defer a.free(payload);
            r.* = try s.put([]const u8, a, payload, R);
            try s.commit();
        }
    }
    // An 8-byte window forces a refill edge inside every header and body.
    var s = try StoreWAL.openWith(a, sc.base, true, 8);
    defer s.deinit();
    for (recs, 0..) |r, i| {
        const want = try bytes(a, i + 20, 300 + i * 100);
        defer a.free(want);
        const got = (try getRaw(&s, a, r)).?;
        defer a.free(@constCast(got));
        try testing.expectEqualSlices(u8, want, got);
    }
}

test "wal3: a body larger than the writer's buffer is streamed whole" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "bigbody");
    defer sc.deinit();
    const big = try bytes(a, 8, (64 << 10) + 4097); // past SINK_BUF
    defer a.free(big);
    var rec: u64 = 0;
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        rec = try s.put([]const u8, a, big, R);
        try s.commit();
    }
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    const got = (try getRaw(&s, a, rec)).?;
    defer a.free(@constCast(got));
    try testing.expectEqualSlices(u8, big, got);
}

// ------------------------------------------------------------ the seam (W)

/// Open a store with a seam installed; the caller owns the seam's lifetime
/// (it must outlive the store — the installer's obligation the seam type
/// documents).
fn openTraced(a: Allocator, base: []const u8, seam: *const wal_io.WalIo, segment_bytes: u64) !StoreWAL {
    return StoreWAL.openCfg(a, base, .{ .segment_bytes = segment_bytes, .io = seam });
}

/// The recorded kinds from `from` on (owned; caller frees).
fn kindsFrom(rec: *const RecordingIo, a: Allocator, from: usize) ![]WalOpKind {
    const out = try a.alloc(WalOpKind, rec.events.items.len - from);
    for (rec.events.items[from..], 0..) |e, i| out[i] = e.kind;
    return out;
}

test "wal3 W1/W4: header, body, then the data force — every commit, in order" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "order");
    defer sc.deinit();
    var rec = RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    var s = try openTraced(a, sc.base, &seam, wal.DEFAULT_SEGMENT_BYTES);
    defer s.deinit();
    const mark = rec.events.items.len;
    _ = try putLong(&s, a, 1);
    try s.commit();
    _ = try putLong(&s, a, 2);
    try s.commit();
    const ks = try kindsFrom(&rec, a, mark);
    defer a.free(ks);
    try testing.expectEqualSlices(WalOpKind, &.{
        .sec_header, .sec_body, .force_data,
        .sec_header, .sec_body, .force_data,
    }, ks);
}

test "wal3 W3: a rollover seals with a full force before the successor is created" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "sealev");
    defer sc.deinit();
    var rec = RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    var s = try openTraced(a, sc.base, &seam, TINY);
    defer s.deinit();
    _ = try putLong(&s, a, 1);
    try s.commit();
    const mark = rec.events.items.len;
    _ = try putLong(&s, a, 2);
    try s.commit(); // rolls: segment 1 is past TINY
    const ks = try kindsFrom(&rec, a, mark);
    defer a.free(ks);
    // Seal (full force) strictly before the successor's create; the new
    // section lands only after the create's own durability chain.
    try testing.expectEqual(WalOpKind.force_full, ks[0]);
    const create_at = std.mem.indexOfScalar(WalOpKind, ks, .create).?;
    const hdr_at = std.mem.indexOfScalar(WalOpKind, ks, .sec_header).?;
    const dirsync_at = std.mem.indexOfScalar(WalOpKind, ks, .dir_sync).?;
    try testing.expect(create_at > 0);
    try testing.expect(dirsync_at > create_at);
    try testing.expect(hdr_at > dirsync_at);
}

test "wal3 W7: a torn tail is truncated, then forced, then rotated — observed on reopen" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "w7ev");
    defer sc.deinit();
    var end1: u64 = 0;
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        _ = try putLong(&s, a, 1);
        try s.commit();
        end1 = try s.logBytes();
        _ = try putLong(&s, a, 2);
        try s.commit();
        try s.close();
    }
    try truncateSeg(&sc, 1, end1 + 3); // torn tail in the active segment
    var rec = RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    var s = try openTraced(a, sc.base, &seam, wal.DEFAULT_SEGMENT_BYTES);
    defer s.deinit();
    const ks = try kindsFrom(&rec, a, 0);
    defer a.free(ks);
    const trunc_at = std.mem.indexOfScalar(WalOpKind, ks, .truncate).?;
    const create_at = std.mem.lastIndexOfScalar(WalOpKind, ks, .create).?;
    // W7's own force sits BETWEEN the truncate and the rotation's create —
    // the create chain then emits its own W2 full force, which is not it.
    const ff_at = trunc_at + std.mem.indexOfScalar(WalOpKind, ks[trunc_at..], .force_full).?;
    try testing.expect(trunc_at < ff_at);
    try testing.expect(ff_at < create_at);
}

test "wal3 W9: a failure at ANY seam point during commit fails the store closed, all-or-nothing" {
    const a = testing.allocator;
    // Workload: one plain commit into segment 1, then a second commit that
    // ROLLS OVER (tiny segments), so the sweep covers the seal, the create
    // chain, the section writes and both force flavours.
    var k: usize = 0;
    var swept: usize = 0;
    while (true) : (k += 1) {
        var sc = try Scratch.init(a, "w9sweep");
        defer sc.deinit();
        var rec = RecordingIo.init(a);
        defer rec.deinit();
        const seam = rec.io();
        var s = try openTraced(a, sc.base, &seam, TINY);
        var deinited = false;
        defer if (!deinited) s.deinit();
        const first = try putLong(&s, a, 1);
        try s.commit();
        const second = try putLong(&s, a, 2);
        const lsn_before = s.nextLsn();
        rec.fail_at = rec.calls + k; // the k-th seam call of THIS commit
        const res = s.commit();
        if (res) |_| {
            // Sweep exhausted: the whole commit ran without hitting the
            // injected index.
            try testing.expect(!s.isClosed());
            swept = k;
            break;
        } else |e| {
            try testing.expectEqual(error.Io, e);
            // W9, the caller's half: EVERY writer error closes the store...
            try testing.expect(s.isClosed());
            try testing.expectError(error.StoreClosed, s.commit());
            try testing.expectError(error.StoreClosed, getLong(&s, a, first));
            // ...with the store Diag carrying the static write reason, and
            // `next_lsn` NOT advanced: only a successfully forced section
            // moves it (the reservation only read it).
            try testing.expectEqual(wal.W_COMMIT_WRITE.ptr, s.lastDiag().reason.ptr);
            try testing.expectEqual(lsn_before, s.nextLsn());
        }
        s.deinit();
        deinited = true;
        // Reopen: all-or-nothing. The first commit is always there; the
        // injected one either replays whole or was truncated away.
        var s2 = try StoreWAL.open(a, sc.base, true);
        defer s2.deinit();
        try testing.expectEqual(@as(?i64, 1), try getLong(&s2, a, first));
        if (getLong(&s2, a, second)) |v| {
            try testing.expectEqual(@as(?i64, 2), v);
        } else |e| {
            try testing.expectEqual(error.GetVoid, e);
        }
        _ = try putLong(&s2, a, 3); // and the reopened store accepts writes
        try s2.commit();
    }
    try testing.expect(swept >= 6); // seal + create chain + section + force at least
}

test "wal3 W9: a PARTIAL raw write fails the store closed and reopen truncates the tear" {
    const a = testing.allocator;
    // (which pwrite of the second commit fails, bytes let through)
    const cases = [_]RecordingIo.PwriteFail{
        .{ .at = 2, .partial = 10 }, // mid-HEADER tear
        .{ .at = 3, .partial = 3 }, // mid-BODY tear (header written/visible; nothing forced yet)
    };
    for (cases) |pf| {
        var sc = try Scratch.init(a, "partial");
        defer sc.deinit();
        var rec = RecordingIo.init(a);
        defer rec.deinit();
        const seam = rec.io();
        var s = try openTraced(a, sc.base, &seam, wal.DEFAULT_SEGMENT_BYTES);
        var deinited = false;
        defer if (!deinited) s.deinit();
        const first = try putLong(&s, a, 1);
        try s.commit(); // pwrites 0 (header) and 1 (body flush)
        const second = try putLong(&s, a, 2);
        const lsn_before = s.nextLsn();
        rec.pwrite_fail = pf;
        try testing.expectError(error.Io, s.commit());
        // The shorter-retry refusal: after a partial write NOTHING can append
        // into this segment through this handle again — and the failed
        // section's reservation never advanced `next_lsn`.
        try testing.expect(s.isClosed());
        try testing.expectError(error.StoreClosed, s.commit());
        try testing.expectEqual(wal.W_COMMIT_WRITE.ptr, s.lastDiag().reason.ptr);
        try testing.expectEqual(lsn_before, s.nextLsn());
        s.deinit();
        deinited = true;
        // The partial bytes are a torn tail — the crash shape recovery
        // already classifies — so reopen truncates them away.
        var s2 = try StoreWAL.open(a, sc.base, true);
        defer s2.deinit();
        try testing.expectEqual(@as(?i64, 1), try getLong(&s2, a, first));
        try testing.expectError(error.GetVoid, getLong(&s2, a, second));
        _ = try putLong(&s2, a, 3);
        try s2.commit();
    }
}

// --------------------------------------------------- on-disk entry framing

/// Java-packLong decode: MSB-first 7-bit groups, the LAST byte has bit 7 set.
fn unpackAt(buf: []const u8, pos: *usize) u64 {
    var v: u64 = 0;
    while (true) {
        const b = buf[pos.*];
        pos.* += 1;
        v = (v << 7) | (b & 0x7F);
        if (b & 0x80 != 0) return v;
    }
}

test "wal3: an append is stamped with the LSN of the image it extends" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "stamp");
    defer sc.deinit();
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    const rec = try s.put([]const u8, a, "base", R); // section LSN 1 — the base image
    try s.commit();
    _ = try putLong(&s, a, 9); // section LSN 2 — unrelated
    try s.commit();
    try testing.expectEqual(AppendNewSize(6), try s.append(rec, "-t")); // section LSN 3
    try s.commit();
    try s.close();
    // Decode the third section's body straight off the device: the T_APPEND
    // frame must carry delta = 3 - 1 = 2, the base identity as a distance.
    const p = try sc.segPath(1);
    defer a.free(p);
    const f = try std.fs.cwd().openFile(p, .{});
    defer f.close();
    const img = try f.readToEndAlloc(a, 1 << 20);
    defer a.free(img);
    var off: usize = SEG_HDR;
    var section: usize = 0;
    while (section < 2) : (section += 1) { // skip sections at LSN 1 and 2
        const hdr = wr.parseSecHdr(img[off..][0..@as(usize, SEC_HDR)]);
        off += @as(usize, SEC_HDR) + @as(usize, @intCast(hdr.body_len));
    }
    var pos: usize = off + @as(usize, SEC_HDR); // third section's body
    try testing.expectEqual(@as(u8, 3), img[pos]); // T_APPEND
    pos += 1;
    try testing.expectEqual(rec, unpackAt(img, &pos)); // recid
    try testing.expectEqual(@as(u64, 2), unpackAt(img, &pos)); // LSN delta
    try testing.expectEqual(@as(u64, 2), unpackAt(img, &pos)); // payload len
}

test "wal3: a transaction that creates and deletes one recid logs nothing for it" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "transient");
    defer sc.deinit();
    var sec_end: u64 = 0;
    {
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        const doomed = try putLong(&s, a, 7);
        try s.delete(doomed);
        const len0 = try s.logBytes();
        try s.commit();
        // The section exists (an LSN was burnt for the transaction) but its
        // body is EMPTY: nothing about the transient recid reached the log.
        sec_end = try s.logBytes();
        try testing.expectEqual(len0 + @as(u64, SEC_HDR), sec_end);
        try testing.expectError(error.GetVoid, getLong(&s, a, doomed));
    }
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    // The preallocated recid was freed at apply: the allocator hands it out again.
    const again = try putLong(&s, a, 8);
    try s.commit();
    try testing.expectEqual(@as(?i64, 8), try getLong(&s, a, again));
}

// ------------------------------------------------------- zig crash shapes

/// Stages the OOM sweep's second commit so the post-durability apply half
/// allocates at EVERY identity site, not just in the writer half. Apply runs
/// in ascending-recid order == allocation order here, and both maps hold one
/// entry (capacity 8) from the first commit, so with 5 fresh content puts
/// first, the map GROWTH (the 7th insert, at the default load factor) lands
/// exactly inside the
/// `stateOnly` call (the prealloc) for `state_lsn` and inside the `content`
/// call (the linked put) for `content_base_lsn` — a swallowed failure at
/// either site is a swallowed real allocation, not a no-op.
fn stageOomCommit(s: *StoreWAL, alloc: Allocator, base: u64, big2: []const u8) !struct { second: u64, small: u64 } {
    var small: u64 = 0;
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const r = try s.put(i64, alloc, @as(i64, @intCast(i)), L);
        if (i == 0) small = r;
    }
    _ = try s.preallocate();
    const second = try s.put([]const u8, alloc, big2, R);
    _ = try s.append(base, "-tail");
    return .{ .second = second, .small = small };
}

test "wal3: allocator failure at EVERY index of a commit is OutOfMemory and all-or-nothing" {
    const a = testing.allocator;
    const big2 = try bytes(a, 42, @as(usize, iv.MAX_CAPACITY) + 4096);
    defer a.free(big2);
    // Counting run: how many allocations one commit costs.
    var commit_allocs: usize = 0;
    {
        var sc = try Scratch.init(a, "oomcount");
        defer sc.deinit();
        var fa = FailingAllocator{ .inner = a, .fail_at = null };
        var s = try StoreWAL.open(fa.allocator(), sc.base, true);
        defer s.deinit();
        const base = try s.put([]const u8, fa.allocator(), "base", R);
        try s.commit();
        _ = try stageOomCommit(&s, fa.allocator(), base, big2);
        const c0 = fa.calls;
        try s.commit();
        commit_allocs = fa.calls - c0;
    }
    try testing.expect(commit_allocs > 4);
    // Injected runs: the k-th allocation of the SAME commit fails, and the
    // commit MUST report exactly `OutOfMemory` — never success (a swallowed
    // failure), never another error class (risk 14: operational, NEVER
    // corruption). The workload is identical run to run, so every index is
    // genuinely reached. Reopen must show an all-or-nothing image.
    var durable_errors: usize = 0;
    var k: usize = 0;
    while (k < commit_allocs) : (k += 1) {
        var sc = try Scratch.init(a, "oomsweep");
        defer sc.deinit();
        var fa = FailingAllocator{ .inner = a, .fail_at = null };
        var s = try StoreWAL.open(fa.allocator(), sc.base, true);
        var deinited = false;
        defer if (!deinited) s.deinit();
        const base = try s.put([]const u8, fa.allocator(), "base", R);
        try s.commit();
        const staged = try stageOomCommit(&s, fa.allocator(), base, big2);
        const lsn_before = s.nextLsn();
        fa.fail_at = fa.calls + k;
        try testing.expectError(error.OutOfMemory, s.commit());
        const closed_after = s.isClosed();
        // A failure BEFORE the durability point leaves the store open with
        // the reservation unconsumed; `next_lsn` moves only on success.
        if (!closed_after) try testing.expectEqual(lsn_before, s.nextLsn());
        s.deinit();
        deinited = true;
        var s2 = try StoreWAL.open(a, sc.base, true);
        defer s2.deinit();
        // All-or-nothing, never torn, never corrupt: base always present,
        // and the second commit's effects appear together or not at all.
        const b = (try getRaw(&s2, a, base)).?;
        defer a.free(@constCast(b));
        const second_state: ?[]const u8 = s2.get([]const u8, a, staged.second, R) catch |e| blk: {
            try testing.expectEqual(error.GetVoid, e);
            break :blk null;
        };
        if (second_state) |v| {
            defer a.free(@constCast(v));
            try testing.expectEqualStrings("base-tail", b);
            try testing.expectEqualSlices(u8, big2, v);
            try testing.expectEqual(@as(?i64, 0), try getLong(&s2, a, staged.small));
            // The section was DURABLE, so the error can only have come from
            // the post-durability half — and every failure there must have
            // closed the store (memory and log had diverged).
            try testing.expect(closed_after);
            durable_errors += 1;
        } else {
            try testing.expectEqualStrings("base", b);
            try testing.expectError(error.GetVoid, getLong(&s2, a, staged.small));
        }
        _ = try putLong(&s2, a, 3);
        try s2.commit();
    }
    // The post-durability arm was actually exercised — the sweep's apply-half
    // assertions are not vacuously green.
    try testing.expect(durable_errors > 0);
}

/// The oracle rounds' canonical LSN-edge image: a LONE retained segment at
/// seq 2 whose only section is a valid `'K'` at `lsn`, its header and the
/// mark's logStart both stating `lsn` (a cleaned log whose live range starts
/// at its own mark). The frozen reference OPENS the `i64::MAX` version of
/// this, by wrapping — the ports refuse, and that divergence is Q8.
fn writeLsnEdgeImage(a: Allocator, sc: *const Scratch, lsn: i64) !void {
    var set = try segments.WalSegmentSet.open(a, sc.base, false);
    defer set.deinit();
    _ = try set.createSegment(1); // burned by the "clean": unlinked below
    _ = try set.createSegment(lsn); // seq 2, header states `lsn`
    try set.unlinkThrough(1);
    const mark = wr.buildMarkBody(1, lsn); // through seq 1 (K4: 1 < 2)
    var ctx = RawEntry{ .bytes = &mark, .alloc = a };
    try wal_write.appendSection(&set, wal.DEFAULT_SEGMENT_BYTES, null, wr.TAG_MARK, lsn, a, &ctx, emitRaw);
}

test "wal3 Q8: LSN exhaustion refuses with StoreFull, before anything is written" {
    const a = testing.allocator;
    // An image whose highest valid LSN is i64::MAX - 1 OPENS with
    // next_lsn == MAX; the next commit refuses BEFORE the write, with the
    // store open and the transaction intact.
    {
        var sc = try Scratch.init(a, "q8edge");
        defer sc.deinit();
        try writeLsnEdgeImage(a, &sc, std.math.maxInt(i64) - 1);
        var s = try StoreWAL.open(a, sc.base, true);
        defer s.deinit();
        try testing.expectEqual(std.math.maxInt(i64), s.nextLsn());
        _ = try putLong(&s, a, 1);
        const len0 = try s.logBytes();
        try testing.expectError(error.StoreFull, s.commit());
        try testing.expect(!s.isClosed());
        try testing.expectEqual(len0, try s.logBytes());
        try s.rollback();
    }
    // An image AT i64::MAX refuses the open itself (recovery's half of the
    // same ruling).
    {
        var sc = try Scratch.init(a, "q8open");
        defer sc.deinit();
        try writeLsnEdgeImage(a, &sc, std.math.maxInt(i64));
        try testing.expectError(error.StoreFull, StoreWAL.open(a, sc.base, true));
    }
}

// --------------------------------------------------- 'C'/'K' end to end

const RawEntry = struct {
    bytes: []const u8,
    alloc: Allocator,
};

/// Emits pre-framed entry bytes verbatim (both passes see the same slice).
fn emitRaw(ctx: *const RawEntry, sink: *wal_write.BodySink) DbError!void {
    try sink.write(ctx.bytes);
}

/// One T_RECORD frame for `recid` with plain-capacity `content` (owned).
fn recordFrame(a: Allocator, recid: u64, content: []const u8) ![]u8 {
    var out = DataOutput2.init(a);
    errdefer out.deinit();
    try out.writeU8(2); // T_RECORD
    try out.packLong(recid);
    try out.packLong((4 + content.len + 15) & ~@as(usize, 15)); // capacity
    try out.packLong(content.len + 1);
    try out.writeAll(content);
    return out.toOwnedSlice();
}

test "wal3: 'C' and 'K' tag semantics, end to end through the public open" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "tags");
    defer sc.deinit();
    // Author what a cleaner leaves behind, with the writer's own machinery:
    //   seg 1: 'S' at LSN 1 — recid 5 = "old" (the image the clean re-homed)
    //   seg 2: 'C' at LSN 2 — recid 5 = "new" (the re-homed image)
    //   seg 3: 'K' at LSN 3 — through seq 1, log starts at LSN 2
    {
        var set = try segments.WalSegmentSet.open(a, sc.base, false);
        defer set.deinit();
        _ = try set.createSegment(1);
        const old_frame = try recordFrame(a, 5, "old");
        defer a.free(old_frame);
        var old_ctx = RawEntry{ .bytes = old_frame, .alloc = a };
        try wal_write.appendSection(&set, TINY, null, wr.TAG_SECTION, 1, a, &old_ctx, emitRaw);
        const new_frame = try recordFrame(a, 5, "new");
        defer a.free(new_frame);
        var new_ctx = RawEntry{ .bytes = new_frame, .alloc = a };
        try wal_write.appendSection(&set, TINY, null, wr.TAG_IMAGE, 2, a, &new_ctx, emitRaw);
        const mark = wr.buildMarkBody(1, 2);
        var mark_ctx = RawEntry{ .bytes = &mark, .alloc = a };
        try wal_write.appendSection(&set, TINY, null, wr.TAG_MARK, 3, a, &mark_ctx, emitRaw);
    }
    try testing.expectEqual(@as(usize, 3), try segCount(&sc));
    // The PUBLIC open honours the mark: segment 1 (through = 1) is unlinked,
    // and the 'C' image — not the retired 'S' record — is what replay
    // installed. A store that ignored either tag returns "old", keeps three
    // segments, or refuses.
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    const seg1 = try sc.segPath(1);
    defer a.free(seg1);
    try testing.expect(!pathExists(seg1));
    const got = (try getRaw(&s, a, 5)).?;
    defer a.free(@constCast(got));
    try testing.expectEqualStrings("new", got);
    // And the recovered successor is exercised by USE: commit works on top.
    _ = try putLong(&s, a, 61);
    try s.commit();
}

// ------------------------------------------------------------- D2 failure

test "wal3 D2: delete on close refuses when it cannot read the namespace" {
    if (std.os.linux.geteuid() == 0) return; // root ignores mode bits
    const a = testing.allocator;
    var sc = try Scratch.init(a, "d2fail");
    defer sc.deinit();
    var s = try StoreWAL.open(a, sc.base, true);
    defer s.deinit();
    _ = try putLong(&s, a, 1);
    try s.commit();
    s.setDeleteOnClose(true);
    try std.posix.fchmodat(std.fs.cwd().fd, sc.dir, 0o000, 0);
    defer std.posix.fchmodat(std.fs.cwd().fd, sc.dir, 0o755, 0) catch {};
    // An unreadable directory is an ERROR, never an empty namespace: the
    // close reports it instead of "succeeding" with the segments left behind.
    try testing.expectError(error.Io, s.close());
}

test {
    std.testing.refAllDecls(@This());
}
