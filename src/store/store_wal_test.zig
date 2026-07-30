//! StoreWAL-specific tests, ported from
//! `mapdb-rust-store/tests/store_wal.rs`: commit durability across reopen (log
//! replay), multi-section replay, delete/append replay, rollback, torn-tail
//! truncation vs mid-log corruption (D4), checkpoint compaction,
//! crash-during-checkpoint temp recovery, auto-checkpoint, streaming-replay
//! refill edges, close linearization, headroom overflow. The inner StoreDirect
//! is heap-backed, so *all* durability is carried by the log file.

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
const StoreWAL = @import("wal.zig").StoreWAL;
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

/// Deterministic LCG-filled buffer (owned; caller frees). Matches Rust `bytes`.
fn bytes(alloc: Allocator, seed: u64, len: usize) ![]u8 {
    var x = seed *% 0x9E37_79B9_7F4A_7C15 +% 1;
    const out = try alloc.alloc(u8, len);
    for (out) |*b| {
        x = x *% 6364136223846793005 +% 1442695040888963407;
        b.* = @truncate(x >> 33);
    }
    return out;
}

/// A resolved absolute path inside a tmp dir (caller frees).
fn tmpPath(alloc: Allocator, tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &buf);
    return std.fs.path.join(alloc, &.{ dir, name });
}

fn ckptOf(alloc: Allocator, path: []const u8) ![]u8 {
    return std.mem.concat(alloc, u8, &.{ path, ".ckpt" });
}

fn fileLen(path: []const u8) !u64 {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();
    return (try f.stat()).size;
}

fn pathExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn getLong(s: *StoreWAL, alloc: Allocator, recid: u64) !?i64 {
    return s.get(i64, alloc, recid, L);
}

test "WAL: old framed magic is rejected without rewrite" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "old-magic.wal");
    defer a.free(p);
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        try s.close();
    }
    {
        const f = try std.fs.cwd().openFile(p, .{ .mode = .write_only });
        defer f.close();
        try f.pwriteAll("MDB5.WAL", 0);
    }
    const before = try std.fs.cwd().readFileAlloc(a, p, 1024);
    defer a.free(before);

    try testing.expectError(error.DataCorruption, StoreWAL.open(a, p, true));
    const after = try std.fs.cwd().readFileAlloc(a, p, 1024);
    defer a.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

test "WAL: valid legacy headerless WAL is migrated" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "legacy.wal");
    defer a.free(p);

    // PREALLOC recid 1, followed by the legacy COMMIT seal and the CRC32 of
    // the operation bytes. A real legacy stream therefore begins with opcode
    // 1, not an ASCII magic byte.
    var legacy = [_]u8{ 1, 0x81, 8, 0, 0, 0, 0 };
    std.mem.writeInt(u32, legacy[3..7], std.hash.crc.Crc32.hash(legacy[0..2]), .big);
    {
        const f = try std.fs.cwd().createFile(p, .{});
        defer f.close();
        try f.writeAll(&legacy);
    }

    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    try s.verify();
    try s.close();
    const migrated = try std.fs.cwd().readFileAlloc(a, p, 1024);
    defer a.free(migrated);
    try testing.expectEqualSlices(u8, "MDBS.WAL", migrated[0..8]);
}

test "WAL: one and two byte legacy tails are safe" {
    const a = testing.allocator;
    const tails = [_][]const u8{ &[_]u8{1}, &[_]u8{ 1, 0x81 } };
    const names = [_][]const u8{ "one-byte.wal", "two-byte.wal" };

    inline for (tails, names) |tail, name| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const p = try tmpPath(a, &tmp, name);
        defer a.free(p);
        {
            const f = try std.fs.cwd().createFile(p, .{});
            defer f.close();
            try f.writeAll(tail);
        }

        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        try s.verify();
        try s.close();
        const migrated = try std.fs.cwd().readFileAlloc(a, p, 1024);
        defer a.free(migrated);
        try testing.expectEqualSlices(u8, "MDBS.WAL", migrated[0..8]);
    }
}

// ---------------------------------------------------------------------------
// Durability: only committed state survives a reopen.
// ---------------------------------------------------------------------------

test "WAL: committed state survives reopen" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "a.wal");
    defer a.free(p);

    var r1: u64 = undefined;
    var r2: u64 = undefined;
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        r1 = try s.put(i64, a, @as(i64, 11), L);
        r2 = try s.put(i64, a, @as(i64, 22), L);
        try s.commit();
        try s.close();
    }
    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    try testing.expectEqual(@as(?i64, 11), try getLong(&s, a, r1));
    try testing.expectEqual(@as(?i64, 22), try getLong(&s, a, r2));
    try s.verify();
}

test "WAL: uncommitted state is lost on reopen" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "b.wal");
    defer a.free(p);

    var r: u64 = undefined;
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        r = try s.put(i64, a, @as(i64, 99), L);
        // NO commit.
        try s.close();
    }
    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    try testing.expectError(error.GetVoid, getLong(&s, a, r));
}

test "WAL: multi-section replay, last write wins" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "c.wal");
    defer a.free(p);

    var r: u64 = undefined;
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        r = try s.put(i64, a, @as(i64, 1), L);
        try s.commit();
        try s.update(i64, a, r, @as(i64, 2), L);
        try s.commit();
        try s.update(i64, a, r, @as(i64, 3), L);
        try s.commit();
        try s.close();
    }
    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    try testing.expectEqual(@as(?i64, 3), try getLong(&s, a, r));
}

test "WAL: delete and append replay" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "d.wal");
    defer a.free(p);

    const base = try bytes(a, 1, 10);
    defer a.free(base);

    var rkeep: u64 = undefined;
    var rdel: u64 = undefined;
    var rapp: u64 = undefined;
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        rkeep = try s.put(i64, a, @as(i64, 7), L);
        rdel = try s.put(i64, a, @as(i64, 8), L);
        rapp = try s.put([]const u8, a, base, R);
        try s.updateWithHeadroom([]const u8, a, rapp, base, R, 64);
        try s.commit();
        try s.delete(rdel);
        _ = try s.append(rapp, &[_]u8{ 100, 101, 102 });
        try s.commit();
        try s.close();
    }
    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    try testing.expectEqual(@as(?i64, 7), try getLong(&s, a, rkeep));
    try testing.expectError(error.GetVoid, getLong(&s, a, rdel));
    const want = try std.mem.concat(a, u8, &.{ base, &[_]u8{ 100, 101, 102 } });
    defer a.free(want);
    const got = (try s.get([]const u8, a, rapp, R)).?;
    defer a.free(got);
    try testing.expectEqualSlices(u8, want, got);
    try s.verify();
}

test "WAL: linked oversize record replays" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "e.wal");
    defer a.free(p);

    const big = try bytes(a, 42, 200_000); // forces an oversize/linked record
    defer a.free(big);
    var r: u64 = undefined;
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        r = try s.put([]const u8, a, big, R);
        try s.commit();
        try s.close();
    }
    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    const got = (try s.get([]const u8, a, r, R)).?;
    defer a.free(got);
    try testing.expectEqualSlices(u8, big, got);
    try s.verify();
}

// ---------------------------------------------------------------------------
// Rollback discards staged, keeps committed.
// ---------------------------------------------------------------------------

test "WAL: rollback discards staged, keeps committed" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "f.wal");
    defer a.free(p);

    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    const gen0 = s.structuralGeneration();
    const r = try s.put(i64, a, @as(i64, 5), L);
    try s.commit();
    try s.update(i64, a, r, @as(i64, 500), L);
    const rtmp = try s.put(i64, a, @as(i64, 123), L);
    try s.rollback();
    try testing.expectEqual(@as(?i64, 5), try getLong(&s, a, r));
    try testing.expectError(error.GetVoid, getLong(&s, a, rtmp));
    try testing.expect(s.structuralGeneration() > gen0);
    try s.verify();
}

// ---------------------------------------------------------------------------
// Torn tail (availability): a truncated final section is dropped. D4.
// ---------------------------------------------------------------------------

fn truncateFile(path: []const u8, len: u64) !void {
    const f = try std.fs.cwd().openFile(path, .{ .mode = .write_only });
    defer f.close();
    try f.setEndPos(len);
}

test "WAL: torn tail body is truncated, not fatal" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "g.wal");
    defer a.free(p);

    var r1: u64 = undefined;
    var len_after_first: u64 = undefined;
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        r1 = try s.put(i64, a, @as(i64, 1000), L);
        try s.commit();
        len_after_first = try fileLen(p);
        _ = try s.put(i64, a, @as(i64, 2000), L);
        try s.commit();
        try s.close();
    }
    try truncateFile(p, len_after_first + 1); // one byte into 2nd section body

    var r3: u64 = undefined;
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        try testing.expectEqual(@as(?i64, 1000), try getLong(&s, a, r1));
        try s.verify();
        // A subsequent commit reuses the truncated tail region and reopens cleanly.
        r3 = try s.put(i64, a, @as(i64, 3000), L);
        try s.commit();
        try s.close();
    }
    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    try testing.expectEqual(@as(?i64, 1000), try getLong(&s, a, r1));
    try testing.expectEqual(@as(?i64, 3000), try getLong(&s, a, r3));
    try s.verify();
}

test "WAL: torn tail within section header is truncated" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "h.wal");
    defer a.free(p);

    var r1: u64 = undefined;
    var len_after_first: u64 = undefined;
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        r1 = try s.put(i64, a, @as(i64, 11), L);
        try s.commit();
        len_after_first = try fileLen(p);
        _ = try s.put(i64, a, @as(i64, 22), L);
        try s.commit();
        try s.close();
    }
    try truncateFile(p, len_after_first + 5); // 5 header bytes present

    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    try testing.expectEqual(@as(?i64, 11), try getLong(&s, a, r1));
    try s.verify();
}

// ---------------------------------------------------------------------------
// Mid-log corruption (integrity): a damaged section FOLLOWED by a valid one is
// not a torn tail — reopen must refuse. D4.
// ---------------------------------------------------------------------------

fn flipByte(path: []const u8, off: u64, xor: u8) !void {
    const f = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer f.close();
    var b: [1]u8 = undefined;
    _ = try f.preadAll(&b, off);
    b[0] ^= xor;
    try f.pwriteAll(&b, off);
    try f.sync();
}

test "WAL: mid-log body corruption is fatal" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "i.wal");
    defer a.free(p);

    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        _ = try s.put(i64, a, @as(i64, 1), L);
        try s.commit();
        _ = try s.put(i64, a, @as(i64, 2), L);
        try s.commit(); // a valid section AFTER the one we corrupt
        try s.close();
    }
    // body of the first section starts at file header + section header = 16 + 25.
    try flipByte(p, 16 + 25, 0xFF);
    try testing.expectError(error.DataCorruption, StoreWAL.open(a, p, true));
}

test "WAL: mid-log header corruption is fatal" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "j.wal");
    defer a.free(p);

    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        _ = try s.put(i64, a, @as(i64, 1), L);
        try s.commit();
        _ = try s.put(i64, a, @as(i64, 2), L);
        try s.commit();
        try s.close();
    }
    // corrupt the FIRST section's tag byte (offset 16).
    try flipByte(p, 16, 0x55);
    try testing.expectError(error.DataCorruption, StoreWAL.open(a, p, true));
}

test "WAL: unsupported version is rejected" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "k.wal");
    defer a.free(p);

    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        _ = try s.put(i64, a, @as(i64, 1), L);
        try s.commit();
        try s.close();
    }
    // bump the version word (offset 8..12) to an unknown value.
    {
        const f = try std.fs.cwd().openFile(p, .{ .mode = .write_only });
        defer f.close();
        var vb: [4]u8 = undefined;
        std.mem.writeInt(i32, &vb, 99, .big);
        try f.pwriteAll(&vb, 8);
        try f.sync();
    }
    try testing.expectError(error.DataCorruption, StoreWAL.open(a, p, true));
}

test "WAL: nonzero v1 header flags are rejected without rewrite" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "badflags.wal");
    defer a.free(p);

    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        _ = try s.put(i64, a, @as(i64, 1), L);
        try s.commit();
        try s.close();
    }
    // set the low byte of the flags word (offset 12..16, big-endian) to 1.
    {
        const f = try std.fs.cwd().openFile(p, .{ .mode = .write_only });
        defer f.close();
        try f.pwriteAll(&[_]u8{1}, 15);
        try f.sync();
    }
    const before = try std.fs.cwd().readFileAlloc(a, p, 1024);
    defer a.free(before);

    // magic + version == 1 + flags != 0 must be an EXPLICIT DataCorruption
    // (not a silent "not v1" that would fall through to the framed-MDB guard),
    // and the failed open must leave the file bytes unchanged.
    try testing.expectError(error.DataCorruption, StoreWAL.open(a, p, true));
    const after = try std.fs.cwd().readFileAlloc(a, p, 1024);
    defer a.free(after);
    try testing.expectEqualSlices(u8, before, after);
}

// ---------------------------------------------------------------------------
// Checkpoint: compacts the log to one snapshot section, preserving state.
// ---------------------------------------------------------------------------

test "WAL: checkpoint compacts log and preserves state" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "l.wal");
    defer a.free(p);
    const ck = try ckptOf(a, p);
    defer a.free(ck);

    var recids: [50]u64 = undefined;
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        var i: i64 = 0;
        while (i < 50) : (i += 1) {
            recids[@intCast(i)] = try s.put(i64, a, i, L);
            try s.commit();
        }
        const before = try fileLen(p);
        try s.checkpoint();
        const after = try fileLen(p);
        try testing.expect(after < before);
        try testing.expect(!pathExists(ck));
        for (recids, 0..) |r, idx| try testing.expectEqual(@as(?i64, @intCast(idx)), try getLong(&s, a, r));
        try s.verify();
        try s.close();
    }
    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    for (recids, 0..) |r, idx| try testing.expectEqual(@as(?i64, @intCast(idx)), try getLong(&s, a, r));
    try s.verify();
    const r = try s.put(i64, a, @as(i64, 777), L);
    try s.commit();
    try testing.expectEqual(@as(?i64, 777), try getLong(&s, a, r));
}

test "WAL: crash during checkpoint recovers from temp" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "m.wal");
    defer a.free(p);
    const ck = try ckptOf(a, p);
    defer a.free(ck);

    var r: u64 = undefined;
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        r = try s.put(i64, a, @as(i64, 314), L);
        try s.commit();
        try s.checkpoint(); // log is now itself a valid ckpt-format snapshot
        try s.close();
    }
    // simulate the crash: copy the (snapshot) log to <file>.ckpt, delete the log.
    try std.fs.cwd().copyFile(p, std.fs.cwd(), ck, .{});
    try std.fs.cwd().deleteFile(p);
    try testing.expect(!pathExists(p) and pathExists(ck));

    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    try testing.expectEqual(@as(?i64, 314), try getLong(&s, a, r));
    try testing.expect(pathExists(p)); // temp promoted to log
    try testing.expect(!pathExists(ck)); // temp consumed
    try s.verify();
}

test "WAL: auto-checkpoint bounds log growth" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "n.wal");
    defer a.free(p);

    var recids: [200]u64 = undefined;
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        try s.setAutoCheckpointBytes(4096); // tiny threshold → frequent compaction
        var i: i64 = 0;
        while (i < 200) : (i += 1) {
            recids[@intCast(i)] = try s.put(i64, a, i, L);
            try s.commit();
        }
        const sz = try fileLen(p);
        try testing.expect(sz < 200 * 64);
        for (recids, 0..) |r, idx| try testing.expectEqual(@as(?i64, @intCast(idx)), try getLong(&s, a, r));
        try s.verify();
        try s.close();
    }
    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    for (recids, 0..) |r, idx| try testing.expectEqual(@as(?i64, @intCast(idx)), try getLong(&s, a, r));
}

// ---------------------------------------------------------------------------
// Streaming replay: a tiny replay window forces refill edges mid-record.
// ---------------------------------------------------------------------------

test "WAL: streaming replay with a tiny window" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "o.wal");
    defer a.free(p);

    var recids: [30]u64 = undefined;
    var vals: [30][]u8 = undefined;
    {
        var s = try StoreWAL.openWith(a, p, true, 8, false);
        defer s.deinit();
        var i: u64 = 0;
        while (i < 30) : (i += 1) {
            const v = try bytes(a, i, 40 + @as(usize, @intCast(i % 17)));
            recids[i] = try s.put([]const u8, a, v, R);
            vals[i] = v;
            try s.commit();
        }
        try s.close();
    }
    defer for (vals) |v| a.free(v);

    var s = try StoreWAL.openWith(a, p, true, 8, false);
    defer s.deinit();
    for (recids, 0..) |r, idx| {
        const got = (try s.get([]const u8, a, r, R)).?;
        defer a.free(got);
        try testing.expectEqualSlices(u8, vals[idx], got);
    }
    try s.verify();
}

// ---------------------------------------------------------------------------
// close() linearization: every write op after close returns StoreClosed.
// ---------------------------------------------------------------------------

test "WAL: write ops after close return StoreClosed" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "q.wal");
    defer a.free(p);

    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    const r = try s.put(i64, a, @as(i64, 1), L);
    try s.commit();
    try s.close();

    try testing.expectError(error.StoreClosed, s.update(i64, a, r, @as(i64, 2), L));
    try testing.expectError(error.StoreClosed, s.delete(r));
    try testing.expectError(error.StoreClosed, s.commit());
    try testing.expectError(error.StoreClosed, s.rollback());
    try testing.expectError(error.StoreClosed, s.preallocate());
    try testing.expectError(error.StoreClosed, s.put(i64, a, @as(i64, 9), L));
    try testing.expectError(error.StoreClosed, s.append(r, &[_]u8{1}));
    try testing.expectError(error.StoreClosed, s.checkpoint());
}

test "WAL: double close is ok" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "r.wal");
    defer a.free(p);

    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    _ = try s.put(i64, a, @as(i64, 7), L);
    try s.commit();
    try s.close();
    try s.close();
    try testing.expect(s.isClosed());
}

// ---------------------------------------------------------------------------
// Headroom that would push a plain record past MAX_CAPACITY must be rejected:
// otherwise commit would emit an invalid cap=0 T_RECORD for
// non-oversize content — a WAL neither Rust nor Java can reopen.
// ---------------------------------------------------------------------------

test "WAL: headroom past MAX_CAPACITY is rejected, log stays reopenable" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "s.wal");
    defer a.free(p);

    const small = try bytes(a, 1, 10);
    defer a.free(small);
    const v2 = try bytes(a, 2, 20);
    defer a.free(v2);

    var r: u64 = undefined;
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        r = try s.put([]const u8, a, small, R);
        try s.commit();
        // content fits, but content+headroom rounds past MAX_CAPACITY.
        try testing.expectError(error.RecordTooLarge, s.updateWithHeadroom([]const u8, a, r, small, R, iv.MAX_CAPACITY));
        // usize::MAX headroom must also be rejected (checked arithmetic, no wrap).
        try testing.expectError(error.RecordTooLarge, s.updateWithHeadroom([]const u8, a, r, small, R, std.math.maxInt(usize)));
        // the rejected update staged nothing invalid: a normal commit + reopen works.
        try s.update([]const u8, a, r, v2, R);
        try s.commit();
        try s.close();
    }
    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    const got = (try s.get([]const u8, a, r, R)).?;
    defer a.free(got);
    try testing.expectEqualSlices(u8, v2, got);
    try s.verify();
}

// ---------------------------------------------------------- differential fuzz
// StoreWAL vs the StoreByteArray oracle. WAL reads merge staged
// mutations so it tracks the oracle at every step even before commit; periodic
// commits + a final reopen exercise the log-write + replay path end-to-end.

const StoreByteArray = @import("bytearray.zig").StoreByteArray;

const Prng = struct {
    x: u64,
    fn next(self: *Prng) u64 {
        self.x = self.x *% 6364136223846793005 +% 1;
        return self.x >> 33;
    }
};

const Handle = struct { ro: u64, rw: u64, expect: ?[]u8 };

test "WAL: differential vs StoreByteArray oracle (+commit/reopen)" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "diff.wal");
    defer a.free(p);

    var oracle = try StoreByteArray.init(a, true);
    defer oracle.deinit();

    var handles: std.ArrayListUnmanaged(Handle) = .empty;
    defer {
        for (handles.items) |h| if (h.expect) |e| a.free(e);
        handles.deinit(a);
    }

    var prng = Prng{ .x = 0x0bad_c0de_1234_5678 };
    {
        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();

        var step: u64 = 0;
        while (step < 1500) : (step += 1) {
            const op = prng.next() % 100;
            if (op < 45 or handles.items.len == 0) {
                const len: usize = @intCast(prng.next() % 500 + (if (prng.next() % 25 == 0) @as(u64, 200_000) else 0));
                const v = try bytes(a, step, len);
                defer a.free(v);
                const ro = try oracle.put([]const u8, a, v, R);
                const rw = try s.put([]const u8, a, v, R);
                try handles.append(a, .{ .ro = ro, .rw = rw, .expect = try a.dupe(u8, v) });
            } else if (op < 65) {
                const i = @as(usize, @intCast(prng.next())) % handles.items.len;
                const h = handles.items[i];
                if (prng.next() % 8 == 0) {
                    try oracle.update([]const u8, a, h.ro, null, R);
                    try s.update([]const u8, a, h.rw, null, R);
                    if (handles.items[i].expect) |e| a.free(e);
                    handles.items[i].expect = null;
                } else {
                    const len: usize = @intCast(prng.next() % 800);
                    const v = try bytes(a, step ^ 0xabc, len);
                    defer a.free(v);
                    try oracle.update([]const u8, a, h.ro, v, R);
                    try s.update([]const u8, a, h.rw, v, R);
                    if (handles.items[i].expect) |e| a.free(e);
                    handles.items[i].expect = try a.dupe(u8, v);
                }
            } else if (op < 80) {
                const i = @as(usize, @intCast(prng.next())) % handles.items.len;
                const h = handles.orderedRemove(i);
                try oracle.delete(h.ro);
                try s.delete(h.rw);
                if (h.expect) |e| a.free(e);
            } else if (op < 90) {
                const i = @as(usize, @intCast(prng.next())) % handles.items.len;
                const h = handles.items[i];
                const len: usize = @intCast(prng.next() % 300);
                const newv = try bytes(a, step ^ 0x555, len);
                defer a.free(newv);
                const exp: ?[]const u8 = h.expect;
                const ok_o = try oracle.compareAndSwap([]const u8, a, h.ro, exp, newv, R);
                const ok_w = try s.compareAndSwap([]const u8, a, h.rw, exp, newv, R);
                try testing.expectEqual(ok_o, ok_w);
                if (ok_o) {
                    if (handles.items[i].expect) |e| a.free(e);
                    handles.items[i].expect = try a.dupe(u8, newv);
                }
            } else {
                const ro = try oracle.preallocate();
                const rw = try s.preallocate();
                try handles.append(a, .{ .ro = ro, .rw = rw, .expect = null });
            }

            if (step % 40 == 0) try s.commit();

            if (step % 200 == 0) {
                for (handles.items) |h| {
                    const go = try oracle.get([]const u8, a, h.ro, R);
                    defer if (go) |g| a.free(g);
                    const gw = try s.get([]const u8, a, h.rw, R);
                    defer if (gw) |g| a.free(g);
                    if (h.expect) |e| {
                        try testing.expect(go != null and gw != null);
                        try testing.expectEqualSlices(u8, e, go.?);
                        try testing.expectEqualSlices(u8, go.?, gw.?);
                    } else {
                        try testing.expect(go == null and gw == null);
                    }
                }
                try s.verify();
                try oracle.verify();
            }
        }
        try s.commit(); // durably persist the final staged state
        try s.close();
    }

    // reopen: committed state must match the oracle exactly (replay round-trip).
    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    for (handles.items) |h| {
        const go = try oracle.get([]const u8, a, h.ro, R);
        defer if (go) |g| a.free(g);
        const gw = try s.get([]const u8, a, h.rw, R);
        defer if (gw) |g| a.free(g);
        if (go) |g| {
            try testing.expect(gw != null);
            try testing.expectEqualSlices(u8, g, gw.?);
        } else {
            try testing.expect(gw == null);
        }
    }
    try s.verify();
}

// ===========================================================================
// Adversarial test vectors for the WAL.
// ===========================================================================

// ---------------------------------------------------------------------------
// every serializer/action callback made while `rw` is held runs
// under an ActionGuard, so a reentrant callback trips the Debug assert instead
// of deadlocking. We cannot catch the assert panic, so the deterministic proxy
// is: probe the action depth FROM INSIDE the callback and prove it is > 0 (the
// exact condition `assertNotInAction` would reject). Debug-only (the tracker
// compiles away in release, where reentry deadlocks by contract).
// ---------------------------------------------------------------------------

/// RecordRead that records the action depth observed inside each dispatch.
const DepthProbeAction = struct {
    depth_on_null: u32 = 0,
    depth_on_bytes: u32 = 0,
    called_null: bool = false,
    called_bytes: bool = false,

    fn onBytes(ptr: *anyopaque, input: *DataInput2, size: usize) DbError!i64 {
        _ = input;
        _ = size;
        const self: *DepthProbeAction = @ptrCast(@alignCast(ptr));
        self.depth_on_bytes = mod.actionDepthForTest();
        self.called_bytes = true;
        return 0;
    }
    fn onObject(_: *anyopaque, _: *const anyopaque, _: mod.TypeId) DbError!i64 {
        return error.DataCorruption;
    }
    fn onNull(ptr: *anyopaque) DbError!i64 {
        const self: *DepthProbeAction = @ptrCast(@alignCast(ptr));
        self.depth_on_null = mod.actionDepthForTest();
        self.called_null = true;
        return 0;
    }
    const vtable = mod.RecordRead.VTable{ .onBytes = onBytes, .onObject = onObject, .onNull = onNull };
    fn action(self: *DepthProbeAction) mod.RecordRead {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

test "WAL: staged-null read dispatches on_null under an ActionGuard" {
    if (builtin.mode != .Debug) return error.SkipZigTest;
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "f1null.wal");
    defer a.free(p);

    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    // A staged, preallocated (never written) recid: `merged` yields null, so
    // `read` takes the staged-null branch and dispatches `on_null`.
    const r = try s.preallocate();
    var probe = DepthProbeAction{};
    _ = try s.read(r, probe.action());
    try testing.expect(probe.called_null);
    try testing.expect(!probe.called_bytes);
    try testing.expect(probe.depth_on_null > 0); // guard published: reentry would assert
}

test "WAL: staged live read dispatches on_bytes under an ActionGuard" {
    if (builtin.mode != .Debug) return error.SkipZigTest;
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "f1bytes.wal");
    defer a.free(p);

    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    const v = try bytes(a, 3, 24);
    defer a.free(v);
    const r = try s.put([]const u8, a, v, R); // staged live, uncommitted
    var probe = DepthProbeAction{};
    _ = try s.read(r, probe.action());
    try testing.expect(probe.called_bytes);
    try testing.expect(probe.depth_on_bytes > 0);
}

/// Probe shared by the CAS serializer callbacks.
const CasProbe = struct {
    depth_serialize: ?u32 = null,
    depth_equals: ?u32 = null,
    depth_deinit: ?u32 = null,
};

/// Stateful i64 serializer that records the action depth seen in each callback.
/// (StoreWAL/StoreDirect accept a stateful serializer — only StoreOnHeap does
/// not.) `serialize` also runs outside any lock in `put`; the CAS test resets
/// the probe immediately before the CAS so only the under-lock callbacks count.
const DepthSer = struct {
    p: *CasProbe,
    pub const Elem = i64;
    pub fn serialize(self: DepthSer, out: *DataOutput2, v: i64) DbError!void {
        self.p.depth_serialize = mod.actionDepthForTest();
        try out.writeI64(v);
    }
    pub fn deserialize(_: DepthSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!i64 {
        return input.readI64();
    }
    pub fn cloneElem(_: DepthSer, _: Allocator, v: i64) DbError!i64 {
        return v;
    }
    pub fn deinitElem(self: DepthSer, _: Allocator, _: i64) void {
        self.p.depth_deinit = mod.actionDepthForTest();
    }
    pub fn compare(_: DepthSer, a: i64, b: i64) std.math.Order {
        return std.math.order(a, b);
    }
    pub fn equals(self: DepthSer, a: i64, b: i64) bool {
        self.p.depth_equals = mod.actionDepthForTest();
        return a == b;
    }
    pub fn fixedSize(_: DepthSer) ?usize {
        return 8;
    }
    pub fn equalsBySerializedBytes(_: DepthSer) bool {
        return true;
    }
};

test "WAL: CAS serialize/equals/deinit callbacks run under an ActionGuard" {
    if (builtin.mode != .Debug) return error.SkipZigTest;
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "f1cas.wal");
    defer a.free(p);

    var probe = CasProbe{};
    const ds = DepthSer{ .p = &probe };

    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    const r = try s.put(i64, a, @as(i64, 7), ds);
    try s.commit(); // committed → CAS resolves `current` via inner.get (else branch)

    probe = CasProbe{}; // only the CAS-time callbacks below should register
    const ok = try s.compareAndSwap(i64, a, r, @as(?i64, 7), @as(?i64, 8), ds);
    try testing.expect(ok);
    // equals (expect vs current), serialize(new), and deinitElem(current) all
    // fired under the single outer guard while holding the global write lock.
    try testing.expect(probe.depth_equals != null and probe.depth_equals.? > 0);
    try testing.expect(probe.depth_serialize != null and probe.depth_serialize.? > 0);
    try testing.expect(probe.depth_deinit != null and probe.depth_deinit.? > 0);
}

// ---------------------------------------------------------------------------
// close linearization. The minimum sanctioned shape — call close(),
// then assert every read/config method returns StoreClosed (the in-lock recheck
// makes the staged branches refuse rather than return post-close content). The
// write-op close test already exists ("write ops after close return
// StoreClosed"); this covers the read/config surface.
// ---------------------------------------------------------------------------

test "WAL: read and config ops after close return StoreClosed" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "f2close.wal");
    defer a.free(p);

    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    const r = try s.put(i64, a, @as(i64, 1), L);
    try s.commit();
    // stage an uncommitted mutation too, so the staged read branch is reachable.
    try s.update(i64, a, r, @as(i64, 2), L);
    try s.close();

    var probe = DepthProbeAction{};
    try testing.expectError(error.StoreClosed, s.get(i64, a, r, L));
    try testing.expectError(error.StoreClosed, s.read(r, probe.action()));
    try testing.expectError(error.StoreClosed, s.verify());
    try testing.expectError(error.StoreClosed, s.getAllRecids(a));
    try testing.expectError(error.StoreClosed, s.capacityRemaining(r));
    try testing.expectError(error.StoreClosed, s.setAutoCheckpointBytes(4096));
}

// ---------------------------------------------------------------------------
// a poisoned WAL (namespace durability indeterminate) must refuse
// EVERY mutation with the gate error, leave staged/inner state unchanged, and
// still permit reads and `close`.
// ---------------------------------------------------------------------------

test "WAL: poisoned store gates all mutations, reads and close still work" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "f3poison.wal");
    defer a.free(p);

    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();
    const r = try s.put(i64, a, @as(i64, 42), L);
    try s.commit();

    const ids_before = try s.getAllRecids(a);
    defer a.free(ids_before);

    s.poisonForTest();

    // Every mutation path is gated with the poison error (DataCorruption).
    try testing.expectError(error.DataCorruption, s.preallocate());
    try testing.expectError(error.DataCorruption, s.put(i64, a, @as(i64, 9), L));
    try testing.expectError(error.DataCorruption, s.update(i64, a, r, @as(i64, 100), L));
    try testing.expectError(error.DataCorruption, s.updateWithHeadroom(i64, a, r, @as(i64, 100), L, 16));
    try testing.expectError(error.DataCorruption, s.compareAndSwap(i64, a, r, @as(?i64, 42), @as(?i64, 43), L));
    try testing.expectError(error.DataCorruption, s.delete(r));
    try testing.expectError(error.DataCorruption, s.append(r, &[_]u8{1}));
    try testing.expectError(error.DataCorruption, s.rollback());
    try testing.expectError(error.DataCorruption, s.commit());
    try testing.expectError(error.DataCorruption, s.checkpoint());
    try testing.expectError(error.DataCorruption, s.setAutoCheckpointBytes(4096));

    // Reads are NOT gated: state is unchanged and still visible.
    try testing.expectEqual(@as(?i64, 42), try getLong(&s, a, r));
    const ids_after = try s.getAllRecids(a);
    defer a.free(ids_after);
    try testing.expectEqualSlices(u64, ids_before, ids_after);

    // close still works: it retries the directory fsync (which succeeds here,
    // clearing the poison) and releases resources.
    try s.close();
    try testing.expect(s.isClosed());
}

// ---------------------------------------------------------------------------
// put/preallocate reserve the staged-map slot BEFORE allocating the
// inner recid, so an OOM cannot orphan a P recid in `inner`. Sweep a failing
// allocator (shared with `inner`) over both ops; after each attempt the store
// stays consistent and rolls back to exactly its committed recid set — no leak,
// no monotonic recid consumption.
// ---------------------------------------------------------------------------

test "WAL: FailingAllocator sweep on put/preallocate leaks no recid into inner" {
    const a = testing.allocator;
    var idx: usize = 0;
    while (idx < 32) : (idx += 1) {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        const p = try tmpPath(a, &tmp, "f4oom.wal");
        defer a.free(p);

        var s = try StoreWAL.open(a, p, true);
        defer s.deinit();
        // committed baseline.
        _ = try s.put(i64, a, @as(i64, 1), L);
        _ = try s.put(i64, a, @as(i64, 2), L);
        try s.commit();
        const base = try s.getAllRecids(a);
        defer a.free(base);

        // Point BOTH the staged-map allocator and the inner store at the failing
        // allocator so either the reserve or the inner allocation can fail.
        var failing = testing.FailingAllocator.init(a, .{ .fail_index = idx });
        s.alloc = failing.allocator();
        s.state.alloc = failing.allocator();
        s.state.inner.alloc = failing.allocator();

        const v = try a.alloc(u8, 8); // build value with the real allocator
        defer a.free(v);
        @memset(v, 0xAB);
        _ = s.preallocate() catch {};
        _ = s.put([]const u8, a, v, R) catch {};

        // restore before any fallible bookkeeping.
        s.alloc = a;
        s.state.alloc = a;
        s.state.inner.alloc = a;

        // rollback drops any staged (created) recids; the committed set must be
        // exactly the baseline — nothing orphaned, nothing consumed.
        try s.rollback();
        const after = try s.getAllRecids(a);
        defer a.free(after);
        try testing.expectEqualSlices(u64, base, after);
        try s.verify();

        // and the store still commits + reopens cleanly.
        _ = try s.put(i64, a, @as(i64, 3), L);
        try s.commit();
        try s.close();

        var s2 = try StoreWAL.open(a, p, true);
        defer s2.deinit();
        try s2.verify();
    }
}

// ---------------------------------------------------------------------------
// Rollback-heavy differential vs a pure in-memory model, with periodic reopen
// mid-run (review gap #4). The model tracks a committed layer + a staged
// overlay and applies WAL commit/rollback/reopen semantics, so reads are
// checked at every compare epoch and after every reopen (replay round-trip).
// ---------------------------------------------------------------------------

const RollbackModel = struct {
    const Entry = struct {
        c_data: ?[]u8, // committed value; null = committed void (not live)
        s_set: bool, // staged overlay present
        s_data: ?[]u8, // staged value; null = staged delete
        created: bool, // created in the current uncommitted txn
    };
    map: std.AutoHashMapUnmanaged(u64, Entry) = .empty,
    alloc: Allocator,

    fn deinit(self: *RollbackModel) void {
        var it = self.map.valueIterator();
        while (it.next()) |e| {
            if (e.c_data) |d| self.alloc.free(d);
            if (e.s_data) |d| self.alloc.free(d);
        }
        self.map.deinit(self.alloc);
    }

    fn putNew(self: *RollbackModel, recid: u64, v: []const u8) !void {
        // A fresh put may REUSE a recid freed by a committed delete (its model
        // entry lingers as committed-void); free any residual data first.
        if (self.map.getPtr(recid)) |old| {
            if (old.c_data) |d| self.alloc.free(d);
            if (old.s_data) |d| self.alloc.free(d);
        }
        const dup = try self.alloc.dupe(u8, v);
        try self.map.put(self.alloc, recid, .{ .c_data = null, .s_set = true, .s_data = dup, .created = true });
    }
    fn stageVal(self: *RollbackModel, recid: u64, v: ?[]const u8) !void {
        const e = self.map.getPtr(recid).?;
        if (e.s_data) |d| self.alloc.free(d);
        e.s_data = if (v) |vv| try self.alloc.dupe(u8, vv) else null;
        e.s_set = true;
    }
    fn commit(self: *RollbackModel) void {
        var it = self.map.valueIterator();
        while (it.next()) |e| {
            if (e.s_set) {
                if (e.c_data) |d| self.alloc.free(d);
                e.c_data = e.s_data; // move
                e.s_data = null;
                e.s_set = false;
                e.created = false;
            }
        }
    }
    /// Discard staged; created-uncommitted recids are freed → drop them. Returns
    /// nothing; used for both rollback and reopen-loses-uncommitted.
    fn dropStaged(self: *RollbackModel) void {
        var kill: std.ArrayListUnmanaged(u64) = .empty;
        defer kill.deinit(self.alloc);
        var it = self.map.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr;
            if (e.created) {
                kill.append(self.alloc, kv.key_ptr.*) catch @panic("oom");
            } else if (e.s_set) {
                if (e.s_data) |d| self.alloc.free(d);
                e.s_data = null;
                e.s_set = false;
            }
        }
        for (kill.items) |k| {
            const e = self.map.getPtr(k).?;
            if (e.c_data) |d| self.alloc.free(d);
            if (e.s_data) |d| self.alloc.free(d);
            _ = self.map.remove(k);
        }
    }
    /// Effective visible value: null pointer result means "void / GetVoid".
    fn effective(e: *const Entry) ?[]const u8 {
        if (e.s_set) return e.s_data;
        return e.c_data;
    }
};

test "WAL: rollback-heavy differential vs model + periodic reopen" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try tmpPath(a, &tmp, "rbdiff.wal");
    defer a.free(p);

    var model = RollbackModel{ .alloc = a };
    defer model.deinit();
    var recids: std.ArrayListUnmanaged(u64) = .empty;
    defer recids.deinit(a);

    var prng = Prng{ .x = 0xfeed_face_dead_beef };
    var s = try StoreWAL.open(a, p, true);
    defer s.deinit();

    const verifyAll = struct {
        fn go(sw: *StoreWAL, m: *RollbackModel, al: Allocator) !void {
            var it = m.map.iterator();
            while (it.next()) |kv| {
                const eff = RollbackModel.effective(kv.value_ptr);
                const got = sw.get([]const u8, al, kv.key_ptr.*, R);
                if (eff) |want| {
                    const g = (try got).?;
                    defer al.free(g);
                    try testing.expectEqualSlices(u8, want, g);
                } else {
                    try testing.expectError(error.GetVoid, got);
                }
            }
            try sw.verify();
        }
    }.go;

    var step: u64 = 0;
    while (step < 1400) : (step += 1) {
        const op = prng.next() % 100;
        if (op < 40 or recids.items.len == 0) {
            const len: usize = @intCast(prng.next() % 180 + 1 + (if (prng.next() % 40 == 0) @as(u64, 200_000) else 0));
            const v = try bytes(a, step, len);
            defer a.free(v);
            const r = try s.put([]const u8, a, v, R);
            try model.putNew(r, v);
            try recids.append(a, r);
        } else if (op < 62) {
            const i = @as(usize, @intCast(prng.next())) % recids.items.len;
            const r = recids.items[i];
            const e = model.map.getPtr(r) orelse continue;
            const len: usize = @intCast(prng.next() % 200 + 1);
            const v = try bytes(a, step ^ 0x777, len);
            defer a.free(v);
            // WAL refuses a write to a void/staged-deleted recid with GetVoid.
            if (RollbackModel.effective(e) == null) {
                try testing.expectError(error.GetVoid, s.update([]const u8, a, r, v, R));
            } else {
                try s.update([]const u8, a, r, v, R);
                try model.stageVal(r, v);
            }
        } else if (op < 74) {
            const i = @as(usize, @intCast(prng.next())) % recids.items.len;
            const r = recids.items[i];
            if (model.map.getPtr(r) == null) continue;
            const eff = RollbackModel.effective(model.map.getPtr(r).?);
            if (eff == null) {
                try testing.expectError(error.GetVoid, s.delete(r));
            } else {
                try s.delete(r);
                try model.stageVal(r, null);
            }
        } else if (op < 84) {
            try s.commit();
            model.commit();
        } else if (op < 96) {
            try s.rollback();
            model.dropStaged();
        } else {
            // reopen mid-run: 50% commit first (replay committed), else lose staged.
            if (prng.next() % 2 == 0) {
                try s.commit();
                model.commit();
            }
            model.dropStaged();
            try s.close();
            s.deinit();
            s = try StoreWAL.open(a, p, true);
            try verifyAll(&s, &model, a);
        }

        if (step % 120 == 0) try verifyAll(&s, &model, a);
    }
    try verifyAll(&s, &model, a);
}

// ---------------------------------------------------------------------------
// Every-byte truncation sweep over a small multi-section WAL (review gap #1).
// For each truncation offset, reopen must either recover a committed prefix or
// refuse — never crash, never hang, never return a wrong/resurrected value.
// All data is committed, so a "resurrected uncommitted" record would show as a
// wrong value; we assert every present record reads its committed value or
// GetVoid. The file is bounded tiny so the sweep is fast.
// ---------------------------------------------------------------------------

test "WAL: every-byte truncation sweep never crashes or resurrects data" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const src = try tmpPath(a, &tmp, "trsrc.wal");
    defer a.free(src);
    const work = try tmpPath(a, &tmp, "trwork.wal");
    defer a.free(work);
    const work_ck = try ckptOf(a, work);
    defer a.free(work_ck);

    // Build a small multi-section WAL: 5 committed i64 records, one section each.
    var rids: [5]u64 = undefined;
    {
        var s = try StoreWAL.open(a, src, true);
        defer s.deinit();
        var i: i64 = 0;
        while (i < 5) : (i += 1) {
            rids[@intCast(i)] = try s.put(i64, a, i * 1000 + 7, L);
            try s.commit();
        }
        try s.close();
    }
    const full = try fileLen(src);
    try testing.expect(full < 1024); // bounded

    var off: u64 = 0;
    while (off <= full) : (off += 1) {
        std.fs.cwd().deleteFile(work) catch {};
        std.fs.cwd().deleteFile(work_ck) catch {};
        try std.fs.cwd().copyFile(src, std.fs.cwd(), work, .{});
        try truncateFile(work, off);

        var s = StoreWAL.open(a, work, true) catch |e| {
            // Refusal is acceptable for a mid-log-corrupting cut.
            try testing.expect(e == error.DataCorruption or e == error.Io);
            continue;
        };
        defer s.deinit();
        // Any surviving record must read its committed value or be absent —
        // never a wrong or resurrected value.
        var i: i64 = 0;
        while (i < 5) : (i += 1) {
            const got = getLong(&s, a, rids[@intCast(i)]);
            if (got) |v| {
                if (v) |vv| try testing.expectEqual(i * 1000 + 7, vv);
            } else |e| {
                try testing.expect(e == error.GetVoid);
            }
        }
        try s.verify();
    }
}

test {
    testing.refAllDecls(@This());
}
