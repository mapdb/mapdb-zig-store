//! StoreDirect-specific tests, ported from
//! `mapdb-rust-store/tests/store_direct.rs`: verify() tiling oracle, linked/oversize
//! records, free-space reuse + compact, file reopen + crash detection, geometry-
//! corruption refusals, headroom overflow, differential fuzz vs the
//! StoreByteArray oracle, and the round-4 crafted-file allocator hardening
//! regressions. Acceptance: `error.DataCorruption`, never panic/OOB/hang, in
//! Debug AND ReleaseSafe.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const mod = @import("mod.zig");
const parity = @import("parity.zig");
const iv = @import("index_val.zig");
const StoreDirect = @import("direct.zig").StoreDirect;
const StoreByteArray = @import("bytearray.zig").StoreByteArray;

// ---------------------------------------------------------------- fixtures

/// Raw-bytes serializer: content == value (framed by `size`), so a record's
/// on-disk content equals the logical value — ideal for differential testing.
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

/// Deterministic LCG-filled buffer (owned; caller frees). Matches the Rust
/// `bytes(seed, len)` byte-for-byte.
fn bytes(alloc: Allocator, seed: u64, len: usize) ![]u8 {
    var x = seed *% 0x9E37_79B9_7F4A_7C15 +% 1;
    const out = try alloc.alloc(u8, len);
    for (out) |*b| {
        x = x *% 6364136223846793005 +% 1442695040888963407;
        b.* = @truncate(x >> 33);
    }
    return out;
}

fn expectContent(s: *StoreDirect, alloc: Allocator, recid: u64, expected: []const u8) !void {
    const g = (try s.get([]const u8, alloc, recid, R)).?;
    defer alloc.free(g);
    try testing.expectEqualSlices(u8, expected, g);
}

/// A resolved absolute path inside a tmp dir (caller frees).
fn tmpPath(alloc: Allocator, tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &buf);
    return std.fs.path.join(alloc, &.{ dir, name });
}

// ------------------------------------------------------------- basic tests

test "basic roundtrip and verify (heap)" {
    const a = testing.allocator;
    var s = try StoreDirect.init(a, true);
    defer s.deinit();
    const v = try bytes(a, 1, 100);
    defer a.free(v);
    const r = try s.put([]const u8, a, v, R);
    try s.verify();
    try expectContent(&s, a, r, v);

    const v2 = try bytes(a, 2, 50);
    defer a.free(v2);
    try s.update([]const u8, a, r, v2, R);
    try s.verify();
    try expectContent(&s, a, r, v2);

    const v3 = try bytes(a, 3, 5000);
    defer a.free(v3);
    try s.update([]const u8, a, r, v3, R);
    try s.verify();
    try expectContent(&s, a, r, v3);

    try s.delete(r);
    try s.verify();
    try testing.expectError(error.GetVoid, s.get([]const u8, a, r, R));
}

test "linked oversize record (heap)" {
    const a = testing.allocator;
    var s = try StoreDirect.init(a, true);
    defer s.deinit();
    const big = try bytes(a, 7, 3_000_000);
    defer a.free(big);
    const r = try s.put([]const u8, a, big, R);
    try s.verify();
    try expectContent(&s, a, r, big);

    const big2 = try bytes(a, 8, 2_100_000);
    defer a.free(big2);
    try s.update([]const u8, a, r, big2, R);
    try s.verify();
    try expectContent(&s, a, r, big2);

    const small = try bytes(a, 9, 10);
    defer a.free(small);
    try s.update([]const u8, a, r, small, R);
    try s.verify();
    try expectContent(&s, a, r, small);

    try s.delete(r);
    try s.verify();
}

test "free space reuse and compact (heap)" {
    const a = testing.allocator;
    var s = try StoreDirect.init(a, true);
    defer s.deinit();
    var rs: [200]u64 = undefined;
    for (0..200) |i| {
        const v = try bytes(a, i, 500);
        defer a.free(v);
        rs[i] = try s.put([]const u8, a, v, R);
    }
    try s.verify();
    var i: usize = 0;
    while (i < 200) : (i += 2) try s.delete(rs[i]);
    try s.verify();
    const size_before = s.getCurrentSize();
    for (0..100) |j| {
        const v = try bytes(a, 1000 + j, 480);
        defer a.free(v);
        _ = try s.put([]const u8, a, v, R);
    }
    try s.verify();
    const survivor = rs[1];
    const expect = (try s.get([]const u8, a, survivor, R)).?;
    defer a.free(expect);
    try s.compact();
    try s.verify();
    try expectContent(&s, a, survivor, expect);
    try testing.expect(s.getCurrentSize() <= size_before + 100 * 512 + (1 << 20));
}

test "append and headroom (heap)" {
    const a = testing.allocator;
    var s = try StoreDirect.init(a, true);
    defer s.deinit();
    const r = try s.preallocate();
    try testing.expect((try s.append(r, &.{ 1, 2, 3 })).eql(.{ .new_size = 3 }));
    try s.verify();
    // used=3 + 4-byte counter = 7, capacity rounds to 16 → 9 spare bytes remain.
    try testing.expectEqual(@as(usize, 9), try s.capacityRemaining(r));
    try testing.expect((try s.append(r, &.{4})).eql(.{ .new_size = 4 }));

    const v20 = try bytes(a, 5, 20);
    defer a.free(v20);
    const r2 = try s.put([]const u8, a, v20, R);
    const v20b = try bytes(a, 6, 20);
    defer a.free(v20b);
    try s.updateWithHeadroom([]const u8, a, r2, v20b, R, 16);
    const rem = try s.capacityRemaining(r2);
    try testing.expect(rem >= 16);
    try testing.expect((try s.append(r2, &(.{9} ** 10))).eql(.{ .new_size = 30 }));
    try s.verify();
    try testing.expectEqual(rem - 10, try s.capacityRemaining(r2));
}

test "headroom overflow is RecordTooLarge (heap)" {
    const a = testing.allocator;
    var s = try StoreDirect.init(a, true);
    defer s.deinit();
    const small = try bytes(a, 1, 8);
    defer a.free(small);
    const r = try s.put([]const u8, a, small, R);
    try testing.expectError(error.RecordTooLarge, s.updateWithHeadroom([]const u8, a, r, small, R, iv.MAX_CAPACITY));
    try testing.expectError(error.RecordTooLarge, s.updateWithHeadroom([]const u8, a, r, small, R, std.math.maxInt(usize)));
    // untouched + still verifies
    try expectContent(&s, a, r, small);
    try s.verify();
}

// ------------------------------------------------------------- file tests

test "file reopen clean roundtrip" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);

    var recids: [50]u64 = undefined;
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        for (0..50) |i| {
            const v = try bytes(a, i, 300 + i);
            defer a.free(v);
            recids[i] = try s.put([]const u8, a, v, R);
        }
        try s.commit();
        try s.verify();
        try s.close();
    }
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        try s.verify();
        for (0..50) |i| {
            const v = try bytes(a, i, 300 + i);
            defer a.free(v);
            try expectContent(&s, a, recids[i], v);
        }
        try s.close();
    }
}

test "old file magic is rejected" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "old-magic.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        try s.close();
    }
    {
        const f = try std.fs.cwd().openFile(path, .{ .mode = .write_only });
        defer f.close();
        try f.pwriteAll("MDB5.SD1", 0);
    }

    try testing.expectError(error.DataCorruption, StoreDirect.openFile(a, path, true));
}

test "file reopen after uncommitted change refuses (crash sim)" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true);
        const v = try bytes(a, 1, 100);
        defer a.free(v);
        _ = try s.put([]const u8, a, v, R);
        try s.commit();
        // mutate again WITHOUT committing, then abandon (simulated crash)
        const v2 = try bytes(a, 2, 100);
        defer a.free(v2);
        _ = try s.put([]const u8, a, v2, R);
        s.abandonForTest(); // no close()/stamp
    }
    // reopen must refuse: header checksum no longer matches the mutated words
    try testing.expectError(error.DataCorruption, StoreDirect.openFile(a, path, true));
}

test "free list reuse across reopen hot path" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);
    var survivors: [100]u64 = undefined;
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        var rs: [400]u64 = undefined;
        for (0..400) |i| {
            const v = try bytes(a, i, 64);
            defer a.free(v);
            rs[i] = try s.put([]const u8, a, v, R);
        }
        for (0..300) |i| try s.delete(rs[i]);
        @memcpy(&survivors, rs[300..400]);
        try s.verify();
        try s.close();
    }
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        try s.verify();
        var fresh: [300]u64 = undefined;
        for (0..300) |i| {
            const v = try bytes(a, 1000 + i, 64);
            defer a.free(v);
            fresh[i] = try s.put([]const u8, a, v, R);
        }
        try s.verify();
        for (0..300) |i| {
            const v = try bytes(a, 1000 + i, 64);
            defer a.free(v);
            try expectContent(&s, a, fresh[i], v);
        }
        for (fresh) |r| try s.delete(r);
        try s.verify();
        for (0..100) |i| {
            const v = try bytes(a, 300 + i, 64);
            defer a.free(v);
            try expectContent(&s, a, survivors[i], v);
        }
        try s.close();
    }
}

// -------------------------------------------------- crafted-file regressions

const O_HEAD_CHECKSUM: usize = 16;
const O_DATA_TAIL: usize = 24;
const O_MAX_RECID: usize = 32;
const O_FREE_RECID_STACK: usize = 64;
const MASTER_U1: usize = 72; // O_FREE_DATA_STACKS
const ZERO_SLOTS_START: usize = 524352;
const PAGE_SIZE: u64 = 1 << 20;

/// Recompute + rewrite the v1 header checksum so a crafted file opens "clean"
/// (mirrors StoreDirect.headChecksum: seed 0x5D1BA5E1, i32 at offset 16, mixed
/// region [O_DATA_TAIL=24, ZERO_SLOTS_START=524352) in 8-byte steps).
fn restampHeaderChecksum(buf: []u8) void {
    var c: i32 = @bitCast(@as(u32, 0x5D1B_A5E1));
    var o: usize = O_DATA_TAIL;
    while (o < ZERO_SLOTS_START) : (o += 8) {
        const v = std.mem.readInt(u64, buf[o..][0..8], .big);
        c = c *% 31 +% @as(i32, @bitCast(@as(u32, @truncate(v ^ (v >> 32)))));
    }
    std.mem.writeInt(i32, buf[O_HEAD_CHECKSUM..][0..4], c, .big);
}

fn packLongSize(v: u64) usize {
    var c: usize = 1;
    var x = v;
    while (true) {
        x >>= 7;
        if (x == 0) break;
        c += 1;
    }
    return c;
}

/// Encode a packed long (7-bit groups MSB-first, terminator byte | 0x80) into
/// `dst`, returning the byte count.
fn encodePackedLong(dst: []u8, raw: u64) usize {
    const size = packLongSize(raw);
    var shift: i64 = @as(i64, @intCast(size - 1)) * 7;
    var i: usize = 0;
    while (shift > 0) : (shift -= 7) {
        dst[i] = @truncate((raw >> @intCast(shift)) & 0x7F);
        i += 1;
    }
    dst[i] = @truncate((raw & 0x7F) | 0x80);
    return size;
}

fn readWholeFile(a: Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(a, path, 64 * 1024 * 1024);
}
fn writeWholeFile(path: []const u8, data: []const u8) !void {
    const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer f.close();
    try f.writeAll(data);
}

test "reopen with invalid dataTail refuses" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true); // empty: fileTail=PAGE, dataTail=0
        defer s.deinit();
        try s.close();
    }
    var buf = try readWholeFile(a, path);
    defer a.free(buf);
    // dataTail == PAGE_SIZE: page-aligned AND == fileTail → illegal geometry.
    std.mem.writeInt(u64, buf[O_DATA_TAIL..][0..8], parity.p4set(PAGE_SIZE), .big);
    restampHeaderChecksum(buf);
    try writeWholeFile(path, buf);
    try testing.expectError(error.DataCorruption, StoreDirect.openFile(a, path, true));
}

test "reopen with maxRecid beyond index pages refuses" {
    const a = testing.allocator;
    const RECIDS_PER_ZERO_PAGE: u64 = 65528;
    const BAD_RECID: u64 = RECIDS_PER_ZERO_PAGE + 1;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        const v = try bytes(a, 1, 100);
        defer a.free(v);
        const r = try s.put([]const u8, a, v, R); // recid 1, maxRecid=1
        try s.delete(r); // free-recid stack: one chunk, value = p1set(1<<1)
        try s.close();
    }
    var buf = try readWholeFile(a, path);
    defer a.free(buf);
    // 1) crank maxRecid to a recid with no index page (stored p4set(v<<4))
    std.mem.writeInt(u64, buf[O_MAX_RECID..][0..8], parity.p4set(BAD_RECID << 4), .big);
    // 2) overwrite the single free-recid value with the crafted recid
    const master = try parity.p4get(std.mem.readInt(u64, buf[O_FREE_RECID_STACK..][0..8], .big));
    const chunk_off: usize = @intCast(master & iv.MOFFSET);
    try testing.expect(chunk_off >= 1 << 20);
    const raw = parity.p1set(BAD_RECID << 1);
    var enc: [10]u8 = undefined;
    const size = encodePackedLong(&enc, raw);
    @memcpy(buf[chunk_off + 8 .. chunk_off + 8 + size], enc[0..size]);
    const new_master = parity.p4set((@as(u64, 8 + size) << 48) | @as(u64, chunk_off));
    std.mem.writeInt(u64, buf[O_FREE_RECID_STACK..][0..8], new_master, .big);
    restampHeaderChecksum(buf);
    try writeWholeFile(path, buf);

    // open rejects the bad maxRecid, or (belt-and-suspenders) the first alloc's
    // reuse backstop does — never a panic.
    if (StoreDirect.openFile(a, path, true)) |*s_const| {
        var s = s_const.*;
        defer s.deinit();
        try testing.expectError(error.DataCorruption, s.preallocate());
    } else |err| {
        try testing.expectEqual(DbError.DataCorruption, err);
    }
}

test "corrupt free-recid chunk header fails gracefully" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        const v1 = try bytes(a, 1, 100);
        defer a.free(v1);
        const v2 = try bytes(a, 2, 100);
        defer a.free(v2);
        const r1 = try s.put([]const u8, a, v1, R);
        const r2 = try s.put([]const u8, a, v2, R);
        try s.delete(r1);
        try s.delete(r2);
        try s.close(); // stamps clean
    }
    var buf = try readWholeFile(a, path);
    defer a.free(buf);
    const chunk_off: usize = @intCast(std.mem.readInt(u64, buf[O_FREE_RECID_STACK..][0..8], .big) & iv.MOFFSET);
    try testing.expect(chunk_off >= 1 << 20);
    // parity-valid header claiming chunk size 8 (< 16, illegal)
    std.mem.writeInt(u64, buf[chunk_off..][0..8], parity.p4set(@as(u64, 8) << 48), .big);
    restampHeaderChecksum(buf);
    try writeWholeFile(path, buf);

    var s = try StoreDirect.openFile(a, path, true); // open only counts free entries
    defer s.deinit();
    try testing.expectError(error.DataCorruption, s.preallocate());
}

test "free-data reuse offset overflow fails gracefully" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        // 12-byte record → cap 16 (size class u=1); delete frees it onto u=1.
        const v = try bytes(a, 1, 12);
        defer a.free(v);
        const r = try s.put([]const u8, a, v, R);
        try s.delete(r);
        try s.close();
    }
    var buf = try readWholeFile(a, path);
    defer a.free(buf);
    const master = try parity.p4get(std.mem.readInt(u64, buf[MASTER_U1..][0..8], .big));
    const chunk_off: usize = @intCast(master & iv.MOFFSET);
    try testing.expect(chunk_off >= 1 << 20);
    // crafted maximum aligned offset for the 16-byte class: off + 16 overflows.
    const off_target: u64 = std.math.maxInt(u64) - 15; // 0xFFFF..FFF0, 16-aligned
    const raw = parity.p1set(off_target >> 3); // reuse computes p1get(v) << 3
    var enc: [10]u8 = undefined;
    const size = encodePackedLong(&enc, raw);
    for (enc[0..size]) |b| try testing.expect(b != 0);
    @memcpy(buf[chunk_off + 8 .. chunk_off + 8 + size], enc[0..size]);
    const new_master = parity.p4set((@as(u64, 8 + size) << 48) | @as(u64, chunk_off));
    std.mem.writeInt(u64, buf[MASTER_U1..][0..8], new_master, .big);
    restampHeaderChecksum(buf);
    try writeWholeFile(path, buf);

    var s = try StoreDirect.openFile(a, path, true); // open only counts free entries
    defer s.deinit();
    const v2 = try bytes(a, 2, 12);
    defer a.free(v2);
    try testing.expectError(error.DataCorruption, s.put([]const u8, a, v2, R));
}

// ------------------------------------------------ hardening regressions

const HEAD_END: usize = 524336;
const ZERO_PAGE_LINK: usize = HEAD_END; // index-page chain head link word

fn u64At(buf: []const u8, off: usize) u64 {
    return std.mem.readInt(u64, buf[off..][0..8], .big);
}
fn putU64At(buf: []u8, off: usize, v: u64) void {
    std.mem.writeInt(u64, buf[off..][0..8], v, .big);
}

/// A byte-budgeted allocator: fails any allocation that would push outstanding
/// bytes past `cap`. Used by the cycle-detection tests to PROVE bounded memory —
/// a runaway traversal (regression) would exhaust the budget and surface
/// `OutOfMemory` instead of the expected `DataCorruption`.
const CappedAllocator = struct {
    parent: Allocator,
    remaining: usize,
    const Al = std.mem.Alignment;

    fn init(parent: Allocator, cap: usize) CappedAllocator {
        return .{ .parent = parent, .remaining = cap };
    }
    fn allocator(self: *CappedAllocator) Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }
    const vtable = Allocator.VTable{ .alloc = allocFn, .resize = resizeFn, .remap = remapFn, .free = freeFn };
    fn allocFn(ctx: *anyopaque, len: usize, a: Al, ret: usize) ?[*]u8 {
        const self: *CappedAllocator = @ptrCast(@alignCast(ctx));
        if (len > self.remaining) return null;
        const p = self.parent.rawAlloc(len, a, ret) orelse return null;
        self.remaining -= len;
        return p;
    }
    fn resizeFn(ctx: *anyopaque, buf: []u8, a: Al, new_len: usize, ret: usize) bool {
        const self: *CappedAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len and (new_len - buf.len) > self.remaining) return false;
        if (!self.parent.rawResize(buf, a, new_len, ret)) return false;
        if (new_len > buf.len) self.remaining -= (new_len - buf.len) else self.remaining += (buf.len - new_len);
        return true;
    }
    fn remapFn(ctx: *anyopaque, buf: []u8, a: Al, new_len: usize, ret: usize) ?[*]u8 {
        const self: *CappedAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len and (new_len - buf.len) > self.remaining) return null;
        const p = self.parent.rawRemap(buf, a, new_len, ret) orelse return null;
        if (new_len > buf.len) self.remaining -= (new_len - buf.len) else self.remaining += (buf.len - new_len);
        return p;
    }
    fn freeFn(ctx: *anyopaque, buf: []u8, a: Al, ret: usize) void {
        const self: *CappedAllocator = @ptrCast(@alignCast(ctx));
        self.parent.rawFree(buf, a, ret);
        self.remaining += buf.len;
    }
};

// (a) A free-data value whose high bits are set aliases a LIVE extent once the
// `<< 3` discards them. The pre-shift wire-domain bound must reject it, leaving
// the live record intact.
test "crafted free-data value with high bits aliases a live extent → DataCorruption" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        const va = try bytes(a, 1, 12); // recid 1 (A), 16-byte class
        defer a.free(va);
        const vb = try bytes(a, 2, 12); // recid 2 (B), 16-byte class
        defer a.free(vb);
        _ = try s.put([]const u8, a, va, R);
        const rb = try s.put([]const u8, a, vb, R);
        try s.delete(rb); // frees B's 16-byte extent onto the u=1 free-data stack
        try s.close();
    }
    var buf = try readWholeFile(a, path);
    defer a.free(buf);
    // A's data offset from recid 1's index slot.
    const iv_a = try parity.p1get(u64At(buf, ZERO_SLOTS_START));
    const a_off = iv.offset(iv_a);
    // The u=1 free-data stack's single value, replaced by (A_off>>3) with bit 61
    // set: `<< 3` would discard bit 61 and yield exactly A_off.
    const master = try parity.p4get(u64At(buf, MASTER_U1));
    const chunk_off: usize = @intCast(master & iv.MOFFSET);
    const crafted = parity.p1set((a_off >> 3) | (@as(u64, 1) << 61));
    var enc: [10]u8 = undefined;
    const size = encodePackedLong(&enc, crafted);
    @memcpy(buf[chunk_off + 8 .. chunk_off + 8 + size], enc[0..size]);
    putU64At(buf, MASTER_U1, parity.p4set((@as(u64, 8 + size) << 48) | @as(u64, chunk_off)));
    restampHeaderChecksum(buf);
    try writeWholeFile(path, buf);

    var s = try StoreDirect.openFile(a, path, true);
    defer s.deinit();
    const vc = try bytes(a, 3, 12);
    defer a.free(vc);
    // reusing the crafted free extent must be rejected pre-shift, NOT alias A.
    try testing.expectError(error.DataCorruption, s.put([]const u8, a, vc, R));
    // A survives untouched.
    const va2 = try bytes(a, 1, 12);
    defer a.free(va2);
    try expectContent(&s, a, 1, va2);
}

// (b) A parity-valid index slot with capUnits==0 must yield DataCorruption on
// the DESTRUCTIVE paths (delete/update) rather than tripping a debug assert.
// Runs in Debug where the asserts are live.
test "capUnits==0 index slot → DataCorruption on delete and update (no trap)" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        const v = try bytes(a, 1, 12);
        defer a.free(v);
        _ = try s.put([]const u8, a, v, R);
        try s.close();
    }
    const buf = try readWholeFile(a, path);
    defer a.free(buf);
    // recid 1 slot (outside the header checksum region): keep the real data
    // offset but force capUnits to 0.
    const iv_a = try parity.p1get(u64At(buf, ZERO_SLOTS_START));
    const bad = iv.compose(0, iv.offset(iv_a), 0);
    putU64At(buf, ZERO_SLOTS_START, parity.p1set(bad));
    try writeWholeFile(path, buf); // slot is outside checksum → no restamp needed

    var s = try StoreDirect.openFile(a, path, true);
    defer s.deinit();
    try testing.expectError(error.DataCorruption, s.delete(1));
    try testing.expectError(error.DataCorruption, s.update([]const u8, a, 1, null, R));
    // read path already rejected it; confirm it still does, no trap.
    try testing.expectError(error.DataCorruption, s.get([]const u8, a, 1, R));
}

// (c) A parity-corrupt (bit-flipped) index slot must surface DataCorruption
// through getAllRecids, not silently emit/omit a recid.
test "parity-corrupt index slot → getAllRecids DataCorruption" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        const v1 = try bytes(a, 1, 20);
        defer a.free(v1);
        const v2 = try bytes(a, 2, 20);
        defer a.free(v2);
        _ = try s.put([]const u8, a, v1, R);
        _ = try s.put([]const u8, a, v2, R);
        try s.close();
    }
    const buf = try readWholeFile(a, path);
    defer a.free(buf);
    // flip one bit in recid 2's slot (breaks parity1; slot outside checksum).
    const slot2 = ZERO_SLOTS_START + 8;
    putU64At(buf, slot2, u64At(buf, slot2) ^ 0x100);
    try writeWholeFile(path, buf);

    var s = try StoreDirect.openFile(a, path, true);
    defer s.deinit();
    try testing.expectError(error.DataCorruption, s.getAllRecids(a));
}

// (d) One-node cycles in the index-page chain, a long-stack chain, and a
// linked-record chain must all yield DataCorruption with BOUNDED memory: the
// capped allocator would surface OutOfMemory on a runaway traversal.
test "one-node index-page chain cycle → DataCorruption, bounded memory" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        const v = try bytes(a, 1, 100); // allocates a data page → fileTail = 2*PAGE
        defer a.free(v);
        _ = try s.put([]const u8, a, v, R);
        try s.close();
    }
    const buf = try readWholeFile(a, path);
    defer a.free(buf);
    // point the index-page chain head at page P=PAGE_SIZE, whose forward link
    // points back at itself.
    const P: u64 = PAGE_SIZE;
    putU64At(buf, ZERO_PAGE_LINK, parity.p16set(P)); // inside checksum → restamp
    putU64At(buf, @intCast(P + 8), parity.p16set(P)); // self-cycle (data page, outside)
    restampHeaderChecksum(buf);
    try writeWholeFile(path, buf);

    var capped = CappedAllocator.init(a, 64 << 20);
    try testing.expectError(error.DataCorruption, StoreDirect.openFile(capped.allocator(), path, true));
}

test "one-node long-stack chain cycle → DataCorruption, bounded memory" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        const v = try bytes(a, 1, 12);
        defer a.free(v);
        const r = try s.put([]const u8, a, v, R);
        try s.delete(r); // one chunk on the u=1 free-data stack
        try s.close();
    }
    const buf = try readWholeFile(a, path);
    defer a.free(buf);
    const master = try parity.p4get(u64At(buf, MASTER_U1));
    const chunk_off: u64 = master & iv.MOFFSET;
    const chunk_size = (try parity.p4get(u64At(buf, @intCast(chunk_off)))) >> 48;
    // rewrite the chunk header so its prev-link points at itself (self-cycle);
    // chunk is in the data area, outside the checksum → no restamp.
    putU64At(buf, @intCast(chunk_off), parity.p4set((chunk_size << 48) | chunk_off));
    try writeWholeFile(path, buf);

    var capped = CappedAllocator.init(a, 64 << 20);
    try testing.expectError(error.DataCorruption, StoreDirect.openFile(capped.allocator(), path, true));
}

test "one-node linked-record chain cycle → DataCorruption, bounded memory" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "store.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true);
        defer s.deinit();
        const big = try bytes(a, 1, 1_100_000); // oversize → linked chain
        defer a.free(big);
        _ = try s.put([]const u8, a, big, R);
        try s.close();
    }
    const buf = try readWholeFile(a, path);
    defer a.free(buf);
    const iv_h = try parity.p1get(u64At(buf, ZERO_SLOTS_START));
    const head_off = iv.offset(iv_h);
    const cap_units: u64 = iv.capUnits(iv_h);
    // head chunk's `next` link points back at the head (self-cycle); head chunk
    // is in the data area, outside the checksum → no restamp.
    putU64At(buf, @intCast(head_off + 4), parity.p1set((cap_units << 48) | head_off));
    try writeWholeFile(path, buf);

    var capped = CappedAllocator.init(a, 64 << 20);
    const ca = capped.allocator();
    var s = try StoreDirect.openFile(ca, path, true);
    defer s.deinit();
    try testing.expectError(error.DataCorruption, s.get([]const u8, ca, 1, R));
}

// (e) FailingAllocator sweep at the index-page mirror publication + the compact
// snapshot append. Volume-level publication/shrink/openFile
// sweeps live in volume.zig.
test "FailingAllocator: index-page mirror publication OOM stays consistent" {
    const a = testing.allocator;
    const RECIDS_PER_ZERO_PAGE: usize = 65528;
    var s = try StoreDirect.init(a, true);
    defer s.deinit();
    // fill the zero page so the next recid forces a NEW index page.
    var i: usize = 0;
    while (i < RECIDS_PER_ZERO_PAGE) : (i += 1) _ = try s.preallocate();
    // force the mirror-array allocation to fail; geometry must stay untouched.
    var failing = testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    s.alloc = failing.allocator();
    try testing.expectError(error.OutOfMemory, s.preallocate());
    s.alloc = a;
    // store is still consistent: the next allocation now succeeds and verifies.
    _ = try s.preallocate();
    try s.verify();
}

test "FailingAllocator sweep: compact snapshot append (linked + plain), no leak" {
    const a = testing.allocator;
    var idx: usize = 0;
    while (idx < 40) : (idx += 1) {
        var s = try StoreDirect.init(a, true);
        defer s.deinit();
        const big = try bytes(a, idx, 1_100_000); // linked
        defer a.free(big);
        const small = try bytes(a, idx +% 7, 40);
        defer a.free(small);
        _ = try s.put([]const u8, a, big, R);
        _ = try s.put([]const u8, a, small, R);
        var failing = testing.FailingAllocator.init(a, .{ .fail_index = idx });
        s.alloc = failing.allocator();
        s.compact() catch {}; // OOM in snapshot must not leak the linked content
        s.alloc = a; // restore so deinit frees cleanly
    }
}

// (f) A freshly-created file store exercises the parent-directory fsync path
// (fault injection sanctioned-deferred).
test "file create exercises parent-dir fsync path" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(a, &tmp, "created.sd1");
    defer a.free(path);
    {
        var s = try StoreDirect.openFile(a, path, true); // create → syncParentDir
        defer s.deinit();
        const v = try bytes(a, 1, 32);
        defer a.free(v);
        _ = try s.put([]const u8, a, v, R);
        try s.close();
    }
    // the directory entry is present and the store reopens cleanly.
    try std.fs.cwd().access(path, .{});
    var s = try StoreDirect.openFile(a, path, true);
    defer s.deinit();
    try s.verify();
    try s.close();
}

// ---------------------------------------------------------- differential fuzz

const Prng = struct {
    x: u64,
    fn next(self: *Prng) u64 {
        self.x = self.x *% 6364136223846793005 +% 1;
        return self.x >> 33;
    }
};

const Handle = struct { ro: u64, rd: u64, expect: ?[]u8 };

test "differential vs StoreByteArray oracle (3000 ops)" {
    const a = testing.allocator;
    var oracle = try StoreByteArray.init(a, true);
    defer oracle.deinit();
    var direct = try StoreDirect.init(a, true);
    defer direct.deinit();

    var handles: std.ArrayListUnmanaged(Handle) = .empty;
    defer {
        for (handles.items) |h| if (h.expect) |e| a.free(e);
        handles.deinit(a);
    }

    var prng = Prng{ .x = 0x1234_5678_9abc_def0 };

    var step: u64 = 0;
    while (step < 3000) : (step += 1) {
        const op = prng.next() % 100;
        if (op < 45 or handles.items.len == 0) {
            // put (occasionally oversize → linked)
            const len: usize = @as(usize, @intCast(prng.next() % 900)) + (if (prng.next() % 20 == 0) @as(usize, 1_100_000) else 0);
            const v = try bytes(a, step, len);
            defer a.free(v);
            const ro = try oracle.put([]const u8, a, v, R);
            const rd = try direct.put([]const u8, a, v, R);
            try handles.append(a, .{ .ro = ro, .rd = rd, .expect = try a.dupe(u8, v) });
        } else if (op < 65) {
            const i = @as(usize, @intCast(prng.next())) % handles.items.len;
            const h = handles.items[i];
            if (prng.next() % 8 == 0) {
                try oracle.update([]const u8, a, h.ro, null, R);
                try direct.update([]const u8, a, h.rd, null, R);
                if (handles.items[i].expect) |e| a.free(e);
                handles.items[i].expect = null;
            } else {
                const len: usize = @intCast(prng.next() % 1500);
                const v = try bytes(a, step ^ 0xabc, len);
                defer a.free(v);
                try oracle.update([]const u8, a, h.ro, v, R);
                try direct.update([]const u8, a, h.rd, v, R);
                if (handles.items[i].expect) |e| a.free(e);
                handles.items[i].expect = try a.dupe(u8, v);
            }
        } else if (op < 80) {
            const i = @as(usize, @intCast(prng.next())) % handles.items.len;
            const h = handles.orderedRemove(i);
            try oracle.delete(h.ro);
            try direct.delete(h.rd);
            if (h.expect) |e| a.free(e);
        } else if (op < 90) {
            const i = @as(usize, @intCast(prng.next())) % handles.items.len;
            const h = handles.items[i];
            const len: usize = @intCast(prng.next() % 400);
            const newv = try bytes(a, step ^ 0x555, len);
            defer a.free(newv);
            const exp: ?[]const u8 = h.expect;
            const ok_o = try oracle.compareAndSwap([]const u8, a, h.ro, exp, newv, R);
            const ok_d = try direct.compareAndSwap([]const u8, a, h.rd, exp, newv, R);
            try testing.expectEqual(ok_o, ok_d);
            if (ok_o) {
                if (handles.items[i].expect) |e| a.free(e);
                handles.items[i].expect = try a.dupe(u8, newv);
            }
        } else {
            const ro = try oracle.preallocate();
            const rd = try direct.preallocate();
            try handles.append(a, .{ .ro = ro, .rd = rd, .expect = null });
        }

        // Full-state compare + verify() at epoch boundaries. Every
        // handle's content is checked against the expected image AND cross-checked
        // oracle-vs-direct; live-record counts must match; both stores verify().
        if (step % 200 == 0) {
            for (handles.items) |h| {
                const go = try oracle.get([]const u8, a, h.ro, R);
                defer if (go) |g| a.free(g);
                const gd = try direct.get([]const u8, a, h.rd, R);
                defer if (gd) |g| a.free(g);
                if (h.expect) |e| {
                    try testing.expect(go != null);
                    try testing.expectEqualSlices(u8, e, go.?);
                } else {
                    try testing.expect(go == null);
                }
                if (go) |g| {
                    try testing.expect(gd != null);
                    try testing.expectEqualSlices(u8, g, gd.?);
                } else {
                    try testing.expect(gd == null);
                }
            }
            const ao = try oracle.getAllRecids(a);
            defer a.free(ao);
            const ad = try direct.getAllRecids(a);
            defer a.free(ad);
            try testing.expectEqual(ao.len, ad.len);
            try direct.verify();
            try oracle.verify();
        }
    }
    try direct.verify();
}

// The open diagnostic is THIS open's answer or nothing.
//
// codex round 2 on C5t: `OpenNote` was filled on the refusal paths and never
// cleared, so a caller reusing one saw the previous open's reason reported for a
// later refusal that annotates nothing — the deep structural walks note nothing
// by design. A diagnostic that can outlive the refusal it describes is worse
// than none, because a predicate reading it cannot tell the two apart, and
// `xfix.assertFamily` is exactly such a predicate.
//
// Two opens through ONE note: a bad-magic refusal, then a clean open. The
// second must leave the note empty, and it is the clear-on-entry that does it.
test "openFileDiag: the note is this open's answer or nothing" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const bad = try tmpPath(a, &tmp, "bad-magic.sd1");
    defer a.free(bad);
    {
        // A file long enough to reach the magic word and holding the wrong one.
        const f = try std.fs.cwd().createFile(bad, .{});
        defer f.close();
        const filler = try a.alloc(u8, 1 << 20); // one slice: past the header page
        defer a.free(filler);
        @memset(filler, 0x5A);
        try f.writeAll(filler);
    }

    var note: StoreDirect.OpenNote = .{};
    try testing.expectError(error.DataCorruption, StoreDirect.openFileDiag(a, bad, true, &note));
    try testing.expectEqualStrings(StoreDirect.D_BAD_MAGIC, note.reason);

    const good = try tmpPath(a, &tmp, "good.sd1");
    defer a.free(good);
    {
        var s = try StoreDirect.openFileDiag(a, good, true, &note);
        defer s.deinit();
        try s.close();
    }
    try testing.expectEqualStrings("", note.reason);
}

test {
    testing.refAllDecls(@This());
}
