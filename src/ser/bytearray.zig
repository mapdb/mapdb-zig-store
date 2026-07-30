//! Binary-capable group formats for `byte[]` keys (Java `ByteArrayFormat` and
//! `ByteArrayPrefixFormat`, rules R6/R7). Both use `Group = [][]const u8` and
//! order by UNSIGNED lexicographic (`memcmp`) on both sides. Ported from
//! `mapdb-rust-store/src/ser/bytearray.rs`.
//!
//! `ByteArrayFormat` wire: `i32 blobLen; i32 off[n]; blob`. `ByteArrayPrefixFormat`
//! wire: `i32 blobLen; i32 restartOff[ceil(n/16)]; blob` where the blob holds
//! entries `packInt(shared) packInt(suffixLen) suffix`, front-coded with a restart
//! every 16 entries. All torn-read clamps ported verbatim.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const mod = @import("mod.zig");
const utf8 = @import("utf8.zig");
const serializers = @import("serializers.zig");
const SearchResult = mod.SearchResult;
const codec = serializers.ByteArrayUnsignedSer.instance;

const RESTART_INTERVAL: usize = 16;

fn nRestarts(count: usize) usize {
    return count / RESTART_INTERVAL + @intFromBool(count % RESTART_INTERVAL != 0);
}

fn bsearchUnsigned(_: void, a: []const u8, b: []const u8) Order {
    return utf8.compareUnsignedBytes(a, b);
}

// ============================================================ ByteArrayFormat

/// Unsigned-lexicographic compare of stored element `idx` against `probe`, sign
/// convention `stored - probe`, comparing in place — no allocation.
fn compareStoredTo(input: *DataInput2, off_base: usize, blob_base: usize, blob_len: usize, count: usize, idx: usize, probe: []const u8) DbError!Order {
    try input.seek(try mod.elemOff(off_base, idx, 4));
    const s = try input.readI32();
    const e = if (idx + 1 < count) try input.readI32() else @as(i32, @intCast(blob_len));
    if (s < 0 or e < s or @as(usize, @intCast(e)) > blob_len) return error.DataCorruption;
    const stored_len: usize = @intCast(e - s);
    try input.seek(try mod.ckAdd(blob_base, @as(usize, @intCast(s))));
    const n = @min(stored_len, probe.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const c: i32 = @as(i32, try input.readU8()) - @as(i32, probe[i]);
        if (c != 0) return if (c < 0) Order.lt else Order.gt;
    }
    return std.math.order(stored_len, probe.len);
}

pub const ByteArrayFormat = struct {
    const Self = @This();
    pub const Elem = []const u8;
    pub const Group = [][]const u8;
    pub const Cursor = mod.BinaryGetCursor(Self);
    pub const instance: Self = .{};

    /// Zero-length groups are allocator-owned: freeable by `deinitGroup`.
    pub fn empty(_: Self, alloc: Allocator) DbError!Group {
        return alloc.alloc(std.meta.Child(Group), 0);
    }
    pub fn size(_: Self, g: *const Group) usize {
        return g.len;
    }
    pub fn compare(_: Self, a: Elem, b: Elem) Order {
        return utf8.compareUnsignedBytes(a, b);
    }
    /// Logical element equality (btree CAS ops).
    pub fn equalsElem(_: Self, a: Elem, b: Elem) bool {
        return std.mem.eql(u8, a, b);
    }
    /// Byte arrays order by unsigned byte value = their natural ordering.
    pub fn naturalOrder(_: Self) bool {
        return true;
    }
    pub fn cloneElem(_: Self, alloc: Allocator, v: Elem) DbError!Elem {
        return codec.cloneElem(alloc, v);
    }
    pub fn deinitElem(_: Self, alloc: Allocator, v: Elem) void {
        codec.deinitElem(alloc, v);
    }
    pub fn get(_: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Elem {
        return codec.cloneElem(alloc, g.*[pos]);
    }
    pub fn search(_: Self, g: *const Group, key: Elem) SearchResult {
        return mod.bsearch(Elem, g.*, key, {}, bsearchUnsigned);
    }
    pub fn insert(_: Self, alloc: Allocator, g: *const Group, pos: usize, v: Elem) DbError!Group {
        return mod.deepInsert(Elem, alloc, codec, g.*, pos, v);
    }
    pub fn set(_: Self, alloc: Allocator, g: *const Group, pos: usize, v: Elem) DbError!Group {
        return mod.deepSet(Elem, alloc, codec, g.*, pos, v);
    }
    pub fn delete(_: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Group {
        return mod.deepDelete(Elem, alloc, codec, g.*, pos);
    }
    pub fn copyRange(_: Self, alloc: Allocator, g: *const Group, from: usize, to: usize) DbError!Group {
        return mod.deepCopyRange(Elem, alloc, codec, g.*, from, to);
    }
    pub fn fromSlice(_: Self, alloc: Allocator, values: []const Elem) DbError!Group {
        return mod.deepClone(Elem, alloc, codec, values);
    }
    pub fn cloneGroup(_: Self, alloc: Allocator, g: *const Group) DbError!Group {
        return mod.deepClone(Elem, alloc, codec, g.*);
    }
    pub fn deinitGroup(_: Self, alloc: Allocator, g: Group) void {
        mod.deepDeinit(Elem, alloc, codec, g);
    }

    pub fn serializeGroup(_: Self, out: *DataOutput2, g: *const Group) DbError!void {
        var blob_len: usize = 0;
        for (g.*) |b| blob_len += b.len;
        try out.writeI32(@intCast(blob_len));
        var off: i32 = 0;
        for (g.*) |b| {
            try out.writeI32(off);
            off += @intCast(b.len);
        }
        for (g.*) |b| try out.writeAll(b);
    }
    pub fn deserializeGroup(_: Self, alloc: Allocator, input: *DataInput2, count: usize) DbError!Group {
        const blob_len_i = try input.readI32();
        if (blob_len_i < 0) return error.DataCorruption;
        const blob_len: usize = @intCast(blob_len_i);
        // Validate the whole declared extent (offset table + blob) against the
        // actual input BEFORE allocating from the tainted count.
        if (try mod.ckAdd(try mod.ckMul(count, 4), blob_len) > input.remaining()) return error.DataCorruption;
        const off = try alloc.alloc(i32, count);
        defer alloc.free(off);
        for (off) |*slot| slot.* = try input.readI32();
        const blob = try input.takeBytes(blob_len);
        const r = try alloc.alloc([]const u8, count);
        var n: usize = 0;
        errdefer {
            for (r[0..n]) |e| alloc.free(e);
            alloc.free(r);
        }
        while (n < count) : (n += 1) {
            const s = off[n];
            const e = if (n + 1 < count) off[n + 1] else blob_len_i;
            if (s < 0 or e < s or @as(usize, @intCast(e)) > blob_len) return error.DataCorruption;
            r[n] = try alloc.dupe(u8, blob[@intCast(s)..@intCast(e)]);
        }
        return r;
    }

    pub fn supportsBinary(_: Self) bool {
        return true;
    }
    pub fn binarySearch(_: Self, _: Allocator, key: Elem, input: *DataInput2, count: usize) DbError!SearchResult {
        const start = input.pos;
        const blob_len_i = try input.readI32();
        if (blob_len_i < 0) return error.DataCorruption;
        const blob_len: usize = @intCast(blob_len_i);
        const off_base = try mod.ckAdd(start, 4);
        const blob_base = try mod.elemOff(off_base, count, 4);
        const blob_end = try mod.ckAdd(blob_base, blob_len);
        var lo: isize = 0;
        var hi: isize = @as(isize, @intCast(count)) - 1;
        var found: ?usize = null;
        while (lo <= hi) {
            const mid: usize = @intCast(@divTrunc(lo + hi, 2));
            switch (try compareStoredTo(input, off_base, blob_base, blob_len, count, mid, key)) {
                .eq => {
                    found = mid;
                    break;
                },
                .lt => lo = @as(isize, @intCast(mid)) + 1,
                .gt => hi = @as(isize, @intCast(mid)) - 1,
            }
        }
        try input.seek(blob_end);
        if (found) |i| return .{ .found = i };
        return .{ .insert = @intCast(lo) };
    }
    pub fn binaryGet(_: Self, alloc: Allocator, input: *DataInput2, count: usize, pos: usize) DbError!Elem {
        const start = input.pos;
        const blob_len_i = try input.readI32();
        if (blob_len_i < 0) return error.DataCorruption;
        const blob_len: usize = @intCast(blob_len_i);
        if (pos >= count) return error.DataCorruption;
        const off_base = try mod.ckAdd(start, 4);
        const blob_base = try mod.elemOff(off_base, count, 4);
        const blob_end = try mod.ckAdd(blob_base, blob_len);
        try input.seek(try mod.elemOff(off_base, pos, 4));
        const s = try input.readI32();
        const e = if (pos + 1 < count) try input.readI32() else blob_len_i;
        if (s < 0 or e < s or @as(usize, @intCast(e)) > blob_len) return error.DataCorruption;
        try input.seek(try mod.ckAdd(blob_base, @as(usize, @intCast(s))));
        const raw = try input.takeBytes(@intCast(e - s));
        const out = try alloc.dupe(u8, raw);
        errdefer alloc.free(out);
        try input.seek(blob_end);
        return out;
    }
    pub fn rangeCursor(self: Self, alloc: Allocator, input: *DataInput2, count: usize, from: usize, to: usize) DbError!Cursor {
        if (from > to or to > count) return error.DataCorruption;
        return Cursor.init(self, alloc, input, count, from, to);
    }
};

// ====================================================== ByteArrayPrefixFormat

fn seekRestart(input: *DataInput2, rest_base: usize, blob_base: usize, blob_len: usize, r: usize) DbError!void {
    try input.seek(try mod.elemOff(rest_base, r, 4));
    const off = try input.readI32();
    if (off < 0 or @as(usize, @intCast(off)) > blob_len) return error.DataCorruption;
    try input.seek(try mod.ckAdd(blob_base, @as(usize, @intCast(off))));
}

/// Decode one entry, appending its suffix onto the shared prefix already in
/// `scratch` (restart entries must carry `shared == 0`). Every length clamped.
fn readEntry(input: *DataInput2, alloc: Allocator, scratch: *std.ArrayList(u8), end: usize, restart: bool) DbError!void {
    const cur_len = scratch.items.len;
    const shared = try input.unpackInt();
    if (shared < 0 or (if (restart) shared != 0 else @as(usize, @intCast(shared)) > cur_len))
        return error.DataCorruption;
    const shared_u: usize = @intCast(shared);
    const suffix_len = try input.unpackInt();
    if (suffix_len < 0 or input.pos > end) return error.DataCorruption;
    const rem = end - input.pos;
    if (@as(usize, @intCast(suffix_len)) > rem) return error.DataCorruption;
    const new_len = shared_u + @as(usize, @intCast(suffix_len));
    scratch.shrinkRetainingCapacity(shared_u); // keep the shared prefix
    try scratch.resize(alloc, new_len);
    try input.readFully(scratch.items[shared_u..new_len]);
}

/// Unsigned in-place compare of restart `r`'s stored bytes against `key`
/// (restart entries carry `shared == 0`, so the suffix IS the full key).
fn compareRestart(input: *DataInput2, rest_base: usize, blob_base: usize, blob_len: usize, r: usize, key: []const u8) DbError!Order {
    try seekRestart(input, rest_base, blob_base, blob_len, r);
    const shared = try input.unpackInt();
    if (shared != 0) return error.DataCorruption;
    const len = try input.unpackInt();
    const end = try mod.ckAdd(blob_base, blob_len);
    if (len < 0 or input.pos > end) return error.DataCorruption;
    const rem = end - input.pos;
    if (@as(usize, @intCast(len)) > rem) return error.DataCorruption;
    const len_u: usize = @intCast(len);
    const n = @min(len_u, key.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const c: i32 = @as(i32, try input.readU8()) - @as(i32, key[i]);
        if (c != 0) return if (c < 0) Order.lt else Order.gt;
    }
    return std.math.order(len_u, key.len);
}

pub const ByteArrayPrefixFormat = struct {
    const Self = @This();
    pub const Elem = []const u8;
    pub const Group = [][]const u8;
    pub const Cursor = mod.BinaryGetCursor(Self);
    pub const instance: Self = .{};

    /// Zero-length groups are allocator-owned: freeable by `deinitGroup`.
    pub fn empty(_: Self, alloc: Allocator) DbError!Group {
        return alloc.alloc(std.meta.Child(Group), 0);
    }
    pub fn size(_: Self, g: *const Group) usize {
        return g.len;
    }
    pub fn compare(_: Self, a: Elem, b: Elem) Order {
        return utf8.compareUnsignedBytes(a, b);
    }
    /// Logical element equality (btree CAS ops).
    pub fn equalsElem(_: Self, a: Elem, b: Elem) bool {
        return std.mem.eql(u8, a, b);
    }
    /// Byte arrays order by unsigned byte value = their natural ordering.
    pub fn naturalOrder(_: Self) bool {
        return true;
    }
    pub fn cloneElem(_: Self, alloc: Allocator, v: Elem) DbError!Elem {
        return codec.cloneElem(alloc, v);
    }
    pub fn deinitElem(_: Self, alloc: Allocator, v: Elem) void {
        codec.deinitElem(alloc, v);
    }
    pub fn get(_: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Elem {
        return codec.cloneElem(alloc, g.*[pos]);
    }
    pub fn search(_: Self, g: *const Group, key: Elem) SearchResult {
        return mod.bsearch(Elem, g.*, key, {}, bsearchUnsigned);
    }
    pub fn insert(_: Self, alloc: Allocator, g: *const Group, pos: usize, v: Elem) DbError!Group {
        return mod.deepInsert(Elem, alloc, codec, g.*, pos, v);
    }
    pub fn set(_: Self, alloc: Allocator, g: *const Group, pos: usize, v: Elem) DbError!Group {
        return mod.deepSet(Elem, alloc, codec, g.*, pos, v);
    }
    pub fn delete(_: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Group {
        return mod.deepDelete(Elem, alloc, codec, g.*, pos);
    }
    pub fn copyRange(_: Self, alloc: Allocator, g: *const Group, from: usize, to: usize) DbError!Group {
        return mod.deepCopyRange(Elem, alloc, codec, g.*, from, to);
    }
    pub fn fromSlice(_: Self, alloc: Allocator, values: []const Elem) DbError!Group {
        return mod.deepClone(Elem, alloc, codec, values);
    }
    pub fn cloneGroup(_: Self, alloc: Allocator, g: *const Group) DbError!Group {
        return mod.deepClone(Elem, alloc, codec, g.*);
    }
    pub fn deinitGroup(_: Self, alloc: Allocator, g: Group) void {
        mod.deepDeinit(Elem, alloc, codec, g);
    }

    pub fn serializeGroup(_: Self, out: *DataOutput2, g: *const Group) DbError!void {
        const n = g.len;
        const n_rest = nRestarts(n);
        const rest_off = try out.alloc.alloc(i32, n_rest);
        defer out.alloc.free(rest_off);
        @memset(rest_off, 0);
        var blob = DataOutput2.init(out.alloc);
        defer blob.deinit();
        var prev: []const u8 = &.{};
        for (g.*, 0..) |enc, i| {
            const shared: usize = if (i % RESTART_INTERVAL == 0) blk: {
                rest_off[i / RESTART_INTERVAL] = @intCast(blob.pos());
                break :blk 0;
            } else utf8.commonPrefixLen(prev, enc);
            try blob.packInt(@intCast(shared));
            try blob.packInt(@intCast(enc.len - shared));
            try blob.writeAll(enc[shared..]);
            prev = enc;
        }
        try out.writeI32(@intCast(blob.pos()));
        for (rest_off) |off| try out.writeI32(off);
        try out.writeAll(blob.bytes());
    }

    pub fn deserializeGroup(_: Self, alloc: Allocator, input: *DataInput2, count: usize) DbError!Group {
        const blob_len_i = try input.readI32();
        if (blob_len_i < 0) return error.DataCorruption;
        const blob_len: usize = @intCast(blob_len_i);
        const n_rest = nRestarts(count);
        // Validate the whole declared extent (restart table + blob) against the
        // actual input, and bound count by the blob (every entry is >= 2 bytes:
        // two packInts), BEFORE any allocation or scratch resize.
        if (try mod.ckAdd(try mod.ckMul(n_rest, 4), blob_len) > input.remaining()) return error.DataCorruption;
        if (try mod.ckMul(count, 2) > blob_len) return error.DataCorruption;
        try input.skipBytes(try mod.ckMul(n_rest, 4)); // sequential decode skips restart table
        const end = try mod.ckAdd(input.pos, blob_len);
        const r = try alloc.alloc([]const u8, count);
        var n: usize = 0;
        errdefer {
            for (r[0..n]) |e| alloc.free(e);
            alloc.free(r);
        }
        var scratch = std.ArrayList(u8){};
        defer scratch.deinit(alloc);
        while (n < count) : (n += 1) {
            try readEntry(input, alloc, &scratch, end, n % RESTART_INTERVAL == 0);
            r[n] = try alloc.dupe(u8, scratch.items);
        }
        // Framing: the count entries must consume exactly the declared blob;
        // trailing bytes inside the blob are non-canonical → corruption.
        if (input.pos != end) return error.DataCorruption;
        return r;
    }

    pub fn supportsBinary(_: Self) bool {
        return true;
    }

    pub fn binarySearch(_: Self, alloc: Allocator, key: Elem, input: *DataInput2, count: usize) DbError!SearchResult {
        const start = input.pos;
        const blob_len_i = try input.readI32();
        if (blob_len_i < 0) return error.DataCorruption;
        const blob_len: usize = @intCast(blob_len_i);
        const n_rest = nRestarts(count);
        const rest_base = try mod.ckAdd(start, 4);
        const blob_base = try mod.elemOff(rest_base, n_rest, 4);
        const end = try mod.ckAdd(blob_base, blob_len);
        // Declared group end must lie within the actual input BEFORE any
        // restart access or scratch allocation (torn-input clamp, D4).
        if (end > input.len()) return error.DataCorruption;

        // 1. binary-search restarts for the RIGHTMOST restart <= key (in place)
        var lo: isize = 0;
        var hi: isize = @as(isize, @intCast(n_rest)) - 1;
        var r: isize = -1;
        while (lo <= hi) {
            const mid: usize = @intCast(@divTrunc(lo + hi, 2));
            const c = try compareRestart(input, rest_base, blob_base, blob_len, mid, key);
            if (c != .gt) {
                r = @intCast(mid);
                lo = @as(isize, @intCast(mid)) + 1;
            } else {
                hi = @as(isize, @intCast(mid)) - 1;
            }
        }
        if (r < 0) {
            try input.seek(end); // key sorts below the first entry
            return .{ .insert = 0 };
        }

        // 2. roll forward through interval r (<= K entries), reconstructing
        const ri: usize = @intCast(r);
        const first = ri * RESTART_INTERVAL;
        const limit = @min(first + RESTART_INTERVAL, count);
        try seekRestart(input, rest_base, blob_base, blob_len, ri);
        var scratch = std.ArrayList(u8){};
        defer scratch.deinit(alloc);
        var result: SearchResult = .{ .insert = limit };
        var i = first;
        while (i < limit) : (i += 1) {
            try readEntry(input, alloc, &scratch, end, i == first);
            switch (utf8.compareUnsignedBytes(scratch.items, key)) {
                .eq => {
                    result = .{ .found = i };
                    break;
                },
                .gt => {
                    result = .{ .insert = i };
                    break;
                },
                .lt => {},
            }
        }
        try input.seek(end);
        return result;
    }

    pub fn binaryGet(_: Self, alloc: Allocator, input: *DataInput2, count: usize, pos: usize) DbError!Elem {
        const start = input.pos;
        const blob_len_i = try input.readI32();
        if (blob_len_i < 0) return error.DataCorruption;
        const blob_len: usize = @intCast(blob_len_i);
        if (pos >= count) return error.DataCorruption;
        const n_rest = nRestarts(count);
        const rest_base = try mod.ckAdd(start, 4);
        const blob_base = try mod.elemOff(rest_base, n_rest, 4);
        const end = try mod.ckAdd(blob_base, blob_len);
        // Declared group end must lie within the actual input BEFORE any
        // restart access or scratch allocation (torn-input clamp, D4).
        if (end > input.len()) return error.DataCorruption;
        const r = pos / RESTART_INTERVAL;
        try seekRestart(input, rest_base, blob_base, blob_len, r);
        var scratch = std.ArrayList(u8){};
        defer scratch.deinit(alloc);
        const first = r * RESTART_INTERVAL;
        var i = first;
        while (i <= pos) : (i += 1) {
            try readEntry(input, alloc, &scratch, end, i == first);
        }
        try input.seek(end);
        return scratch.toOwnedSlice(alloc);
    }

    pub fn rangeCursor(self: Self, alloc: Allocator, input: *DataInput2, count: usize, from: usize, to: usize) DbError!Cursor {
        if (from > to or to > count) return error.DataCorruption;
        return Cursor.init(self, alloc, input, count, from, to);
    }
};

// ------------------------------------------------------------------- tests

const testing = std.testing;

fn serGroup(comptime F: type, a: Allocator, g: [][]const u8) ![]u8 {
    var out = DataOutput2.init(a);
    defer out.deinit();
    var group: F.Group = g;
    try F.instance.serializeGroup(&out, &group);
    return out.copyBytes(a);
}

fn checkCoherence(comptime F: type, a: Allocator, g: [][]const u8, probes: []const []const u8) !void {
    const f = F.instance;
    const bytes = try serGroup(F, a, g);
    defer a.free(bytes);
    var group: F.Group = g;
    // round-trip
    var di = DataInput2.init(bytes);
    const back = try f.deserializeGroup(a, &di, g.len);
    defer f.deinitGroup(a, back);
    try testing.expectEqual(g.len, back.len);
    for (g, back) |x, y| try testing.expectEqualSlices(u8, x, y);
    try testing.expectEqual(bytes.len, di.pos);
    for (0..g.len) |pos| {
        var ig = DataInput2.init(bytes);
        const v = try f.binaryGet(a, &ig, g.len, pos);
        defer f.deinitElem(a, v);
        try testing.expectEqualSlices(u8, g[pos], v);
        try testing.expectEqual(bytes.len, ig.pos);
    }
    for (probes) |key| {
        const obj = f.search(&group, key);
        var inp = DataInput2.init(bytes);
        const byte_res = try f.binarySearch(a, key, &inp, g.len);
        try testing.expect(obj.eql(byte_res));
        try testing.expectEqual(bytes.len, inp.pos);
    }
}

/// unsigned-sorted tricky group: empty, NUL, ascending, high bytes.
fn trickyGroup() [12][]const u8 {
    return .{
        &.{},     &.{0x00}, &.{ 0x00, 0x00 }, &.{ 0x00, 0x01 },
        &.{0x01}, &.{0x7f}, &.{0x80},         &.{ 0x80, 0x00 },
        &.{0xfe}, &.{0xff}, &.{ 0xff, 0x00 }, &.{ 0xff, 0xff },
    };
}

fn trickyProbes() [13][]const u8 {
    return .{
        &.{},                   &.{0x00},         &.{ 0x00, 0x00, 0x00 }, &.{0x01},
        &.{0x40},               &.{0x7f},         &.{0x80},               &.{ 0x80, 0x00 },
        &.{ 0x80, 0x01 },       &.{ 0xfe, 0xff }, &.{0xff},               &.{ 0xff, 0xff },
        &.{ 0xff, 0xff, 0xff },
    };
}

test "byte array format unsigned order coherence" {
    const a = testing.allocator;
    var g = trickyGroup();
    const probes = trickyProbes();
    try checkCoherence(ByteArrayFormat, a, &g, &probes);
    // 0x80 sorts AFTER 0x7f (unsigned, not signed)
    var two = [_][]const u8{ &.{0x7f}, &.{0x80} };
    var grp: ByteArrayFormat.Group = &two;
    try testing.expect(ByteArrayFormat.instance.search(&grp, &.{0x80}).eql(.{ .found = 1 }));
}

test "byte array prefix unsigned order coherence" {
    const a = testing.allocator;
    var g = trickyGroup();
    const probes = trickyProbes();
    try checkCoherence(ByteArrayPrefixFormat, a, &g, &probes);
}

/// n distinct sorted keys with a long shared prefix + an embedded NUL.
fn prefixGroup(a: Allocator, n: usize) ![][]const u8 {
    const r = try a.alloc([]const u8, n);
    var i: usize = 0;
    errdefer {
        for (r[0..i]) |e| a.free(e);
        a.free(r);
    }
    while (i < n) : (i += 1) {
        r[i] = try std.fmt.allocPrint(a, "common/prefix/key\x00{d:0>3}", .{i});
    }
    std.mem.sort([]const u8, r, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    return r;
}

test "byte array prefix restart boundaries 15/16/17" {
    const a = testing.allocator;
    for ([_]usize{ 1, 15, 16, 17, 32, 33, 50 }) |n| {
        const g = try prefixGroup(a, n);
        defer {
            for (g) |e| a.free(e);
            a.free(g);
        }
        // probes: every stored key + below/above + near-boundary "just above"
        var probes = std.ArrayList([]const u8){};
        defer {
            for (probes.items) |e| a.free(e);
            probes.deinit(a);
        }
        try probes.append(a, try a.dupe(u8, "a"));
        try probes.append(a, try a.dupe(u8, "zzz"));
        for (g) |k| try probes.append(a, try a.dupe(u8, k));
        for ([_]usize{ 0, 14, 15, 16, 30 }) |idx| {
            if (idx < n) {
                try probes.append(a, try std.fmt.allocPrint(a, "common/prefix/key\x00{d:0>3}\x00", .{idx}));
            }
        }
        try checkCoherence(ByteArrayPrefixFormat, a, g, probes.items);
    }
}

test "both byte[] formats agree on object + byte search" {
    const a = testing.allocator;
    const g = try prefixGroup(a, 40);
    defer {
        for (g) |e| a.free(e);
        a.free(g);
    }
    var grp: ByteArrayFormat.Group = g;
    const ba = try serGroup(ByteArrayFormat, a, g);
    defer a.free(ba);
    const bp = try serGroup(ByteArrayPrefixFormat, a, g);
    defer a.free(bp);
    for (g) |key| {
        try testing.expect(ByteArrayFormat.instance.search(&grp, key).eql(ByteArrayPrefixFormat.instance.search(&grp, key)));
        var ia = DataInput2.init(ba);
        var ip = DataInput2.init(bp);
        const ra = try ByteArrayFormat.instance.binarySearch(a, key, &ia, g.len);
        const rp = try ByteArrayPrefixFormat.instance.binarySearch(a, key, &ip, g.len);
        try testing.expect(ra.eql(rp));
    }
}
