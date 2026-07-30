//! `StringPrefixFormat` — front-coded (shared-prefix compressed) group format for
//! `String`, the LevelDB/RocksDB block style (rule R7). Periodic RESTART points
//! keep the byte side O(log n). Ported from `mapdb-rust-store/src/ser/string_prefix.rs`.
//!
//! Each entry is `packInt(sharedPrefixLen) packInt(suffixLen) suffix_utf8`, where
//! `sharedPrefixLen` is the byte length shared with the PREVIOUS entry's UTF-8.
//! Entry `i` with `i % 16 == 0` is a restart (`shared==0`, addressable via the
//! restart table). Wire: `i32 blobLen; i32 restartOff[ceil(n/16)]; blob`.
//! Order is `String.compareTo` (UTF-16), matched on the byte side by
//! `compareUtf8`. Every length is clamped (torn-read safety). Group is
//! `[][]const u8` (owned, lossily-materialized strings).

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
const codec = serializers.StringSer.instance;

const RESTART_INTERVAL: usize = 16;

fn nRestarts(count: usize) usize {
    return count / RESTART_INTERVAL + @intFromBool(count % RESTART_INTERVAL != 0);
}

fn seekRestart(input: *DataInput2, rest_base: usize, blob_base: usize, blob_len: usize, r: usize) DbError!void {
    try input.seek(try mod.elemOff(rest_base, r, 4));
    const off = try input.readI32();
    if (off < 0 or @as(usize, @intCast(off)) > blob_len) return error.DataCorruption;
    try input.seek(try mod.ckAdd(blob_base, @as(usize, @intCast(off))));
}

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
    scratch.shrinkRetainingCapacity(shared_u); // keep shared prefix
    try scratch.resize(alloc, new_len);
    try input.readFully(scratch.items[shared_u..new_len]);
}

/// Compare restart `r` against `key` (valid UTF-8) in place, no copy.
fn compareRestart(input: *DataInput2, rest_base: usize, blob_base: usize, blob_len: usize, r: usize, key: []const u8) DbError!Order {
    try seekRestart(input, rest_base, blob_base, blob_len, r);
    const shared = try input.unpackInt();
    if (shared != 0) return error.DataCorruption;
    const len = try input.unpackInt();
    const end = try mod.ckAdd(blob_base, blob_len);
    if (len < 0 or input.pos > end) return error.DataCorruption;
    const rem = end - input.pos;
    if (@as(usize, @intCast(len)) > rem) return error.DataCorruption;
    return utf8.compareUtf8(input, @intCast(len), key);
}

pub const StringPrefixFormat = struct {
    const Self = @This();
    pub const Elem = []const u8;
    pub const Group = [][]const u8;
    pub const Cursor = mod.BinaryGetCursor(Self);
    pub const instance: Self = .{};

    fn cmp(_: void, a: Elem, b: Elem) Order {
        return utf8.compareUtf16(a, b);
    }

    /// Zero-length groups are allocator-owned: freeable by `deinitGroup`.
    pub fn empty(_: Self, alloc: Allocator) DbError!Group {
        return alloc.alloc(std.meta.Child(Group), 0);
    }
    pub fn size(_: Self, g: *const Group) usize {
        return g.len;
    }
    pub fn compare(_: Self, a: Elem, b: Elem) Order {
        return utf8.compareUtf16(a, b);
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
        return mod.bsearch(Elem, g.*, key, {}, cmp);
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
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const enc = g.*[i];
            const shared: usize = if (i % RESTART_INTERVAL == 0) blk: {
                rest_off[i / RESTART_INTERVAL] = @intCast(blob.pos());
                break :blk 0;
            } else utf8.commonPrefixLen(g.*[i - 1], enc);
            try blob.packInt(@intCast(shared));
            try blob.packInt(@intCast(enc.len - shared));
            try blob.writeAll(enc[shared..]);
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
        try input.skipBytes(try mod.ckMul(n_rest, 4));
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
            r[n] = try utf8.utf8Lossy(alloc, scratch.items);
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
            try input.seek(end);
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
            var si = DataInput2.init(scratch.items);
            switch (try utf8.compareUtf8(&si, scratch.items.len, key)) {
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
        return utf8.utf8Lossy(alloc, scratch.items);
    }

    pub fn rangeCursor(self: Self, alloc: Allocator, input: *DataInput2, count: usize, from: usize, to: usize) DbError!Cursor {
        if (from > to or to > count) return error.DataCorruption;
        return Cursor.init(self, alloc, input, count, from, to);
    }
};

// ------------------------------------------------------------------- tests

const testing = std.testing;

fn serGroup(a: Allocator, g: [][]const u8) ![]u8 {
    var out = DataOutput2.init(a);
    defer out.deinit();
    var group: StringPrefixFormat.Group = g;
    try StringPrefixFormat.instance.serializeGroup(&out, &group);
    return out.copyBytes(a);
}

fn sortDedup(a: Allocator, items: []const []const u8) ![][]const u8 {
    var list = std.ArrayList([]const u8){};
    errdefer list.deinit(a);
    try list.appendSlice(a, items);
    std.mem.sort([]const u8, list.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return utf8.compareUtf16(x, y) == .lt;
        }
    }.lt);
    // dedup
    var w: usize = 0;
    for (list.items, 0..) |it, idx| {
        if (idx == 0 or utf8.compareUtf16(it, list.items[w - 1]) != .eq) {
            list.items[w] = it;
            w += 1;
        }
    }
    list.shrinkRetainingCapacity(w);
    return list.toOwnedSlice(a);
}

fn checkCoherence(a: Allocator, g: [][]const u8, probes: []const []const u8) !void {
    const f = StringPrefixFormat.instance;
    const bytes = try serGroup(a, g);
    defer a.free(bytes);
    var group: StringPrefixFormat.Group = g;
    var di = DataInput2.init(bytes);
    const back = try f.deserializeGroup(a, &di, g.len);
    defer f.deinitGroup(a, back);
    try testing.expectEqual(g.len, back.len);
    for (g, back) |x, y| try testing.expectEqualStrings(x, y);
    for (probes) |key| {
        const obj = f.search(&group, key);
        var inp = DataInput2.init(bytes);
        const byte_res = try f.binarySearch(a, key, &inp, g.len);
        try testing.expect(obj.eql(byte_res));
        try testing.expectEqual(bytes.len, inp.pos);
    }
    for (0..g.len) |pos| {
        var ig = DataInput2.init(bytes);
        const v = try f.binaryGet(a, &ig, g.len, pos);
        defer f.deinitElem(a, v);
        try testing.expectEqualStrings(g[pos], v);
        try testing.expectEqual(bytes.len, ig.pos);
    }
}

test "string prefix shared prefixes + coherence" {
    const a = testing.allocator;
    const raw = [_][]const u8{ "apple", "application", "apply", "appliance", "app", "banana" };
    const g = try sortDedup(a, &raw);
    defer a.free(g);
    const probes = [_][]const u8{ "", "app", "appl", "apple", "applf", "application", "apply", "appliance", "aardvark", "banana", "zzz" };
    try checkCoherence(a, g, probes[0..]);
}

test "string prefix restart boundaries 15/16/17/33" {
    const a = testing.allocator;
    for ([_]usize{ 0, 1, 15, 16, 17, 31, 32, 33, 48 }) |n| {
        var raw = std.ArrayList([]const u8){};
        defer {
            for (raw.items) |s| a.free(s);
            raw.deinit(a);
        }
        for (0..n) |i| {
            const s = try std.fmt.allocPrint(a, "key{d:0>5}", .{i});
            try raw.append(a, s);
        }
        const g = try sortDedup(a, raw.items);
        defer a.free(g);
        try testing.expectEqual(n, g.len);
        var probes = std.ArrayList([]const u8){};
        defer {
            for (probes.items) |s| a.free(s);
            probes.deinit(a);
        }
        try probes.append(a, try a.dupe(u8, ""));
        try probes.append(a, try a.dupe(u8, "zzzzzz"));
        for (g) |k| {
            try probes.append(a, try a.dupe(u8, k));
            try probes.append(a, try std.fmt.allocPrint(a, "{s}a", .{k}));
        }
        try checkCoherence(a, g, probes.items);
    }
}

test "string prefix supplementary plane" {
    const a = testing.allocator;
    const raw = [_][]const u8{ "a", "\u{10000}", "\u{10000}x", "\u{1F600}", "\u{FF61}", "z" };
    const g = try sortDedup(a, &raw);
    defer a.free(g);
    const probes = [_][]const u8{ "a", "\u{10000}", "\u{10000}x", "\u{1F600}", "\u{FF61}", "\u{FFFF}", "z" };
    try checkCoherence(a, g, probes[0..]);
}
