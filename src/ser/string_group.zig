//! `StringGroupFormat` — length-prefixed blob with a fixed-width per-element
//! i32 offset index (Java `StringGroupFormat`). Byte side binary-searches over
//! stored UTF-8 in place via `compareUtf8`. Wire: `i32 blobLen; i32 off[n]; blob`.
//! Ported from `mapdb-rust-store/src/ser/string_group.rs`. Group = `[][]const u8`
//! (owned, lossily-materialized strings); order is UTF-16 (`String.compareTo`).

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

pub const StringGroupFormat = struct {
    const Self = @This();
    pub const Elem = []const u8;
    pub const Group = [][]const u8;
    pub const Cursor = mod.BinaryGetCursor(Self);
    pub const instance: Self = .{};
    /// Element serializer type (Java `GroupFormat.element()`): used by
    /// external-value BTree maps to encode each value as its own store record.
    pub const ElementSer = serializers.StringSer;

    /// The single-element string `Serializer` backing this group.
    pub fn element(_: Self) serializers.StringSer {
        return serializers.StringSer.instance;
    }

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
    /// Logical element equality (delegates to the string element serializer).
    /// Used by btree CAS ops (`removeIf`/`replaceIf`) and external-value maps.
    pub fn equalsElem(_: Self, a: Elem, b: Elem) bool {
        return codec.equals(a, b);
    }
    /// Strings order by their natural (UTF-16) ordering.
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
        var blob_len: usize = 0;
        for (g.*) |e| blob_len += e.len;
        try out.writeI32(@intCast(blob_len));
        var off: i32 = 0;
        for (g.*) |e| {
            try out.writeI32(off);
            off += @intCast(e.len);
        }
        for (g.*) |e| try out.writeAll(e);
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
            r[n] = try utf8.utf8Lossy(alloc, blob[@intCast(s)..@intCast(e)]);
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
            try input.seek(try mod.elemOff(off_base, mid, 4));
            const s = try input.readI32();
            const e = if (mid + 1 < count) try input.readI32() else blob_len_i;
            if (s < 0 or e < s or @as(usize, @intCast(e)) > blob_len) return error.DataCorruption;
            try input.seek(try mod.ckAdd(blob_base, @as(usize, @intCast(s))));
            switch (try utf8.compareUtf8(input, @intCast(e - s), key)) {
                .eq => {
                    found = mid;
                    break;
                },
                .lt => lo = @as(isize, @intCast(mid)) + 1,
                .gt => hi = @as(isize, @intCast(mid)) - 1,
            }
        }
        try input.seek(blob_end); // leave input at group end
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
        const out = try utf8.utf8Lossy(alloc, raw);
        errdefer alloc.free(out);
        try input.seek(blob_end); // leave input at group end
        return out;
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
    var group: StringGroupFormat.Group = g;
    try StringGroupFormat.instance.serializeGroup(&out, &group);
    return out.copyBytes(a);
}

fn checkCoherence(a: Allocator, g: [][]const u8, probes: []const []const u8) !void {
    const f = StringGroupFormat.instance;
    const bytes = try serGroup(a, g);
    defer a.free(bytes);
    var group: StringGroupFormat.Group = g;
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

test "string group round-trip + coherence (utf-16 order incl supplementary)" {
    const a = testing.allocator;
    // sorted by UTF-16 order: "" < "a" < "apple" < "banana" < "zebra" < U+FF61
    var g = [_][]const u8{ "", "a", "apple", "banana", "zebra", "\u{FF61}" };
    const probes = [_][]const u8{ "", "a", "aardvark", "apple", "app", "banana", "zzz", "\u{FF61}" };
    try checkCoherence(a, &g, &probes);
}

test "string group supplementary sorts below BMP FF61 (utf-16)" {
    const a = testing.allocator;
    // U+10000 sorts before U+FF61 in UTF-16 order
    var g = [_][]const u8{ "\u{10000}", "\u{FF61}" };
    const probes = [_][]const u8{ "\u{10000}", "\u{FF61}", "\u{FFFF}" };
    try checkCoherence(a, &g, &probes);
}
