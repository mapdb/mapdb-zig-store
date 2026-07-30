//! `LongFormat` and `LongDeltaFormat` — fixed-stride-binary and sequential-delta
//! group formats for `i64` (Java `LongFormat`, `LongDeltaFormat`). Object side is
//! `[]i64`. Ported from `mapdb-rust-store/src/ser/long.rs`.

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

/// Fixed 8-byte BE stride; O(log n) true binary search over serialized bytes.
pub const LongFormat = mod.FixedStrideFormat(serializers.LongSer);

fn cmpI64(_: void, a: i64, b: i64) Order {
    return std.math.order(a, b);
}

/// Delta-packed longs: `packLong(zigzag(v0))`, then `packLong(zigzag(vi-vi-1))`.
/// Object side identical to `LongFormat`; byte side is a sequential decode with
/// early exit + `unpackLongSkip` to reach group end.
pub const LongDeltaFormat = struct {
    const Self = @This();
    pub const Elem = i64;
    pub const Group = []i64;
    pub const Cursor = LongDeltaCursor;
    pub const instance: Self = .{};

    /// Zero-length groups are allocator-owned: freeable by `deinitGroup`.
    pub fn empty(_: Self, alloc: Allocator) DbError!Group {
        return alloc.alloc(std.meta.Child(Group), 0);
    }
    pub fn size(_: Self, g: *const Group) usize {
        return g.len;
    }
    pub fn compare(_: Self, a: i64, b: i64) Order {
        return std.math.order(a, b);
    }
    pub fn cloneElem(_: Self, _: Allocator, v: i64) DbError!i64 {
        return v;
    }
    pub fn deinitElem(_: Self, _: Allocator, _: i64) void {}
    pub fn get(_: Self, _: Allocator, g: *const Group, pos: usize) DbError!i64 {
        return g.*[pos];
    }
    pub fn search(_: Self, g: *const Group, key: i64) SearchResult {
        return mod.bsearch(i64, g.*, key, {}, cmpI64);
    }
    pub fn insert(_: Self, alloc: Allocator, g: *const Group, pos: usize, v: i64) DbError!Group {
        return mod.sliceInsert(i64, alloc, g.*, pos, v);
    }
    pub fn set(_: Self, alloc: Allocator, g: *const Group, pos: usize, v: i64) DbError!Group {
        const r = try alloc.dupe(i64, g.*);
        r[pos] = v;
        return r;
    }
    pub fn delete(_: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Group {
        return mod.sliceDelete(i64, alloc, g.*, pos);
    }
    pub fn copyRange(_: Self, alloc: Allocator, g: *const Group, from: usize, to: usize) DbError!Group {
        return mod.sliceCopyRange(i64, alloc, g.*, from, to);
    }
    pub fn fromSlice(_: Self, alloc: Allocator, values: []const i64) DbError!Group {
        return alloc.dupe(i64, values);
    }
    pub fn cloneGroup(_: Self, alloc: Allocator, g: *const Group) DbError!Group {
        return alloc.dupe(i64, g.*);
    }
    pub fn deinitGroup(_: Self, alloc: Allocator, g: Group) void {
        alloc.free(g);
    }

    pub fn serializeGroup(_: Self, out: *DataOutput2, g: *const Group) DbError!void {
        var prev: i64 = 0;
        for (g.*) |v| {
            try out.packLong(utf8.zigzag(v -% prev));
            prev = v;
        }
    }
    pub fn deserializeGroup(_: Self, alloc: Allocator, input: *DataInput2, count: usize) DbError!Group {
        // Every packed value is >= 1 byte, so a count beyond the remaining
        // bytes is corruption — checked BEFORE allocating.
        if (count > input.remaining()) return error.DataCorruption;
        const r = try alloc.alloc(i64, count);
        errdefer alloc.free(r);
        var v: i64 = 0;
        for (r) |*slot| {
            v = v +% utf8.unzigzag(try input.unpackLong());
            slot.* = v;
        }
        return r;
    }

    pub fn supportsBinary(_: Self) bool {
        return true;
    }
    pub fn binarySearch(_: Self, _: Allocator, key: i64, input: *DataInput2, count: usize) DbError!SearchResult {
        var v: i64 = 0;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            v = v +% utf8.unzigzag(try input.unpackLong());
            if (v >= key) {
                try input.unpackLongSkip(count - i - 1); // leave input at group end
                return if (v == key) SearchResult{ .found = i } else SearchResult{ .insert = i };
            }
        }
        return .{ .insert = count };
    }
    pub fn binaryGet(_: Self, _: Allocator, input: *DataInput2, count: usize, pos: usize) DbError!i64 {
        if (pos >= count) return error.DataCorruption;
        var v: i64 = 0;
        var i: usize = 0;
        while (i <= pos) : (i += 1) {
            v = v +% utf8.unzigzag(try input.unpackLong());
        }
        try input.unpackLongSkip(count - pos - 1); // leave input at group end
        return v;
    }
    pub fn rangeCursor(_: Self, _: Allocator, input: *DataInput2, count: usize, from: usize, to: usize) DbError!Cursor {
        if (from > to or to > count) return error.DataCorruption;
        return .{ .input = input, .count = count, .to = to, .idx = from };
    }
};

/// Single forward pass over the zigzag stream (O(n) full scan).
pub const LongDeltaCursor = struct {
    input: *DataInput2,
    count: usize,
    to: usize,
    idx: usize,
    started: bool = false,
    decoded: usize = 0,
    acc: i64 = 0,
    cur: i64 = 0,
    exhausted: bool = false,

    fn consumeTo(self: *LongDeltaCursor, count: usize) DbError!void {
        while (self.decoded < count) : (self.decoded += 1) {
            self.acc = self.acc +% utf8.unzigzag(try self.input.unpackLong());
        }
    }
    pub fn next(self: *LongDeltaCursor) DbError!bool {
        if (self.exhausted) return false;
        if (self.started) {
            self.idx += 1;
        } else {
            self.started = true;
        }
        if (self.idx >= self.to) {
            self.exhausted = true;
            try self.consumeTo(self.count);
            return false;
        }
        try self.consumeTo(self.idx + 1);
        self.cur = self.acc;
        return true;
    }
    pub fn index(self: *const LongDeltaCursor) usize {
        return self.idx;
    }
    pub fn value(self: *const LongDeltaCursor, _: Allocator) DbError!i64 {
        return self.cur;
    }
    pub fn deinit(_: *LongDeltaCursor) void {}
};

// ------------------------------------------------------------------- tests

const testing = std.testing;

fn serGroup(comptime F: type, a: Allocator, g: []const i64) ![]u8 {
    var out = DataOutput2.init(a);
    defer out.deinit();
    var group: F.Group = @constCast(g);
    try F.instance.serializeGroup(&out, &group);
    return out.copyBytes(a);
}

fn checkCoherence(comptime F: type, a: Allocator, g: []const i64, probes: []const i64) !void {
    const f = F.instance;
    const bytes = try serGroup(F, a, g);
    defer a.free(bytes);
    var group: F.Group = @constCast(g);
    // round-trip
    var di = DataInput2.init(bytes);
    const back = try f.deserializeGroup(a, &di, g.len);
    defer f.deinitGroup(a, back);
    try testing.expectEqualSlices(i64, g, back);
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
        try testing.expectEqual(g[pos], v);
        try testing.expectEqual(bytes.len, ig.pos);
    }
}

test "long + long-delta coherence" {
    const a = testing.allocator;
    const g = [_]i64{ -100, -1, 0, 1, 2, 5, 42, 1000, std.math.maxInt(i64) };
    const probes = [_]i64{ -100, -50, 0, 3, 42, 999, std.math.maxInt(i64), std.math.minInt(i64) };
    try checkCoherence(LongFormat, a, &g, &probes);
    try checkCoherence(LongDeltaFormat, a, &g, &probes);
}

test "long-delta range cursor positioning" {
    const a = testing.allocator;
    const g = [_]i64{ 10, 20, 30, 40, 50 };
    const bytes = try serGroup(LongDeltaFormat, a, &g);
    defer a.free(bytes);
    var inp = DataInput2.init(bytes);
    var cur = try LongDeltaFormat.instance.rangeCursor(a, &inp, g.len, 1, 4);
    defer cur.deinit();
    var seen = std.ArrayList(i64){};
    defer seen.deinit(a);
    while (try cur.next()) {
        try seen.append(a, try cur.value(a));
        try testing.expect(cur.index() >= 1 and cur.index() < 4);
    }
    try testing.expectEqualSlices(i64, &.{ 20, 30, 40 }, seen.items);
    try testing.expectEqual(bytes.len, inp.pos);
}
