//! `IntFormat` and `IntDeltaFormat` — the 32-bit mirror of `long.zig` (Java
//! `IntFormat`, `IntDeltaFormat`). Object side is `[]i32`. Delta stream uses
//! `packInt(zigzag32(delta))`; byte-side skip uses `unpackLongSkip` (a packed
//! int is a packed long). Ported from `mapdb-rust-store/src/ser/int.rs`.

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

/// Fixed 4-byte BE stride; O(log n) true binary search over serialized bytes.
pub const IntFormat = mod.FixedStrideFormat(serializers.IntSer);

fn cmpI32(_: void, a: i32, b: i32) Order {
    return std.math.order(a, b);
}

/// Delta-packed ints. Object side identical to `IntFormat`; byte side sequential.
pub const IntDeltaFormat = struct {
    const Self = @This();
    pub const Elem = i32;
    pub const Group = []i32;
    pub const Cursor = IntDeltaCursor;
    pub const instance: Self = .{};

    /// Zero-length groups are allocator-owned: freeable by `deinitGroup`.
    pub fn empty(_: Self, alloc: Allocator) DbError!Group {
        return alloc.alloc(std.meta.Child(Group), 0);
    }
    pub fn size(_: Self, g: *const Group) usize {
        return g.len;
    }
    pub fn compare(_: Self, a: i32, b: i32) Order {
        return std.math.order(a, b);
    }
    pub fn cloneElem(_: Self, _: Allocator, v: i32) DbError!i32 {
        return v;
    }
    pub fn deinitElem(_: Self, _: Allocator, _: i32) void {}
    pub fn get(_: Self, _: Allocator, g: *const Group, pos: usize) DbError!i32 {
        return g.*[pos];
    }
    pub fn search(_: Self, g: *const Group, key: i32) SearchResult {
        return mod.bsearch(i32, g.*, key, {}, cmpI32);
    }
    pub fn insert(_: Self, alloc: Allocator, g: *const Group, pos: usize, v: i32) DbError!Group {
        return mod.sliceInsert(i32, alloc, g.*, pos, v);
    }
    pub fn set(_: Self, alloc: Allocator, g: *const Group, pos: usize, v: i32) DbError!Group {
        const r = try alloc.dupe(i32, g.*);
        r[pos] = v;
        return r;
    }
    pub fn delete(_: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Group {
        return mod.sliceDelete(i32, alloc, g.*, pos);
    }
    pub fn copyRange(_: Self, alloc: Allocator, g: *const Group, from: usize, to: usize) DbError!Group {
        return mod.sliceCopyRange(i32, alloc, g.*, from, to);
    }
    pub fn fromSlice(_: Self, alloc: Allocator, values: []const i32) DbError!Group {
        return alloc.dupe(i32, values);
    }
    pub fn cloneGroup(_: Self, alloc: Allocator, g: *const Group) DbError!Group {
        return alloc.dupe(i32, g.*);
    }
    pub fn deinitGroup(_: Self, alloc: Allocator, g: Group) void {
        alloc.free(g);
    }

    pub fn serializeGroup(_: Self, out: *DataOutput2, g: *const Group) DbError!void {
        var prev: i32 = 0;
        for (g.*) |v| {
            try out.packInt(utf8.zigzag32(v -% prev));
            prev = v;
        }
    }
    pub fn deserializeGroup(_: Self, alloc: Allocator, input: *DataInput2, count: usize) DbError!Group {
        // Every packed value is >= 1 byte, so a count beyond the remaining
        // bytes is corruption — checked BEFORE allocating.
        if (count > input.remaining()) return error.DataCorruption;
        const r = try alloc.alloc(i32, count);
        errdefer alloc.free(r);
        var v: i32 = 0;
        for (r) |*slot| {
            v = v +% utf8.unzigzag32(try input.unpackInt());
            slot.* = v;
        }
        return r;
    }

    pub fn supportsBinary(_: Self) bool {
        return true;
    }
    pub fn binarySearch(_: Self, _: Allocator, key: i32, input: *DataInput2, count: usize) DbError!SearchResult {
        var v: i32 = 0;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            v = v +% utf8.unzigzag32(try input.unpackInt());
            if (v >= key) {
                try input.unpackLongSkip(count - i - 1); // leave input at group end
                return if (v == key) SearchResult{ .found = i } else SearchResult{ .insert = i };
            }
        }
        return .{ .insert = count };
    }
    pub fn binaryGet(_: Self, _: Allocator, input: *DataInput2, count: usize, pos: usize) DbError!i32 {
        if (pos >= count) return error.DataCorruption;
        var v: i32 = 0;
        var i: usize = 0;
        while (i <= pos) : (i += 1) {
            v = v +% utf8.unzigzag32(try input.unpackInt());
        }
        try input.unpackLongSkip(count - pos - 1); // leave input at group end
        return v;
    }
    pub fn rangeCursor(_: Self, _: Allocator, input: *DataInput2, count: usize, from: usize, to: usize) DbError!Cursor {
        if (from > to or to > count) return error.DataCorruption;
        return .{ .input = input, .count = count, .to = to, .idx = from };
    }
};

pub const IntDeltaCursor = struct {
    input: *DataInput2,
    count: usize,
    to: usize,
    idx: usize,
    started: bool = false,
    decoded: usize = 0,
    acc: i32 = 0,
    cur: i32 = 0,
    exhausted: bool = false,

    fn consumeTo(self: *IntDeltaCursor, count: usize) DbError!void {
        while (self.decoded < count) : (self.decoded += 1) {
            self.acc = self.acc +% utf8.unzigzag32(try self.input.unpackInt());
        }
    }
    pub fn next(self: *IntDeltaCursor) DbError!bool {
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
    pub fn index(self: *const IntDeltaCursor) usize {
        return self.idx;
    }
    pub fn value(self: *const IntDeltaCursor, _: Allocator) DbError!i32 {
        return self.cur;
    }
    pub fn deinit(_: *IntDeltaCursor) void {}
};

// ------------------------------------------------------------------- tests

const testing = std.testing;

fn serGroup(comptime F: type, a: Allocator, g: []const i32) ![]u8 {
    var out = DataOutput2.init(a);
    defer out.deinit();
    var group: F.Group = @constCast(g);
    try F.instance.serializeGroup(&out, &group);
    return out.copyBytes(a);
}

fn checkCoherence(comptime F: type, a: Allocator, g: []const i32, probes: []const i32) !void {
    const f = F.instance;
    const bytes = try serGroup(F, a, g);
    defer a.free(bytes);
    var group: F.Group = @constCast(g);
    var di = DataInput2.init(bytes);
    const back = try f.deserializeGroup(a, &di, g.len);
    defer f.deinitGroup(a, back);
    try testing.expectEqualSlices(i32, g, back);
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

fn trickyGroup() [14]i32 {
    return .{ std.math.minInt(i32), std.math.minInt(i32) + 1, -1_000_000, -100, -1, 0, 1, 2, 5, 42, 1000, 1_000_000, std.math.maxInt(i32) - 1, std.math.maxInt(i32) };
}

test "int + int-delta coherence with overflowing deltas" {
    const a = testing.allocator;
    const g = trickyGroup();
    const probes = [_]i32{ std.math.minInt(i32), std.math.minInt(i32) + 2, -1_000_001, -100, -50, 0, 3, 42, 999, 1_000_000, std.math.maxInt(i32) - 2, std.math.maxInt(i32) };
    try checkCoherence(IntFormat, a, &g, &probes);
    try checkCoherence(IntDeltaFormat, a, &g, &probes);
    // fixed 4-byte stride
    const bytes = try serGroup(IntFormat, a, &g);
    defer a.free(bytes);
    try testing.expectEqual(g.len * 4, bytes.len);
}

test "int-delta single-element extremes" {
    const a = testing.allocator;
    for ([_]i32{ std.math.minInt(i32), std.math.maxInt(i32), -1, 0, 1 }) |v| {
        const g = [_]i32{v};
        const bytes = try serGroup(IntDeltaFormat, a, &g);
        defer a.free(bytes);
        var ig = DataInput2.init(bytes);
        try testing.expectEqual(v, try IntDeltaFormat.instance.binaryGet(a, &ig, 1, 0));
        try testing.expectEqual(bytes.len, ig.pos);
        var sb = DataInput2.init(bytes);
        try testing.expect((try IntDeltaFormat.instance.binarySearch(a, v, &sb, 1)).eql(.{ .found = 0 }));
        try testing.expectEqual(bytes.len, sb.pos);
    }
}
