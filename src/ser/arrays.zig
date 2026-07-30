//! Array serializers (Java `Serializers.*_ARRAY` + `ArraySerializer`), MapDB 3
//! parity. Each primitive-array codec is `packInt(len)` + the packed elements;
//! its `Elem` is an OWNED slice `[]T` freed by `deinitElem`. All primitive
//! arrays declare `equalsBySerializedBytes() == true` (canonical encodings; the
//! 620fd6b fix added it to `CHAR_ARRAY`, which the port carries for every
//! sibling). `ObjectArraySerializer(ElemSer)` is the length-framed generic array
//! (Java `ArraySerializer<A>`), whose byte-equality tracks its element codec.
//!
//! Ownership: `cloneElem` deep-copies; `deinitElem` frees element storage
//! then the backing slice. Deserializers validate the declared element count
//! against the real input BEFORE allocating (tainted count → `DataCorruption`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const scalars = @import("serializers.zig");

/// Java `ArraySerializer.MAX_ARRAY_LENGTH`.
pub const MAX_ARRAY_LENGTH: usize = 16_000_000;

/// Read a `packInt` element count and validate it before any allocation: the
/// count must be non-negative, within `MAX_ARRAY_LENGTH`, and its minimum byte
/// footprint (`count * min_elem_bytes`) must fit the record remainder (D4).
fn readArrayLen(input: *DataInput2, min_elem_bytes: usize) DbError!usize {
    const raw = try input.unpackInt();
    if (raw < 0) return error.DataCorruption;
    const count: usize = @intCast(raw);
    if (count > MAX_ARRAY_LENGTH) return error.DataCorruption;
    const floor = std.math.mul(usize, count, min_elem_bytes) catch return error.DataCorruption;
    if (floor > input.remaining()) return error.DataCorruption;
    return count;
}

/// Factory for a fixed-width primitive-array serializer over element serializer
/// `Ser` (which must be a fixed-size scalar). `min_elem_bytes` is the packed
/// element width used for the pre-allocation bound.
fn PrimArraySer(comptime Ser: type, comptime min_elem_bytes: usize) type {
    return struct {
        const Self = @This();
        pub const Elem = []Ser.Elem;
        pub const instance: Self = .{};

        pub fn serialize(_: Self, out: *DataOutput2, v: []Ser.Elem) DbError!void {
            try out.packInt(@intCast(v.len));
            for (v) |e| try Ser.instance.serialize(out, e);
        }
        pub fn deserialize(_: Self, alloc: Allocator, input: *DataInput2, _: ?usize) DbError![]Ser.Elem {
            const count = try readArrayLen(input, min_elem_bytes);
            const r = try alloc.alloc(Ser.Elem, count);
            errdefer alloc.free(r);
            for (r) |*slot| slot.* = try Ser.instance.deserialize(alloc, input, null);
            return r;
        }
        pub fn cloneElem(_: Self, alloc: Allocator, v: []Ser.Elem) DbError![]Ser.Elem {
            return alloc.dupe(Ser.Elem, v);
        }
        pub fn deinitElem(_: Self, alloc: Allocator, v: []Ser.Elem) void {
            alloc.free(v);
        }
        pub fn compare(_: Self, a: []Ser.Elem, b: []Ser.Elem) Order {
            const n = @min(a.len, b.len);
            for (a[0..n], b[0..n]) |x, y| switch (Ser.instance.compare(x, y)) {
                .eq => {},
                else => |o| return o,
            };
            return std.math.order(a.len, b.len);
        }
        pub fn equals(_: Self, a: []Ser.Elem, b: []Ser.Elem) bool {
            if (a.len != b.len) return false;
            for (a, b) |x, y| if (!Ser.instance.equals(x, y)) return false;
            return true;
        }
        pub fn fixedSize(_: Self) ?usize {
            return null;
        }
        pub fn naturalOrder(_: Self) bool {
            return false;
        }
        pub fn equalsBySerializedBytes(_: Self) bool {
            return true;
        }
    };
}

/// `char[]` → `[]u16` (2-byte BE cells).
pub const CharArraySer = PrimArraySer(scalars.CharSer, 2);
/// `short[]` → `[]i16`.
pub const ShortArraySer = PrimArraySer(scalars.ShortSer, 2);
/// `int[]` → `[]i32`.
pub const IntArraySer = PrimArraySer(scalars.IntSer, 4);
/// `long[]` → `[]i64`.
pub const LongArraySer = PrimArraySer(scalars.LongSer, 8);
/// `float[]` → `[]f32`.
pub const FloatArraySer = PrimArraySer(scalars.FloatSer, 4);
/// `double[]` → `[]f64`.
pub const DoubleArraySer = PrimArraySer(scalars.DoubleSer, 8);

/// `long[]` of positive recids (`packLong` per element, min 1 byte each).
pub const RecidArraySer = PrimArraySer(scalars.RecidSer, 1);

/// `boolean[]` → `[]bool`, bit-packed 8 per byte, LSB first (Java `BOOLEAN_ARRAY`).
pub const BooleanArraySer = struct {
    const Self = @This();
    pub const Elem = []bool;
    pub const instance: Self = .{};

    pub fn serialize(_: Self, out: *DataOutput2, v: []bool) DbError!void {
        try out.packInt(@intCast(v.len));
        var offset: usize = 0;
        while (offset < v.len) : (offset += 8) {
            var bits: u8 = 0;
            var bit: usize = 0;
            while (bit < 8 and offset + bit < v.len) : (bit += 1)
                if (v[offset + bit]) {
                    bits |= @as(u8, 1) << @intCast(bit);
                };
            try out.writeU8(bits);
        }
    }
    pub fn deserialize(_: Self, alloc: Allocator, input: *DataInput2, _: ?usize) DbError![]bool {
        const raw = try input.unpackInt();
        if (raw < 0) return error.DataCorruption;
        const count: usize = @intCast(raw);
        if (count > MAX_ARRAY_LENGTH) return error.DataCorruption;
        // ceil(count/8) packed bytes must fit the record remainder.
        const need = (count + 7) / 8;
        if (need > input.remaining()) return error.DataCorruption;
        const r = try alloc.alloc(bool, count);
        errdefer alloc.free(r);
        var offset: usize = 0;
        while (offset < count) : (offset += 8) {
            const bits = try input.readU8();
            var bit: usize = 0;
            while (bit < 8 and offset + bit < count) : (bit += 1)
                r[offset + bit] = (bits & (@as(u8, 1) << @intCast(bit))) != 0;
        }
        return r;
    }
    pub fn cloneElem(_: Self, alloc: Allocator, v: []bool) DbError![]bool {
        return alloc.dupe(bool, v);
    }
    pub fn deinitElem(_: Self, alloc: Allocator, v: []bool) void {
        alloc.free(v);
    }
    pub fn compare(_: Self, a: []bool, b: []bool) Order {
        const n = @min(a.len, b.len);
        for (a[0..n], b[0..n]) |x, y| {
            const o = std.math.order(@intFromBool(x), @intFromBool(y));
            if (o != .eq) return o;
        }
        return std.math.order(a.len, b.len);
    }
    pub fn equals(_: Self, a: []bool, b: []bool) bool {
        return std.mem.eql(bool, a, b);
    }
    pub fn fixedSize(_: Self) ?usize {
        return null;
    }
    pub fn naturalOrder(_: Self) bool {
        return false;
    }
    pub fn equalsBySerializedBytes(_: Self) bool {
        return true;
    }
};

/// Generic length-framed object array (Java `ArraySerializer<A>`), monomorphized
/// over the element serializer `ElemSer`. `Elem` is an OWNED slice whose elements
/// are themselves owned; `deinitElem` frees element storage first, then the slice.
pub fn ObjectArraySerializer(comptime ElemSer: type) type {
    return struct {
        const Self = @This();
        pub const Elem = []ElemSer.Elem;
        pub const instance: Self = .{};
        const E = ElemSer.Elem;

        pub fn serialize(_: Self, out: *DataOutput2, v: []E) DbError!void {
            if (v.len > MAX_ARRAY_LENGTH) return error.DataCorruption;
            try out.packInt(@intCast(v.len));
            for (v) |e| try ElemSer.instance.serialize(out, e);
        }
        pub fn deserialize(_: Self, alloc: Allocator, input: *DataInput2, _: ?usize) DbError![]E {
            // Every element occupies at least 1 byte (framed length prefixes are
            // >= 1 byte); use that as the pre-allocation floor.
            const floor: usize = if (ElemSer.instance.fixedSize()) |f| @max(f, 1) else 1;
            const count = try readArrayLen(input, floor);
            const r = try alloc.alloc(E, count);
            var n: usize = 0;
            errdefer {
                for (r[0..n]) |e| ElemSer.instance.deinitElem(alloc, e);
                alloc.free(r);
            }
            while (n < count) : (n += 1) r[n] = try ElemSer.instance.deserialize(alloc, input, null);
            return r;
        }
        pub fn cloneElem(_: Self, alloc: Allocator, v: []E) DbError![]E {
            const r = try alloc.alloc(E, v.len);
            var n: usize = 0;
            errdefer {
                for (r[0..n]) |e| ElemSer.instance.deinitElem(alloc, e);
                alloc.free(r);
            }
            while (n < v.len) : (n += 1) r[n] = try ElemSer.instance.cloneElem(alloc, v[n]);
            return r;
        }
        pub fn deinitElem(_: Self, alloc: Allocator, v: []E) void {
            for (v) |e| ElemSer.instance.deinitElem(alloc, e);
            alloc.free(v);
        }
        pub fn compare(_: Self, a: []E, b: []E) Order {
            const n = @min(a.len, b.len);
            for (a[0..n], b[0..n]) |x, y| switch (ElemSer.instance.compare(x, y)) {
                .eq => {},
                else => |o| return o,
            };
            return std.math.order(a.len, b.len);
        }
        pub fn equals(_: Self, a: []E, b: []E) bool {
            if (a.len != b.len) return false;
            for (a, b) |x, y| if (!ElemSer.instance.equals(x, y)) return false;
            return true;
        }
        pub fn fixedSize(_: Self) ?usize {
            return null;
        }
        pub fn naturalOrder(_: Self) bool {
            return false;
        }
        /// Tracks the element codec (Java `ArraySerializer.equalsBySerializedBytes`).
        pub fn equalsBySerializedBytes(_: Self) bool {
            return ElemSer.instance.equalsBySerializedBytes();
        }
    };
}

// ------------------------------------------------------------------- tests

const testing = std.testing;
const contracts = @import("mod.zig");

comptime {
    contracts.checkSerializer(CharArraySer, []u16);
    contracts.checkSerializer(BooleanArraySer, []bool);
    contracts.checkSerializer(RecidArraySer, []i64);
    contracts.checkSerializer(ObjectArraySerializer(scalars.StringSer), [][]const u8);
}

fn rtPrim(comptime S: type, v: []const std.meta.Child(S.Elem)) !void {
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try S.instance.serialize(&out, @constCast(v));
    var inp = DataInput2.init(out.bytes());
    const back = try S.instance.deserialize(a, &inp, null);
    defer S.instance.deinitElem(a, back);
    try testing.expectEqual(out.bytes().len, inp.pos);
    try testing.expect(S.instance.equals(@constCast(v), back));
}

test "primitive array round-trips (SerializerParityTest.primitiveArrayRoundTrips)" {
    try rtPrim(BooleanArraySer, &.{ true, false, true, true, false, false, false, true, true });
    try rtPrim(CharArraySer, &.{ 0, 'x', std.math.maxInt(u16) });
    try rtPrim(ShortArraySer, &.{ std.math.minInt(i16), 0, std.math.maxInt(i16) });
    try rtPrim(IntArraySer, &.{ std.math.minInt(i32), 0, std.math.maxInt(i32) });
    try rtPrim(LongArraySer, &.{ std.math.minInt(i64), 0, std.math.maxInt(i64) });
    try rtPrim(FloatArraySer, &.{ -0.0, 1.5, std.math.nan(f32) });
    try rtPrim(DoubleArraySer, &.{ -0.0, 1.5, std.math.nan(f64) });
}

test "RECID_ARRAY round-trip" {
    try rtPrim(RecidArraySer, &.{ 1, 2, std.math.maxInt(i64) });
}

test "ObjectArraySerializer of strings round-trip + hostile length" {
    const a = testing.allocator;
    const ArrS = ObjectArraySerializer(scalars.StringSer);
    var vals = [_][]const u8{ "a", "b" };
    var out = DataOutput2.init(a);
    defer out.deinit();
    try ArrS.instance.serialize(&out, &vals);
    var inp = DataInput2.init(out.bytes());
    const back = try ArrS.instance.deserialize(a, &inp, null);
    defer ArrS.instance.deinitElem(a, back);
    try testing.expect(ArrS.instance.equals(&vals, back));
    try testing.expect(ArrS.instance.equalsBySerializedBytes()); // STRING is canonical

    // hostile length before allocation (parity test case)
    var frame = DataOutput2.init(a);
    defer frame.deinit();
    try frame.packInt(std.math.maxInt(i32));
    var hin = DataInput2.init(frame.bytes());
    try testing.expectError(error.DataCorruption, ArrS.instance.deserialize(a, &hin, null));
}
