//! `ShortFormat`, `CharFormat`, `UuidFormat` — fixed-stride scalar group formats
//! (Java `ShortFormat`/`CharFormat`/`UUIDFormat`), each a stride sibling of
//! `LongFormat`: a packed array of fixed-width big-endian cells giving O(log n)
//! true binary search over serialized bytes. Ported from
//! `mapdb-rust-store/src/ser/scalar.rs`; all three are the shared
//! `FixedStrideFormat` factory over the matching scalar serializer.
//!
//! - `Short` → `i16`, 2-byte BE stride, SIGNED order (decode before compare).
//! - `Character` → `u16`, 2-byte BE stride, UNSIGNED order.
//! - `UUID` → `u128`, 16-byte BE stride, SIGNED msb-then-lsb order.

const mod = @import("mod.zig");
const serializers = @import("serializers.zig");

pub const ShortFormat = mod.FixedStrideFormat(serializers.ShortSer);
pub const CharFormat = mod.FixedStrideFormat(serializers.CharSer);
pub const UuidFormat = mod.FixedStrideFormat(serializers.UuidSer);

const std = @import("std");
const testing = std.testing;
const io = @import("../io.zig");
const uuidFrom = serializers.uuidFrom;

fn serGroup(comptime F: type, a: std.mem.Allocator, g: []const F.Elem) ![]u8 {
    const f = F.instance;
    var out = io.DataOutput2.init(a);
    defer out.deinit();
    var group: F.Group = @constCast(g);
    try f.serializeGroup(&out, &group);
    return out.copyBytes(a);
}

fn checkCoherence(comptime F: type, a: std.mem.Allocator, g: []const F.Elem, probes: []const F.Elem) !void {
    const f = F.instance;
    const bytes = try serGroup(F, a, g);
    defer a.free(bytes);
    var group: F.Group = @constCast(g);
    for (probes) |key| {
        const obj = f.search(&group, key);
        var inp = io.DataInput2.init(bytes);
        const byte_res = try f.binarySearch(a, key, &inp, g.len);
        try testing.expect(obj.eql(byte_res));
        try testing.expectEqual(bytes.len, inp.pos);
    }
    for (0..g.len) |pos| {
        var ig = io.DataInput2.init(bytes);
        const v = try f.binaryGet(a, &ig, g.len, pos);
        defer f.deinitElem(a, v);
        try testing.expectEqual(g[pos], v);
        try testing.expectEqual(bytes.len, ig.pos);
    }
}

test "short format signed order coherence" {
    const a = testing.allocator;
    const g = [_]i16{ std.math.minInt(i16), -30000, -1000, -1, 0, 1, 42, 1000, 30000, std.math.maxInt(i16) };
    const probes = [_]i16{ std.math.minInt(i16), -30001, -30000, -500, -1, 0, 1, 41, 42, 999, 30000, std.math.maxInt(i16), -12345 };
    try checkCoherence(ShortFormat, a, &g, &probes);
}

test "char format unsigned order coherence" {
    const a = testing.allocator;
    const g = [_]u16{ 0, 1, 0x00FF, 0x0100, 0x7FFF, 0x8000, 0xABCD, 0xFFFE, 0xFFFF };
    const probes = [_]u16{ 0, 1, 0x0080, 0x00FF, 0x0100, 0x7FFE, 0x7FFF, 0x8000, 0x8001, 0xABCD, 0xC000, 0xFFFE, 0xFFFF };
    try checkCoherence(CharFormat, a, &g, &probes);
}

test "uuid format signed msb-then-lsb coherence" {
    const a = testing.allocator;
    var g = [_]u128{
        uuidFrom(std.math.minInt(i64), 0), uuidFrom(-1, std.math.minInt(i64)), uuidFrom(-1, -1),
        uuidFrom(-1, 0),                   uuidFrom(-1, std.math.maxInt(i64)), uuidFrom(0, std.math.minInt(i64)),
        uuidFrom(0, -1),                   uuidFrom(0, 0),                     uuidFrom(0, 1),
        uuidFrom(5, -100),                 uuidFrom(5, 100),                   uuidFrom(std.math.maxInt(i64), std.math.maxInt(i64)),
    };
    std.mem.sort(u128, &g, {}, struct {
        fn lt(_: void, x: u128, y: u128) bool {
            return serializers.uuidCompare(x, y) == .lt;
        }
    }.lt);
    const probes = [_]u128{
        uuidFrom(std.math.minInt(i64), std.math.minInt(i64)), uuidFrom(std.math.minInt(i64), 0),
        uuidFrom(-1, -1),                                     uuidFrom(-1, 0),
        uuidFrom(-1, 50),                                     uuidFrom(0, std.math.minInt(i64)),
        uuidFrom(0, 0),                                       uuidFrom(0, 2),
        uuidFrom(5, -100),                                    uuidFrom(5, 0),
        uuidFrom(5, 100),                                     uuidFrom(6, 0),
        uuidFrom(std.math.maxInt(i64), std.math.maxInt(i64)), uuidFrom(std.math.maxInt(i64), std.math.minInt(i64)),
    };
    try checkCoherence(UuidFormat, a, &g, &probes);
}

test "empty scalar group binary_search returns insert(0) at pos 0" {
    const a = testing.allocator;
    const empty: []const i16 = &.{};
    const bytes = try serGroup(ShortFormat, a, empty);
    defer a.free(bytes);
    try testing.expectEqual(@as(usize, 0), bytes.len);
    var inp = io.DataInput2.init(bytes);
    const r = try ShortFormat.instance.binarySearch(a, 5, &inp, 0);
    try testing.expect(r.eql(.{ .insert = 0 }));
    try testing.expectEqual(@as(usize, 0), inp.pos);
}
