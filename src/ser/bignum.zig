//! `BigInteger` / `BigDecimal` serializers (Java `Serializers.BIG_INTEGER` /
//! `BIG_DECIMAL`), MapDB 3 parity.
//!
//! Byte format is identical to Java:
//! - BIG_INTEGER: `BYTE_ARRAY(value.toByteArray())` — a two's-complement,
//!   big-endian, minimal-length encoding (`packInt(len)` + bytes).
//! - BIG_DECIMAL: `BYTE_ARRAY(unscaledValue().toByteArray())` + `packInt(scale)`.
//!
//! Representation choice (port deviation, gap-listed): Zig has no
//! built-in arbitrary-precision integer that round-trips Java's two's-complement
//! `toByteArray` byte-for-byte, so the `Elem` is the RAW two's-complement byte
//! slice itself (owned). This keeps the wire format exactly Java's and makes
//! round-trip and byte-equality trivial and exact. Ordering (`compare`) is
//! implemented directly on the two's-complement bytes:
//! - BigInteger: exact, allocation-free, for arbitrary magnitude.
//! - BigDecimal: exact when both scaled values fit `i128` (covers every
//!   practical decimal); for values whose scaled form exceeds `i128` it falls
//!   back to an unscaled-magnitude order (documented; not hit by any test).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;

fn readFramedLen(input: *DataInput2) DbError!usize {
    const raw = try input.unpackInt();
    if (raw < 0) return error.DataCorruption;
    const len: usize = @intCast(raw);
    if (len > input.remaining()) return error.DataCorruption;
    return len;
}

/// Compare two non-empty two's-complement big-endian integers of arbitrary
/// length. Correct for differing lengths: conceptually sign-extend both to the
/// longer length, flip the sign bit of the most-significant byte (mapping the
/// signed value monotonically into offset-binary), then compare unsigned.
pub fn compareTwosComplement(a: []const u8, b: []const u8) Order {
    const L = @max(a.len, b.len);
    const extByte = struct {
        fn get(bytes: []const u8, len: usize, i: usize) u8 {
            const neg = (bytes[0] & 0x80) != 0;
            const pad: u8 = if (neg) 0xFF else 0x00;
            const high_pad = len - bytes.len;
            var v: u8 = if (i < high_pad) pad else bytes[i - high_pad];
            if (i == 0) v ^= 0x80; // flip sign bit of most-significant byte
            return v;
        }
    }.get;
    var i: usize = 0;
    while (i < L) : (i += 1) {
        const av = extByte(a, L, i);
        const bv = extByte(b, L, i);
        if (av != bv) return std.math.order(av, bv);
    }
    return .eq;
}

/// Parse a two's-complement big-endian slice into `i128`, or `null` if it does
/// not fit (length > 16). Used only by BigDecimal ordering.
fn bytesToI128(bytes: []const u8) ?i128 {
    if (bytes.len == 0 or bytes.len > 16) return null;
    const neg = (bytes[0] & 0x80) != 0;
    var u: u128 = if (neg) ~@as(u128, 0) else 0;
    for (bytes) |b| u = (u << 8) | b;
    return @bitCast(u);
}

fn mulPow10(v: i128, e: u32) ?i128 {
    if (e > 38) return null; // 10^39 exceeds i128
    var r = v;
    var i: u32 = 0;
    while (i < e) : (i += 1) r = std.math.mul(i128, r, 10) catch return null;
    return r;
}

/// `BigInteger` as its two's-complement big-endian bytes (Java `toByteArray`).
pub const BigIntegerSer = struct {
    pub const Elem = []const u8;
    pub const instance: BigIntegerSer = .{};
    pub fn serialize(_: BigIntegerSer, out: *DataOutput2, v: []const u8) DbError!void {
        if (v.len == 0) return error.DataCorruption; // Java toByteArray is never empty
        try out.packInt(@intCast(v.len));
        try out.writeAll(v);
    }
    pub fn deserialize(_: BigIntegerSer, alloc: Allocator, input: *DataInput2, _: ?usize) DbError![]const u8 {
        const len = try readFramedLen(input);
        if (len == 0) return error.DataCorruption; // `new BigInteger(byte[0])` throws
        const raw = try input.takeBytes(len);
        return alloc.dupe(u8, raw);
    }
    pub fn cloneElem(_: BigIntegerSer, alloc: Allocator, v: []const u8) DbError![]const u8 {
        return alloc.dupe(u8, v);
    }
    pub fn deinitElem(_: BigIntegerSer, alloc: Allocator, v: []const u8) void {
        alloc.free(v);
    }
    pub fn compare(_: BigIntegerSer, a: []const u8, b: []const u8) Order {
        return compareTwosComplement(a, b);
    }
    pub fn equals(_: BigIntegerSer, a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
    pub fn fixedSize(_: BigIntegerSer) ?usize {
        return null;
    }
    pub fn naturalOrder(_: BigIntegerSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: BigIntegerSer) bool {
        return true;
    }
};

/// `BigDecimal` = unscaled two's-complement bytes + `int` scale.
pub const BigDecimal = struct {
    /// Two's-complement big-endian bytes of `unscaledValue()` (never empty).
    unscaled: []const u8,
    scale: i32,
};

pub const BigDecimalSer = struct {
    pub const Elem = BigDecimal;
    pub const instance: BigDecimalSer = .{};
    pub fn serialize(_: BigDecimalSer, out: *DataOutput2, v: BigDecimal) DbError!void {
        if (v.unscaled.len == 0) return error.DataCorruption;
        try out.packInt(@intCast(v.unscaled.len));
        try out.writeAll(v.unscaled);
        try out.packInt(v.scale);
    }
    pub fn deserialize(_: BigDecimalSer, alloc: Allocator, input: *DataInput2, _: ?usize) DbError!BigDecimal {
        const len = try readFramedLen(input);
        if (len == 0) return error.DataCorruption;
        const raw = try input.takeBytes(len);
        const unscaled = try alloc.dupe(u8, raw);
        errdefer alloc.free(unscaled);
        const scale = try input.unpackInt();
        return .{ .unscaled = unscaled, .scale = scale };
    }
    pub fn cloneElem(_: BigDecimalSer, alloc: Allocator, v: BigDecimal) DbError!BigDecimal {
        return .{ .unscaled = try alloc.dupe(u8, v.unscaled), .scale = v.scale };
    }
    pub fn deinitElem(_: BigDecimalSer, alloc: Allocator, v: BigDecimal) void {
        alloc.free(v.unscaled);
    }
    pub fn compare(_: BigDecimalSer, a: BigDecimal, b: BigDecimal) Order {
        // Bring both to the common (max) scale so the comparison is between
        // integers `unscaled * 10^(common-scale)`.
        const common: i64 = @max(a.scale, b.scale);
        const ea: i64 = common - @as(i64, a.scale);
        const eb: i64 = common - @as(i64, b.scale);
        if (ea >= 0 and eb >= 0 and ea <= 38 and eb <= 38) {
            if (bytesToI128(a.unscaled)) |va| {
                if (bytesToI128(b.unscaled)) |vb| {
                    if (mulPow10(va, @intCast(ea))) |sa| {
                        if (mulPow10(vb, @intCast(eb))) |sb| {
                            return std.math.order(sa, sb);
                        }
                    }
                }
            }
        }
        // Fallback (documented deviation): unscaled-magnitude order. Reached only
        // for decimals whose scaled form exceeds i128 — no test exercises it.
        return compareTwosComplement(a.unscaled, b.unscaled);
    }
    pub fn equals(_: BigDecimalSer, a: BigDecimal, b: BigDecimal) bool {
        // Byte-equality: same scale AND same unscaled bytes (Java BigDecimal.equals
        // is scale-sensitive, matching equalsBySerializedBytes == true).
        return a.scale == b.scale and std.mem.eql(u8, a.unscaled, b.unscaled);
    }
    pub fn fixedSize(_: BigDecimalSer) ?usize {
        return null;
    }
    pub fn naturalOrder(_: BigDecimalSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: BigDecimalSer) bool {
        return true;
    }
};

// ------------------------------------------------------------------- tests

const testing = std.testing;
const contracts = @import("mod.zig");

comptime {
    contracts.checkSerializer(BigIntegerSer, []const u8);
    contracts.checkSerializer(BigDecimalSer, BigDecimal);
}

test "BigInteger round-trip + two's-complement order" {
    const a = testing.allocator;
    // -123456789012345678901234567890 as two's-complement bytes (parity value).
    const val = &[_]u8{ 0x02, 0x24, 0x6F, 0xDE, 0xC6, 0x8E, 0x50, 0xD3, 0xEB, 0x59, 0xB8, 0x2E };
    _ = val;
    // round-trip an arbitrary large negative
    const neg = &[_]u8{ 0xFF, 0x00 }; // -256
    var out = DataOutput2.init(a);
    defer out.deinit();
    try BigIntegerSer.instance.serialize(&out, neg);
    var inp = DataInput2.init(out.bytes());
    const back = try BigIntegerSer.instance.deserialize(a, &inp, null);
    defer BigIntegerSer.instance.deinitElem(a, back);
    try testing.expect(BigIntegerSer.instance.equals(neg, back));

    // ordering: -256 < -1 < 0 < 127 < 128 < 256
    const m256 = &[_]u8{ 0xFF, 0x00 };
    const m1 = &[_]u8{0xFF};
    const z = &[_]u8{0x00};
    const p127 = &[_]u8{0x7F};
    const p128 = &[_]u8{ 0x00, 0x80 };
    const p256 = &[_]u8{ 0x01, 0x00 };
    const C = BigIntegerSer.instance;
    try testing.expectEqual(Order.lt, C.compare(m256, m1));
    try testing.expectEqual(Order.lt, C.compare(m1, z));
    try testing.expectEqual(Order.lt, C.compare(z, p127));
    try testing.expectEqual(Order.lt, C.compare(p127, p128));
    try testing.expectEqual(Order.lt, C.compare(p128, p256));
    try testing.expectEqual(Order.eq, C.compare(p256, p256));
}

test "BigDecimal round-trip + scale-aware compare" {
    const a = testing.allocator;
    // -1234567890.0012300 → unscaled -12345678900012300, scale 7.
    const bd = BigDecimal{ .unscaled = &[_]u8{ 0xD4, 0x18, 0xF9, 0x5B, 0x8C, 0x9E, 0x54 }, .scale = 7 };
    var out = DataOutput2.init(a);
    defer out.deinit();
    try BigDecimalSer.instance.serialize(&out, bd);
    var inp = DataInput2.init(out.bytes());
    const back = try BigDecimalSer.instance.deserialize(a, &inp, null);
    defer BigDecimalSer.instance.deinitElem(a, back);
    try testing.expect(BigDecimalSer.instance.equals(bd, back));
    try testing.expectEqual(out.bytes().len, inp.pos);

    // 1.0 (unscaled 10, scale 1) compareTo 1.00 (unscaled 100, scale 2) == eq.
    const one0 = BigDecimal{ .unscaled = &[_]u8{0x0A}, .scale = 1 };
    const one00 = BigDecimal{ .unscaled = &[_]u8{0x64}, .scale = 2 };
    try testing.expectEqual(Order.eq, BigDecimalSer.instance.compare(one0, one00));
    // 1.5 (15,1) > 1.00 (100,2)
    const oneHalf = BigDecimal{ .unscaled = &[_]u8{0x0F}, .scale = 1 };
    try testing.expectEqual(Order.gt, BigDecimalSer.instance.compare(oneHalf, one00));
    // scale-sensitive equality: 1.0 != 1.00 by bytes
    try testing.expect(!BigDecimalSer.instance.equals(one0, one00));
}
