//! Built-in element serializers (Java `Serializers`), ported
//! from `mapdb-rust-store/src/ser/serializers.rs`.
//!
//! Java → Zig type map: `Short`→`i16`, `Character`→`u16`, `Integer`→`i32`,
//! `Long`→`i64`, `UUID`→`u128` (msb/lsb signed-pair compare), `String`→owned
//! `[]const u8` (valid UTF-8), `byte[]`→owned `[]const u8`. All built-ins are
//! zero-sized structs with `pub const instance` and `equalsBySerializedBytes()
//! == true`.
//!
//! Ownership: scalar `cloneElem`/`deinitElem` are copies/no-ops; the
//! slice-valued serializers (`StringSer`, `ByteArray*Ser`) return OWNED slices
//! that `deinitElem` frees. Zero-length results are allocator-owned.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const utf8 = @import("utf8.zig");

/// Read a packed length prefix and validate it against the record BEFORE it is
/// used to size an allocation (D4). Java `new byte[len]` throws on a negative
/// length; we reject `len < 0` and any `len` beyond the bytes left in the
/// record, so a tiny corrupt record cannot provoke a giant reservation.
fn readFramedLen(input: *DataInput2) DbError!usize {
    const raw = try input.unpackInt();
    if (raw < 0) return error.DataCorruption;
    const len: usize = @intCast(raw);
    if (len > input.remaining()) return error.DataCorruption;
    return len;
}

/// Signed msb-then-lsb compare of two UUIDs packed as `u128` (`UUID.compareTo`).
pub fn uuidCompare(a: u128, b: u128) Order {
    const amsb: i64 = @bitCast(@as(u64, @truncate(a >> 64)));
    const bmsb: i64 = @bitCast(@as(u64, @truncate(b >> 64)));
    if (amsb != bmsb) return std.math.order(amsb, bmsb);
    const alsb: i64 = @bitCast(@as(u64, @truncate(a)));
    const blsb: i64 = @bitCast(@as(u64, @truncate(b)));
    return std.math.order(alsb, blsb);
}

/// Build a `u128` UUID from a signed msb/lsb pair (test/helper convenience).
pub fn uuidFrom(msb: i64, lsb: i64) u128 {
    const hi: u128 = @as(u64, @bitCast(msb));
    const lo: u128 = @as(u64, @bitCast(lsb));
    return (hi << 64) | lo;
}

// ------------------------------------------------------------------- scalars

pub const ShortSer = struct {
    pub const Elem = i16;
    pub const instance: ShortSer = .{};
    pub fn serialize(_: ShortSer, out: *DataOutput2, v: i16) DbError!void {
        try out.writeI16(v);
    }
    pub fn deserialize(_: ShortSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!i16 {
        return input.readI16();
    }
    pub fn cloneElem(_: ShortSer, _: Allocator, v: i16) DbError!i16 {
        return v;
    }
    pub fn deinitElem(_: ShortSer, _: Allocator, _: i16) void {}
    pub fn compare(_: ShortSer, a: i16, b: i16) Order {
        return std.math.order(a, b);
    }
    pub fn equals(_: ShortSer, a: i16, b: i16) bool {
        return a == b;
    }
    pub fn fixedSize(_: ShortSer) ?usize {
        return 2;
    }
    pub fn naturalOrder(_: ShortSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: ShortSer) bool {
        return true;
    }
};

pub const CharSer = struct {
    pub const Elem = u16;
    pub const instance: CharSer = .{};
    pub fn serialize(_: CharSer, out: *DataOutput2, v: u16) DbError!void {
        try out.writeU16(v);
    }
    pub fn deserialize(_: CharSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!u16 {
        return input.readU16();
    }
    pub fn cloneElem(_: CharSer, _: Allocator, v: u16) DbError!u16 {
        return v;
    }
    pub fn deinitElem(_: CharSer, _: Allocator, _: u16) void {}
    pub fn compare(_: CharSer, a: u16, b: u16) Order {
        return std.math.order(a, b);
    }
    pub fn equals(_: CharSer, a: u16, b: u16) bool {
        return a == b;
    }
    pub fn fixedSize(_: CharSer) ?usize {
        return 2;
    }
    pub fn naturalOrder(_: CharSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: CharSer) bool {
        return true;
    }
};

pub const IntSer = struct {
    pub const Elem = i32;
    pub const instance: IntSer = .{};
    pub fn serialize(_: IntSer, out: *DataOutput2, v: i32) DbError!void {
        try out.writeI32(v);
    }
    pub fn deserialize(_: IntSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!i32 {
        return input.readI32();
    }
    pub fn cloneElem(_: IntSer, _: Allocator, v: i32) DbError!i32 {
        return v;
    }
    pub fn deinitElem(_: IntSer, _: Allocator, _: i32) void {}
    pub fn compare(_: IntSer, a: i32, b: i32) Order {
        return std.math.order(a, b);
    }
    pub fn equals(_: IntSer, a: i32, b: i32) bool {
        return a == b;
    }
    pub fn fixedSize(_: IntSer) ?usize {
        return 4;
    }
    pub fn naturalOrder(_: IntSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: IntSer) bool {
        return true;
    }
};

pub const LongSer = struct {
    pub const Elem = i64;
    pub const instance: LongSer = .{};
    pub fn serialize(_: LongSer, out: *DataOutput2, v: i64) DbError!void {
        try out.writeI64(v);
    }
    pub fn deserialize(_: LongSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!i64 {
        return input.readI64();
    }
    pub fn cloneElem(_: LongSer, _: Allocator, v: i64) DbError!i64 {
        return v;
    }
    pub fn deinitElem(_: LongSer, _: Allocator, _: i64) void {}
    pub fn compare(_: LongSer, a: i64, b: i64) Order {
        return std.math.order(a, b);
    }
    pub fn equals(_: LongSer, a: i64, b: i64) bool {
        return a == b;
    }
    pub fn fixedSize(_: LongSer) ?usize {
        return 8;
    }
    pub fn naturalOrder(_: LongSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: LongSer) bool {
        return true;
    }
};

/// 16-byte UUID: `msb` then `lsb`, each big-endian; `u128` on the wire = the two
/// halves in big-endian order. Signed msb-then-lsb order (`UUID.compareTo`).
pub const UuidSer = struct {
    pub const Elem = u128;
    pub const instance: UuidSer = .{};
    pub fn serialize(_: UuidSer, out: *DataOutput2, v: u128) DbError!void {
        try out.writeU64(@truncate(v >> 64));
        try out.writeU64(@truncate(v));
    }
    pub fn deserialize(_: UuidSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!u128 {
        const hi: u128 = try input.readU64();
        const lo: u128 = try input.readU64();
        return (hi << 64) | lo;
    }
    pub fn cloneElem(_: UuidSer, _: Allocator, v: u128) DbError!u128 {
        return v;
    }
    pub fn deinitElem(_: UuidSer, _: Allocator, _: u128) void {}
    pub fn compare(_: UuidSer, a: u128, b: u128) Order {
        return uuidCompare(a, b);
    }
    pub fn equals(_: UuidSer, a: u128, b: u128) bool {
        return a == b;
    }
    pub fn fixedSize(_: UuidSer) ?usize {
        return 16;
    }
    pub fn naturalOrder(_: UuidSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: UuidSer) bool {
        return true;
    }
};

// -------------------------------------------------------------- string/bytes

/// `packInt(utf8len)` + UTF-8 bytes; UTF-16 code-unit order (`String.compareTo`).
/// serialize requires valid UTF-8 (D9.1); deserialize is LOSSY (U+FFFD).
pub const StringSer = struct {
    pub const Elem = []const u8;
    pub const instance: StringSer = .{};
    pub fn serialize(_: StringSer, out: *DataOutput2, v: []const u8) DbError!void {
        if (!std.unicode.utf8ValidateSlice(v)) return error.DataCorruption;
        try out.packInt(@intCast(v.len));
        try out.writeAll(v);
    }
    pub fn deserialize(_: StringSer, alloc: Allocator, input: *DataInput2, _: ?usize) DbError![]const u8 {
        const len = try readFramedLen(input);
        const raw = try input.takeBytes(len);
        return utf8.utf8Lossy(alloc, raw);
    }
    pub fn cloneElem(_: StringSer, alloc: Allocator, v: []const u8) DbError![]const u8 {
        return alloc.dupe(u8, v);
    }
    pub fn deinitElem(_: StringSer, alloc: Allocator, v: []const u8) void {
        alloc.free(v);
    }
    pub fn compare(_: StringSer, a: []const u8, b: []const u8) Order {
        return utf8.compareUtf16(a, b);
    }
    pub fn equals(_: StringSer, a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
    pub fn fixedSize(_: StringSer) ?usize {
        return null;
    }
    pub fn naturalOrder(_: StringSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: StringSer) bool {
        return true;
    }
};

/// `packInt(len)` + bytes; SIGNED lexicographic order (`Arrays.compare`).
pub const ByteArraySer = struct {
    pub const Elem = []const u8;
    pub const instance: ByteArraySer = .{};
    pub fn serialize(_: ByteArraySer, out: *DataOutput2, v: []const u8) DbError!void {
        try out.packInt(@intCast(v.len));
        try out.writeAll(v);
    }
    pub fn deserialize(_: ByteArraySer, alloc: Allocator, input: *DataInput2, _: ?usize) DbError![]const u8 {
        const len = try readFramedLen(input);
        const raw = try input.takeBytes(len);
        return alloc.dupe(u8, raw);
    }
    pub fn cloneElem(_: ByteArraySer, alloc: Allocator, v: []const u8) DbError![]const u8 {
        return alloc.dupe(u8, v);
    }
    pub fn deinitElem(_: ByteArraySer, alloc: Allocator, v: []const u8) void {
        alloc.free(v);
    }
    pub fn compare(_: ByteArraySer, a: []const u8, b: []const u8) Order {
        return utf8.compareSignedBytes(a, b);
    }
    pub fn equals(_: ByteArraySer, a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
    pub fn fixedSize(_: ByteArraySer) ?usize {
        return null;
    }
    pub fn naturalOrder(_: ByteArraySer) bool {
        return false;
    }
    pub fn equalsBySerializedBytes(_: ByteArraySer) bool {
        return true;
    }
};

/// Same wire/equality as `ByteArraySer` but UNSIGNED (`memcmp`) order.
pub const ByteArrayUnsignedSer = struct {
    pub const Elem = []const u8;
    pub const instance: ByteArrayUnsignedSer = .{};
    pub fn serialize(_: ByteArrayUnsignedSer, out: *DataOutput2, v: []const u8) DbError!void {
        try ByteArraySer.instance.serialize(out, v);
    }
    pub fn deserialize(_: ByteArrayUnsignedSer, alloc: Allocator, input: *DataInput2, size: ?usize) DbError![]const u8 {
        return ByteArraySer.instance.deserialize(alloc, input, size);
    }
    pub fn cloneElem(_: ByteArrayUnsignedSer, alloc: Allocator, v: []const u8) DbError![]const u8 {
        return alloc.dupe(u8, v);
    }
    pub fn deinitElem(_: ByteArrayUnsignedSer, alloc: Allocator, v: []const u8) void {
        alloc.free(v);
    }
    pub fn compare(_: ByteArrayUnsignedSer, a: []const u8, b: []const u8) Order {
        return utf8.compareUnsignedBytes(a, b);
    }
    pub fn equals(_: ByteArrayUnsignedSer, a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
    pub fn fixedSize(_: ByteArrayUnsignedSer) ?usize {
        return null;
    }
    pub fn naturalOrder(_: ByteArrayUnsignedSer) bool {
        return false;
    }
    pub fn equalsBySerializedBytes(_: ByteArrayUnsignedSer) bool {
        return true;
    }
};

// ------------------------------------------------- more scalars (MapDB 3 parity)
//
// Ported from Java `org.mapdb.ser.Serializers` (post-620fd6b). Java→Zig type
// map: `Boolean`→`bool`, `Byte`→`i8`, `Float`→`f32`, `Double`→`f64`,
// packed `Integer`/`Long`→`i32`/`i64`, `Date`→`i64` (epoch millis), `recid`→
// `i64` (positive). All are zero-sized with `pub const instance`.

/// Canonical `Float.floatToIntBits`: every NaN collapses to `0x7fc00000` so the
/// wire form (and hence byte-equality) is canonical.
pub fn floatToIntBits(v: f32) u32 {
    if (std.math.isNan(v)) return 0x7fc00000;
    return @bitCast(v);
}
/// Canonical `Double.doubleToLongBits`: every NaN collapses to
/// `0x7ff8000000000000`.
pub fn doubleToLongBits(v: f64) u64 {
    if (std.math.isNan(v)) return 0x7ff8000000000000;
    return @bitCast(v);
}

/// `Float.compare` total order: `-0.0f < +0.0f`, NaN greater than everything.
pub fn floatCompare(a: f32, b: f32) Order {
    if (a < b) return .lt;
    if (a > b) return .gt;
    const ab: i32 = @bitCast(floatToIntBits(a));
    const bb: i32 = @bitCast(floatToIntBits(b));
    return std.math.order(ab, bb);
}
/// `Double.compare` total order (`-0.0 < +0.0`, NaN greatest).
pub fn doubleCompare(a: f64, b: f64) Order {
    if (a < b) return .lt;
    if (a > b) return .gt;
    const ab: i64 = @bitCast(doubleToLongBits(a));
    const bb: i64 = @bitCast(doubleToLongBits(b));
    return std.math.order(ab, bb);
}

pub const BoolSer = struct {
    pub const Elem = bool;
    pub const instance: BoolSer = .{};
    pub fn serialize(_: BoolSer, out: *DataOutput2, v: bool) DbError!void {
        try out.writeU8(if (v) 1 else 0);
    }
    pub fn deserialize(_: BoolSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!bool {
        const b = try input.readU8();
        if (b > 1) return error.DataCorruption; // Java throws IllegalArgumentException
        return b != 0;
    }
    pub fn cloneElem(_: BoolSer, _: Allocator, v: bool) DbError!bool {
        return v;
    }
    pub fn deinitElem(_: BoolSer, _: Allocator, _: bool) void {}
    pub fn compare(_: BoolSer, a: bool, b: bool) Order {
        return std.math.order(@intFromBool(a), @intFromBool(b));
    }
    pub fn equals(_: BoolSer, a: bool, b: bool) bool {
        return a == b;
    }
    pub fn fixedSize(_: BoolSer) ?usize {
        return 1;
    }
    pub fn naturalOrder(_: BoolSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: BoolSer) bool {
        return true;
    }
};

pub const ByteSer = struct {
    pub const Elem = i8;
    pub const instance: ByteSer = .{};
    pub fn serialize(_: ByteSer, out: *DataOutput2, v: i8) DbError!void {
        try out.writeU8(@bitCast(v));
    }
    pub fn deserialize(_: ByteSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!i8 {
        return input.readI8();
    }
    pub fn cloneElem(_: ByteSer, _: Allocator, v: i8) DbError!i8 {
        return v;
    }
    pub fn deinitElem(_: ByteSer, _: Allocator, _: i8) void {}
    pub fn compare(_: ByteSer, a: i8, b: i8) Order {
        return std.math.order(a, b);
    }
    pub fn equals(_: ByteSer, a: i8, b: i8) bool {
        return a == b;
    }
    pub fn fixedSize(_: ByteSer) ?usize {
        return 1;
    }
    pub fn naturalOrder(_: ByteSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: ByteSer) bool {
        return true;
    }
};

pub const FloatSer = struct {
    pub const Elem = f32;
    pub const instance: FloatSer = .{};
    pub fn serialize(_: FloatSer, out: *DataOutput2, v: f32) DbError!void {
        try out.writeU32(floatToIntBits(v));
    }
    pub fn deserialize(_: FloatSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!f32 {
        return @bitCast(try input.readI32());
    }
    pub fn cloneElem(_: FloatSer, _: Allocator, v: f32) DbError!f32 {
        return v;
    }
    pub fn deinitElem(_: FloatSer, _: Allocator, _: f32) void {}
    pub fn compare(_: FloatSer, a: f32, b: f32) Order {
        return floatCompare(a, b);
    }
    pub fn equals(_: FloatSer, a: f32, b: f32) bool {
        return floatToIntBits(a) == floatToIntBits(b);
    }
    pub fn fixedSize(_: FloatSer) ?usize {
        return 4;
    }
    pub fn naturalOrder(_: FloatSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: FloatSer) bool {
        return true;
    }
};

pub const DoubleSer = struct {
    pub const Elem = f64;
    pub const instance: DoubleSer = .{};
    pub fn serialize(_: DoubleSer, out: *DataOutput2, v: f64) DbError!void {
        try out.writeU64(doubleToLongBits(v));
    }
    pub fn deserialize(_: DoubleSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!f64 {
        return @bitCast(try input.readU64());
    }
    pub fn cloneElem(_: DoubleSer, _: Allocator, v: f64) DbError!f64 {
        return v;
    }
    pub fn deinitElem(_: DoubleSer, _: Allocator, _: f64) void {}
    pub fn compare(_: DoubleSer, a: f64, b: f64) Order {
        return doubleCompare(a, b);
    }
    pub fn equals(_: DoubleSer, a: f64, b: f64) bool {
        return doubleToLongBits(a) == doubleToLongBits(b);
    }
    pub fn fixedSize(_: DoubleSer) ?usize {
        return 8;
    }
    pub fn naturalOrder(_: DoubleSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: DoubleSer) bool {
        return true;
    }
};

/// Packed two's-complement `Integer` (`packInt`/`unpackInt`); negatives use 5 bytes.
pub const IntPackedSer = struct {
    pub const Elem = i32;
    pub const instance: IntPackedSer = .{};
    pub fn serialize(_: IntPackedSer, out: *DataOutput2, v: i32) DbError!void {
        try out.packInt(v);
    }
    pub fn deserialize(_: IntPackedSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!i32 {
        return input.unpackInt();
    }
    pub fn cloneElem(_: IntPackedSer, _: Allocator, v: i32) DbError!i32 {
        return v;
    }
    pub fn deinitElem(_: IntPackedSer, _: Allocator, _: i32) void {}
    pub fn compare(_: IntPackedSer, a: i32, b: i32) Order {
        return std.math.order(a, b);
    }
    pub fn equals(_: IntPackedSer, a: i32, b: i32) bool {
        return a == b;
    }
    pub fn fixedSize(_: IntPackedSer) ?usize {
        return null;
    }
    pub fn naturalOrder(_: IntPackedSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: IntPackedSer) bool {
        return true;
    }
};

/// Packed two's-complement `Long` (`packLong`/`unpackLong`); negatives use 10 bytes.
pub const LongPackedSer = struct {
    pub const Elem = i64;
    pub const instance: LongPackedSer = .{};
    pub fn serialize(_: LongPackedSer, out: *DataOutput2, v: i64) DbError!void {
        try out.packLong(@bitCast(v));
    }
    pub fn deserialize(_: LongPackedSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!i64 {
        return @bitCast(try input.unpackLong());
    }
    pub fn cloneElem(_: LongPackedSer, _: Allocator, v: i64) DbError!i64 {
        return v;
    }
    pub fn deinitElem(_: LongPackedSer, _: Allocator, _: i64) void {}
    pub fn compare(_: LongPackedSer, a: i64, b: i64) Order {
        return std.math.order(a, b);
    }
    pub fn equals(_: LongPackedSer, a: i64, b: i64) bool {
        return a == b;
    }
    pub fn fixedSize(_: LongPackedSer) ?usize {
        return null;
    }
    pub fn naturalOrder(_: LongPackedSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: LongPackedSer) bool {
        return true;
    }
};

/// Positive record id encoded as a packed long (Java `RECID`); rejects `<= 0`.
pub const RecidSer = struct {
    pub const Elem = i64;
    pub const instance: RecidSer = .{};
    pub fn serialize(_: RecidSer, out: *DataOutput2, v: i64) DbError!void {
        if (v <= 0) return error.DataCorruption; // Java throws IllegalArgumentException
        try out.packLong(@bitCast(v));
    }
    pub fn deserialize(_: RecidSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!i64 {
        const raw = try input.unpackLong();
        if (raw == 0 or raw > std.math.maxInt(i64)) return error.DataCorruption;
        return @bitCast(raw);
    }
    pub fn cloneElem(_: RecidSer, _: Allocator, v: i64) DbError!i64 {
        return v;
    }
    pub fn deinitElem(_: RecidSer, _: Allocator, _: i64) void {}
    pub fn compare(_: RecidSer, a: i64, b: i64) Order {
        return std.math.order(a, b);
    }
    pub fn equals(_: RecidSer, a: i64, b: i64) bool {
        return a == b;
    }
    pub fn fixedSize(_: RecidSer) ?usize {
        return null;
    }
    pub fn naturalOrder(_: RecidSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: RecidSer) bool {
        return true;
    }
};

/// `Date` as epoch millis (`writeLong(getTime())`).
pub const DateSer = struct {
    pub const Elem = i64;
    pub const instance: DateSer = .{};
    pub fn serialize(_: DateSer, out: *DataOutput2, v: i64) DbError!void {
        try out.writeI64(v);
    }
    pub fn deserialize(_: DateSer, _: Allocator, input: *DataInput2, _: ?usize) DbError!i64 {
        return input.readI64();
    }
    pub fn cloneElem(_: DateSer, _: Allocator, v: i64) DbError!i64 {
        return v;
    }
    pub fn deinitElem(_: DateSer, _: Allocator, _: i64) void {}
    pub fn compare(_: DateSer, a: i64, b: i64) Order {
        return std.math.order(a, b);
    }
    pub fn equals(_: DateSer, a: i64, b: i64) bool {
        return a == b;
    }
    pub fn fixedSize(_: DateSer) ?usize {
        return 8;
    }
    pub fn naturalOrder(_: DateSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: DateSer) bool {
        return true;
    }
};

// ------------------------------------------- record-length-framed string/bytes
//
// `*_NOSIZE` codecs occupy the WHOLE record with no inner length prefix, so
// deserialize REQUIRES the record size (Java throws when `size < 0`; we map the
// unknown `size == null` to `error.DataCorruption`). STRING_ASCII rejects any
// byte outside 0x00..0x7F on serialize.

/// Raw record bytes, no inner length prefix (Java `BYTE_ARRAY_NOSIZE`).
pub const ByteArrayNoSizeSer = struct {
    pub const Elem = []const u8;
    pub const instance: ByteArrayNoSizeSer = .{};
    pub fn serialize(_: ByteArrayNoSizeSer, out: *DataOutput2, v: []const u8) DbError!void {
        try out.writeAll(v);
    }
    pub fn deserialize(_: ByteArrayNoSizeSer, alloc: Allocator, input: *DataInput2, size: ?usize) DbError![]const u8 {
        const n = size orelse return error.DataCorruption;
        const raw = try input.takeBytes(n);
        return alloc.dupe(u8, raw);
    }
    pub fn cloneElem(_: ByteArrayNoSizeSer, alloc: Allocator, v: []const u8) DbError![]const u8 {
        return alloc.dupe(u8, v);
    }
    pub fn deinitElem(_: ByteArrayNoSizeSer, alloc: Allocator, v: []const u8) void {
        alloc.free(v);
    }
    pub fn compare(_: ByteArrayNoSizeSer, a: []const u8, b: []const u8) Order {
        return utf8.compareSignedBytes(a, b);
    }
    pub fn equals(_: ByteArrayNoSizeSer, a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
    pub fn fixedSize(_: ByteArrayNoSizeSer) ?usize {
        return null;
    }
    pub fn naturalOrder(_: ByteArrayNoSizeSer) bool {
        return false;
    }
    pub fn equalsBySerializedBytes(_: ByteArrayNoSizeSer) bool {
        return true;
    }
};

/// UTF-8 occupying the whole record, no inner length prefix (`STRING_NOSIZE`).
pub const StringNoSizeSer = struct {
    pub const Elem = []const u8;
    pub const instance: StringNoSizeSer = .{};
    pub fn serialize(_: StringNoSizeSer, out: *DataOutput2, v: []const u8) DbError!void {
        if (!std.unicode.utf8ValidateSlice(v)) return error.DataCorruption;
        try out.writeAll(v);
    }
    pub fn deserialize(_: StringNoSizeSer, alloc: Allocator, input: *DataInput2, size: ?usize) DbError![]const u8 {
        const n = size orelse return error.DataCorruption;
        const raw = try input.takeBytes(n);
        return utf8.utf8Lossy(alloc, raw);
    }
    pub fn cloneElem(_: StringNoSizeSer, alloc: Allocator, v: []const u8) DbError![]const u8 {
        return alloc.dupe(u8, v);
    }
    pub fn deinitElem(_: StringNoSizeSer, alloc: Allocator, v: []const u8) void {
        alloc.free(v);
    }
    pub fn compare(_: StringNoSizeSer, a: []const u8, b: []const u8) Order {
        return utf8.compareUtf16(a, b);
    }
    pub fn equals(_: StringNoSizeSer, a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
    pub fn fixedSize(_: StringNoSizeSer) ?usize {
        return null;
    }
    pub fn naturalOrder(_: StringNoSizeSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: StringNoSizeSer) bool {
        return true;
    }
};

/// Seven-bit ASCII string: `packInt(len)` + one byte per char (`STRING_ASCII`).
/// serialize rejects any byte > 0x7F.
pub const StringAsciiSer = struct {
    pub const Elem = []const u8;
    pub const instance: StringAsciiSer = .{};
    pub fn serialize(_: StringAsciiSer, out: *DataOutput2, v: []const u8) DbError!void {
        for (v) |c| if (c > 0x7F) return error.DataCorruption;
        try out.packInt(@intCast(v.len));
        try out.writeAll(v);
    }
    pub fn deserialize(_: StringAsciiSer, alloc: Allocator, input: *DataInput2, _: ?usize) DbError![]const u8 {
        const len = try readFramedLen(input);
        const raw = try input.takeBytes(len);
        return alloc.dupe(u8, raw);
    }
    pub fn cloneElem(_: StringAsciiSer, alloc: Allocator, v: []const u8) DbError![]const u8 {
        return alloc.dupe(u8, v);
    }
    pub fn deinitElem(_: StringAsciiSer, alloc: Allocator, v: []const u8) void {
        alloc.free(v);
    }
    pub fn compare(_: StringAsciiSer, a: []const u8, b: []const u8) Order {
        return utf8.compareUtf16(a, b);
    }
    pub fn equals(_: StringAsciiSer, a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
    pub fn fixedSize(_: StringAsciiSer) ?usize {
        return null;
    }
    pub fn naturalOrder(_: StringAsciiSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: StringAsciiSer) bool {
        return true;
    }
};

// ------------------------------------------------------------------- tests

const testing = std.testing;

fn roundtripScalar(comptime S: type, v: S.Elem) !void {
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try S.instance.serialize(&out, v);
    var inp = DataInput2.init(out.bytes());
    const back = try S.instance.deserialize(a, &inp, null);
    S.instance.deinitElem(a, back);
    try testing.expect(S.instance.equals(v, back));
    try testing.expectEqual(out.bytes().len, inp.pos);
}

test "scalar serializers round-trip" {
    try roundtripScalar(ShortSer, -12345);
    try roundtripScalar(CharSer, 0xABCD);
    try roundtripScalar(IntSer, -1);
    try roundtripScalar(LongSer, std.math.minInt(i64));
    try roundtripScalar(UuidSer, uuidFrom(-1, 5));
}

test "uuid signed msb-then-lsb order" {
    try testing.expectEqual(Order.lt, uuidCompare(uuidFrom(-1, 0), uuidFrom(0, 0)));
    try testing.expectEqual(Order.lt, uuidCompare(uuidFrom(std.math.minInt(i64), 0), uuidFrom(-1, 0)));
    try testing.expectEqual(Order.lt, uuidCompare(uuidFrom(5, -100), uuidFrom(5, 100)));
    try testing.expectEqual(Order.eq, uuidCompare(uuidFrom(7, 7), uuidFrom(7, 7)));
}

test "string serializer lossy decode + golden bytes" {
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try StringSer.instance.serialize(&out, "hi");
    // packInt(2) == 0x82, then 'h','i'
    try testing.expectEqualSlices(u8, &.{ 0x82, 'h', 'i' }, out.bytes());
    var inp = DataInput2.init(out.bytes());
    const back = try StringSer.instance.deserialize(a, &inp, null);
    defer StringSer.instance.deinitElem(a, back);
    try testing.expectEqualStrings("hi", back);
}

test "string serialize rejects invalid utf8" {
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try testing.expectError(error.DataCorruption, StringSer.instance.serialize(&out, &[_]u8{0x80}));
}

test "bytearray signed vs unsigned order" {
    const hi = &[_]u8{0x80};
    const lo = &[_]u8{0x7f};
    // signed: 0x80 == -128 < 0x7f
    try testing.expectEqual(Order.lt, ByteArraySer.instance.compare(hi, lo));
    // unsigned: 0x80 > 0x7f
    try testing.expectEqual(Order.gt, ByteArrayUnsignedSer.instance.compare(hi, lo));
}

test "framed len rejects garbage before allocating" {
    // packInt(-1) → huge unsigned len that exceeds remaining → DataCorruption.
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try out.packInt(1000); // claims 1000 bytes but none follow
    var inp = DataInput2.init(out.bytes());
    try testing.expectError(error.DataCorruption, ByteArraySer.instance.deserialize(a, &inp, null));
}

// ---- new-scalar parity (SerializerParityTest.scalarAndPackedRoundTrips) ----

fn rtScalarNoSize(comptime S: type, v: S.Elem) !void {
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try S.instance.serialize(&out, v);
    var inp = DataInput2.init(out.bytes());
    const back = try S.instance.deserialize(a, &inp, null);
    S.instance.deinitElem(a, back);
    try testing.expect(S.instance.equals(v, back));
    try testing.expectEqual(out.bytes().len, inp.pos);
}

fn rtSlice(comptime S: type, v: []const u8, size: ?usize) !void {
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try S.instance.serialize(&out, v);
    const sz = size orelse out.bytes().len;
    var inp = DataInput2.init(out.bytes());
    const back = try S.instance.deserialize(a, &inp, sz);
    defer S.instance.deinitElem(a, back);
    try testing.expect(S.instance.equals(v, back));
}

test "BOOLEAN/BYTE/FLOAT/DOUBLE round-trips" {
    try rtScalarNoSize(BoolSer, true);
    try rtScalarNoSize(BoolSer, false);
    try rtScalarNoSize(ByteSer, -128);
    try rtScalarNoSize(ByteSer, 127);
    try rtScalarNoSize(FloatSer, -0.0);
    try rtScalarNoSize(FloatSer, std.math.nan(f32));
    try rtScalarNoSize(DoubleSer, std.math.nan(f64));
    try rtScalarNoSize(DoubleSer, -0.0);
    // -0.0f golden: floatToIntBits == 0x80000000
    var out = DataOutput2.init(testing.allocator);
    defer out.deinit();
    try FloatSer.instance.serialize(&out, -0.0);
    try testing.expectEqualSlices(u8, &.{ 0x80, 0, 0, 0 }, out.bytes());
}

test "BOOLEAN rejects byte > 1" {
    var inp = DataInput2.init(&.{2});
    try testing.expectError(error.DataCorruption, BoolSer.instance.deserialize(testing.allocator, &inp, null));
}

test "float/double compare total order (-0<+0, NaN greatest)" {
    try testing.expectEqual(Order.lt, floatCompare(-0.0, 0.0));
    try testing.expectEqual(Order.gt, floatCompare(std.math.nan(f32), std.math.inf(f32)));
    try testing.expectEqual(Order.lt, doubleCompare(-0.0, 0.0));
    try testing.expectEqual(Order.gt, doubleCompare(std.math.nan(f64), std.math.inf(f64)));
    // NaN equals NaN by bits (canonicalized)
    try testing.expect(FloatSer.instance.equals(std.math.nan(f32), std.math.nan(f32)));
    try testing.expect(!FloatSer.instance.equals(-0.0, 0.0));
}

test "INTEGER_PACKED / LONG_PACKED round-trips" {
    for ([_]i32{ std.math.minInt(i32), -1, 0, 1, 127, 128, std.math.maxInt(i32) }) |v|
        try rtScalarNoSize(IntPackedSer, v);
    for ([_]i64{ std.math.minInt(i64), -1, 0, 1, 127, 128, std.math.maxInt(i64) }) |v|
        try rtScalarNoSize(LongPackedSer, v);
}

test "RECID round-trip + positivity guard" {
    try rtScalarNoSize(RecidSer, 123456789);
    var out = DataOutput2.init(testing.allocator);
    defer out.deinit();
    try testing.expectError(error.DataCorruption, RecidSer.instance.serialize(&out, 0));
    try testing.expectError(error.DataCorruption, RecidSer.instance.serialize(&out, -5));
}

test "DATE epoch-millis round-trip" {
    try rtScalarNoSize(DateSer, 123456789);
}

test "NOSIZE + ASCII round-trips" {
    try rtSlice(ByteArrayNoSizeSer, &.{ 1, 2, 3 }, null);
    try rtSlice(StringNoSizeSer, "žluťoučký", null);
    try rtSlice(StringAsciiSer, "plain ASCII", null);
    // NOSIZE requires a known size
    var inp = DataInput2.init(&.{ 1, 2, 3 });
    try testing.expectError(error.DataCorruption, ByteArrayNoSizeSer.instance.deserialize(testing.allocator, &inp, null));
    // ASCII rejects non-ASCII
    var out = DataOutput2.init(testing.allocator);
    defer out.deinit();
    try testing.expectError(error.DataCorruption, StringAsciiSer.instance.serialize(&out, "é"));
}
