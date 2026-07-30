//! Codec descriptor strings — the stable, Java-byte-compatible wire identifiers
//! persisted in the name catalog for every codec. Ported
//! from `mapdb-rust-store/src/db/descriptor.rs` (same registered ids, same recursive
//! grammar, same RFC-4648 URL-safe base64 without padding).
//!
//! Because the port monomorphizes every collection over its concrete
//! `GroupFormat`/`Serializer` (D1/D2), there is no runtime class to reflect on.
//! Instead [`groupDescriptor`] / [`serDescriptor`] switch on the comptime codec
//! type (and read any runtime schema fields, e.g. a `TupleFormat`'s components),
//! returning the exact Java-registered id or `null` for a codec whose wire
//! identity the port cannot reproduce (persisted as the opaque marker [`CUSTOM`]).
//!
//! The port never RECONSTRUCTS a codec from its descriptor (that needs the erased
//! dispatch D1 forbids); typed opens always supply the concrete codec, and
//! verification is a pure string comparison ([`verifyGroup`] / [`verifySer`]).

const std = @import("std");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;

const serializers = @import("../ser/serializers.zig");
const arrays = @import("../ser/arrays.zig");
const bignum = @import("../ser/bignum.zig");
const compression = @import("../ser/compression.zig");
const long = @import("../ser/long.zig");
const int = @import("../ser/int.zig");
const scalar = @import("../ser/scalar.zig");
const string_group = @import("../ser/string_group.zig");
const string_prefix = @import("../ser/string_prefix.zig");
const bytearray = @import("../ser/bytearray.zig");
const object_array = @import("../ser/object_array.zig");
const tuple = @import("../ser/tuple.zig");
const columnar = @import("../ser/columnar.zig");

/// Opaque marker written for a codec whose exact wire identity the port cannot
/// reproduce (Java writes `CUSTOM:<fqcn>`; the port has no class name).
pub const CUSTOM: []const u8 = "CUSTOM";

fn dup(alloc: Allocator, s: []const u8) DbError![]const u8 {
    return alloc.dupe(u8, s);
}

// =========================== base64url (RFC 4648, no padding) ===========================

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// RFC 4648 URL-safe base64 without padding, over UTF-8 (Java
/// `Base64.getUrlEncoder().withoutPadding()`). Owned result.
pub fn b64urlEncode(alloc: Allocator, data: []const u8) DbError![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);
    var i: usize = 0;
    while (i < data.len) : (i += 3) {
        const b0: u32 = data[i];
        const b1: u32 = if (i + 1 < data.len) data[i + 1] else 0;
        const b2: u32 = if (i + 2 < data.len) data[i + 2] else 0;
        const n = (b0 << 16) | (b1 << 8) | b2;
        try out.append(alloc, B64URL[(n >> 18) & 0x3F]);
        try out.append(alloc, B64URL[(n >> 12) & 0x3F]);
        if (i + 1 < data.len) try out.append(alloc, B64URL[(n >> 6) & 0x3F]);
        if (i + 2 < data.len) try out.append(alloc, B64URL[n & 0x3F]);
    }
    return out.toOwnedSlice(alloc);
}

// =========================== element serializer descriptors ===========================

/// The Java-registered id of a built-in element serializer type, or "" if it is
/// not a simple built-in (parameterized / custom handled by the caller).
fn builtinSerId(comptime Se: type) []const u8 {
    if (Se == serializers.LongSer) return "LONG";
    if (Se == serializers.IntSer) return "INTEGER";
    if (Se == serializers.ShortSer) return "SHORT";
    if (Se == serializers.CharSer) return "CHAR";
    if (Se == serializers.UuidSer) return "UUID";
    if (Se == serializers.StringSer) return "STRING";
    if (Se == serializers.ByteArraySer) return "BYTE_ARRAY";
    if (Se == serializers.ByteArrayUnsignedSer) return "BYTE_ARRAY_UNSIGNED";
    if (Se == serializers.BoolSer) return "BOOLEAN";
    if (Se == serializers.ByteSer) return "BYTE";
    if (Se == serializers.FloatSer) return "FLOAT";
    if (Se == serializers.DoubleSer) return "DOUBLE";
    if (Se == serializers.IntPackedSer) return "INTEGER_PACKED";
    if (Se == serializers.LongPackedSer) return "LONG_PACKED";
    if (Se == serializers.ByteArrayNoSizeSer) return "BYTE_ARRAY_NOSIZE";
    if (Se == serializers.StringNoSizeSer) return "STRING_NOSIZE";
    if (Se == serializers.StringAsciiSer) return "STRING_ASCII";
    if (Se == serializers.RecidSer) return "RECID";
    if (Se == serializers.DateSer) return "DATE";
    if (Se == arrays.RecidArraySer) return "RECID_ARRAY";
    if (Se == arrays.BooleanArraySer) return "BOOLEAN_ARRAY";
    if (Se == arrays.CharArraySer) return "CHAR_ARRAY";
    if (Se == arrays.ShortArraySer) return "SHORT_ARRAY";
    if (Se == arrays.IntArraySer) return "INT_ARRAY";
    if (Se == arrays.LongArraySer) return "LONG_ARRAY";
    if (Se == arrays.FloatArraySer) return "FLOAT_ARRAY";
    if (Se == arrays.DoubleArraySer) return "DOUBLE_ARRAY";
    if (Se == bignum.BigIntegerSer) return "BIG_INTEGER";
    if (Se == bignum.BigDecimalSer) return "BIG_DECIMAL";
    return "";
}

/// The stable descriptor for an element serializer value, or `null` (custom).
/// Owned result on success.
pub fn serDescriptor(alloc: Allocator, se: anytype) DbError!?[]const u8 {
    const Se = @TypeOf(se);
    const id = comptime builtinSerId(Se);
    if (comptime id.len != 0) return try dup(alloc, id);
    // DEFLATE:<level>:<b64url(nested)> — Java CompressionSerializer.
    if (comptime @hasDecl(Se, "DelegateSer") and @hasField(Se, "level")) {
        if (comptime Se == compression.CompressionSerializer(Se.DelegateSer)) {
            const nested = (try serDescriptor(alloc, Se.DelegateSer.instance)) orelse return null;
            defer alloc.free(nested);
            const b64 = try b64urlEncode(alloc, nested);
            defer alloc.free(b64);
            return try std.fmt.allocPrint(alloc, "DEFLATE:{d}:{s}", .{ se.level, b64 });
        }
    }
    return null;
}

// =========================== group format descriptors ===========================

fn builtinGroupId(comptime KF: type) []const u8 {
    if (KF == long.LongFormat) return "LONG";
    if (KF == int.IntFormat) return "INT";
    if (KF == scalar.ShortFormat) return "SHORT";
    if (KF == scalar.CharFormat) return "CHAR";
    if (KF == scalar.UuidFormat) return "UUID";
    if (KF == string_group.StringGroupFormat) return "STRING";
    if (KF == string_prefix.StringPrefixFormat) return "STRING_PREFIX";
    if (KF == bytearray.ByteArrayFormat) return "BYTE_ARRAY";
    if (KF == bytearray.ByteArrayPrefixFormat) return "BYTE_ARRAY_PREFIX";
    if (KF == int.IntDeltaFormat) return "INT_DELTA";
    if (KF == long.LongDeltaFormat) return "LONG_DELTA";
    return "";
}

fn tupleComponentName(c: tuple.TupleComponent) []const u8 {
    return switch (c) {
        .int => "INT",
        .long => "LONG",
        .str => "STRING",
        .bytes => "BYTES",
    };
}

fn columnTypeName(c: columnar.ColumnType) []const u8 {
    return switch (c) {
        .long => "LONG",
        .int => "INT",
        .short => "SHORT",
        .byte => "BYTE",
    };
}

/// The stable descriptor for a group-format value, or `null` (custom). Owned.
pub fn groupDescriptor(alloc: Allocator, kf: anytype) DbError!?[]const u8 {
    const KF = @TypeOf(kf);
    const id = comptime builtinGroupId(KF);
    if (comptime id.len != 0) return try dup(alloc, id);

    // TUPLE:<comp>[,<comp>...]
    if (comptime KF == tuple.TupleFormat) {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(alloc);
        try buf.appendSlice(alloc, "TUPLE:");
        for (kf.schema, 0..) |c, i| {
            if (i != 0) try buf.append(alloc, ',');
            try buf.appendSlice(alloc, tupleComponentName(c));
        }
        return try buf.toOwnedSlice(alloc);
    }
    // COLUMNAR:<coltype>[,<coltype>...]
    if (comptime KF == columnar.ColumnarValueFormat) {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(alloc);
        try buf.appendSlice(alloc, "COLUMNAR:");
        for (kf.schema, 0..) |c, i| {
            if (i != 0) try buf.append(alloc, ',');
            try buf.appendSlice(alloc, columnTypeName(c));
        }
        return try buf.toOwnedSlice(alloc);
    }
    // OBJECT_ARRAY:<b64url(element-serializer-descriptor)>
    if (comptime @hasField(KF, "element")) {
        const ElemSer = @TypeOf(kf.element);
        if (comptime KF == object_array.ObjectArrayFormat(ElemSer)) {
            const nested = (try serDescriptor(alloc, kf.element)) orelse return null;
            defer alloc.free(nested);
            const b64 = try b64urlEncode(alloc, nested);
            defer alloc.free(b64);
            return try std.fmt.allocPrint(alloc, "OBJECT_ARRAY:{s}", .{b64});
        }
    }
    return null;
}

// =========================== base64url decode ===========================

/// Decode RFC 4648 URL-safe base64 without padding to owned bytes, or `null` on
/// an illegal alphabet / length group. (Used by descriptor grammar validation.)
pub fn b64urlDecode(alloc: Allocator, s: []const u8) DbError!?[]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);
    var i: usize = 0;
    while (i < s.len) : (i += 4) {
        const chunk_len = @min(s.len - i, 4);
        if (chunk_len == 1) {
            out.deinit(alloc);
            return null; // illegal trailing group of 1
        }
        var n: u32 = 0;
        var j: usize = 0;
        while (j < chunk_len) : (j += 1) {
            const v = b64Val(s[i + j]) orelse {
                out.deinit(alloc);
                return null;
            };
            n = (n << 6) | v;
        }
        n <<= @intCast(6 * (4 - chunk_len));
        try out.append(alloc, @intCast((n >> 16) & 0xFF));
        if (chunk_len >= 3) try out.append(alloc, @intCast((n >> 8) & 0xFF));
        if (chunk_len >= 4) try out.append(alloc, @intCast(n & 0xFF));
    }
    return try out.toOwnedSlice(alloc);
}

fn b64Val(c: u8) ?u32 {
    return switch (c) {
        'A'...'Z' => c - 'A',
        'a'...'z' => @as(u32, c - 'a') + 26,
        '0'...'9' => @as(u32, c - '0') + 52,
        '-' => 62,
        '_' => 63,
        else => null,
    };
}

// =========================== descriptor grammar validation ===========================

const BUILTIN_GROUPS = [_][]const u8{
    "LONG",          "INT",        "SHORT",             "CHAR",      "UUID",       "STRING",
    "STRING_PREFIX", "BYTE_ARRAY", "BYTE_ARRAY_PREFIX", "INT_DELTA", "LONG_DELTA",
};

const BUILTIN_SERS = [_][]const u8{
    "LONG",          "INTEGER",      "SHORT",               "CHAR",        "UUID",
    "STRING",        "BYTE_ARRAY",   "BYTE_ARRAY_UNSIGNED", "BOOLEAN",     "BYTE",
    "FLOAT",         "DOUBLE",       "INTEGER_PACKED",      "LONG_PACKED", "BYTE_ARRAY_NOSIZE",
    "STRING_NOSIZE", "STRING_ASCII", "STRING_INTERN",       "RECID",       "RECID_ARRAY",
    "BOOLEAN_ARRAY", "CHAR_ARRAY",   "SHORT_ARRAY",         "INT_ARRAY",   "LONG_ARRAY",
    "FLOAT_ARRAY",   "DOUBLE_ARRAY", "BIG_INTEGER",         "BIG_DECIMAL", "DATE",
    "CLASS",         "JAVA",
};

const TUPLE_COMPONENTS = [_][]const u8{ "INT", "LONG", "STRING", "BYTES" };
const COLUMN_TYPES = [_][]const u8{ "LONG", "INT", "SHORT", "BYTE" };

fn inList(list: []const []const u8, s: []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, s)) return true;
    return false;
}

fn isCustomMarker(stored: []const u8) bool {
    return std.mem.eql(u8, stored, CUSTOM) or std.mem.startsWith(u8, stored, "CUSTOM:");
}

/// True if every comma-separated component of `list` is in `allowed` (non-empty).
fn allComponents(list: []const u8, allowed: []const []const u8) bool {
    if (list.len == 0) return false;
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |c| if (!inList(allowed, c)) return false;
    return true;
}

/// True if `s` is a valid group-format descriptor (built-in, recursive grammar,
/// or the `CUSTOM` marker). Mirrors Rust `is_valid_group_descriptor`.
pub fn isValidGroupDescriptor(alloc: Allocator, s: []const u8) DbError!bool {
    if (inList(&BUILTIN_GROUPS, s) or isCustomMarker(s)) return true;
    if (std.mem.startsWith(u8, s, "OBJECT_ARRAY:")) {
        const nested = (try b64urlDecode(alloc, s["OBJECT_ARRAY:".len..])) orelse return false;
        defer alloc.free(nested);
        return isValidSerDescriptor(alloc, nested);
    }
    if (std.mem.startsWith(u8, s, "TUPLE:")) return allComponents(s["TUPLE:".len..], &TUPLE_COMPONENTS);
    if (std.mem.startsWith(u8, s, "COLUMNAR:")) return allComponents(s["COLUMNAR:".len..], &COLUMN_TYPES);
    return false;
}

/// True if `s` is a valid element-serializer descriptor. Mirrors Rust
/// `is_valid_ser_descriptor`.
pub fn isValidSerDescriptor(alloc: Allocator, s: []const u8) DbError!bool {
    if (inList(&BUILTIN_SERS, s) or isCustomMarker(s)) return true;
    if (std.mem.startsWith(u8, s, "DEFLATE:")) {
        const rest = s["DEFLATE:".len..];
        const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return false;
        const level = std.fmt.parseInt(i32, rest[0..colon], 10) catch return false;
        if (level < -1 or level > 9) return false; // Java Deflater accepts -1..=9
        const nested = (try b64urlDecode(alloc, rest[colon + 1 ..])) orelse return false;
        defer alloc.free(nested);
        return isValidSerDescriptor(alloc, nested);
    }
    if (std.mem.startsWith(u8, s, "ARRAY:")) {
        const rest = s["ARRAY:".len..];
        const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return false;
        const comp = (try b64urlDecode(alloc, rest[0..colon])) orelse return false;
        alloc.free(comp);
        const nested = (try b64urlDecode(alloc, rest[colon + 1 ..])) orelse return false;
        defer alloc.free(nested);
        return isValidSerDescriptor(alloc, nested);
    }
    return false;
}

// =========================== verification ===========================

/// The descriptor to persist for a group format (custom → [`CUSTOM`]). Owned.
pub fn groupDescriptorOrCustom(alloc: Allocator, kf: anytype) DbError![]const u8 {
    return (try groupDescriptor(alloc, kf)) orelse try dup(alloc, CUSTOM);
}

/// The descriptor to persist for an element serializer (custom → [`CUSTOM`]). Owned.
pub fn serDescriptorOrCustom(alloc: Allocator, se: anytype) DbError![]const u8 {
    return (try serDescriptor(alloc, se)) orelse try dup(alloc, CUSTOM);
}

/// Classify a supplied-vs-stored descriptor comparison. A mismatch against a
/// VALID stored descriptor is `WrongConfiguration`; against a MALFORMED stored
/// descriptor it is catalog `DataCorruption`. A custom (unreproducible) supplied
/// codec matches only a stored custom marker.
fn verify(alloc: Allocator, stored: []const u8, supplied: ?[]const u8, stored_valid: bool) DbError!void {
    if (supplied) |d| {
        defer alloc.free(d);
        if (std.mem.eql(u8, d, stored)) return;
        return if (stored_valid) error.WrongConfiguration else error.DataCorruption;
    }
    if (isCustomMarker(stored)) return;
    return if (stored_valid) error.WrongConfiguration else error.DataCorruption;
}

/// Verify a supplied group format against the stored catalog descriptor.
pub fn verifyGroup(alloc: Allocator, stored: []const u8, kf: anytype) DbError!void {
    const valid = try isValidGroupDescriptor(alloc, stored);
    return verify(alloc, stored, try groupDescriptor(alloc, kf), valid);
}

/// Verify a supplied element serializer against the stored catalog descriptor.
pub fn verifySer(alloc: Allocator, stored: []const u8, se: anytype) DbError!void {
    const valid = try isValidSerDescriptor(alloc, stored);
    return verify(alloc, stored, try serDescriptor(alloc, se), valid);
}

// ------------------------------------------------------------------- tests

const testing = std.testing;

fn expectGroup(kf: anytype, want: []const u8) !void {
    const a = testing.allocator;
    const d = (try groupDescriptor(a, kf)).?;
    defer a.free(d);
    try testing.expectEqualStrings(want, d);
}
fn expectSer(se: anytype, want: []const u8) !void {
    const a = testing.allocator;
    const d = (try serDescriptor(a, se)).?;
    defer a.free(d);
    try testing.expectEqualStrings(want, d);
}

test "built-in group descriptors" {
    try expectGroup(long.LongFormat.instance, "LONG");
    try expectGroup(int.IntFormat.instance, "INT");
    try expectGroup(string_group.StringGroupFormat.instance, "STRING");
    try expectGroup(bytearray.ByteArrayFormat.instance, "BYTE_ARRAY");
}

test "built-in element serializer descriptors" {
    try expectSer(serializers.LongSer.instance, "LONG");
    try expectSer(serializers.IntSer.instance, "INTEGER");
    try expectSer(serializers.BoolSer.instance, "BOOLEAN");
    try expectSer(serializers.StringSer.instance, "STRING");
    try expectSer(bignum.BigIntegerSer.instance, "BIG_INTEGER");
}

test "b64url matches known vectors (Java withoutPadding)" {
    const a = testing.allocator;
    const cases = [_]struct { in: []const u8, out: []const u8 }{
        .{ .in = "STRING", .out = "U1RSSU5H" },
        .{ .in = "", .out = "" },
        .{ .in = "f", .out = "Zg" },
        .{ .in = "fo", .out = "Zm8" },
        .{ .in = "foo", .out = "Zm9v" },
    };
    for (cases) |c| {
        const got = try b64urlEncode(a, c.in);
        defer a.free(got);
        try testing.expectEqualStrings(c.out, got);
    }
}

test "tuple / columnar descriptors use Java names" {
    try expectGroup(tuple.TupleFormat.of(&.{ .str, .long, .int }), "TUPLE:STRING,LONG,INT");
    try expectGroup(columnar.ColumnarValueFormat.of(&.{ .long, .int }), "COLUMNAR:LONG,INT");
}

test "object array wraps nested serializer" {
    const OA = object_array.ObjectArrayFormat(serializers.StringSer);
    const a = testing.allocator;
    const b64 = try b64urlEncode(a, "STRING");
    defer a.free(b64);
    const want = try std.fmt.allocPrint(a, "OBJECT_ARRAY:{s}", .{b64});
    defer a.free(want);
    try expectGroup(OA.init(serializers.StringSer.instance), want);
}

test "verify accepts match, classifies mismatch, custom matches marker" {
    const a = testing.allocator;
    try verifyGroup(a, "LONG", long.LongFormat.instance);
    // A different VALID stored descriptor is a wrong CONFIGURATION, not corruption.
    try testing.expectError(error.WrongConfiguration, verifyGroup(a, "STRING", long.LongFormat.instance));
    // A malformed stored descriptor is catalog corruption.
    try testing.expectError(error.DataCorruption, verifyGroup(a, "BOGUS", long.LongFormat.instance));
    // a custom serializer verifies only against the CUSTOM marker
    const Custom = struct {
        pub const Elem = i64;
        pub const instance: @This() = .{};
    };
    try verifySer(a, CUSTOM, Custom.instance);
    // custom supplied vs a valid stored descriptor → wrong configuration
    try testing.expectError(error.WrongConfiguration, verifySer(a, "LONG", Custom.instance));
}

test "descriptor grammar validators" {
    const a = testing.allocator;
    try testing.expect(try isValidGroupDescriptor(a, "LONG"));
    try testing.expect(try isValidGroupDescriptor(a, "TUPLE:STRING,LONG,INT"));
    try testing.expect(try isValidGroupDescriptor(a, "COLUMNAR:LONG,INT"));
    try testing.expect(!(try isValidGroupDescriptor(a, "TUPLE:")));
    try testing.expect(!(try isValidGroupDescriptor(a, "TUPLE:BOGUS")));
    try testing.expect(!(try isValidGroupDescriptor(a, "BOGUS")));
    try testing.expect(try isValidSerDescriptor(a, "STRING"));
    try testing.expect(try isValidSerDescriptor(a, CUSTOM));
    // OBJECT_ARRAY:<b64url("STRING")> is valid; DEFLATE:6:<b64url("STRING")> too.
    const oa = try b64urlEncode(a, "STRING");
    defer a.free(oa);
    const oa_desc = try std.fmt.allocPrint(a, "OBJECT_ARRAY:{s}", .{oa});
    defer a.free(oa_desc);
    try testing.expect(try isValidGroupDescriptor(a, oa_desc));
    const df = try std.fmt.allocPrint(a, "DEFLATE:6:{s}", .{oa});
    defer a.free(df);
    try testing.expect(try isValidSerDescriptor(a, df));
    const df_bad = try std.fmt.allocPrint(a, "DEFLATE:99:{s}", .{oa});
    defer a.free(df_bad);
    try testing.expect(!(try isValidSerDescriptor(a, df_bad)));
}
