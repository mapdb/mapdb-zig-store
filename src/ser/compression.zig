//! `CompressionSerializer` (Java `org.mapdb.ser.CompressionSerializer`): a
//! DEFLATE/zlib wrapper around any element serializer. Wire frame (byte layout
//! identical to Java): `packInt(plainLen)` + `packInt(compressedLen)` +
//! `compressedLen` bytes of a zlib (RFC 1950) stream.
//!
//! ## Write-side deviation (documented; gap-listed)
//! Java writes zlib produced by `java.util.zip.Deflater`. Zig's `std.compress`
//! DEFLATE *compressor* is incomplete in this toolchain (0.15.2 — the main
//! `Compress` path `@panic`s), and even a complete one would not byte-match
//! zlib across versions/levels. Per the milestone brief, the port therefore
//! emits its OWN deterministic zlib stream using STORED (uncompressed) DEFLATE
//! blocks — a valid RFC 1950 stream that Java's `Inflater` reads back exactly —
//! rather than reproducing Java's exact compressed bytes. The DECOMPRESSED
//! round-trip is always exact, which is the contract that matters. Reading is
//! done with the (complete) std `flate.Decompress`, so real Java-written
//! compressed records decompress correctly too.
//!
//! `equalsBySerializedBytes()` is `false`: DEFLATE output is not
//! canonical, so equal values may serialize to different bytes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const flate = std.compress.flate;

/// Java `MAX_PLAIN_LENGTH` / `MAX_COMPRESSED_LENGTH`.
const MAX_PLAIN_LENGTH: usize = 256 * 1024 * 1024;
const MAX_COMPRESSED_LENGTH: usize = MAX_PLAIN_LENGTH + 1024 * 1024;

/// Java `Deflater.DEFAULT_COMPRESSION` (-1) .. `BEST_COMPRESSION` (9).
const DEFAULT_COMPRESSION: i32 = -1;
const BEST_COMPRESSION: i32 = 9;

/// Adler-32 checksum over `data` (zlib trailer).
fn adler32(data: []const u8) u32 {
    var a: u32 = 1;
    var b: u32 = 0;
    for (data) |c| {
        a = (a + c) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

fn appendU16LE(buf: *std.ArrayListUnmanaged(u8), alloc: Allocator, v: u16) DbError!void {
    var t: [2]u8 = undefined;
    std.mem.writeInt(u16, &t, v, .little);
    try buf.appendSlice(alloc, &t);
}

/// Encode `plain` into a valid zlib (RFC 1950) stream using STORED DEFLATE
/// blocks. Deterministic; readable by any conformant inflater (Java included).
fn zlibStored(alloc: Allocator, plain: []const u8) DbError![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);
    // zlib header: CMF=0x78 (CM=8, CINFO=7), FLG=0x01 (FLEVEL=0, check bits).
    try buf.append(alloc, 0x78);
    try buf.append(alloc, 0x01);
    if (plain.len == 0) {
        // single final empty stored block: BFINAL=1, LEN=0, NLEN=0xFFFF.
        try buf.append(alloc, 0x01);
        try appendU16LE(&buf, alloc, 0);
        try appendU16LE(&buf, alloc, 0xFFFF);
    } else {
        var off: usize = 0;
        while (off < plain.len) {
            const chunk: usize = @min(plain.len - off, 65535);
            const final = (off + chunk == plain.len);
            // Stored block header byte at a byte boundary: bit0 = BFINAL,
            // bits1-2 = BTYPE(00), remaining padding bits 0.
            try buf.append(alloc, if (final) @as(u8, 0x01) else 0x00);
            const len16: u16 = @intCast(chunk);
            try appendU16LE(&buf, alloc, len16);
            try appendU16LE(&buf, alloc, ~len16);
            try buf.appendSlice(alloc, plain[off .. off + chunk]);
            off += chunk;
        }
    }
    var trailer: [4]u8 = undefined;
    std.mem.writeInt(u32, &trailer, adler32(plain), .big); // zlib trailer is big-endian
    try buf.appendSlice(alloc, &trailer);
    return buf.toOwnedSlice(alloc);
}

/// Inflate a zlib stream `compressed` into exactly `plain_len` bytes (owned).
/// Errors (`DataCorruption`) if the stream is malformed or its length differs.
fn zlibInflate(alloc: Allocator, compressed: []const u8, plain_len: usize) DbError![]u8 {
    const plain = try alloc.alloc(u8, plain_len);
    errdefer alloc.free(plain);
    var reader: std.Io.Reader = .fixed(compressed);
    // The decompressor needs its own history window (>= max_window_len); the
    // bufferless "direct" mode requires the OUTPUT writer to hold the window,
    // which an exact-sized destination cannot.
    const window = try alloc.alloc(u8, flate.max_window_len);
    defer alloc.free(window);
    var decompress: flate.Decompress = .init(&reader, .zlib, window);
    const dr = &decompress.reader;
    // Decode exactly `plain_len` bytes ...
    dr.readSliceAll(plain) catch return error.DataCorruption;
    // ... and require the stream to be exhausted (no extra output) — Java's
    // `written == plainLength && inflater.finished()`.
    var extra: [1]u8 = undefined;
    const trailing = dr.readSliceShort(&extra) catch return error.DataCorruption;
    if (trailing != 0) return error.DataCorruption;
    return plain;
}

/// DEFLATE/zlib wrapper monomorphized over element serializer `Delegate`.
/// Constructed with a compression `level` (retained for API parity; the stored
/// encoding ignores it). Not zero-sized, so not usable by the object heap store
/// — matching Java, whose `CompressionSerializer` is stateful.
pub fn CompressionSerializer(comptime Delegate: type) type {
    return struct {
        const Self = @This();
        pub const Elem = Delegate.Elem;
        /// The wrapped serializer type (used by the DB catalog `DEFLATE:` descriptor).
        pub const DelegateSer = Delegate;

        level: i32 = DEFAULT_COMPRESSION,

        /// Default-level instance (Java `new CompressionSerializer<>(delegate)`).
        pub const default: Self = .{ .level = DEFAULT_COMPRESSION };

        pub fn init(level: i32) DbError!Self {
            if (level < DEFAULT_COMPRESSION or level > BEST_COMPRESSION) return error.DataCorruption;
            return .{ .level = level };
        }

        pub fn serialize(self: Self, out: *DataOutput2, value: Elem) DbError!void {
            _ = self;
            var plain_out = DataOutput2.init(out.alloc);
            defer plain_out.deinit();
            try Delegate.instance.serialize(&plain_out, value);
            const plain = plain_out.bytes();
            if (plain.len > MAX_PLAIN_LENGTH) return error.RecordTooLarge;
            const compressed = try zlibStored(out.alloc, plain);
            defer out.alloc.free(compressed);
            if (compressed.len > MAX_COMPRESSED_LENGTH) return error.RecordTooLarge;
            try out.packInt(@intCast(plain.len));
            try out.packInt(@intCast(compressed.len));
            try out.writeAll(compressed);
        }

        pub fn deserialize(self: Self, alloc: Allocator, input: *DataInput2, _: ?usize) DbError!Elem {
            _ = self;
            const plain_len_raw = try input.unpackInt();
            const compressed_len_raw = try input.unpackInt();
            if (plain_len_raw < 0 or compressed_len_raw < 0) return error.DataCorruption;
            const plain_len: usize = @intCast(plain_len_raw);
            const compressed_len: usize = @intCast(compressed_len_raw);
            if (plain_len > MAX_PLAIN_LENGTH or compressed_len > MAX_COMPRESSED_LENGTH)
                return error.DataCorruption;
            if (compressed_len > input.remaining()) return error.DataCorruption;
            const compressed = try input.takeBytes(compressed_len);
            const plain = try zlibInflate(alloc, compressed, plain_len);
            defer alloc.free(plain);
            var plain_in = DataInput2.init(plain);
            return Delegate.instance.deserialize(alloc, &plain_in, plain_len);
        }

        pub fn cloneElem(self: Self, alloc: Allocator, v: Elem) DbError!Elem {
            _ = self;
            return Delegate.instance.cloneElem(alloc, v);
        }
        pub fn deinitElem(self: Self, alloc: Allocator, v: Elem) void {
            _ = self;
            Delegate.instance.deinitElem(alloc, v);
        }
        pub fn compare(self: Self, a: Elem, b: Elem) Order {
            _ = self;
            return Delegate.instance.compare(a, b);
        }
        pub fn equals(self: Self, a: Elem, b: Elem) bool {
            _ = self;
            return Delegate.instance.equals(a, b);
        }
        pub fn fixedSize(self: Self) ?usize {
            _ = self;
            return null;
        }
        pub fn naturalOrder(self: Self) bool {
            _ = self;
            return Delegate.instance.naturalOrder();
        }
        /// Always false: DEFLATE output is not canonical.
        pub fn equalsBySerializedBytes(self: Self) bool {
            _ = self;
            return false;
        }
    };
}

// ------------------------------------------------------------------- tests

const testing = std.testing;
const contracts = @import("mod.zig");
const scalars = @import("serializers.zig");

comptime {
    contracts.checkSerializer(CompressionSerializer(scalars.StringSer), []const u8);
}

test "compression round-trips large and empty values" {
    const a = testing.allocator;
    const StrComp = CompressionSerializer(scalars.StringSer);
    const c = StrComp.default;

    // large string ("abcdefghij" * 10000)
    var big: std.ArrayListUnmanaged(u8) = .empty;
    defer big.deinit(a);
    for (0..10_000) |_| try big.appendSlice(a, "abcdefghij");

    var out = DataOutput2.init(a);
    defer out.deinit();
    try c.serialize(&out, big.items);
    var inp = DataInput2.init(out.bytes());
    const back = try c.deserialize(a, &inp, out.bytes().len);
    defer c.deinitElem(a, back);
    try testing.expectEqualSlices(u8, big.items, back);
    try testing.expect(!c.equalsBySerializedBytes());

    // empty byte[] through BYTE_ARRAY_NOSIZE delegate
    const RawComp = CompressionSerializer(scalars.ByteArrayNoSizeSer);
    const rc = RawComp.default;
    var out2 = DataOutput2.init(a);
    defer out2.deinit();
    try rc.serialize(&out2, &.{});
    var inp2 = DataInput2.init(out2.bytes());
    const back2 = try rc.deserialize(a, &inp2, out2.bytes().len);
    defer rc.deinitElem(a, back2);
    try testing.expectEqual(@as(usize, 0), back2.len);
}

test "compression rejects hostile decompressed length before allocation" {
    const a = testing.allocator;
    var frame = DataOutput2.init(a);
    defer frame.deinit();
    try frame.packInt(std.math.maxInt(i32)); // plain length
    try frame.packInt(0); // compressed length
    const StrComp = CompressionSerializer(scalars.StringSer);
    var inp = DataInput2.init(frame.bytes());
    try testing.expectError(error.DataCorruption, StrComp.default.deserialize(a, &inp, frame.bytes().len));
}

test "read path inflates a real (Huffman/LZ77) zlib stream, not just STORED blocks" {
    // Golden zlib stream produced by a real DEFLATE compressor (zlib level 6,
    // header 0x78 0x9c) — the same wire form java.util.zip.Deflater writes. The
    // Zig WRITE path emits STORED blocks, so this is the only coverage that the
    // READ path (flate.Decompress) handles Java-written compressed records.
    const a = testing.allocator;
    const compressed = [_]u8{
        0x78, 0x9c, 0x2b, 0xc9, 0x48, 0x55, 0x28, 0x2c, 0xcd, 0x4c, 0xce, 0x56, 0x48, 0x2a,
        0xca, 0x2f, 0xcf, 0x53, 0x48, 0xcb, 0xaf, 0x50, 0xc8, 0x2a, 0xcd, 0x2d, 0x28, 0x56,
        0xc8, 0x2f, 0x4b, 0x2d, 0x52, 0x28, 0x01, 0x4a, 0xe7, 0x24, 0x56, 0x55, 0x2a, 0xa4,
        0xe4, 0xa7, 0x83, 0x39, 0xa3, 0x6a, 0x49, 0x53, 0x0b, 0x00, 0x07, 0xbf, 0x80, 0xc9,
    };
    var expected: std.ArrayListUnmanaged(u8) = .empty;
    defer expected.deinit(a);
    for (0..8) |_| try expected.appendSlice(a, "the quick brown fox jumps over the lazy dog ");

    const plain = try zlibInflate(a, &compressed, expected.items.len);
    defer a.free(plain);
    try testing.expectEqualSlices(u8, expected.items, plain);

    // And a full CompressionSerializer.deserialize over a hand-framed record
    // (packInt(plainLen) + packInt(compLen) + the real zlib body) round-trips
    // through the raw-bytes delegate — proving the whole read frame is
    // Java-compatible (the golden plaintext is raw bytes, which the NOSIZE
    // delegate reads directly under size == plainLen).
    var frame = DataOutput2.init(a);
    defer frame.deinit();
    try frame.packInt(@intCast(expected.items.len));
    try frame.packInt(@intCast(compressed.len));
    try frame.writeAll(&compressed);
    const RawComp = CompressionSerializer(scalars.ByteArrayNoSizeSer);
    var inp = DataInput2.init(frame.bytes());
    const back = try RawComp.default.deserialize(a, &inp, frame.bytes().len);
    defer RawComp.default.deinitElem(a, back);
    try testing.expectEqualSlices(u8, expected.items, back);
}

test "level validation" {
    const StrComp = CompressionSerializer(scalars.StringSer);
    try testing.expectError(error.DataCorruption, StrComp.init(-2));
    try testing.expectError(error.DataCorruption, StrComp.init(10));
    _ = try StrComp.init(9);
    _ = try StrComp.init(-1);
}
