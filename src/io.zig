//! io layer — `DataOutput2` / `DataInput2` and the packed-varint wire format.
//! Ported from `mapdb-rust-store/src/io.rs` (itself byte-for-byte from
//! `org.mapdb.io`).
//!
//! Wire primitives:
//! - multi-byte integers are **big-endian**;
//! - **packed long** (mapdb lineage varint): 7 bits per byte, most-significant
//!   group first, the terminating byte has bit `0x80` set; non-negative only.
//!
//! Every read is an EXPLICIT bounds check returning `error.DataCorruption` on
//! overrun (ReleaseFast has no implicit checks; these are the defense).

const std = @import("std");
const Allocator = std.mem.Allocator;
const DbError = @import("errors.zig").DbError;

/// Max bytes a valid packed u64 occupies (ceil(64/7)). Torn-safe decoders
/// reject longer runs so garbage terminates quickly (D4).
pub const max_packed_long_bytes: usize = 10;
pub const max_packed_int_bytes: usize = 5;

/// Growable serialization buffer. `pos() == buf.items.len` (append-only).
pub const DataOutput2 = struct {
    buf: std.ArrayList(u8) = .empty,
    alloc: Allocator,

    pub fn init(alloc: Allocator) DataOutput2 {
        return .{ .alloc = alloc };
    }

    /// Initial-capacity hint; floored at 16 like Java's `max(16, sizeHint)`.
    pub fn initCapacity(alloc: Allocator, size_hint: usize) DbError!DataOutput2 {
        var out = DataOutput2{ .alloc = alloc };
        try out.buf.ensureTotalCapacity(alloc, @max(16, size_hint));
        return out;
    }

    pub fn deinit(self: *DataOutput2) void {
        self.buf.deinit(self.alloc);
    }

    pub fn pos(self: *const DataOutput2) usize {
        return self.buf.items.len;
    }

    pub fn bytes(self: *const DataOutput2) []const u8 {
        return self.buf.items;
    }

    pub fn writeU8(self: *DataOutput2, v: u8) DbError!void {
        try self.buf.append(self.alloc, v);
    }

    /// Java `writeByte(int)` — low 8 bits.
    pub fn writeByte(self: *DataOutput2, v: i32) DbError!void {
        try self.buf.append(self.alloc, @truncate(@as(u32, @bitCast(v))));
    }

    pub fn writeAll(self: *DataOutput2, b: []const u8) DbError!void {
        try self.buf.appendSlice(self.alloc, b);
    }

    fn writeBe(self: *DataOutput2, comptime T: type, v: T) DbError!void {
        var tmp: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
        std.mem.writeInt(T, &tmp, v, .big);
        try self.buf.appendSlice(self.alloc, &tmp);
    }

    pub fn writeI16(self: *DataOutput2, v: i16) DbError!void {
        try self.writeBe(i16, v);
    }
    pub fn writeU16(self: *DataOutput2, v: u16) DbError!void {
        try self.writeBe(u16, v);
    }
    pub fn writeI32(self: *DataOutput2, v: i32) DbError!void {
        try self.writeBe(i32, v);
    }
    pub fn writeU32(self: *DataOutput2, v: u32) DbError!void {
        try self.writeBe(u32, v);
    }
    pub fn writeI64(self: *DataOutput2, v: i64) DbError!void {
        try self.writeBe(i64, v);
    }
    pub fn writeU64(self: *DataOutput2, v: u64) DbError!void {
        try self.writeBe(u64, v);
    }

    /// Packed long; non-negative domain (`u64`). Faithful transcription of
    /// Java `packLong` (see mapdb-rust-store/src/io.rs `pack_long` for the
    /// shift-derivation notes; for v==0 the loop is skipped and a single
    /// terminator byte 0x80 is emitted).
    pub fn packLong(self: *DataOutput2, value: u64) DbError!void {
        var shift: i32 = 63 - @as(i32, @clz(value));
        // @clz(u64) is 64 for value==0 → shift = -1; Zig @rem truncates like Java %.
        shift -= @rem(shift, 7);
        while (shift != 0) : (shift -= 7) {
            try self.buf.append(self.alloc, @truncate((value >> @intCast(shift)) & 0x7F));
        }
        try self.buf.append(self.alloc, @truncate((value & 0x7F) | 0x80));
    }

    /// `packInt(v) == packLong(v as u32)` — Java masks to 32 bits.
    pub fn packInt(self: *DataOutput2, value: i32) DbError!void {
        try self.packLong(@as(u32, @bitCast(value)));
    }

    /// Owned copy of the written bytes (Java `copyBytes`).
    pub fn copyBytes(self: *const DataOutput2, alloc: Allocator) DbError![]u8 {
        return alloc.dupe(u8, self.buf.items);
    }

    /// Consume and return the owned buffer; the DataOutput2 is reset empty.
    pub fn toOwnedSlice(self: *DataOutput2) DbError![]u8 {
        return self.buf.toOwnedSlice(self.alloc);
    }
};

/// Positioned, seekable read cursor over a contiguous byte slice. Covers the
/// Rust `SliceInput` (the only DataInput2 impl).
///
/// Repositioning via `setPos` is unchecked (matching Java `pos(int)`); the
/// following read bounds-checks. Torn-safe decode paths use `seek`, which
/// validates eagerly (D4).
pub const DataInput2 = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) DataInput2 {
        return .{ .buf = buf };
    }

    pub fn at(buf: []const u8, pos_: usize) DataInput2 {
        return .{ .buf = buf, .pos = pos_ };
    }

    pub fn len(self: *const DataInput2) usize {
        return self.buf.len;
    }

    pub fn isEmpty(self: *const DataInput2) bool {
        return self.buf.len == 0;
    }

    /// Bytes remaining from the current position (saturating).
    pub fn remaining(self: *const DataInput2) usize {
        return self.buf.len -| self.pos;
    }

    /// Reposition without validation (Java `pos(int)`). Reads still check.
    pub fn setPos(self: *DataInput2, p: usize) void {
        self.pos = p;
    }

    /// Checked reposition (torn-safe subset). Error if `p > len`.
    pub fn seek(self: *DataInput2, p: usize) DbError!void {
        if (p > self.buf.len) return error.DataCorruption;
        self.pos = p;
    }

    /// Skip `n` bytes, checked.
    pub fn skipBytes(self: *DataInput2, n: usize) DbError!void {
        const p = std.math.add(usize, self.pos, n) catch return error.DataCorruption;
        try self.seek(p);
    }

    /// Borrow the underlying slice (byte-side in-place compares).
    pub fn slice(self: *const DataInput2) []const u8 {
        return self.buf;
    }

    /// Subslice `[start, start+n)` if fully in range; else corruption.
    pub fn subslice(self: *const DataInput2, start: usize, n: usize) DbError![]const u8 {
        const end = std.math.add(usize, start, n) catch return error.DataCorruption;
        if (end > self.buf.len or start > end) return error.DataCorruption;
        return self.buf[start..end];
    }

    pub fn readU8(self: *DataInput2) DbError!u8 {
        if (self.pos >= self.buf.len) return error.DataCorruption;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }

    /// Java `readByte()` — signed.
    pub fn readI8(self: *DataInput2) DbError!i8 {
        return @bitCast(try self.readU8());
    }

    /// Java `readUnsignedByte()`.
    pub fn readUnsignedByte(self: *DataInput2) DbError!i32 {
        return @as(i32, try self.readU8());
    }

    /// Fill `dst` fully, advancing by `dst.len`. Error on overrun.
    pub fn readFully(self: *DataInput2, dst: []u8) DbError!void {
        const src = try self.takeBytes(dst.len);
        @memcpy(dst, src);
    }

    /// Borrow the next `n` bytes and advance (checked).
    pub fn takeBytes(self: *DataInput2, n: usize) DbError![]const u8 {
        const end = std.math.add(usize, self.pos, n) catch return error.DataCorruption;
        if (end > self.buf.len) return error.DataCorruption;
        const src = self.buf[self.pos..end];
        self.pos = end;
        return src;
    }

    fn readBe(self: *DataInput2, comptime T: type) DbError!T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        const src = try self.takeBytes(n);
        return std.mem.readInt(T, src[0..n], .big);
    }

    /// 2-byte big-endian signed (Short).
    pub fn readI16(self: *DataInput2) DbError!i16 {
        return self.readBe(i16);
    }
    /// 2-byte big-endian unsigned (Char).
    pub fn readU16(self: *DataInput2) DbError!u16 {
        return self.readBe(u16);
    }
    /// 4-byte big-endian (Java `readInt`).
    pub fn readI32(self: *DataInput2) DbError!i32 {
        return self.readBe(i32);
    }
    /// 8-byte big-endian (Java `readLong`).
    pub fn readI64(self: *DataInput2) DbError!i64 {
        return self.readBe(i64);
    }
    /// Raw big-endian u64 (DirTree bitmaps, long-stack chunk headers).
    pub fn readU64(self: *DataInput2) DbError!u64 {
        return self.readBe(u64);
    }

    /// Decode a packed varint, rejecting a run longer than `max_bytes`
    /// (10 for u64, 5 for the 32-bit form) — an over-long run is corruption.
    fn unpackCapped(self: *DataInput2, max_bytes: usize) DbError!u64 {
        var ret: u64 = 0;
        var i: usize = 0;
        while (i < max_bytes) : (i += 1) {
            const v = try self.readU8();
            ret = (ret << 7) | @as(u64, v & 0x7F);
            if (v & 0x80 != 0) return ret;
        }
        return error.DataCorruption;
    }

    pub fn unpackLong(self: *DataInput2) DbError!u64 {
        return self.unpackCapped(max_packed_long_bytes);
    }

    /// Java `unpackInt() == (int) unpackLong()`, capped at 5 bytes (D4) so
    /// `unpackInt` and `unpackLongSkip` agree on over-long runs.
    pub fn unpackInt(self: *DataInput2) DbError!i32 {
        const v = try self.unpackCapped(max_packed_int_bytes);
        return @bitCast(@as(u32, @truncate(v)));
    }

    /// Skip `count` packed longs without decoding, scanning for terminator
    /// bytes (bit 0x80). Each skipped value capped at 10 bytes, matching
    /// `unpackLong`, so a value the decoder would reject cannot be skipped.
    pub fn unpackLongSkip(self: *DataInput2, count: usize) DbError!void {
        var remaining_vals = count;
        while (remaining_vals > 0) : (remaining_vals -= 1) {
            var run: usize = 0;
            while (true) {
                const terminated = (try self.readU8()) & 0x80 != 0;
                run += 1;
                if (terminated) break;
                if (run >= max_packed_long_bytes) return error.DataCorruption;
            }
        }
    }

    /// Compare the next `expected.len` bytes against `expected`. The position
    /// ALWAYS advances by `expected.len`, match or not. Error on overrun.
    pub fn matchBytes(self: *DataInput2, expected: []const u8) DbError!bool {
        const src = try self.takeBytes(expected.len);
        return std.mem.eql(u8, src, expected);
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn packed_(alloc: Allocator, v: u64) ![]u8 {
    var o = DataOutput2.init(alloc);
    defer o.deinit();
    try o.packLong(v);
    return o.copyBytes(alloc);
}

test "pack_long boundaries (rust io.rs golden)" {
    const a = testing.allocator;
    const cases = [_]struct { v: u64, want: []const u8 }{
        .{ .v = 0, .want = &.{0x80} },
        .{ .v = 1, .want = &.{0x81} },
        .{ .v = 127, .want = &.{0xFF} },
        .{ .v = 128, .want = &.{ 0x01, 0x80 } },
        .{ .v = 300, .want = &.{ 0x02, 0xAC } },
        .{ .v = 16383, .want = &.{ 0x7F, 0xFF } },
        .{ .v = 16384, .want = &.{ 0x01, 0x00, 0x80 } },
    };
    for (cases) |c| {
        const got = try packed_(a, c.v);
        defer a.free(got);
        try testing.expectEqualSlices(u8, c.want, got);
    }
    const m = try packed_(a, @intCast(std.math.maxInt(i64)));
    defer a.free(m);
    try testing.expectEqual(@as(usize, 9), m.len);
    try testing.expectEqual(@as(u8, 0xFF), m[m.len - 1]);
    const mm = try packed_(a, std.math.maxInt(u64));
    defer a.free(mm);
    try testing.expectEqual(@as(usize, 10), mm.len);
}

test "pack/unpack roundtrip" {
    const a = testing.allocator;
    const vals = [_]u64{
        0,       1,                              63,                       64,                   127,   128,
        129,     255,                            256,                      16383,                16384, 1 << 20,
        1 << 35, @intCast(std.math.maxInt(i64)), std.math.maxInt(u64) - 1, std.math.maxInt(u64), 300,   99999,
    };
    for (vals) |v| {
        const b = try packed_(a, v);
        defer a.free(b);
        var inp = DataInput2.init(b);
        try testing.expectEqual(v, try inp.unpackLong());
        try testing.expectEqual(b.len, inp.pos);
    }
}

test "packInt masks to 32 bits" {
    const a = testing.allocator;
    var o = DataOutput2.init(a);
    defer o.deinit();
    try o.packInt(-1);
    var inp = DataInput2.init(o.bytes());
    try testing.expectEqual(@as(i32, -1), try inp.unpackInt());

    var o2 = DataOutput2.init(a);
    defer o2.deinit();
    try o2.packInt(5);
    const p5 = try packed_(a, 5);
    defer a.free(p5);
    try testing.expectEqualSlices(u8, p5, o2.bytes());
}

test "big-endian ints" {
    const a = testing.allocator;
    var o = DataOutput2.init(a);
    defer o.deinit();
    try o.writeI32(0x01020304);
    try o.writeI64(0x0102030405060708);
    try o.writeI16(-2);
    const b = o.bytes();
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, b[0..4]);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, b[4..12]);
    try testing.expectEqualSlices(u8, &.{ 0xFF, 0xFE }, b[12..14]);
    var inp = DataInput2.init(b);
    try testing.expectEqual(@as(i32, 0x01020304), try inp.readI32());
    try testing.expectEqual(@as(i64, 0x0102030405060708), try inp.readI64());
    try testing.expectEqual(@as(i16, -2), try inp.readI16());
}

test "unpackLongSkip matches decode" {
    const a = testing.allocator;
    var o = DataOutput2.init(a);
    defer o.deinit();
    const vals = [_]u64{ 0, 200, 128, 99999, 7 };
    for (vals) |v| try o.packLong(v);
    var inp = DataInput2.init(o.bytes());
    try inp.unpackLongSkip(3);
    try testing.expectEqual(@as(u64, 99999), try inp.unpackLong());
    try testing.expectEqual(@as(u64, 7), try inp.unpackLong());
}

test "matchBytes always advances" {
    var inp = DataInput2.init("MDB5.SD1extra");
    try testing.expect(try inp.matchBytes("MDB5.SD1"));
    try testing.expectEqual(@as(usize, 8), inp.pos);
    var inp2 = DataInput2.init("MDB5.SD1extra");
    try testing.expect(!try inp2.matchBytes("XXXX.SD1"));
    try testing.expectEqual(@as(usize, 8), inp2.pos);
}

test "reads error, never crash" {
    var inp = DataInput2.init(&.{ 0, 0 });
    try testing.expectError(error.DataCorruption, inp.readI32());
    var inp2 = DataInput2.init(&.{ 0, 0 });
    try testing.expectError(error.DataCorruption, inp2.readI64());
    const bad = [_]u8{0} ** 12;
    var inp3 = DataInput2.init(&bad);
    try testing.expectError(error.DataCorruption, inp3.unpackLong());
    var inp4 = DataInput2.init(&.{ 0, 0 });
    try testing.expectError(error.DataCorruption, inp4.seek(3));
    try inp4.seek(2);
}
