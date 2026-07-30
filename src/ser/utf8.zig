//! Shared ser helpers: zigzag, Java-exact comparisons, in-place UTF-8 compare,
//! and lossy UTF-8 materialization. Ported from `mapdb-rust-store/src/ser/util.rs`.
//!
//! Order coherence (top-risk #3): each comparison mirrors an exact Java
//! semantic. `compareUtf16` = `String.compareTo` (UTF-16 code-unit order);
//! `compareSignedBytes` = `Arrays.compare` (signed); `compareUtf8` matches
//! `String.compareTo` against stored UTF-8 in place (`Utf8`).
//!
//! Malformed-UTF-8 split: `compareUtf8` (search/compare path) is STRICT
//! (malformed → `error.DataCorruption`, RFC 3629). `utf8Lossy`
//! (materialization) is LOSSY — U+FFFD replacement with WHATWG maximal-subpart
//! granularity, matching Rust `String::from_utf8_lossy`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const DataInput2 = @import("../io.zig").DataInput2;

// ------------------------------------------------------------- zigzag (i64)

/// `(v<<1) ^ (v>>63)` — signed → unsigned zigzag.
pub fn zigzag(v: i64) u64 {
    const u: u64 = @bitCast(v);
    // arithmetic shift right by 63 = sign broadcast.
    const sign: u64 = @bitCast(v >> 63);
    return (u << 1) ^ sign;
}

/// `(v>>>1) ^ -(v&1)` — inverse of [`zigzag`].
pub fn unzigzag(v: u64) i64 {
    const half: i64 = @bitCast(v >> 1);
    const neg: i64 = -@as(i64, @intCast(v & 1));
    return half ^ neg;
}

// ------------------------------------------------------------- zigzag (i32)

/// `(v<<1) ^ (v>>31)` — 32-bit zigzag (Java `IntDeltaFormat.zigzag`).
pub fn zigzag32(v: i32) i32 {
    const u: u32 = @bitCast(v);
    const sign: u32 = @bitCast(v >> 31);
    return @bitCast((u << 1) ^ sign);
}

/// `(v>>>1) ^ -(v&1)` — inverse of [`zigzag32`].
pub fn unzigzag32(v: i32) i32 {
    const u: u32 = @bitCast(v);
    const half: i32 = @bitCast(u >> 1);
    return half ^ -(v & 1);
}

// ------------------------------------------------------------- byte compares

/// `Arrays.compare(byte[], byte[])`: signed-byte lexicographic, shorter-is-less
/// on a shared prefix.
pub fn compareSignedBytes(a: []const u8, b: []const u8) Order {
    const n = @min(a.len, b.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const x: i8 = @bitCast(a[i]);
        const y: i8 = @bitCast(b[i]);
        if (x != y) return if (x < y) .lt else .gt;
    }
    return std.math.order(a.len, b.len);
}

/// `Arrays.compareUnsigned(byte[], byte[])`: unsigned (memcmp) lexicographic.
pub fn compareUnsignedBytes(a: []const u8, b: []const u8) Order {
    return switch (std.mem.order(u8, a, b)) {
        .lt => .lt,
        .eq => .eq,
        .gt => .gt,
    };
}

/// Length of the common **byte** prefix of two byte slices.
pub fn commonPrefixLen(a: []const u8, b: []const u8) usize {
    const n = @min(a.len, b.len);
    var i: usize = 0;
    while (i < n and a[i] == b[i]) : (i += 1) {}
    return i;
}

// ------------------------------------------------------------- UTF-16 compare

/// Iterator over the UTF-16 code units of a **valid** UTF-8 slice. Lenient on
/// malformed input (each stray byte → U+FFFD advancing one byte) — inputs on
/// this path are already valid (serialize checks / lossy materialization), so
/// leniency never triggers in practice but keeps the compare total.
const Utf16Iter = struct {
    b: []const u8,
    i: usize = 0,
    lo: ?u16 = null,

    fn next(self: *Utf16Iter) ?u16 {
        if (self.lo) |l| {
            self.lo = null;
            return l;
        }
        if (self.i >= self.b.len) return null;
        const cp = self.decodeCp();
        if (cp < 0x10000) return @intCast(cp);
        const v = cp - 0x10000;
        self.lo = @intCast(0xDC00 | (v & 0x3FF));
        return @intCast(0xD800 | (v >> 10));
    }

    fn decodeCp(self: *Utf16Iter) u32 {
        const b0: u32 = self.b[self.i];
        if (b0 < 0x80) {
            self.i += 1;
            return b0;
        }
        var need: usize = 0;
        var cp: u32 = 0;
        if (b0 & 0xE0 == 0xC0) {
            need = 1;
            cp = b0 & 0x1F;
        } else if (b0 & 0xF0 == 0xE0) {
            need = 2;
            cp = b0 & 0x0F;
        } else if (b0 & 0xF8 == 0xF0) {
            need = 3;
            cp = b0 & 0x07;
        } else {
            self.i += 1;
            return 0xFFFD;
        }
        if (self.i + 1 + need > self.b.len) {
            self.i += 1;
            return 0xFFFD;
        }
        var k: usize = 1;
        while (k <= need) : (k += 1) {
            const c: u32 = self.b[self.i + k];
            if (c & 0xC0 != 0x80) {
                self.i += 1;
                return 0xFFFD;
            }
            cp = (cp << 6) | (c & 0x3F);
        }
        self.i += 1 + need;
        return cp;
    }
};

/// `String.compareTo`: UTF-16 code-unit lexicographic order. Differs from
/// code-point order only for supplementary characters.
pub fn compareUtf16(a: []const u8, b: []const u8) Order {
    var ia = Utf16Iter{ .b = a };
    var ib = Utf16Iter{ .b = b };
    while (true) {
        const ua = ia.next();
        const ub = ib.next();
        if (ua == null and ub == null) return .eq;
        if (ua == null) return .lt;
        if (ub == null) return .gt;
        if (ua.? != ub.?) return if (ua.? < ub.?) .lt else .gt;
    }
}

// ------------------------------------------------------------- in-place UTF-8

/// Compare one produced UTF-16 unit against the next key unit. Returns non-null
/// Order to stop, null to continue.
fn cmpUnit(kit: *Utf16Iter, unit: u16) ?Order {
    const ku = kit.next() orelse return .gt; // key is a strict prefix of stored
    if (unit != ku) return if (unit < ku) Order.lt else Order.gt;
    return null;
}

/// Sign of `stored.compareTo(key)` where `stored` is the UTF-8 string spanning
/// exactly `byte_len` bytes at `input`'s position and `key` is a valid-UTF-8
/// slice (compared in UTF-16 code-unit order). Consumes at most `byte_len` bytes
/// (fewer on early difference; caller re-seeks). Zero allocation.
///
/// STRICT on the STORED bytes: malformed/torn UTF-8 → `error.DataCorruption`
/// (RFC 3629 well-formedness), never a plausible-looking key.
pub fn compareUtf8(input: *DataInput2, byte_len: usize, key_utf8: []const u8) DbError!Order {
    var kit = Utf16Iter{ .b = key_utf8 };
    var rem = byte_len;
    while (rem > 0) {
        const b0: u32 = try input.readU8();
        rem -= 1;
        var cp: u32 = 0;
        var need: usize = 0;
        if (b0 < 0x80) {
            cp = b0;
            need = 0;
        } else if (b0 & 0xE0 == 0xC0) {
            cp = b0 & 0x1F;
            need = 1;
        } else if (b0 & 0xF0 == 0xE0) {
            cp = b0 & 0x0F;
            need = 2;
        } else if (b0 & 0xF8 == 0xF0) {
            cp = b0 & 0x07;
            need = 3;
        } else {
            return error.DataCorruption;
        }
        if (need > rem) return error.DataCorruption;
        var k: usize = 0;
        while (k < need) : (k += 1) {
            const b: u32 = try input.readU8();
            if (b & 0xC0 != 0x80) return error.DataCorruption;
            cp = (cp << 6) | (b & 0x3F);
        }
        rem -= need;
        // RFC 3629 well-formedness.
        switch (need) {
            1 => if (cp < 0x80) return error.DataCorruption,
            2 => if (cp < 0x800 or (cp >= 0xD800 and cp <= 0xDFFF)) return error.DataCorruption,
            3 => if (cp < 0x10000 or cp > 0x10FFFF) return error.DataCorruption,
            else => {},
        }
        if (cp < 0x10000) {
            if (cmpUnit(&kit, @intCast(cp))) |o| return o;
        } else {
            const v = cp - 0x10000;
            const hi: u16 = @intCast(0xD800 | (v >> 10));
            const lo: u16 = @intCast(0xDC00 | (v & 0x3FF));
            if (cmpUnit(&kit, hi)) |o| return o;
            if (cmpUnit(&kit, lo)) |o| return o;
        }
    }
    // stored exhausted: equal, or stored is a strict prefix of key.
    return if (kit.next() == null) .eq else .lt;
}

// ------------------------------------------------------------- lossy decode

const REPLACEMENT: [3]u8 = .{ 0xEF, 0xBF, 0xBD }; // U+FFFD

/// The (lower,upper) valid range of the FIRST continuation byte and the number
/// of continuation bytes for a given lead byte. Returns null for an invalid
/// lead byte (0x80..=0xC1, 0xF5..=0xFF).
fn leadInfo(b0: u8) ?struct { lower: u8, upper: u8, needed: usize } {
    return switch (b0) {
        0xC2...0xDF => .{ .lower = 0x80, .upper = 0xBF, .needed = 1 },
        0xE0 => .{ .lower = 0xA0, .upper = 0xBF, .needed = 2 },
        0xE1...0xEC => .{ .lower = 0x80, .upper = 0xBF, .needed = 2 },
        0xED => .{ .lower = 0x80, .upper = 0x9F, .needed = 2 },
        0xEE...0xEF => .{ .lower = 0x80, .upper = 0xBF, .needed = 2 },
        0xF0 => .{ .lower = 0x90, .upper = 0xBF, .needed = 3 },
        0xF1...0xF3 => .{ .lower = 0x80, .upper = 0xBF, .needed = 3 },
        0xF4 => .{ .lower = 0x80, .upper = 0x8F, .needed = 3 },
        else => null,
    };
}

/// Lossy UTF-8 → owned valid UTF-8 with U+FFFD substituted for each maximal
/// ill-formed subpart (WHATWG / Unicode "maximal subpart" replacement, matching
/// Rust `String::from_utf8_lossy`). Fast-paths already-valid input to a dupe.
pub fn utf8Lossy(alloc: Allocator, bytes: []const u8) DbError![]u8 {
    if (std.unicode.utf8ValidateSlice(bytes)) return alloc.dupe(u8, bytes);

    var out = std.ArrayList(u8){};
    errdefer out.deinit(alloc);
    var i: usize = 0;
    while (i < bytes.len) {
        const b0 = bytes[i];
        if (b0 < 0x80) {
            try out.append(alloc, b0);
            i += 1;
            continue;
        }
        const info = leadInfo(b0) orelse {
            // Invalid lead byte: one U+FFFD, advance one byte.
            try out.appendSlice(alloc, &REPLACEMENT);
            i += 1;
            continue;
        };
        // Count how many continuation bytes are valid (maximal subpart).
        var valid: usize = 0;
        var ok = true;
        while (valid < info.needed) : (valid += 1) {
            const idx = i + 1 + valid;
            if (idx >= bytes.len) {
                ok = false;
                break;
            }
            const c = bytes[idx];
            const lower: u8 = if (valid == 0) info.lower else 0x80;
            const upper: u8 = if (valid == 0) info.upper else 0xBF;
            if (c < lower or c > upper) {
                ok = false;
                break;
            }
        }
        if (ok and valid == info.needed) {
            try out.appendSlice(alloc, bytes[i .. i + 1 + info.needed]);
            i += 1 + info.needed;
        } else {
            try out.appendSlice(alloc, &REPLACEMENT);
            i += 1 + valid; // consume the maximal valid subpart
        }
    }
    return out.toOwnedSlice(alloc);
}

// ------------------------------------------------------------------- tests

const testing = std.testing;

test "zigzag round-trips (i64)" {
    const vals = [_]i64{ 0, -1, 1, -2, 2, std.math.minInt(i64), std.math.maxInt(i64), -100, 1000 };
    for (vals) |v| try testing.expectEqual(v, unzigzag(zigzag(v)));
    try testing.expectEqual(@as(u64, 0), zigzag(0));
    try testing.expectEqual(@as(u64, 1), zigzag(-1));
    try testing.expectEqual(@as(u64, 2), zigzag(1));
}

test "zigzag round-trips (i32)" {
    const vals = [_]i32{ 0, -1, 1, std.math.minInt(i32), std.math.maxInt(i32), -100, 1000 };
    for (vals) |v| try testing.expectEqual(v, unzigzag32(zigzag32(v)));
}

test "compareUtf16 supplementary vs BMP" {
    // U+10000 (surrogate D800 DC00) < U+FF61 (0xFF61) in UTF-16 order.
    try testing.expectEqual(Order.lt, compareUtf16("\u{10000}", "\u{FF61}"));
    // code-point order would say the opposite (0x10000 > 0xFF61).
    try testing.expectEqual(Order.lt, compareUtf16("a", "b"));
    try testing.expectEqual(Order.eq, compareUtf16("abc", "abc"));
    try testing.expectEqual(Order.lt, compareUtf16("ab", "abc"));
}

test "compareUtf8 matches compareUtf16" {
    const io = @import("../io.zig");
    const stored = "apple";
    var inp = io.DataInput2.init(stored);
    try testing.expectEqual(Order.lt, try compareUtf8(&inp, stored.len, "apply"));
    // key is strict prefix of stored → stored greater
    var inp2 = io.DataInput2.init(stored);
    try testing.expectEqual(Order.gt, try compareUtf8(&inp2, stored.len, "app"));
    // supplementary vs BMP agrees with compareUtf16
    var inp3 = io.DataInput2.init("\u{10000}");
    try testing.expectEqual(Order.lt, try compareUtf8(&inp3, "\u{10000}".len, "\u{FF61}"));
}

test "compareUtf8 strict rejects malformed stored" {
    const io = @import("../io.zig");
    const bad = [_]u8{ 0xC0, 0x80 }; // overlong
    var inp = io.DataInput2.init(&bad);
    try testing.expectError(error.DataCorruption, compareUtf8(&inp, bad.len, "x"));
}

test "utf8Lossy maximal-subpart replacement (WHATWG vectors)" {
    const a = testing.allocator;
    // valid passes through
    {
        const r = try utf8Lossy(a, "héllo");
        defer a.free(r);
        try testing.expectEqualStrings("héllo", r);
    }
    // lone 0x80 continuation → one U+FFFD
    {
        const r = try utf8Lossy(a, &[_]u8{ 'a', 0x80, 'b' });
        defer a.free(r);
        try testing.expectEqualStrings("a\u{FFFD}b", r);
    }
    // truncated 3-byte seq E2 82 (needs one more) → one U+FFFD
    {
        const r = try utf8Lossy(a, &[_]u8{ 0xE2, 0x82 });
        defer a.free(r);
        try testing.expectEqualStrings("\u{FFFD}", r);
    }
    // 0xF0 0x28 (0x28 not a valid first continuation for F0) → FFFD then '('
    {
        const r = try utf8Lossy(a, &[_]u8{ 0xF0, 0x28, 0x8C, 0x28 });
        defer a.free(r);
        try testing.expectEqualStrings("\u{FFFD}(\u{FFFD}(", r);
    }
    // 0xED 0xA0 0x80 is a surrogate encoding: 0xA0 out of ED's range 0x80..0x9F
    // → FFFD then 0xA0 lone → FFFD then 0x80 lone → FFFD
    {
        const r = try utf8Lossy(a, &[_]u8{ 0xED, 0xA0, 0x80 });
        defer a.free(r);
        try testing.expectEqualStrings("\u{FFFD}\u{FFFD}\u{FFFD}", r);
    }
}
