//! Bit-parity encodings for on-volume pointers/counters (Java `Parity`,
//! §5), ported from `mapdb-rust-store/src/store/parity.rs`. The low N bits of the
//! stored long carry a checksum of the payload bits: `p1` for 2-aligned
//! payloads, `p4` for 16-aligned, `p16` for 1 MiB-aligned.
//!
//! A raw stored value of 0 always FAILS its parity check, so "never written /
//! lost update" is distinguishable from every legitimately-stored value
//! (including the encoded 0 used for empty links — `p1set(0) == 1`).

const std = @import("std");
const DbError = @import("../errors.zig").DbError;

inline fn ones(v: u64) u64 {
    return @popCount(v);
}

/// `v` must have bit 0 clear; result has an odd total bit count.
pub inline fn p1set(v: u64) u64 {
    std.debug.assert(v & 1 == 0); // parity1 payload uses bit 0
    return v | ((ones(v) + 1) & 1);
}

/// Validate and strip parity1.
pub inline fn p1get(v: u64) DbError!u64 {
    if (ones(v) & 1 != 1) return error.DataCorruption; // parity1 broken
    return v & ~@as(u64, 1);
}

/// `v` must have the low 4 bits clear.
pub inline fn p4set(v: u64) u64 {
    std.debug.assert(v & 0xF == 0); // parity4 payload uses low 4 bits
    return v | ((ones(v) + 1) & 0xF);
}

pub inline fn p4get(v: u64) DbError!u64 {
    const x = v & ~@as(u64, 0xF);
    if ((v & 0xF) != ((ones(x) + 1) & 0xF)) return error.DataCorruption; // parity4 broken
    return x;
}

/// `v` must have the low 16 bits clear.
pub inline fn p16set(v: u64) u64 {
    std.debug.assert(v & 0xFFFF == 0); // parity16 payload uses low 16 bits
    return v | ((ones(v) + 1) & 0xFFFF);
}

pub inline fn p16get(v: u64) DbError!u64 {
    const x = v & ~@as(u64, 0xFFFF);
    if ((v & 0xFFFF) != ((ones(x) + 1) & 0xFFFF)) return error.DataCorruption; // parity16 broken
    return x;
}

// ------------------------------------------------------------------- tests

const testing = std.testing;

test "roundtrip and raw-zero fails (the never-written guarantee)" {
    for ([_]u64{ 0, 16, 0x10, 0xFF0, 1 << 20, 0x0000_FFFF_FFFF_FFF0 }) |v| {
        try testing.expectEqual(v, try p1get(p1set(v)));
    }
    for ([_]u64{ 0, 16, 0x10, 0xFF0, 1 << 20, 0x0000_FFFF_FFFF_FFF0 }) |v| {
        try testing.expectEqual(v, try p4get(p4set(v)));
    }
    for ([_]u64{ 0, 1 << 16, 1 << 20, 1 << 40 }) |v| {
        try testing.expectEqual(v, try p16get(p16set(v)));
    }
    // raw 0 fails every parity check
    try testing.expectError(error.DataCorruption, p1get(0));
    try testing.expectError(error.DataCorruption, p4get(0));
    try testing.expectError(error.DataCorruption, p16get(0));
    // p*set(0) is a valid non-zero encoding of 0
    try testing.expectEqual(@as(u64, 1), p1set(0));
    try testing.expectEqual(@as(u64, 0), try p1get(p1set(0)));
}

test "corrupt bit-flip detected" {
    const good = p4set(0x1230);
    try testing.expectError(error.DataCorruption, p4get(good ^ 0x100)); // flip a payload bit
}
