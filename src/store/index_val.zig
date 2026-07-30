//! Capacity-based index-value encoding (Java `IndexVal`), ported
//! from `mapdb-rust-store/src/store/index_val.rs`:
//!
//! ```text
//! bit 63..48  capacityUnits (16 bits) — capacity = capacityUnits * 16 bytes
//! bit 47..4   offset (44 bits, 16-aligned)
//! bit 3       linked   (oversize records as chunk chains)
//! bit 2       prealloc (P state)
//! bit 1       archive  (reserved)
//! bit 0       parity   (parity1 over the whole slot once stored)
//! ```
//! Record data layout at offset: 4-byte used-length header, then content.

const std = @import("std");

/// Mask of the 44-bit, 16-aligned offset field.
pub const MOFFSET: u64 = 0x0000_FFFF_FFFF_FFF0;

pub const FLAG_LINKED: u64 = 8;
pub const FLAG_PREALLOC: u64 = 4;
pub const FLAG_ARCHIVE: u64 = 2;

/// capacityUnits sentinel: record content is null (P state iff `FLAG_PREALLOC`).
pub const CAP_NULL: u32 = 0xFFFF;
/// capacityUnits sentinel: recid deleted (tombstone).
pub const CAP_DELETED: u32 = 0xFFFE;
pub const CAP_MAX_UNITS: u32 = 0xFFFD;
/// Max plain-record capacity incl. 4-byte header: ~1 MiB − 48.
pub const MAX_CAPACITY: usize = @as(usize, CAP_MAX_UNITS) * 16;

pub inline fn compose(cap_units: u32, off: u64, flags: u64) u64 {
    std.debug.assert(off & ~MOFFSET == 0); // offset not 16-aligned or out of range
    return (@as(u64, cap_units) << 48) | off | flags;
}

pub inline fn capUnits(iv: u64) u32 {
    return @truncate(iv >> 48);
}

pub inline fn offset(iv: u64) u64 {
    return iv & MOFFSET;
}

pub inline fn isPrealloc(iv: u64) bool {
    return iv & FLAG_PREALLOC != 0;
}

pub inline fn isLinked(iv: u64) bool {
    return iv & FLAG_LINKED != 0;
}

pub inline fn roundUp16(n: usize) usize {
    return (n + 15) & ~@as(usize, 15);
}

// ------------------------------------------------------------------- tests

const testing = std.testing;

test "compose / decompose" {
    const iv = compose(3, 0x1_0000, FLAG_LINKED);
    try testing.expectEqual(@as(u32, 3), capUnits(iv));
    try testing.expectEqual(@as(u64, 0x1_0000), offset(iv));
    try testing.expect(isLinked(iv));
    try testing.expect(!isPrealloc(iv));

    const p = compose(CAP_NULL, 0, FLAG_PREALLOC);
    try testing.expectEqual(CAP_NULL, capUnits(p));
    try testing.expectEqual(@as(u64, 0), offset(p));
    try testing.expect(isPrealloc(p));
}

test "roundUp16" {
    try testing.expectEqual(@as(usize, 0), roundUp16(0));
    try testing.expectEqual(@as(usize, 16), roundUp16(1));
    try testing.expectEqual(@as(usize, 16), roundUp16(16));
    try testing.expectEqual(@as(usize, 32), roundUp16(17));
}
