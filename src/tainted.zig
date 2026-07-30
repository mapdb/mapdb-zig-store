//! `tainted` — the ONE audited conversion boundary for persisted-derived values.
//! Every value decoded from on-volume bytes is *tainted*: it may only be
//! narrowed, shifted, range-checked or turned into a slice through the helpers
//! here, each mapping a violation to `error.DataCorruption`. OUTSIDE this module,
//! on any tainted-derived path (reads AND writes), direct `@intCast` /
//! `@enumFromInt` / `@alignCast` / `unreachable` and unchecked `off + len` on
//! tainted values are BANNED (enforced by review + grep). This is the audited
//! surface the Rust hardening rounds converged on (corrupt-index-driven
//! writes clobbering metadata were a real finding).
//!
//! v1 is 64-bit only (comptime-asserted): `usize == u64`, so a u64 length always
//! fits a `usize` and `u64ToUsize` is lossless. A 32-bit target would need a
//! per-conversion contract nobody is asking for.

const std = @import("std");
const DbError = @import("errors.zig").DbError;

comptime {
    // Every narrowing here assumes usize can hold any u64.
    std.debug.assert(@bitSizeOf(usize) == 64);
    std.debug.assert(usize == u64 or @bitSizeOf(usize) == @bitSizeOf(u64));
}

/// Narrow a tainted u64 to `usize`. Lossless on 64-bit (identity); the fallible
/// signature is kept so callers route through the audited surface uniformly.
pub inline fn u64ToUsize(v: u64) DbError!usize {
    return @intCast(v); // usize == u64: never truncates
}

/// `a + b` with overflow → `error.DataCorruption` (a crafted `off ≈ maxInt` must
/// not wrap into a small accepted value — the Rust hazard class).
pub inline fn checkedAdd(comptime T: type, a: T, b: T) DbError!T {
    return std.math.add(T, a, b) catch error.DataCorruption;
}

pub inline fn checkedSub(comptime T: type, a: T, b: T) DbError!T {
    return std.math.sub(T, a, b) catch error.DataCorruption;
}

pub inline fn checkedMul(comptime T: type, a: T, b: T) DbError!T {
    return std.math.mul(T, a, b) catch error.DataCorruption;
}

/// Left shift of a tainted u64 by a possibly-tainted `amount`; an out-of-range
/// amount (>= 64) is corruption. The result is a plain (wrapping) logical shift,
/// matching the on-volume `<< 3` offset packing — callers range-check the
/// *result* separately via `checkedRange`/`checkedAdd`.
pub inline fn checkedShift(v: u64, amount: u32) DbError!u64 {
    if (amount >= 64) return error.DataCorruption;
    return v << @intCast(amount);
}

/// Prove `[off, off+len)` lies within `[0, extent)` with no wrap. The single
/// guard every value-derived volume access must pass before raw byte access
/// (ReleaseFast has no implicit checks; ReleaseSafe panics are ALSO failures for
/// crafted input — this returns a clean error instead).
pub inline fn checkedRange(off: u64, len: u64, extent: u64) DbError!void {
    const end = try checkedAdd(u64, off, len);
    if (end > extent) return error.DataCorruption;
}

/// Sub-slice `buf[off..off+len]` with a bounds check → `error.DataCorruption`.
pub inline fn checkedSlice(buf: []const u8, off: usize, len: usize) DbError![]const u8 {
    const end = try checkedAdd(usize, off, len);
    if (end > buf.len) return error.DataCorruption;
    return buf[off..end];
}

/// Mutable variant of `checkedSlice`.
pub inline fn checkedSliceMut(buf: []u8, off: usize, len: usize) DbError![]u8 {
    const end = try checkedAdd(usize, off, len);
    if (end > buf.len) return error.DataCorruption;
    return buf[off..end];
}

/// Turn a tainted integer tag into an enum value, rejecting an out-of-domain tag.
pub inline fn checkedEnum(comptime E: type, tag: @typeInfo(E).@"enum".tag_type) DbError!E {
    return std.meta.intToEnum(E, tag) catch error.DataCorruption;
}

// ------------------------------------------------------------------- tests

const testing = std.testing;

test "u64ToUsize is lossless on 64-bit" {
    try testing.expectEqual(@as(usize, 0), try u64ToUsize(0));
    try testing.expectEqual(@as(usize, std.math.maxInt(u64)), try u64ToUsize(std.math.maxInt(u64)));
}

test "checkedAdd/Sub/Mul overflow → DataCorruption" {
    try testing.expectEqual(@as(u64, 30), try checkedAdd(u64, 10, 20));
    try testing.expectError(error.DataCorruption, checkedAdd(u64, std.math.maxInt(u64), 1));
    try testing.expectError(error.DataCorruption, checkedAdd(u64, std.math.maxInt(u64) - 15, 16));
    try testing.expectEqual(@as(u64, 5), try checkedSub(u64, 20, 15));
    try testing.expectError(error.DataCorruption, checkedSub(u64, 0, 1));
    try testing.expectEqual(@as(u64, 200), try checkedMul(u64, 20, 10));
    try testing.expectError(error.DataCorruption, checkedMul(u64, std.math.maxInt(u64), 2));
}

test "checkedShift rejects out-of-range amount, wraps the result" {
    try testing.expectEqual(@as(u64, 0x80), try checkedShift(0x10, 3));
    try testing.expectError(error.DataCorruption, checkedShift(1, 64));
    try testing.expectError(error.DataCorruption, checkedShift(1, 999));
    // the crafted-file vector: (0xFFFF_FFFF_FFFF_FFF0 >> 3) << 3 == 0xFFFF_FFFF_FFFF_FFF0
    const off = (@as(u64, 0xFFFF_FFFF_FFFF_FFF0) >> 3);
    try testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFF0), try checkedShift(off, 3));
}

test "checkedRange boundary + overflow" {
    try checkedRange(0, 16, 16);
    try checkedRange(8, 8, 16);
    try testing.expectError(error.DataCorruption, checkedRange(8, 9, 16));
    try testing.expectError(error.DataCorruption, checkedRange(std.math.maxInt(u64) - 15, 16, std.math.maxInt(u64)));
}

test "checkedSlice bounds" {
    const buf = [_]u8{ 1, 2, 3, 4, 5 };
    try testing.expectEqualSlices(u8, &.{ 2, 3 }, try checkedSlice(&buf, 1, 2));
    try testing.expectEqualSlices(u8, &.{}, try checkedSlice(&buf, 5, 0));
    try testing.expectError(error.DataCorruption, checkedSlice(&buf, 4, 2));
    try testing.expectError(error.DataCorruption, checkedSlice(&buf, std.math.maxInt(usize), 1));
}

test "checkedEnum rejects out-of-domain tag" {
    const E = enum(u8) { a = 0, b = 1, c = 2 };
    try testing.expectEqual(E.b, try checkedEnum(E, 1));
    try testing.expectError(error.DataCorruption, checkedEnum(E, 7));
}
