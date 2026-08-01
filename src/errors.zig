//! Error set — the Java `DBException` hierarchy / Rust `DbError` enum
//! mapped to a Zig error set.
//!
//! Zig errors carry no payload; context (recid, corruption reason) moves to
//! a per-store `ErrorCtx` diagnostic slot written before returning the error.
//! TCK ports assert exact error identities, so member identity is contract.

const std = @import("std");

pub const DbError = error{
    /// Read of a Void or Deleted recid.
    GetVoid,
    /// Record content exceeds the maximum single-record capacity.
    RecordTooLarge,
    /// Persisted bytes failed a structural/parity/checksum invariant.
    DataCorruption,
    /// Allocator hit the 44-bit volume ceiling (or backing store full).
    StoreFull,
    /// Operation attempted on a closed store.
    StoreClosed,
    /// `verify()` found the on-disk tiling inconsistent.
    VerifyFailed,
    /// Pump input was not strictly ascending (misorder or duplicate).
    NotSorted,
    /// A conflicting handle already holds the open lease.
    AlreadyOpen,
    /// The WAL store lock is held by another process, or by another open in
    /// THIS process. Distinct from `AlreadyOpen`, which is the in-handle lease:
    /// this one is the cross-process store lock of WAL format v3 (`<base>.lock`,
    /// an OFD record lock plus a process-local claim). Java throws
    /// `DBException` for both; the ports separate them because only this one
    /// says "another owner has the store", which a caller may reasonably retry.
    Locked,
    /// `Db.close()` while a facade-created handle (map/set/atomic/queue) is still
    /// open (Zig teardown-order enforcement).
    HandlesOpen,
    /// A DB maker/catalog operation was given an illegal configuration (unknown
    /// name, name collision, illegal name, read-only empty store, bad option
    /// combination); Java `IllegalArgumentException`/`DBException.WrongConfiguration`.
    WrongConfiguration,
    /// A named object exists but with a different `#type` than the maker requested
    /// (Java `DBException.WrongConfiguration` "different type").
    WrongType,
    /// Genuine allocation failure (allocations from persisted lengths are
    /// bounds-validated FIRST, so an unbounded-garbage length surfaces as
    /// DataCorruption, never as OOM).
    OutOfMemory,
    /// Underlying I/O failure (posix errors folded at the volume boundary).
    Io,
    /// Mutation attempted through a logically read-only store view
    /// (`StoreReadOnlyWrapper`); Java `UnsupportedOperationException`.
    ReadOnly,
    /// Operation not supported in the current configuration (e.g. bulk
    /// `createFromSorted` / columnar scan on an external-value map); Java
    /// `UnsupportedOperationException`.
    Unsupported,
};

/// Diagnostic side channel: stores/maps embed one and fill it just
/// before returning an error. Never load-bearing for control flow.
pub const ErrorCtx = struct {
    /// Static reason string naming the failed check (parity, magic, bounds...).
    reason: []const u8 = "",
    /// Offending recid, when meaningful (GetVoid, AlreadyOpen).
    recid: u64 = 0,

    pub fn set(self: *ErrorCtx, reason: []const u8, recid: u64) void {
        self.* = .{ .reason = reason, .recid = recid };
    }
};

test "error set members are distinct and nameable" {
    const e: DbError = error.DataCorruption;
    try std.testing.expect(e == error.DataCorruption);
    try std.testing.expect(e != error.GetVoid);
}
