//! mapdb5 — Zig port of the mapdb5 storage engine.
//! Ported from the Rust implementation (github.com/mapdb/mapdb-rust-store);
//! the reference implementation is the Java engine
//! (github.com/mapdb/mapdb-java-store). The on-disk format is NOT stabilised
//! and carries no cross-implementation or cross-version compatibility
//! guarantee. See `doc/` for the contracts.

// --- layer namespaces (bottom-up; see doc/architecture.md) ---
/// Error set + diagnostics.
pub const errors = @import("errors.zig");
/// Wire primitives: DataInput2/DataOutput2, packed varints.
pub const io = @import("io.zig");
/// Serializers + group formats + the comptime contracts.
pub const ser = @import("ser/mod.zig");
/// Store interface + the four store impls + volume/locks.
pub const store = @import("store/mod.zig");
/// `Shared(T)` — mutex-guarded pinned snapshots.
pub const shared = @import("shared.zig");
/// The audited persisted-value conversion boundary.
pub const tainted = @import("tainted.zig");
/// BTreeMap + navigable views + TreePump.
pub const btree = @import("btree/mod.zig");
/// Map modification listeners + ModificationAwareMap/MapExtra shape contracts.
pub const listener = @import("listener.zig");
/// Persistent queue primitives: QueueLong + PersistentBlockingQueue.
pub const queue = @import("queue/mod.zig");
/// DB/DBMaker facade: name catalog, typed makers, Atomic, Bind.
pub const db = @import("db/mod.zig");
/// Cross-port conformance fixture tests (golden files in src/xfixtures/data/
/// and src/xfixtures/data-v2/, consumed via @embedFile; generator wired as
/// `zig build fixtures`).
pub const xfixtures = @import("xfixtures/conformance_test.zig");
/// Stage C slice C3z: the shared v1/v2 manifest dispatch reader and WAL v3
/// decoder, plus its synthetic decoder battery.
pub const xfixtures_xfix = @import("xfixtures/xfix.zig");
pub const xfixtures_wal3_decode = @import("xfixtures/wal3_decode_test.zig");
/// Stage C slice C2z: the WAL v3 accept-bundle generator and its gate
/// (`zig build fixtures -- --wal3 <dir>`).
pub const xfixtures_wal3 = @import("xfixtures/wal3_fixtures.zig");

/// The single error set every public API returns.
pub const DbError = errors.DbError;
pub const DataInput2 = io.DataInput2;
pub const DataOutput2 = io.DataOutput2;
pub const SearchResult = ser.SearchResult;
pub const Value = ser.Value;
pub const Shared = shared.Shared;
/// In-memory object store (live records; fastest, non-durable).
pub const StoreOnHeap = store.StoreOnHeap;
/// In-memory byte store — the reference oracle for the byte-format stores.
pub const StoreByteArray = store.StoreByteArray;
/// Durable single-file store (mmap volume, format `MDBS.SD1`).
pub const StoreDirect = store.StoreDirect;
/// Transactional store: StoreDirect + write-ahead log (`MDBS.WAL`).
pub const StoreWAL = store.StoreWAL;
pub const Volume = store.Volume;
pub const RecordRead = store.RecordRead;
pub const AppendResult = store.AppendResult;
pub const LeaseTable = store.LeaseTable;
pub const SegmentLocks = store.SegmentLocks;
/// Persistent FIFO of `(timestamp,value)` long pairs (direct store primitive).
pub const QueueLong = queue.QueueLong;
/// Generic blocking FIFO/LIFO/circular queue over a Store.
pub const PersistentBlockingQueue = queue.PersistentBlockingQueue;

test {
    @import("std").testing.refAllDecls(@This());
}
