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
/// Stage C slice C2z: the WAL v3 accept-bundle generator and its gate
/// (`zig build fixtures -- --wal3 <dir>`). PUBLIC because
/// `src/xfixtures/generator.zig` is a separate executable that reaches it
/// through this module.
pub const xfixtures_wal3 = @import("xfixtures/wal3_fixtures.zig");

// The cross-port conformance suites, pulled in for TEST DISCOVERY ONLY.
//
// `pub const` would publish them: a downstream importer could name the WAL v3
// decoder, the manifest executor and the format constants it re-exports, and
// depend on shapes that exist to be rewritten every time the fixture protocol
// moves. The C3z review found exactly that, and the fix is that a test root
// references a test module rather than exporting it. Golden files live in
// src/xfixtures/data/ and src/xfixtures/data-v2/ and are consumed via
// @embedFile; the generator is wired as `zig build fixtures`.
test {
    _ = @import("xfixtures/conformance_test.zig");
    _ = @import("xfixtures/wal3_decode_test.zig");
    _ = @import("xfixtures/corpus_test.zig");
}

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
