# Architecture

The library is a bottom-up stack: each layer depends only on those below it.
Source layout under `src/` mirrors this order (and the Rust port's).

```
btree/          BTreeMap, node, view, pump
   depends on ↓
store/          Store interface + 4 impls
   ├─ direct.zig / wal.zig  depend on ↓
   ├─ volume.zig  (raw mmap projection)
   └─ shared.zig  (Shared(T) pin kernel)
   depends on ↓
ser/            serializers + group formats
   depends on ↓
io/             DataInput2/DataOutput2, packed varints
   depends on ↓
errors.zig      DbError + diagnostics
tainted.zig     the audited persisted-value conversion boundary
```

## Layers

**`io.zig`** — the wire primitives. `DataOutput2` is a growable byte buffer with
big-endian integer writes and mapdb's packed varints (`packLong`/`packInt`,
7 bits/byte, MSB group first, terminator bit `0x80`). `DataInput2` is a
positioned, seekable cursor over a `[]const u8`; every read is an explicit
bounds check → `error.DataCorruption` (never a crash — Debug safety checks are
not relied upon). Varint decoders are hard-capped (10 bytes for u64, 5 for u32).

**`ser/`** — element codecs and node array formats, built on two comptime
duck-typed contracts (documented in `ser/mod.zig`):
- **Serializer** — one element's encode/decode/order/equality/clone/deinit.
  Built-ins: SHORT, CHAR, INTEGER, LONG, UUID (u128), STRING (UTF-16-order
  compare), BYTE_ARRAY (signed / unsigned).
- **GroupFormat** — the packed key/value array of one btree node, with an
  OBJECT side (materialized copy-on-write edits) and a BYTE side (search/get
  directly on serialized bytes). Families: fixed-stride scalar, zigzag delta,
  offset-table string/bytes, restart-block prefix, self-delimiting object-array,
  tuple (memcomparable), and columnar (column-major fixed cells).

**`shared.zig`** — `Shared(T)`: mutex-guarded, reference-counted, atomically
republishable snapshots. Replaces Rust's `ArcSwap<Vec<T>>` at the three sites
that publish mutable shared state without a lock over the whole reader use:
btree `left_edges`, StoreDirect `index_pages`, volume slice tables. Implemented
and stress-tested before its first consumer. See [concurrency.md](concurrency.md).

**`store/`** — the `Store` comptime interface (put/get/read/update/CAS/delete/
commit/close/verify/…, plus `StoreDelta` append and `StoreTx` rollback) and its
impls. A store maps `recid: u64 → record bytes/object`; it knows nothing about
keys or ordering. `RecordRead` is the one dynamic-dispatch point (an
Allocator-style ptr+vtable) for push-down reads. Shared store-layer machinery:
`SegmentLocks` (64 cache-line-padded RwLocks), `LeaseTable` (open exclusion,
the open-lease registry), `RecidAlloc`, the `TypeId` token factory.

**`btree/`** — `BTreeMap(S, KF, VF)`: a B-link tree whose nodes are records in
any `Store`. Push-down readers (`GetAction` via `store.read`, no node locks) +
Lehman-Yao writers (≤1 node lock). `RangeView` is the navigable sub-map/
descending layer; `TreePump` is the bottom-up bulk builder. Nodes and their
serializer are *not* re-exported from `root.zig` — the map is the sole node
writer, so no caller can smuggle a structurally-impossible node past decode
validation.

## The four stores — when to use which

All four satisfy the same `Store` contract, so the `BTreeMap` (and the TCK)
runs identically over each. They differ in durability and cost:

| Store | Backing | Durable | Delta (append) | Tx (rollback) | Use when |
|-------|---------|:-------:|:--------------:|:-------------:|----------|
| `StoreOnHeap` | live objects, never serialized | no | no | no | fastest in-memory maps; tests |
| `StoreByteArray` | one `[]u8` per record | no | yes | no | the reference oracle; in-memory with byte semantics |
| `StoreDirect` | single mmap file (`MDB5.SD1`) | yes (on `commit`) | yes | no | durable maps without transactions |
| `StoreWAL` | `StoreDirect` (heap volume) + write-ahead log (`MDB5.WAL`) | yes (on `commit`) | yes | yes | durable maps with atomic commit/rollback and crash recovery |

- **`StoreOnHeap`** keeps records as boxed live objects and dispatches
  `onObject` push-down reads; it requires a **stateless** (zero-sized)
  serializer. No serialization on the hot path.
- **`StoreByteArray`** is deliberately dumb — its value is being obviously
  correct. It is the differential-fuzz oracle the other stores are checked
  against.
- **`StoreDirect`** puts the recid index, free lists, allocator metadata and
  record data all on the volume, in the layout ported from the Rust port.
  `verify()` is a stop-the-world on-disk tiling check.
- **`StoreWAL`** wraps a heap-volume `StoreDirect`, staging mutations in a WAL
  file until `commit` fsyncs them; `rollback` discards staged work; a checkpoint
  compacts the log into a fresh snapshot via atomic rename. Single global writer.

## How the TCK ties them together

`store/tck.zig` exposes `runCore(comptime S)` — a generic conformance suite
(record state machine, CAS, recid reuse, owned-slice records, the delta suite,
`verify()` after every mutation, thread-safe and single-threaded modes). It runs
against all four stores, so each new store is held to identical observable
behavior. On top of that, `store_direct_test.zig` / `store_wal_test.zig` add a
3000-op (StoreDirect) / 1500-op (StoreWAL) **differential fuzz** that lock-steps
the store against `StoreByteArray` with full-state comparison, plus every
crafted-corruption regression ported from the Rust hardening rounds. The btree
runs its own smoke/differential/concurrency/crafted suites over each store type.
The build runs every one of these under `zig build test`; there is no separate
integration tier.
