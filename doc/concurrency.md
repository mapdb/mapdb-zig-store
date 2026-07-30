# Concurrency

The concurrency contract follows the Rust port, not Java's
optimistic mode: **locked reads are the v1 baseline** (no seqlock/optimistic
path). Since Zig has no `Drop`, the recurring hazard is a lock/lease/refcount
released on one path but leaked on an error path — so every acquire pairs with a
same-scope `defer`/`errdefer`, and guards are non-copyable-by-discipline
. This doc gives the model per layer and the reentrancy rules.

## Primitives

| Need | Zig |
|------|-----|
| acquire/release publish | `std.atomic.Value(T)` `.load(.acquire)` / `.store(.release)` |
| CAS | `cmpxchgStrong(.acq_rel, .acquire)` |
| reader/writer & mutual exclusion | `std.Thread.RwLock` / `std.Thread.Mutex` |
| republish shared state | `Shared(T)` (see below) |
| sharded maps | `RwLock + std.AutoHashMapUnmanaged` |
| park/wake backoff | `std.Thread.Futex.timedWait` + `Futex.wake` on a counter |

No TSan in Zig; correctness is defended by high-iteration stress tests plus the
`Shared` kernel being unit/stress-tested in isolation before any consumer.

## `Shared(T)` — the pin kernel

`shared.zig` replaces Rust's `ArcSwap<Vec<T>>` for the three sites that publish
mutable shared state read without holding a lock over the whole use. Protocol
(**mutex-guarded pin** — the naive "load pointer → bump refcount → recheck" is a
use-after-free and must never be reintroduced):

- `loadInto(&g)` — lock; bump the current snapshot's refcount; unlock. The
  out-param `Guard` is the *only* dereference surface.
- `store(new)` / `prepare`+`publish` — build the new snapshot outside the lock;
  lock; swap; unlock; release the old publication ref. `prepare`/`publish` split
  the fallible allocation from an infallible swap, so a caller can finish every
  fallible step and then publish with no consume-on-OOM double-free.
- `release()` — `fetchSub(.release)`; the last ref does an acquire-load barrier
  then frees. Reclamation cannot race a pin because a live snapshot always
  carries the publication ref, dropped only after the swap.

**Guard discipline:** guards (`Shared.Guard`, `SegReadGuard`/
`SegWriteGuard`, `NodeGuard`) are initialized *in their final stack location* via
an out-param and passed by pointer only — never copied, returned, or reassigned.
In Debug each guard records its own address and asserts placement + not-yet-
released on use, so an aliased copy trips an assert instead of double-freeing.
The idiom:

```zig
var g: Shared([]u64).Guard = undefined;
sh.loadInto(&g);
defer g.release();
const edges = g.get().*; // borrow, valid until release
```

Consequence for the btree: readers touching `left_edges` take this short pin
mutex, so the precise wording is "readers acquire **no node locks**", not "lock-free".

## Per-layer model

**Serializers / group formats** are pure and hold no shared state; concurrency
lives entirely in the store and map layers.

**`SegmentLocks`** (`store/segment_locks.zig`) — a fixed bank of 64
cache-line-padded `RwLock`s keyed by recid low bits; a no-op bank when the store
is constructed with `thread_safe = false`. A Debug threadlocal tracker enforces
≤1 segment lock per thread and rejects reentrancy.

**`StoreOnHeap` / `StoreByteArray`** — sharded `RwLock + map` per recid.
Concurrent, not lock-free. Serialization happens *outside* the record lock; CAS
deserializes the current image *under* the lock and compares with the
serializer's logical `equals`.

**`StoreDirect`** — three lock tiers, hierarchy top-to-bottom:
1. `commit_lock: RwLock` — shared per operation, **exclusive** for
   `commit`/`close`/`compact`/`verify`; each op rechecks `closed` after
   acquiring.
2. `SegmentLocks` — per-record. **All reads take the segment read lock** (the
   locked baseline; a plain read racing a write is UB).
3. `structural_lock: Mutex` — allocator state (free lists, fileTail).

Invariant: never take a segment lock while holding the structural lock. `verify`
runs stop-the-world; `getAllRecids` takes each recid's read lock. `index_pages`
is published via `Shared([]u64)`.

**`StoreWAL`** — a single global `RwLock` over the whole `WalState` (inner
StoreDirect on a heap volume, WAL file, staged map, LSN counters). **One global
writer**: `commit`/`rollback` are transaction boundaries that never race
in-flight mutations. Reads take the atomic `closed` fast-path, then `lockShared`
and re-gate on `closed`. Every mutation additionally gates on `poisoned` (a
poisoned store fails `DataCorruption`); `close` is exempt so it can retry the
directory fsync and is poison-aware idempotent. `rollback` bumps
`structuralGeneration` so open collections know their structural caches may have
reverted.

**`BTreeMap`** —
- *Readers* (`get`, `containsKey`, iteration): push-down `GetAction` via
  `store.read`, re-descend on a B-link `link`, loop until 0. **No node locks** at
  the map layer (only the short `left_edges` pin). Safe with concurrent writers.
- *Writers* (`put`/`remove`/`replace`/split): **Lehman-Yao**, holding **≤1 node
  lock** at a time. The lock table is a fixed-stripe `Mutex + set keyed by exact
  recid` (never striped-to-one-lock — that would deadlock tree-order
  acquisition), with `Futex` backoff. Non-reentrant (owner-assert in Debug).
- *Split publish hand-off* — the one place a lock deliberately crosses scope:
  write the right sibling FIRST (referent before referrer), republish the left
  half with `link=q`, release the child lock, THEN lock the parent. Root growth
  is gated on the `LEFT|RIGHT` flag **and** a current-root identity check.
- *Thread-safety of a handle*: a plain by-value copy of a `BTreeMap` shares
  `Inner` without bumping the refcount — use it only for a scoped handoff to a
  worker joined before the original's `deinit`. Use `clone()` for a handle that
  outlives the original (it bumps the refcount and needs its own `deinit`). On a
  `thread_safe=false` (or tx) store the map is not write-scaling.

## Reentrancy: what you may NOT do from a callback (A3)

The push-down `RecordRead` action and any serializer callback run **while a
record lock (or the store's internal locks) is held**. From inside such a
callback you must **never call back into the store or map** — no nested
`get`/`put`/`read`, etc. `RecordRead` implementations additionally must reset all
output state on every invocation, bounds-clamp every decoded length, never call
back into the store, and never run user callbacks.

This is enforced by a Debug threadlocal action-depth tracker (`ActionGuard` /
`assertNotInAction`): a reentrant store op trips an assert. **In release builds
the tracker compiles away** — a reentrant callback then simply *deadlocks* on the
record lock (or forms a lock-order cycle). The contract is real either way;
Debug just turns the deadlock into a catchable assertion. The columnar-scan user
callback (`forEachValueColumn`) is the sanctioned exception: it runs *outside*
the `RecordRead`, after validation, precisely so it is free of this restriction.
