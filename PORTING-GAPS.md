# PORTING-GAPS — mapdb5 Java to Zig

Deliberate deviations from the Java `org.mapdb` reference implementation
(<https://github.com/mapdb/mapdb-java-store>). These are intentional v1 choices,
not defects: each preserves correctness and, for persisted formats, Java
byte-compatibility. Read this before depending on a behaviour that matters to
you — it is the honest limits list for this port.

## Both ports (serializer scope)
- **Skipped serializers:** `STRING_INTERN` (JVM string intern pool), `CLASS`, and
  `JAVA` (JVM object serialization) have no cross-language meaning and are not
  ported.

## Serializers
- **CompressionSerializer writes STORED (uncompressed) DEFLATE blocks.** Zig
  0.15.2's DEFLATE compressor is incomplete, so the write side emits valid STORED
  blocks; the read side inflates real `java.util.zip` DEFLATE. Interop is
  preserved (Zig-written records are readable by Java and vice-versa) but
  Zig-written "compressed" records are larger than Java's.
- **`BIG_DECIMAL.compare`** is exact when both scaled forms fit `i128`; beyond that
  it falls back to unscaled-magnitude order.
- **`TupleFormat.of()` borrows its schema slice** (ownership ruling) vs
  Java/Rust owned defensive copy; a `schemaCopy` accessor was added.

## BTreeMap
- **Listener contexts are borrowed / caller-owned.** Removing a listener does
  NOT permit freeing its context (an in-flight fire snapshot may still hold it);
  the context must outlive the map or a quiesce point. No refcounted quiescing
  removal in v1 (vs Java `CopyOnWriteArrayList` retaining the object).
- **External-split non-atomicity** on a store/alloc failure orphans the new value
  record (and possibly sibling B) before the left leaf republishes — Java-parity
  non-tx failure atomicity (garbage, not corruption; tree stays consistent).
- **Inline vs external are distinct comptime types** (`BTreeMap` /
  `BTreeMapExternal`, monomorphization). `element()` exists only on FixedStride
  + StringGroup formats.
- **Double-open rejection** (`error.AlreadyOpen`) vs Java two-live-handles
  sharing the counter record. Sync-listener re-entry: an inline **read** back into
  the same map is safe, but a re-entrant **write** reacquires the covering leaf
  node lock and asserts/spins (the callback runs under that write lock); external
  self-deadlocks on read/iteration too (`std.Thread.RwLock`/node locks non-reentrant
  vs Java `ReentrantReadWriteLock`). Re-entrant writes are forbidden.

## Queues (QueueLong, blocking queue)
- **Non-negative i64 domain on u64 fields** (as Rust): values `> i64::MAX`
  rejected to preserve Java read-back. **No thread interruption** — timeout methods
  + close flag returning `StoreClosed`. **Re-entrant callback errors** rather than
  deadlocking (`std` locks non-reentrant vs Java reentrant). **`printContent`** not
  ported.
- **Timed waits use the realtime clock** (`nanoTimestamp`) for the deadline vs the
  monotonic futex clock in `Condition.timedWait` — a wall-clock jump can
  stretch/shorten a poll/offer timeout; correctness holds (predicate re-checked).
  Cosmetic; a monotonic `std.time.Instant` is a possible later refinement.

## DB facade
- **No instance cache (Zig-only ruling).** Unlike Java's strong `instances` map and
  the Rust port's DB-owned cache, `Db(comptime S)` keeps no per-name handle cache
  (a heterogeneous cache would need a type-erased pointer + token + refcount +
  destructor vtable + safe reconstruction of the exact comptime `MapState` — the
  erased machinery this design avoids). A 2nd writable open of a live map/queue takes
  an RW lease on the root/header recid and returns `error.AlreadyOpen`. Sharing
  a live **map/set** handle is via `clone()` (refcounted); a **queue** has no
  `clone` — the DB returns a stable heap pointer callers share directly. Handle-count
  close/deinit contract: makers `incHandle`; the caller tears down via
  `closeMap`/`closeSet`/`closeAtomic`/`closeQueue` (`close*` refuse with
  `error.HandlesOpen` unless the handle is the last BTree ref); `Db.close()` fails
  `HandlesOpen` while any handle is open; `Db.deinit()` asserts
  `state==closed && open_handles==0`. **Raw-handle lifetime contract:** the last-ref
  close linearizes the *decision* among independently-owned clones, but cloning (or
  by-value copy-sharing) a single handle on a thread that may be concurrently doing
  its FINAL close is caller-UB (the clone can CAS through a just-freed `Inner`) —
  give each thread its own `clone`; same class as issuing a new queue op concurrent
  with `closeQueue`.
- **`maxNodeSize` domain** is `[4, maxInt(i32)]` (Java's positive `int` domain) at
  both create (→`WrongConfiguration`) and reopen/validate (→`DataCorruption`).
  Matches Java exactly — no artificial cap (the Rust port caps at `1<<20`).
- **Bind in-memory secondaries are restricted to hashable, copy-managed types**
  (`std.AutoHashMap`): owned-slice keys/values in an in-memory secondary are
  unsupported — use a `PersistentSecMap` (persistent `BTreeMap`) for those.
  Persistent-map secondaries are supported for the single-valued map indexes
  (`secondaryValue`/`secondaryKey`/`mapInverse`). Persistent SET secondaries (for
  `secondaryKeys`/`secondaryValues`) and a persistent `histogram` are NOT provided
  (in-memory only) — same trimming as the Rust port. `Bind.putUnique`'s
  same-key-tolerance comparison dispatches through each adapter's `valuesEqual`:
  `SecondaryMap` uses `std.meta.eql` (in-memory copy-key semantics), while
  `PersistentSecMap` uses format-aware `BTreeMap.valueEquals`.
- **`Db.delete` leaves interior nodes allocated.** It frees the known structural
  records best-effort (atomic `recid`; tree `rootRecidRecid`+`counterRecid`; queue
  `headerRecid`), but interior tree nodes and queue node records are NOT reclaimed:
  the no-instance-cache facade has no typed handle to `clear()` entries at delete
  time, and store `compact` PACKS live records but is not reachability GC, so
  repeated create/delete grows the store until it is rebuilt. Java/Rust clear via a
  cached/reopened handle.
- **NavigableSet lazy range/descending views** (`subSet`/`headSet`/`tailSet`/
  `descendingSet`) and the TreeSet maker **`createFrom`** bulk route are not implemented.
  Present: `create`/`createOrOpen`, scalar navigation
  (first/last/lower/floor/ceiling/higher), `pollFirst`/`pollLast`, ascending +
  descending materialized snapshots (`toSlice`/`toSliceDescending`), and Atomic
  `getAndSet`. `toSliceDescending` is a snapshot, not a lazy view. (Zig set
  navigation already exceeds the Rust sibling's first/last/to_vec.)
- **Bare `CUSTOM` descriptor matches any custom codec** (same as Rust): a
  configurable custom codec persists an opaque `CUSTOM` marker with no config
  fingerprint; two differently-configured instances are indistinguishable on
  reopen. **Nested stateful DEFLATE** — `CompressionSerializer(CompressionSerializer(X))`
  does not compile (`serDescriptor` uses `Se.DelegateSer.instance`, and the inner
  Compression type has `default` not `instance`); single-level `DEFLATE:<lvl>:<b64>`
  works through AtomicVar/queue.
- **`Db.getType`** returns an OWNED copy of the `#type` string (caller frees), not a
  borrowed slice.
- **Payloadless close error combining.** When BOTH `store.close()` and the
  delete-after-close cleanup fail, only the store-close error (primary) is
  returned; the cleanup error is dropped (Zig errors carry no payload; the Rust
  port combines both messages). Both cleanup paths still always run. `Db.close()`
  publishes CLOSED even when `store.close()` fails (one-shot terminal transition).
- **Raw-handle lifetime contract:** a NEW queue operation issued concurrently with
  `closeQueue`'s `destroy` is a caller-side use-after-close (same class as Java
  use-after-close). The waiter-join in `closeHandle` covers every waiter and
  in-flight op that ENTERED the queue before close.

## What "byte-for-byte with Java" means in this source

Comments throughout name a value encoding as byte-for-byte or byte-compatible
with Java's — the packed varints, the name catalog, the codec descriptor
strings, the queue node records, the serializer families. Those statements are
narrow and they are tested: each is pinned by golden vectors taken from the
encoding it was ported from.

They are **not** a statement that a store file interoperates. A store file is
those codecs plus a header, an allocator layout, a WAL framing and a recovery
protocol, and those have diverged — the Java engine is on segmented WAL format
v3 while this lineage is on v1. A per-codec fidelity claim says the bytes of one
value match; it says nothing about whether another engine can open the file
those bytes live in. It cannot.
