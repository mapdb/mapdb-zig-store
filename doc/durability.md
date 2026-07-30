# Durability and crash recovery

This covers what survives a crash, when, and the documented limits. It is
self-contained for the durability *behaviour* a user must reason about.

The **on-disk formats are not restated here**, and this port is not their
authority. **The format is not stabilised and no cross-implementation
compatibility is claimed** — this port was written against the Java reference
implementation at
<https://github.com/mapdb/mapdb-java-store>, whose `StoreDirect` and `StoreWAL`
sources define the layouts (`MDB5.SD1`, `MDB5.WAL`, index-slot bit packing,
long-stack free lists, linked-record chunking, header checksum). Read those if
you need the bytes; where this port and they disagree, they are right.

Durability claims are Linux-scoped: they rely on `fsync` of files and of parent
directories.

The two in-memory stores (`StoreOnHeap`, `StoreByteArray`) are non-durable;
everything here concerns `StoreDirect` and `StoreWAL`.

## `StoreDirect` — durable, non-transactional

Backed by a single mmap file, magic `MDB5.SD1`. Records, the recid index, free
lists and allocator metadata all live on the volume.

**Commit is the durability point.** `commit()` uses a strict **two-phase sync**
so a crash never exposes a header that points at unsynced data:

1. `msync` all record/index data, then `File.sync` — data is on disk first.
2. Stamp the page-0 header checksum (the clean-close / consistency marker).
3. Sync the header page.

Ordering data-before-header is what makes recovery sound: after a crash, either
the header is old (and consistent with old data) or new (and its data was synced
in step 1). On first *create*, the parent directory is fsync'd too, so the new
file's directory entry is durable.

**Reopen refuses an unclean store (bare StoreDirect).** `openFile` validates geometry (dataTail,
fileTail, maxRecid, index-page links) against the header checksum via the *same*
helper `verify()` uses, so they can't drift. A store that was not cleanly
committed/closed — the checksum marker doesn't match — fails to reopen with
`DataCorruption` rather than silently serving torn state. (There is no crash
*recovery* for a bare StoreDirect; that is what `StoreWAL` adds.)

**Bounds & tainted values.** Every raw volume accessor bounds-checks
unconditionally, and every persisted word the allocator dereferences (free-stack
chunk links, offsets, capacities) is validated on the hot path, not just at
open — so a crafted or corrupt file yields `DataCorruption`, never OOB, in Debug
*and* ReleaseSafe. See [ownership-and-errors.md](ownership-and-errors.md).

**`compact()`** rewrites live records into a fresh layout with a
snapshot-before-crash-barrier ordering; a failure mid-compact sets a **poisoned**
flag rather than leaving torn geometry.

## `StoreWAL` — transactional, crash-recoverable

A `StoreDirect` (on a heap volume) fronted by a write-ahead log file, magic
`MDB5.WAL`. Mutations are **staged** in memory and appended to the log; reads
merge staged-over-inner. There is one global writer.

**Commit protocol** (the fsync is the durability point):
1. Build the section body (the staged operations), frame it with a 25-byte
   header (tag, strictly-increasing LSN, body length, header CRC, body CRC — all
   IEEE CRC32).
2. Write header + body to the log and **fsync** it — *now* the transaction is
   durable.
3. Apply the staged operations to the inner StoreDirect.
4. Auto-checkpoint if the log has grown past its bound.

**`rollback()`** discards the staged operations (nothing was applied yet) and
bumps `structuralGeneration`, so an open `BTreeMap` knows to rebuild its
left-edge spine cache before the next structural op.

**`checkpoint()`** streams a compacted snapshot to `<file>.ckpt`, fsyncs it,
atomically `rename`s it over the live file, then fsyncs the parent directory. A
crash mid-checkpoint is recovered on next open: a *complete* temp snapshot wins,
an incomplete one is discarded. The retained temp file handle is reused across
the rename (no path reopen).

### What recovery guarantees

On reopen, `StoreWAL` replays the log with an O(1)-memory streaming decoder that
distinguishes two failure shapes precisely, using an exact-next-LSN lookahead:

- **Torn tail** — a crash mid-append leaves a truncated or partial trailing
  section. Recovery **truncates** at the last fully-valid section. Everything
  committed before the crash survives; the in-flight, un-fsynced transaction is
  cleanly lost. This is the expected crash outcome.
- **Mid-log corruption** — a CRC-valid gap or a broken section *before* the tail
  (i.e. not explainable as a torn tail) is **not** recoverable and fails
  `DataCorruption`, rather than silently resurrecting or skipping data.

A section whose header/body CRC is valid but whose recid is the reserved 0, or
whose framing is inconsistent, is `DataCorruption`. Unsupported log versions are
rejected. Property tests assert the bar: an every-byte truncation sweep over a
multi-section log either refuses with `DataCorruption` or reopens with `verify()`
passing and every record reading its committed value or `GetVoid` — **never** a
crash, hang, or resurrected/torn value.

### fsync guarantees

- `commit` fsyncs the log section body before returning (StoreWAL) / data then
  header (StoreDirect).
- File creation and post-rename fsync the **parent directory** (opened with
  `.iterate = true` so the fd is fsync-able on Linux — a plain `openDir` yields
  an O_PATH fd that `EBADF`s).
- The Zig port uses full `fsync` where Rust used `fdatasync`/`sync_data`; that is
  a strict superset, so durability is at-least-as-strong and the byte format is
  unaffected.

## Documented-deferred gaps (know the limits)

These are inherited from the Rust port verbatim (same status), not Zig
regressions:

- **StoreDirect** — no incremental dirty tracking (`commit` stamps
  the whole header); and an allocator error mid-`writeNewLinked` can orphan
  already-allocated chunks on the free lists until the next `compact()` (no
  partial rollback of a failed linked write).
- **WAL fault injection is untested** — the poison flag, poison-aware idempotent
  `close`, and directory-fsync failure handling are implemented and code-guarded,
  but this environment cannot *inject* a partial-write / sync / rename / dir-fsync
  failure, so those specific failure paths lack executable coverage. A durable
  section can, in principle, be fsync'd just before an unexpected inner-apply
  error (the fault-injection question is deferred, same as Rust).
- **Cross-engine open is not supported and not tested** — the golden vectors in
  the test suite pin individual *value codecs* against the encodings they were
  ported from, and that is all they establish. There is no automated whole-store
  cross-open, and the store-level formats have already diverged: the Java engine
  is on segmented WAL format v3 while this port and the Rust port are on v1, and
  each refuses a version it does not recognise. Treat a file written by another
  engine as unreadable here.
- **btree crafted off-spine reads** — the read-only push-down fast paths do not
  full-frame-validate; a crafted, checksum-valid, never-written, off-open-spine
  leaf can return a *wrong or absent value to a pure read* (never a crash / OOB /
  hang). Uneven-depth crafted trees are not detected at open. These narrow the
  corruption-acceptance bar identically to Rust; the hard
  guarantees (no crash/OOB/hang/false-durability) still hold.
- Background auto-checkpoint executor is deferred; the inline synchronous
  auto-checkpoint in `commit` is the correctness fallback.

The list above is the complete set of durability gaps this port knows about.
`PORTING-GAPS.md` at the repository root records the wider set of things this
port does not carry over from the Java and Rust implementations.
