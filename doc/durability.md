# Durability and crash recovery

This covers what survives a crash, when, and the documented limits. It is
self-contained for the durability *behaviour* a user must reason about.

The **on-disk formats are not restated here**, and this port is not their
authority. **The format is not stabilised and no cross-implementation
compatibility is claimed** — this port was written against the Java reference
implementation at
<https://github.com/mapdb/mapdb-java-store>, whose `StoreDirect` and `StoreWAL`
sources are the behavioural reference for the layouts (`MDBS.SD1`, segmented
`MDBS.WAL` v3, index-slot bit packing, long-stack free lists, linked-record
chunking, header checksum). Read the
committed Java and Zig sources for the current bytes; neither is a public
format stability promise.

Durability claims are Linux-scoped: they rely on `fsync` of files and of parent
directories.

The two in-memory stores (`StoreOnHeap`, `StoreByteArray`) are non-durable;
everything here concerns `StoreDirect` and `StoreWAL`.

## `StoreDirect` — durable, non-transactional

Backed by a single mmap file, magic `MDBS.SD1`. Records, the recid index, free
lists and allocator metadata all live on the volume.

**Commit is the durability point.** `commit()` syncs data before stamping and
syncing the header checksum:

1. `msync` all record/index data, then `File.sync` — data is on disk first.
2. Stamp the page-0 checksum of allocator header words.
3. Sync the header page.

The ordering makes an acknowledged commit durable, but this in-place store does
not provide atomic rollback of an interrupted commit. Its checksum does not
authenticate record payloads or every index mutation. On first *create*, the
parent directory is fsync'd too, so the new file's directory entry is durable.

**Reopen checks detected inconsistencies (bare StoreDirect).** `openFile`
checks the allocator header checksum and validates geometry (dataTail,
fileTail, maxRecid, index-page links). Detected failures refuse the open with
`DataCorruption`. An in-place payload or index change can leave the covered
header words unchanged, so a crash before `commit()` may evade these checks.
There is no crash recovery for a bare StoreDirect; `StoreWAL` provides that.

**Bounds & tainted values.** Every raw volume accessor bounds-checks
unconditionally, and every persisted word the allocator dereferences (free-stack
chunk links, offsets, capacities) is validated on the hot path, not just at
open — so a crafted or corrupt file yields `DataCorruption`, never OOB, in Debug
*and* ReleaseSafe. See [ownership-and-errors.md](ownership-and-errors.md).

**`compact()`** rewrites live records into a fresh layout with a
snapshot-before-crash-barrier ordering; a failure mid-compact sets a **poisoned**
flag rather than leaving torn geometry.

## `StoreWAL` — transactional, crash-recoverable

A `StoreDirect` (on a heap volume) fronted by a v3 write-ahead log segment set.
Its files are named `<base>.wal.<16 lowercase hex digits>`; each segment header
uses magic `MDBS.WAL` and version 3. Mutations are **staged** in memory; reads
merge staged-over-inner. There is one global writer.

**Commit protocol** (the section's data sync is the durability point):
1. Build the staged operations and frame them as a section with a 25-byte
   header (tag, LSN, body length, header CRC, body CRC). The CRCs include the
   segment header and section offset in their domain.
2. Append the section to the active segment and **fdatasync** it — *now* the
   transaction is durable. At a segment boundary, seal the predecessor with a
   full fsync before creating and syncing its successor and directory entry.
3. Apply the staged operations to the inner StoreDirect.
4. Run a budgeted inline cleaner step when the log crosses its configured
   trigger; above the hard ceiling, cleaning may take longer in `commit()`.

**`rollback()`** discards the staged operations (nothing was applied yet) and
bumps `structuralGeneration`, so an open `BTreeMap` knows to rebuild its
left-edge spine cache before the next structural op.

**`checkpoint()`** runs the segment cleaner without a budget. It rolls to a
fresh segment, re-emits committed state as `C` image sections, forces a `K`
clean mark authorizing retirement of older segments, then unlinks them and
fsyncs the parent directory. There is no snapshot rename or `.ckpt` output;
an existing `.ckpt` from v1 makes the v3 opener refuse the store.

### What recovery guarantees

On reopen, `StoreWAL` scans segment boundaries and held corruption verdicts,
then streams entry replay in a second pass. It distinguishes these failure
shapes using the recorded LSNs and a suspect-section lookahead:

- **Torn active tail** — a crash mid-append leaves a truncated or partial
  trailing section in the highest segment. Recovery **truncates** at the last
  fully valid section, forces the truncation, and rotates the segment.
  A transaction acknowledged before the crash survives; a partially written
  trailing section is discarded.
- **Mid-log corruption** — a broken section in a non-final retained segment,
  or a damaged section followed by a valid one in the active segment, fails
  `DataCorruption`, rather than silently resurrecting or skipping data.

A section whose header/body CRC is valid but whose recid is the reserved 0, or
whose framing is inconsistent, is `DataCorruption`. Unsupported log versions are
rejected. Recovery tests cover torn active tails, damaged retained segments,
clean marks, and replay across segment boundaries.

### fsync guarantees

- `commit` fdatasyncs the WAL section before acknowledging it (StoreWAL), or
  syncs data then header (StoreDirect).
- Segment creation and post-unlink fsync the **parent directory** (opened with
  `.iterate = true` so the fd is fsync-able on Linux — a plain `openDir` yields
  an O_PATH fd that `EBADF`s).
- Section appends and clean marks use `fdatasync`; segment creation, rollover
  sealing, and post-truncation forcing use full `fsync`.

## Limits and validation

The following limits and coverage boundaries remain relevant to this port:

- **StoreDirect** — no incremental dirty tracking (`commit` stamps
  the whole header); and an allocator error mid-`writeNewLinked` can orphan
  already-allocated chunks on the free lists until the next `compact()` (no
  partial rollback of a failed linked write).
- **WAL I/O failure paths** — seam tests inject section-write, force, rollover,
  checkpoint, and directory-sync failures. A failed write or post-force apply
  closes the handle; reopen replays whatever was durably logged. These tests do
  not establish behaviour under every real device failure.
- **Cross-engine open is not promised** — Java, Rust, and Zig now implement
  segmented WAL v3 and share a sealed cross-engine fixture corpus. That tests
  specified cases, not arbitrary whole-store cross-opens or a stable format.
  Legacy v1 single-file WAL artifacts are refused by the v3 opener; do not
  assume a file from another engine will open here.
- **btree crafted off-spine reads** — the read-only push-down fast paths do not
  full-frame-validate; a crafted, checksum-valid, never-written, off-open-spine
  leaf can return a *wrong or absent value to a pure read* (never a crash / OOB /
  hang). Uneven-depth crafted trees are not detected at open. These narrow the
  corruption-acceptance bar identically to Rust; the hard
  guarantees (no crash/OOB/hang/false-durability) still hold.
- Background maintenance executor is deferred; `commit` runs a budgeted inline
  cleaner and `checkpoint()` can clean the full log explicitly.

These are the durability limits documented here.
`PORTING-GAPS.md` at the repository root records the wider set of things this
port does not carry over from the Java and Rust implementations.
