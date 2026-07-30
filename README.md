# mapdb-zig-store

An embedded storage engine and persistent, ordered `BTreeMap` library: a Zig
port of the Java **mapdb5** engine, written from the reviewed Rust port.

> **The on-disk format is not stabilised.** There is no compatibility guarantee —
> not between the Java, Rust and Zig implementations, and not between versions of
> any one of them. A file written by one engine may not open under another, or
> under a later build of the same engine. Implementers may change the format
> freely and without notice; there is no migration path and none is planned.
> Do not put data you care about in it.

- <https://github.com/mapdb/mapdb-java-store> — the original this lineage was
  ported from. It is the reference for *behaviour*, not a format authority:
  nothing here is guaranteed to open a file it wrote, or the reverse.
- <https://github.com/mapdb/mapdb-rust-store> — the Rust port. This code mirrors
  its module layout so diffs between the two stay mechanical, and inherits its
  hardening fixes and sanctioned deviations.

## Support status

**This is not a supported release.** It has never been published, the API has
no stability guarantee, and it has not been run in production by anyone. It is
a complete and tested port of a defined subset, which is a different claim from
"ready".

Read it as: the tests are real, the scope is narrow, and there is no release
engineering behind it yet. The format is not one of the things you can rely on
— see the notice at the top.

## Scope

Built:

| Area | Contents |
|---|---|
| `io` | `DataInput2`/`DataOutput2`, packed varints, errors |
| `ser` | serializers and all group formats (scalar, delta, prefix, tuple, columnar), UTF-16-order compare |
| store core | `Store` interface, `StoreOnHeap`, `StoreByteArray`, segment locks, lease table, the `Shared(T)` pin kernel |
| `StoreDirect` | durable single-file store (`MDB5.SD1`), volume, two-phase sync, `verify`, `compact` |
| `StoreWAL` | transactional store (`MDB5.WAL`), streaming replay, checkpoint, rollback |
| `BTreeMap` | B-link tree, push-down readers with Lehman-Yao writers, `RangeView`, `TreePump`, columnar scan |

**Not built:** `StoreAppendOnly`, `BufferedPageFormat` + `BufferTreeMap`, the
htree family, indextree, sortedtable, and the background maintenance/checkpoint
executor.

**Deliberate v1 limits:** locked reads only (no optimistic or seqlock read
path), synchronous operations only (no async), no C ABI, 64-bit targets only,
and ReleaseSafe as the shipping profile. `PORTING-GAPS.md` records what this
port does not carry over from the Rust and Java implementations.

## Requirements

- **Zig 0.15.2** (declared as `minimum_zig_version` in `build.zig.zon`).
- A 64-bit target. Linux and macOS are what the code has been exercised on.
- No external dependencies — Zig std only (CRC32 via `std.hash.crc`; mmap,
  locks and atomics via std).

## Build and test

From the repository root:

```sh
# Debug — implicit safety checks on; catches what explicit checks miss.
# The suite takes a few minutes; give it a generous timeout.
zig build test --summary all

# ReleaseSafe — the shipping profile. A few Debug-only reentry probes
# compile away and are reported as skipped.
zig build test --summary all -Doptimize=ReleaseSafe
```

`std.testing.allocator` is used throughout, so any leak fails the build.

## Usage

An ordered `i64 → i64` map over a durable single-file store:

```zig
const std = @import("std");
const mapdb = @import("mapdb_zig_store");

const StoreDirect = mapdb.StoreDirect;
const BTreeMap = mapdb.btree.BTreeMap;
const LongFormat = mapdb.ser.long.LongFormat; // i64 group format (key & value)

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Durable store, created if absent. `true` = thread-safe.
    var store = try StoreDirect.openFile(alloc, "example.db", true);
    defer store.deinit();

    // Ordered map. Formats are passed by value (`.{}` — they are zero-sized
    // for scalars); 32 is max_node_size.
    const Map = BTreeMap(StoreDirect, LongFormat, LongFormat);
    var map = try Map.create(alloc, &store, .{}, .{}, 32);
    defer map.deinit();

    // put: key/value are BORROWED (cloned in); the returned displaced value is
    // owned by `alloc` (null here, so nothing to free).
    _ = try map.put(1, 100);
    _ = try map.put(2, 200);
    _ = try map.put(3, 300);

    // get: `key` borrowed; the returned value is owned (an i64 owns nothing).
    if (try map.get(&@as(i64, 2))) |v| {
        std.debug.print("key 2 -> {d}\n", .{v}); // 200
    }

    // Ordered iteration. Each Entry is owned by `alloc`; deinit the iterator.
    var it = try map.iter();
    defer it.deinit();
    while (try it.next()) |e| {
        std.debug.print("{d} = {d}\n", .{ e.key, e.val });
        // For owned-slice keys/values you would `map.deinitEntry(e)` here.
    }

    // Note the tree's root-pointer recid so it can be reopened later.
    const rrr = map.rootRecidRecid();

    // Make it durable (fsync data then header), then close cleanly.
    try store.commit();
    try store.close();

    // Reopen: same store, then `BTreeMap.open` with the saved root recid.
    var store2 = try StoreDirect.openFile(alloc, "example.db", true);
    defer store2.deinit();
    var map2 = try Map.open(alloc, &store2, rrr, .{}, .{}, 32);
    defer map2.deinit();
    std.debug.print("reopened key 3 -> {?d}\n", .{try map2.get(&@as(i64, 3))});
}
```

For a **transactional** store, swap `StoreDirect.openFile(alloc, path, true)`
for `mapdb.StoreWAL.open(alloc, path, true)` and use `store.commit()` /
`store.rollback()` as transaction boundaries — see
[`doc/durability.md`](doc/durability.md). For an **in-memory** map, use
`mapdb.StoreOnHeap.init(alloc, true)` (no path, non-durable).

Owned-slice keys and values (for example `[]const u8` via
`ser.bytearray.ByteArrayFormat`) follow the same shape but require freeing what
you get back — see [`doc/ownership-and-errors.md`](doc/ownership-and-errors.md).

## Documentation

[`doc/`](doc/) is the complete, self-contained documentation set: the layer
map, the ownership and error contract, the concurrency model, and the
durability contract.

## Layout

```
build.zig             one module "mapdb_zig_store", one `test` step
build.zig.zon
src/
  root.zig            public exports (the library surface)
  errors.zig          DbError + ErrorCtx diagnostics
  io.zig              DataInput2/DataOutput2, packed varints
  tainted.zig         the audited persisted-value conversion boundary
  shared.zig          Shared(T) — mutex-guarded pinned snapshots
  ser/                serializers, group formats, comptime contracts
  store/              Store interface + four implementations + volume + locks
  btree/              BTreeMap, node, view, pump
doc/                  user and developer documentation
```

## License

Dual EPL-1.0 / EDL-1.0 (`SPDX-License-Identifier: EPL-1.0 OR BSD-3-Clause`).
See [`LICENSE-EPL-1.0.txt`](LICENSE-EPL-1.0.txt),
[`LICENSE-EDL-1.0.txt`](LICENSE-EDL-1.0.txt) and [`NOTICE.md`](NOTICE.md).
