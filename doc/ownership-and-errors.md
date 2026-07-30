# Ownership and errors

Zig has no GC and no `Drop`. Memory ownership is therefore an explicit,
uniform contract across the whole API — it is the #1 question at every call
site. This document states the rules (the ownership ruling), the `DbError`
taxonomy, and the tainted-data discipline.

## The ownership rule

> **Explicit allocator in, owned values out, typed deinit.**

Every function that *materializes* a value or group takes an `Allocator` and
returns a result **owned by the caller**, freed through the codec's typed
`deinitElem` / `deinitGroup` (or a container's `deinit*` helper). Concretely:

- **Inputs are borrowed.** Even though Zig passes slices/values by descriptor,
  a callee never takes ownership of a parameter; it *clones* whatever it keeps.
  `map.put(key, value)` clones `key`/`value` into the tree — the caller still
  owns and must free the originals it passed.
- **Returned values are owned by the passed allocator.** `store.get`, `map.get`,
  `map.remove`, iterator `Entry`s, `getAllRecids` — all owned by *you*.
- **A component frees what it retains with its own allocator.** A store's
  internal record buffers / heap-record clones, a map's published groups, and
  `RangeView` bound keys are cloned with and freed by that component's
  `self.alloc` (fixed at construction), never the per-call allocator.
- **Zero-length slices are still allocator-owned.** `alloc.alloc(u8, 0)` is
  valid and freeable; `deinitElem`/`deinitGroup` may free unconditionally. Never
  return a static literal as an "owned" value.

### `cloneElem` / `deinitElem` (the deep-clone contract)

Every serializer and every group format carries `cloneElem(alloc, v)` (deep
copy into fresh `alloc`-owned memory) paired with `deinitElem(alloc, v)`. This
is the half Rust got for free from `R: Clone`. Without it, `StoreOnHeap` and CAS
have no sound semantics: a shallow bit-copy of a slice-bearing value would alias
ownership and double-free. For scalar elements both are no-ops.

Object-side group mutators (`insert`/`set`/`delete`/`copyRange`/`cloneGroup`)
are **pure copy-on-write**: the input group is borrowed and untouched, a fresh
group is returned, and on error every partial output is freed (the *strong*
exception guarantee). If a key materializes but the value allocation then fails,
the key is freed before the error propagates.

## The ownership table

| Thing | Constructed by | Owner / freed by |
|-------|----------------|------------------|
| `Elem` (scalar) | any codec op | trivially owned; `deinitElem` is a no-op |
| `Elem` (`[]const u8`, `Value`) | `get`/`deserialize`/`cloneElem` | caller, via `ser/format.deinitElem(alloc, v)` |
| `Group` (incl. `empty`'s zero-length one) | `deserializeGroup`, CoW mutators | caller, via `format.deinitGroup(alloc, g)` |
| store `get` result `?R` | `store.get(R, alloc, …)` | caller, via the serializer's `deinitElem` |
| `getAllRecids` `[]u64` | `store.getAllRecids(alloc)` | caller, `alloc.free` |
| btree `Entry{key,val}` | iterator / navigator / `entries` | caller, via `map.deinitEntry(e)` |
| `[]Entry` | `map.entries` / `view.entries` | caller, via `deinitEntries(es)` |
| `EntryIter` | `map.iter` / `map.entryIter` | caller, via `it.deinit()` (safe mid-scan) |
| `RangeView` | `map.view`/`subMap`/… | value type; borrows the map, holds bound keys by value; no deinit |
| map `Inner` / lease | `create`/`open` (+ `clone`) | last `map.deinit()` (refcount → 0) releases the lease + frees `Inner` |

**BTreeMap put/remove/replace summary** — the map holds one allocator, fixed at
`create`/`open`:
- `put`/`putIfAbsent`/`putOnly`: `key`, `value` **borrowed** (cloned in). `put`/
  `putIfAbsent` return the OWNED displaced value; `putOnly` frees it for you.
- `get`/`containsKey`/`remove`/`replace`: `key` borrowed; the returned `?Val` is
  OWNED. `removeIf`/`replaceIf`/`removeOnly` free the compared/displaced value
  internally and return a `bool`.
- `RangeView` never bumps the lease and holds bound keys by value: scalar bounds
  are copies; an owned-slice-key view (not exercised in v1) would require the
  caller to keep the bound keys alive.

Guardrails: `std.testing.allocator` is used in every test, so any leak fails the
build. There is **no global allocator** anywhere in the library.

## The `DbError` taxonomy

One error set (`errors.zig`), no payloads. Members and when each occurs:

| Error | Raised when |
|-------|-------------|
| `GetVoid` | read/get of a **Void** (never-allocated) or **Deleted** recid. (Get of a *preallocated* record returns `null`, not this.) |
| `RecordTooLarge` | record content, or headroom arithmetic, exceeds the max single-record capacity (~1 MiB − 48). |
| `DataCorruption` | any persisted-bytes invariant failed — parity/checksum, geometry, a bad structural link, an out-of-range tainted length, a torn/forged WAL section, recid 0 in a decoded slot, a malformed node. The catch-all for "these bytes are not trustworthy". |
| `StoreFull` | the volume allocator hit the 44-bit volume-offset ceiling, or the backing store is full. |
| `StoreClosed` | any op on a closed store (also the in-lock recheck after a concurrent `close`). |
| `VerifyFailed` | `verify()` found the on-disk tiling / free-space accounting inconsistent. |
| `NotSorted` | `TreePump`/`createFromSorted` fed non-ascending input. (A `RangeView` sub-map bound outside the parent range surfaces as an assert/panic, not this error.) |
| `AlreadyOpen` | a conflicting lease already exists (RW-while-any, or RW-while-RO). |
| `OutOfMemory` | a *genuine* allocation failure. Allocations sized from persisted lengths are bounds-validated FIRST, so garbage lengths surface as `DataCorruption`, never as OOM. |
| `Io` | an underlying I/O failure; narrower posix errors are folded to this at the volume boundary. |

### Diagnostics

Errors carry no context. Two side channels supply it when needed:
- **Hot concurrent ops** — the error *identity* is the whole contract. A
  best-effort `ErrorCtx` (reason string + recid), mutex-protected with a
  sequence number, is readable but explicitly global/best-effort: do **not**
  tie it to a specific concurrent failure.
- **Administrative ops** (`open`, `verify`, replay) — a caller-provided
  diagnostic out-param carries exact context; these are the only calls whose
  context tests assert.

## Tainted-data discipline

Every value decoded from persisted bytes is **tainted**. It may be narrowed,
shifted, range-checked, enum-converted or turned into a sub-slice **only**
through `src/tainted.zig` (`u64ToUsize`, `checkedAdd/Sub/Mul`, `checkedShift`,
`checkedRange`, `checkedSlice`, `checkedEnum`) or the parity helpers — each maps
a violation to `error.DataCorruption`. Outside that one audited module, on any
tainted-derived path (reads **and** writes), the raw operations that are illegal
behavior in ReleaseFast — `@intCast`/`@enumFromInt`/`@alignCast`, oversized
shifts, unchecked `off + len`, `unreachable` — are banned (enforced by review +
grep). This is not a nicety: the Rust hardening rounds found corrupt-index-driven
*writes* clobbering header/allocator words, so writes derived from persisted
indices validate their target extent before mutating it.

Because ReleaseSafe traps illegal behavior (rather than optimizing around it),
it is the v1 shipping profile. ReleaseFast is benchmark-only until an explicit
taint audit clears the gate. All of this is why a crafted, checksum-valid file
yields a clean `error.DataCorruption` — never a crash, OOB, hang, or unbounded
allocation. (One documented narrowing: the btree read-only push-down fast paths
may return a *wrong pure-read result* for a crafted off-open-spine leaf; see
[durability.md](durability.md).)
