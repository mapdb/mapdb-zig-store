# doc/ — mapdb5 (Zig) documentation

Documentation for *using* and *developing on* the library. **This directory is
complete on its own**: every rule you need in order to use or evaluate the
engine is stated here, and nothing here defers to a document you cannot read.
Note that the on-disk format is not stabilised — see the root `README.md`.

Start with [architecture.md](architecture.md) for the layer map, then the topic
docs.

| File | Contents |
|---|---|
| [architecture.md](architecture.md) | Layer map, per-layer roles, the four store implementations compared, the test model |
| [ownership-and-errors.md](ownership-and-errors.md) | Who owns which bytes, the clone/deinit contract, the full `DbError` taxonomy, diagnostics, tainted-data discipline |
| [concurrency.md](concurrency.md) | Locking primitives, the `Shared(T)` pin protocol, guard discipline, per-layer lock hierarchies, reentrancy |
| [durability.md](durability.md) | Two-phase sync, unclean-reopen refusal, the WAL commit protocol, torn-tail handling, fsync guarantees, and the documented gaps |

Repository-level information — support status, scope, requirements, build
commands, usage example, license — is in the [root README](../README.md).
