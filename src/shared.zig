//! `Shared(T)` — mutex-guarded pinned snapshots. The Rust `ArcSwap<T>`
//! sites (btree `left_edges`, StoreDirect `index_pages`, volume slice tables)
//! become this small utility. Implemented + stress-tested BEFORE its first
//! consumer.
//!
//! Protocol (mutex-guarded pin — the r0 "load pointer → refcount++ → re-check"
//! protocol was a use-after-free; do NOT reintroduce it):
//! - `loadInto`: lock; `cur.refcount += 1` (reclamation excluded by the mutex);
//!            unlock; the out-param `Guard` is the only dereference surface.
//! - `store`: build the new snapshot OUTSIDE the lock; lock; swap `cur`; unlock;
//!            release the old publication ref.
//! - release: `refcount.fetchSub(1, .release)`; the last ref does an
//!            acquire (load) barrier, then runs `deinitFn` + frees the node.
//!
//! Acquire/release publishes CONTENTS, not lifetime — the mutex, held for a
//! counter bump only, is what excludes reclamation during a pin.
//!
//! Guard discipline: guards are initialized IN their final
//! stack location via the out-param `loadInto` and passed by pointer only —
//! never copied, returned, or reassigned. In Debug builds each guard records
//! its own address at init; `get`/`release` assert the guard still lives there,
//! so an aliased copy trips an assert instead of double-releasing.
//!
//! Deviation: Zig 0.15 removed the `@fence` builtin, so the
//! last-ref acquire barrier is a `refcount.load(.acquire)` on the same atomic
//! immediately after the releasing `fetchSub` (equivalent synchronizes-with).

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const DbError = @import("errors.zig").DbError;

const guard_debug = builtin.mode == .Debug;

/// A mutex-guarded, reference-counted, atomically-republishable snapshot of an
/// owned `T`. `deinitFn(alloc, *T)` frees whatever `T` owns.
pub fn Shared(comptime T: type) type {
    return struct {
        const Self = @This();
        pub const DeinitFn = *const fn (Allocator, *T) void;

        const Snapshot = struct {
            value: T,
            refcount: std.atomic.Value(usize),
        };

        /// The ONLY dereference surface: initialized in its final stack
        /// location by `loadInto`, passed by pointer only, released exactly
        /// once. Debug builds assert both rules (home-address + released state).
        pub const Guard = struct {
            /// null after release (released state marker).
            snap: ?*Snapshot,
            owner: *Self,
            /// Debug: the address this guard was initialized at. A copied guard
            /// lives elsewhere → `get`/`release` assert instead of corrupting.
            home: if (guard_debug) ?*const Guard else void,

            inline fn assertPlacement(self: *const Guard) void {
                if (guard_debug) {
                    // Guard was copied/moved after init (lock-discipline violation), or used
                    // after release.
                    std.debug.assert(self.home == self);
                    std.debug.assert(self.snap != null);
                }
            }

            /// Borrow the pinned value (valid until `release`).
            pub fn get(self: *const Guard) *const T {
                self.assertPlacement();
                return &self.snap.?.value;
            }

            /// Drop this pin's reference. Call exactly once, on the same guard
            /// address `loadInto` initialized (Debug-asserted).
            pub fn release(self: *Guard) void {
                self.assertPlacement();
                const s = self.snap orelse return; // Release builds: tolerate no-op
                self.snap = null;
                self.owner.releaseSnap(s);
            }

            /// Alias for `release` (guard teardown convention).
            pub fn deinit(self: *Guard) void {
                self.release();
            }
        };

        mu: std.Thread.Mutex = .{},
        cur: *Snapshot,
        alloc: Allocator,
        deinitFn: DeinitFn,

        /// Publish `initial` as the first snapshot (publication refcount = 1).
        /// Takes ownership of `initial` even on failure: if the snapshot node
        /// allocation fails, `deinitFn` is invoked on it before returning.
        pub fn init(alloc: Allocator, initial: T, deinitFn: DeinitFn) DbError!Self {
            var v = initial;
            const snap = alloc.create(Snapshot) catch |e| {
                deinitFn(alloc, &v);
                return e;
            };
            snap.* = .{ .value = v, .refcount = std.atomic.Value(usize).init(1) };
            return .{ .cur = snap, .alloc = alloc, .deinitFn = deinitFn };
        }

        /// Release the current publication ref (frees the last snapshot).
        ///
        /// Contract: requires FULL quiescence — no concurrent
        /// `loadInto`/`store`/`deinit` may run concurrently with or after this
        /// call, and the `Shared` object must outlive every guard release
        /// (outstanding guards dereference `owner` when released). Teardown only.
        pub fn deinit(self: *Self) void {
            self.releaseSnap(self.cur);
            self.cur = undefined;
        }

        /// Pin the current snapshot into `g` — an out-param so the guard is
        /// initialized in its FINAL stack location (see module doc). The
        /// mutex is held for a counter bump only.
        pub fn loadInto(self: *Self, g: *Guard) void {
            self.mu.lock();
            defer self.mu.unlock();
            _ = self.cur.refcount.fetchAdd(1, .acquire);
            g.* = .{
                .snap = self.cur,
                .owner = self,
                .home = if (guard_debug) g else {},
            };
        }

        /// Publish `new_value`, retiring the previous snapshot. Takes ownership
        /// of `new_value` even on failure: if the snapshot node allocation
        /// fails, `deinitFn` is invoked on it before returning; on success it
        /// is freed via `deinitFn` when its last ref drops.
        pub fn store(self: *Self, new_value: T) DbError!void {
            var v = new_value;
            const snap = self.alloc.create(Snapshot) catch |e| {
                self.deinitFn(self.alloc, &v);
                return e;
            };
            snap.* = .{ .value = v, .refcount = std.atomic.Value(usize).init(1) };
            self.mu.lock();
            const old = self.cur;
            self.cur = snap;
            self.mu.unlock();
            self.releaseSnap(old);
        }

        /// An opaque, prepared-but-unpublished snapshot node (from `prepare`).
        /// The caller either hands it to `publish` (infallible) or discards it
        /// with `cancel`; it must never be dropped without one of the two.
        pub const Prepared = *Snapshot;

        /// Allocate a snapshot node for `new_value` WITHOUT publishing it, so
        /// the caller can complete every fallible step and then publish
        /// INFALLIBLY (no `store`-consumes-on-OOM
        /// double-free, and no persistent geometry mutated before a fallible
        /// publication). UNLIKE `store`, on failure `new_value` is NOT consumed
        /// — the caller retains ownership.
        pub fn prepare(self: *Self, new_value: T) DbError!Prepared {
            const snap = self.alloc.create(Snapshot) catch return error.OutOfMemory;
            snap.* = .{ .value = new_value, .refcount = std.atomic.Value(usize).init(1) };
            return snap;
        }

        /// Publish a node from `prepare`, retiring the previous snapshot.
        /// Infallible: the fallible allocation already happened in `prepare`.
        pub fn publish(self: *Self, prepared: Prepared) void {
            self.mu.lock();
            const old = self.cur;
            self.cur = prepared;
            self.mu.unlock();
            self.releaseSnap(old);
        }

        /// Discard a `prepare`d node that will never be published, freeing the
        /// node and its owned value via `deinitFn`.
        pub fn cancel(self: *Self, prepared: Prepared) void {
            self.deinitFn(self.alloc, &prepared.value);
            self.alloc.destroy(prepared);
        }

        fn releaseSnap(self: *Self, snap: *Snapshot) void {
            if (snap.refcount.fetchSub(1, .release) == 1) {
                // Last ref: acquire barrier (see module note re: @fence removal),
                // then reclaim. Reclamation cannot race a pin — a live `cur`
                // node always carries the publication ref, dropped only by
                // `store`/`deinit` after the swap.
                _ = snap.refcount.load(.acquire);
                self.deinitFn(self.alloc, &snap.value);
                self.alloc.destroy(snap);
            }
        }
    };
}

// ------------------------------------------------------------------- tests

const testing = std.testing;

/// A snapshot payload that owns a slice; every element equals `stamp` so a
/// reader can detect a torn / use-after-free read.
const Payload = struct {
    stamp: u64,
    buf: []u64,

    fn create(alloc: Allocator, stamp: u64, n: usize) DbError!Payload {
        const buf = try alloc.alloc(u64, n);
        for (buf) |*b| b.* = stamp;
        return .{ .stamp = stamp, .buf = buf };
    }
};

var freed_count = std.atomic.Value(usize).init(0);

fn deinitPayload(alloc: Allocator, p: *Payload) void {
    _ = freed_count.fetchAdd(1, .monotonic);
    alloc.free(p.buf);
}

test "Shared: load/store/release single-threaded" {
    const S = Shared(Payload);
    freed_count.store(0, .monotonic);
    var sh = try S.init(testing.allocator, try Payload.create(testing.allocator, 1, 4), deinitPayload);
    defer sh.deinit();

    {
        var g: S.Guard = undefined;
        sh.loadInto(&g);
        defer g.release();
        try testing.expectEqual(@as(u64, 1), g.get().stamp);
    }
    // publish a new snapshot; an already-held guard keeps the old alive
    var g_old: S.Guard = undefined;
    sh.loadInto(&g_old);
    try sh.store(try Payload.create(testing.allocator, 2, 4));
    try testing.expectEqual(@as(u64, 1), g_old.get().stamp); // old still pinned
    {
        var g_new: S.Guard = undefined;
        sh.loadInto(&g_new);
        defer g_new.release();
        try testing.expectEqual(@as(u64, 2), g_new.get().stamp);
    }
    g_old.release(); // frees snapshot 1
    // snapshot 1 freed once; snapshot 2 freed at deinit
}

test "Shared: init/store OOM does not leak the taken-ownership value" {
    const S = Shared(Payload);

    // init: payload buf from the working allocator; Snapshot node alloc fails.
    {
        freed_count.store(0, .monotonic);
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        const p = try Payload.create(testing.allocator, 1, 4);
        try testing.expectError(
            error.OutOfMemory,
            S.init(failing.allocator(), p, deinitPayload),
        );
        try testing.expectEqual(@as(usize, 1), freed_count.load(.monotonic));
    }
    // store: node alloc fails after ownership transfer.
    {
        freed_count.store(0, .monotonic);
        var sh = try S.init(testing.allocator, try Payload.create(testing.allocator, 1, 4), deinitPayload);
        const good_alloc = sh.alloc;
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        sh.alloc = failing.allocator(); // fail only store's node allocation
        const p2 = try Payload.create(testing.allocator, 2, 4);
        try testing.expectError(error.OutOfMemory, sh.store(p2));
        try testing.expectEqual(@as(usize, 1), freed_count.load(.monotonic)); // p2 freed
        sh.alloc = good_alloc;
        {
            var g: S.Guard = undefined;
            sh.loadInto(&g);
            defer g.release();
            try testing.expectEqual(@as(u64, 1), g.get().stamp); // original intact
        }
        sh.deinit();
        try testing.expectEqual(@as(usize, 2), freed_count.load(.monotonic));
    }
}

test "Shared: prepare/publish is infallible after prepare; cancel frees unpublished" {
    const S = Shared(Payload);

    // prepare failure does NOT consume the value (caller still owns it).
    {
        freed_count.store(0, .monotonic);
        var sh = try S.init(testing.allocator, try Payload.create(testing.allocator, 1, 4), deinitPayload);
        defer sh.deinit();
        const good_alloc = sh.alloc;
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        sh.alloc = failing.allocator();
        var p2 = try Payload.create(testing.allocator, 2, 4);
        try testing.expectError(error.OutOfMemory, sh.prepare(p2));
        // value NOT consumed → caller frees it.
        try testing.expectEqual(@as(usize, 0), freed_count.load(.monotonic));
        deinitPayload(testing.allocator, &p2);
        sh.alloc = good_alloc;
    }
    // prepare + publish swaps in the new snapshot; the old one is freed.
    {
        freed_count.store(0, .monotonic);
        var sh = try S.init(testing.allocator, try Payload.create(testing.allocator, 1, 4), deinitPayload);
        const prepared = try sh.prepare(try Payload.create(testing.allocator, 2, 4));
        sh.publish(prepared); // frees snapshot 1
        try testing.expectEqual(@as(usize, 1), freed_count.load(.monotonic));
        {
            var g: S.Guard = undefined;
            sh.loadInto(&g);
            defer g.release();
            try testing.expectEqual(@as(u64, 2), g.get().stamp);
        }
        sh.deinit(); // frees snapshot 2
        try testing.expectEqual(@as(usize, 2), freed_count.load(.monotonic));
    }
    // cancel frees a prepared-but-unpublished node + its value, leaving cur intact.
    {
        freed_count.store(0, .monotonic);
        var sh = try S.init(testing.allocator, try Payload.create(testing.allocator, 1, 4), deinitPayload);
        defer sh.deinit();
        const prepared = try sh.prepare(try Payload.create(testing.allocator, 9, 4));
        sh.cancel(prepared); // frees the unpublished value
        try testing.expectEqual(@as(usize, 1), freed_count.load(.monotonic));
        var g: S.Guard = undefined;
        sh.loadInto(&g);
        defer g.release();
        try testing.expectEqual(@as(u64, 1), g.get().stamp); // cur unchanged
    }
}

test "Shared: multithread load/release racing a publisher (leak/UAF/double-free)" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const S = Shared(Payload);
    const alloc = testing.allocator;
    freed_count.store(0, .monotonic);

    const N_READERS = 8;
    const ITERS = 100_000;

    var sh = try S.init(alloc, try Payload.create(alloc, 0, 8), deinitPayload);

    const Reader = struct {
        fn run(shared: *S) void {
            var i: usize = 0;
            while (i < ITERS) : (i += 1) {
                var g: S.Guard = undefined;
                shared.loadInto(&g);
                // Touch every element to catch a torn / UAF read: all must
                // equal the snapshot's own stamp.
                const p = g.get();
                for (p.buf) |v| std.debug.assert(v == p.stamp);
                g.release();
            }
        }
    };

    const Publisher = struct {
        fn run(shared: *S, a: Allocator, published: *usize) void {
            var stamp: u64 = 1;
            while (stamp <= ITERS) : (stamp += 1) {
                const pl = Payload.create(a, stamp, 8) catch @panic("oom");
                shared.store(pl) catch @panic("oom");
                published.* += 1;
            }
        }
    };

    var threads: [N_READERS]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Reader.run, .{&sh});
    var published: usize = 0;
    const pub_t = try std.Thread.spawn(.{}, Publisher.run, .{ &sh, alloc, &published });

    for (&threads) |*t| t.join();
    pub_t.join();

    sh.deinit(); // drops the last publication ref → frees the final snapshot

    // Every snapshot ever published (initial + each store) is freed exactly once.
    const total_published = published + 1; // +1 for the initial snapshot
    try testing.expectEqual(total_published, freed_count.load(.monotonic));
}
