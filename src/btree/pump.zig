//! `TreePump` — bottom-up bulk builder for the B-link trees,
//! ported from `mapdb-rust-store/src/btree/pump.rs`. Feed strictly ascending entries
//! via `put`, then `finish` once; every node is written EXACTLY once via
//! preallocate-next-sibling-then-write (forward links, no back-patching), so on
//! a fresh store recids and data lay out sequentially in key order.
//!
//! `Sink` is a comptime duck-typed interface that materializes + writes one
//! finished node, keeping the pump serialization-free. It must expose:
//! ```
//! pub const Key; pub const Val;
//! compareKeys(self, a: Key, b: Key) std.math.Order
//! cloneKey(self, alloc, k: Key) DbError!Key
//! deinitKey(self, alloc, k: Key) void
//! deinitVal(self, alloc, v: Val) void
//! writeLeaf(self, recid, flags: i32, link: u64, keys: []const Key, values: []const Val) DbError!void
//! writeDir(self, recid, flags: i32, link: u64, keys: []const Key, children: []const u64) DbError!void
//! ```
//! `writeLeaf`/`writeDir` BORROW the slices (they clone into the node); the pump
//! frees them afterwards.

const std = @import("std");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const nodemod = @import("node.zig");
const DIR = nodemod.DIR;
const LEFT = nodemod.LEFT;
const RIGHT = nodemod.RIGHT;

pub fn TreePump(comptime S: type, comptime Sink: type) type {
    return struct {
        const Self = @This();
        const Key = Sink.Key;
        const Val = Sink.Val;

        const Level = struct {
            keys: std.ArrayListUnmanaged(Key) = .empty,
            values: std.ArrayListUnmanaged(Val) = .empty, // leaf level only
            children: std.ArrayListUnmanaged(u64) = .empty, // dir levels only
            /// Preallocated recid of this level's NEXT node; 0 = none yet.
            pending: u64 = 0,
            /// No node flushed at this level yet (LEFT candidate).
            first: bool = true,
        };

        alloc: Allocator,
        store: *S,
        sink: *const Sink,
        node_fill: usize,
        levels: std.ArrayListUnmanaged(Level),
        prev_key: ?Key,
        finished: bool,

        /// Default pump fill: 3/4 of maxNodeSize (mapdb1/2/3 lineage).
        pub fn defaultFill(max_node_size: usize) usize {
            return @max(max_node_size * 3 / 4, 2);
        }

        pub fn init(alloc: Allocator, store: *S, sink: *const Sink, max_node_size: usize, node_fill: usize) DbError!Self {
            // Public boundary: reject invalid fill parameters instead of asserting.
            if (node_fill < 2 or node_fill > max_node_size) return error.WrongConfiguration;
            var levels: std.ArrayListUnmanaged(Level) = .empty;
            try levels.append(alloc, .{});
            return .{
                .alloc = alloc,
                .store = store,
                .sink = sink,
                .node_fill = node_fill,
                .levels = levels,
                .prev_key = null,
                .finished = false,
            };
        }

        /// Free any un-flushed accumulated state (abandonment path).
        pub fn deinit(self: *Self) void {
            for (self.levels.items) |*lvl| {
                for (lvl.keys.items) |k| self.sink.deinitKey(self.alloc, k);
                for (lvl.values.items) |v| self.sink.deinitVal(self.alloc, v);
                lvl.keys.deinit(self.alloc);
                lvl.values.deinit(self.alloc);
                lvl.children.deinit(self.alloc);
            }
            self.levels.deinit(self.alloc);
            if (self.prev_key) |pk| self.sink.deinitKey(self.alloc, pk);
        }

        /// Feed one entry. Takes OWNERSHIP of `key` and `value` (moved into the
        /// pump, like the Rust oracle). On `error.NotSorted` the rejected entry is
        /// NOT consumed — the caller still owns it.
        pub fn put(self: *Self, key: Key, value: Val) DbError!void {
            std.debug.assert(!self.finished);
            if (self.prev_key) |prev| {
                if (self.sink.compareKeys(prev, key) != .lt) {
                    return error.NotSorted; // caller retains key/value ownership
                }
            }
            // flush BEFORE adding: interior leaves hold exactly node_fill entries.
            if (self.levels.items[0].keys.items.len == self.node_fill) {
                try self.flushLeaf();
            }
            // Clone the NEW previous key BEFORE mutating any state, so an OOM here
            // leaves `prev_key`/the leaf arrays untouched.
            const new_prev = try self.sink.cloneKey(self.alloc, key);
            errdefer self.sink.deinitKey(self.alloc, new_prev);
            try self.levels.items[0].keys.append(self.alloc, key); // key moved in
            errdefer _ = self.levels.items[0].keys.pop();
            self.levels.items[0].values.append(self.alloc, value) catch |e| {
                self.sink.deinitVal(self.alloc, value); // value not yet retained
                return e;
            };
            if (self.prev_key) |pk| self.sink.deinitKey(self.alloc, pk);
            self.prev_key = new_prev;
        }

        fn nodeRecid(self: *Self, level: usize) DbError!u64 {
            const pending = self.levels.items[level].pending;
            if (pending != 0) return pending;
            return self.store.preallocate();
        }

        fn flushLeaf(self: *Self) DbError!void {
            const recid = try self.nodeRecid(0);
            const link = try self.store.preallocate();
            const leaf = &self.levels.items[0];
            leaf.pending = link;
            const flags: i32 = if (leaf.first) LEFT else 0;
            leaf.first = false;
            const keys = try leaf.keys.toOwnedSlice(self.alloc);
            defer {
                for (keys) |k| self.sink.deinitKey(self.alloc, k);
                self.alloc.free(keys);
            }
            const values = try leaf.values.toOwnedSlice(self.alloc);
            defer {
                for (values) |v| self.sink.deinitVal(self.alloc, v);
                self.alloc.free(values);
            }
            // Write FIRST, then clone the separator: the only fallible step after
            // the clone is the consuming `pushUp`, so no errdefer on `sep` is
            // needed here. `keys` is still alive (freed by the `defer`).
            try self.sink.writeLeaf(recid, flags, link, keys, values);
            const sep = try self.sink.cloneKey(self.alloc, keys[keys.len - 1]);
            try self.pushUp(1, sep, recid);
        }

        /// Register a flushed node with its parent level; CONSUMES `sep` (frees it
        /// on any error here).
        fn pushUp(self: *Self, level_idx: usize, sep: Key, child: u64) DbError!void {
            errdefer self.sink.deinitKey(self.alloc, sep);
            if (self.levels.items.len == level_idx) {
                try self.levels.append(self.alloc, .{});
            }
            if (self.levels.items[level_idx].keys.items.len == self.node_fill) {
                try self.flushDir(level_idx);
            }
            try self.levels.items[level_idx].keys.append(self.alloc, sep);
            // If the child append fails, pop the key we just added so the errdefer
            // above frees `sep` exactly once (not also via pump teardown).
            errdefer _ = self.levels.items[level_idx].keys.pop();
            try self.levels.items[level_idx].children.append(self.alloc, child);
        }

        fn flushDir(self: *Self, level_idx: usize) DbError!void {
            const recid = try self.nodeRecid(level_idx);
            const link = try self.store.preallocate();
            const dir = &self.levels.items[level_idx];
            dir.pending = link;
            const flags: i32 = DIR | @as(i32, if (dir.first) LEFT else 0);
            dir.first = false;
            const keys = try dir.keys.toOwnedSlice(self.alloc);
            defer {
                for (keys) |k| self.sink.deinitKey(self.alloc, k);
                self.alloc.free(keys);
            }
            const children = try dir.children.toOwnedSlice(self.alloc);
            defer self.alloc.free(children);
            // Write FIRST, then clone the separator.
            try self.sink.writeDir(recid, flags, link, keys, children);
            const sep = try self.sink.cloneKey(self.alloc, keys[keys.len - 1]);
            try self.pushUp(level_idx + 1, sep, recid);
        }

        /// Flush the final (rightmost) node of every level, bottom-up; returns the
        /// root NODE recid. Consumes the pump (`deinit` still valid afterwards).
        pub fn finish(self: *Self) DbError!u64 {
            std.debug.assert(!self.finished);
            self.finished = true;
            const child0 = try self.nodeRecid(0);
            {
                const leaf = &self.levels.items[0];
                const leaf_flags: i32 = (if (leaf.first) LEFT else 0) | RIGHT;
                const keys = try leaf.keys.toOwnedSlice(self.alloc);
                defer {
                    for (keys) |k| self.sink.deinitKey(self.alloc, k);
                    self.alloc.free(keys);
                }
                const values = try leaf.values.toOwnedSlice(self.alloc);
                defer {
                    for (values) |v| self.sink.deinitVal(self.alloc, v);
                    self.alloc.free(values);
                }
                try self.sink.writeLeaf(child0, leaf_flags, 0, keys, values);
            }
            var child = child0;
            var i: usize = 1;
            while (i < self.levels.items.len) : (i += 1) {
                const recid = try self.nodeRecid(i);
                const dir = &self.levels.items[i];
                const flags: i32 = DIR | @as(i32, if (dir.first) LEFT else 0) | RIGHT;
                const keys = try dir.keys.toOwnedSlice(self.alloc);
                defer {
                    for (keys) |k| self.sink.deinitKey(self.alloc, k);
                    self.alloc.free(keys);
                }
                var children = dir.children;
                dir.children = .empty;
                defer children.deinit(self.alloc);
                try children.append(self.alloc, child); // rightmost extra child (RIGHT dir shape)
                try self.sink.writeDir(recid, flags, 0, keys, children.items);
                child = recid;
            }
            return child;
        }
    };
}
