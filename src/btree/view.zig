//! Shared navigable range/view layer, ported from
//! `mapdb-rust-store/src/btree/view.rs`. Java's `OrderedMapAdapter`/
//! `OrderedNavigableView`/`ConcurrentOrderedNavigableView`/`OrderedKeySet` stack
//! collapses to one generic `RangeView(Map)` struct carrying a `descending`
//! flag over any map exposing the adapter surface (BTreeMap here).
//!
//! Semantics preserved: bound INTERSECTION never widens the parent; JDK
//! inclusivity-at-equality; inverted / exclusive-equal ranges are empty;
//! `descending()` flips a flag without touching the interval; navigation is
//! orientation-mapped (descending ceiling = backing floor, etc.).
//!
//! Deviation from Rust: `RangeView` stores its bound keys BY VALUE (borrowed).
//! For scalar keys this is a copy; for owned-slice keys the caller must keep the
//! bound keys alive for the view's lifetime (v1 exercises only scalar-key views).

const std = @import("std");
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;

/// Fully-bounded, live navigable view over `Map` (borrowed). A `descending`
/// flag reverses orientation without touching the backing interval.
pub fn RangeView(comptime Map: type) type {
    return struct {
        const Self = @This();
        const Key = Map.Key;
        const Val = Map.Val;
        const Entry = Map.Entry;

        map: *const Map,
        lo: ?Key,
        lo_inc: bool,
        hi: ?Key,
        hi_inc: bool,
        descending_flag: bool,

        /// Unbounded ascending view over the whole map (borrows `map`).
        pub fn full(map: *const Map) Self {
            return .{ .map = map, .lo = null, .lo_inc = true, .hi = null, .hi_inc = true, .descending_flag = false };
        }
        pub fn isDescending(self: Self) bool {
            return self.descending_flag;
        }

        inline fn cmp(self: Self, a: Key, b: Key) Order {
            return self.map.compareKeys(a, b);
        }

        // ---- bound predicates (backing order) ----

        fn tooLow(self: Self, k: Key) bool {
            if (self.lo) |lo| {
                const c = self.cmp(k, lo);
                return c == .lt or (c == .eq and !self.lo_inc);
            }
            return false;
        }
        fn tooHigh(self: Self, k: Key) bool {
            if (self.hi) |hi| {
                const c = self.cmp(k, hi);
                return c == .gt or (c == .eq and !self.hi_inc);
            }
            return false;
        }
        pub fn inRange(self: Self, k: Key) bool {
            return !self.tooLow(k) and !self.tooHigh(k);
        }

        fn rangeEmpty(self: Self, lo2: ?Key, lo_inc2: bool, hi2: ?Key, hi_inc2: bool) bool {
            if (lo2) |l| {
                if (hi2) |h| {
                    const c = self.cmp(l, h);
                    if (c == .gt) return true;
                    if (c == .eq) return !(lo_inc2 and hi_inc2);
                }
            }
            return false;
        }

        /// JDK-conform sub-view bound check. `error.NotSorted` = out of range.
        fn checkBoundKey(self: Self, k: Key, k_inc: bool) DbError!void {
            if (self.lo) |lo| {
                const c = self.cmp(k, lo);
                if (c == .lt or (c == .eq and k_inc and !self.lo_inc)) return error.NotSorted;
            }
            if (self.hi) |hi| {
                const c = self.cmp(k, hi);
                if (c == .gt or (c == .eq and k_inc and !self.hi_inc)) return error.NotSorted;
            }
        }

        const Bound = struct { key: Key, inc: bool };

        fn effLower(self: Self, k: Key, k_inc: bool) Bound {
            if (self.lo) |lo| {
                return switch (self.cmp(k, lo)) {
                    .gt => .{ .key = k, .inc = k_inc },
                    .lt => .{ .key = lo, .inc = self.lo_inc },
                    .eq => .{ .key = lo, .inc = self.lo_inc and k_inc },
                };
            }
            return .{ .key = k, .inc = k_inc };
        }
        fn effUpper(self: Self, k: Key, k_inc: bool) Bound {
            if (self.hi) |hi| {
                return switch (self.cmp(k, hi)) {
                    .lt => .{ .key = k, .inc = k_inc },
                    .gt => .{ .key = hi, .inc = self.hi_inc },
                    .eq => .{ .key = hi, .inc = self.hi_inc and k_inc },
                };
            }
            return .{ .key = k, .inc = k_inc };
        }

        // ---- backing (ascending-order) navigation over [lo,hi] ----

        fn firstOf(self: Self, lo2: ?Key, lo_inc2: bool, hi2: ?Key, hi_inc2: bool) DbError!?Entry {
            if (self.rangeEmpty(lo2, lo_inc2, hi2, hi_inc2)) return null;
            var it = try self.map.entryIter(lo2, lo_inc2, hi2, hi_inc2);
            defer it.deinit();
            return try it.next();
        }
        /// Greatest in-range entry via ascending scan-keep-last (O(range) time).
        fn lastOf(self: Self, lo2: ?Key, lo_inc2: bool, hi2: ?Key, hi_inc2: bool) DbError!?Entry {
            if (self.rangeEmpty(lo2, lo_inc2, hi2, hi_inc2)) return null;
            var it = try self.map.entryIter(lo2, lo_inc2, hi2, hi_inc2);
            defer it.deinit();
            var last: ?Entry = null;
            errdefer if (last) |l| self.map.deinitEntry(l); // free retained on iterator error
            while (try it.next()) |e| {
                if (last) |l| self.map.deinitEntry(l);
                last = e;
            }
            return last;
        }

        fn backingCeiling(self: Self, k: Key) DbError!?Entry {
            const b = self.effLower(k, true);
            return self.firstOf(b.key, b.inc, self.hi, self.hi_inc);
        }
        fn backingHigher(self: Self, k: Key) DbError!?Entry {
            const b = self.effLower(k, false);
            return self.firstOf(b.key, b.inc, self.hi, self.hi_inc);
        }
        fn backingFloor(self: Self, k: Key) DbError!?Entry {
            const b = self.effUpper(k, true);
            return self.lastOf(self.lo, self.lo_inc, b.key, b.inc);
        }
        fn backingLower(self: Self, k: Key) DbError!?Entry {
            const b = self.effUpper(k, false);
            return self.lastOf(self.lo, self.lo_inc, b.key, b.inc);
        }
        fn backingFirst(self: Self) DbError!?Entry {
            return self.firstOf(self.lo, self.lo_inc, self.hi, self.hi_inc);
        }
        fn backingLast(self: Self) DbError!?Entry {
            return self.lastOf(self.lo, self.lo_inc, self.hi, self.hi_inc);
        }
        fn backingPollFirst(self: Self) DbError!?Entry {
            if (self.rangeEmpty(self.lo, self.lo_inc, self.hi, self.hi_inc)) return null;
            return self.map.pollFirstEntry(self.lo, self.lo_inc, self.hi, self.hi_inc);
        }
        fn backingPollLast(self: Self) DbError!?Entry {
            if (self.rangeEmpty(self.lo, self.lo_inc, self.hi, self.hi_inc)) return null;
            return self.map.pollLastEntry(self.lo, self.lo_inc, self.hi, self.hi_inc);
        }

        // ---- entry navigation (orientation-mapped) ----
        //
        // All return an OWNED `?Entry` (free with `map.deinitEntry`) resolved in
        // THIS view's orientation: on a descending view `firstEntry` is the
        // largest in-range key, `ceilingEntry` maps to the backing floor, etc.

        /// Smallest (largest, if descending) in-range entry, or `null`.
        pub fn firstEntry(self: Self) DbError!?Entry {
            return if (self.descending_flag) self.backingLast() else self.backingFirst();
        }
        pub fn lastEntry(self: Self) DbError!?Entry {
            return if (self.descending_flag) self.backingFirst() else self.backingLast();
        }
        pub fn lowerEntry(self: Self, k: Key) DbError!?Entry {
            return if (self.descending_flag) self.backingHigher(k) else self.backingLower(k);
        }
        pub fn floorEntry(self: Self, k: Key) DbError!?Entry {
            return if (self.descending_flag) self.backingCeiling(k) else self.backingFloor(k);
        }
        pub fn ceilingEntry(self: Self, k: Key) DbError!?Entry {
            return if (self.descending_flag) self.backingFloor(k) else self.backingCeiling(k);
        }
        pub fn higherEntry(self: Self, k: Key) DbError!?Entry {
            return if (self.descending_flag) self.backingLower(k) else self.backingHigher(k);
        }
        pub fn pollFirstEntry(self: Self) DbError!?Entry {
            return if (self.descending_flag) self.backingPollLast() else self.backingPollFirst();
        }
        pub fn pollLastEntry(self: Self) DbError!?Entry {
            return if (self.descending_flag) self.backingPollFirst() else self.backingPollLast();
        }

        // ---- point ops (bounded, orientation-independent) ----
        //
        // Reads/removes of an out-of-range key are no-ops (`null`/`false`);
        // `put`/`putIfAbsent` of an out-of-range key ASSERT (a JDK sub-map
        // contract violation). `key`/`value` args are borrowed; displaced/returned
        // values are OWNED, same as the underlying map ops.

        /// Value for `key` if in range and present, else `null` (owned).
        pub fn get(self: Self, key: Key) DbError!?Val {
            if (self.inRange(key)) return self.map.get(&key);
            return null;
        }
        pub fn containsKey(self: Self, key: Key) DbError!bool {
            if (self.inRange(key)) return self.map.containsKey(&key);
            return false;
        }
        /// Insert/replace an in-range key; asserts if `key` is out of range.
        pub fn put(self: Self, key: Key, value: Val) DbError!?Val {
            std.debug.assert(self.inRange(key)); // key out of submap range
            return self.map.put(key, value);
        }
        pub fn remove(self: Self, key: Key) DbError!?Val {
            if (self.inRange(key)) return self.map.remove(&key);
            return null;
        }
        pub fn removeIf(self: Self, key: Key, value: Val) DbError!bool {
            if (self.inRange(key)) return self.map.removeIf(&key, &value);
            return false;
        }
        pub fn putIfAbsent(self: Self, key: Key, value: Val) DbError!?Val {
            std.debug.assert(self.inRange(key));
            return self.map.putIfAbsent(key, value);
        }
        pub fn replace(self: Self, key: Key, value: Val) DbError!?Val {
            if (self.inRange(key)) return self.map.replace(&key, value);
            return null;
        }
        pub fn replaceIf(self: Self, key: Key, old: Val, new: Val) DbError!bool {
            if (self.inRange(key)) return self.map.replaceIf(&key, &old, new);
            return false;
        }

        // ---- bulk / size ----

        /// Count of in-range entries (O(range)).
        pub fn sizeLong(self: Self) DbError!u64 {
            if (self.rangeEmpty(self.lo, self.lo_inc, self.hi, self.hi_inc)) return 0;
            return self.map.sizeLongRange(self.lo, self.lo_inc, self.hi, self.hi_inc);
        }
        /// `true` iff no in-range entries; propagates iterator errors.
        pub fn isEmpty(self: Self) DbError!bool {
            const e = try self.firstEntry();
            if (e) |ent| {
                self.map.deinitEntry(ent);
                return false;
            }
            return true;
        }

        /// Removes ONLY in-range entries (snapshots keys first).
        pub fn clear(self: Self) DbError!void {
            const alloc = self.map.a();
            var keys: std.ArrayListUnmanaged(Key) = .empty;
            defer {
                for (keys.items) |k| self.map.kf().deinitElem(alloc, k);
                keys.deinit(alloc);
            }
            if (!self.rangeEmpty(self.lo, self.lo_inc, self.hi, self.hi_inc)) {
                var it = try self.map.entryIter(self.lo, self.lo_inc, self.hi, self.hi_inc);
                defer it.deinit();
                while (try it.next()) |e| {
                    self.map.vf().deinitElem(alloc, e.val);
                    keys.append(alloc, e.key) catch |err| {
                        self.map.kf().deinitElem(alloc, e.key);
                        return err;
                    };
                }
            }
            for (keys.items) |*k| {
                if (try self.map.remove(k)) |old| self.map.vf().deinitElem(alloc, old);
            }
        }

        /// Collect all in-range entries in orientation order (owned `[]Entry`).
        pub fn entries(self: Self) DbError![]Entry {
            const alloc = self.map.a();
            var out: std.ArrayListUnmanaged(Entry) = .empty;
            errdefer {
                for (out.items) |e| self.map.deinitEntry(e);
                out.deinit(alloc);
            }
            if (!self.rangeEmpty(self.lo, self.lo_inc, self.hi, self.hi_inc)) {
                var it = try self.map.entryIter(self.lo, self.lo_inc, self.hi, self.hi_inc);
                defer it.deinit();
                while (try it.next()) |e| out.append(alloc, e) catch |err| {
                    self.map.deinitEntry(e);
                    return err;
                };
            }
            const slice = try out.toOwnedSlice(alloc);
            if (self.descending_flag) std.mem.reverse(Entry, slice);
            return slice;
        }
        /// Free a slice returned by `entries`.
        pub fn deinitEntries(self: Self, es: []Entry) void {
            for (es) |e| self.map.deinitEntry(e);
            self.map.a().free(es);
        }

        // ---- descending / sub-map views ----
        //
        // `subMap`/`headMap`/`tailMap` take bounds in THIS view's orientation and
        // INTERSECT with the current bounds (never widen the parent); an
        // out-of-parent-range bound asserts. `descending` flips orientation
        // without touching the interval. All return a new borrowed view.

        /// This view with orientation reversed.
        pub fn descending(self: Self) Self {
            return .{ .map = self.map, .lo = self.lo, .lo_inc = self.lo_inc, .hi = self.hi, .hi_inc = self.hi_inc, .descending_flag = !self.descending_flag };
        }

        fn makeSub(self: Self, lo_arg: ?Bound, hi_arg: ?Bound) DbError!Self {
            var n_lo = self.lo;
            var n_lo_inc = self.lo_inc;
            if (lo_arg) |arg| {
                try self.checkBoundKey(arg.key, arg.inc);
                const b = self.effLower(arg.key, arg.inc);
                n_lo = b.key;
                n_lo_inc = b.inc;
            }
            var n_hi = self.hi;
            var n_hi_inc = self.hi_inc;
            if (hi_arg) |arg| {
                try self.checkBoundKey(arg.key, arg.inc);
                const b = self.effUpper(arg.key, arg.inc);
                n_hi = b.key;
                n_hi_inc = b.inc;
            }
            return .{ .map = self.map, .lo = n_lo, .lo_inc = n_lo_inc, .hi = n_hi, .hi_inc = n_hi_inc, .descending_flag = self.descending_flag };
        }

        /// `subMap(from, fromInc, to, toInc)` — args in THIS view's orientation.
        pub fn subMap(self: Self, from: Key, from_inc: bool, to: Key, to_inc: bool) Self {
            const r = if (!self.descending_flag) blk: {
                std.debug.assert(self.cmp(from, to) != .gt); // fromKey > toKey
                break :blk self.makeSub(.{ .key = from, .inc = from_inc }, .{ .key = to, .inc = to_inc });
            } else blk: {
                std.debug.assert(self.cmp(to, from) != .gt);
                break :blk self.makeSub(.{ .key = to, .inc = to_inc }, .{ .key = from, .inc = from_inc });
            };
            return r catch unreachable; // sub_map bound out of range
        }
        pub fn headMap(self: Self, to: Key, inc: bool) Self {
            const r = if (self.descending_flag)
                self.makeSub(.{ .key = to, .inc = inc }, null)
            else
                self.makeSub(null, .{ .key = to, .inc = inc });
            return r catch unreachable;
        }
        pub fn tailMap(self: Self, from: Key, inc: bool) Self {
            const r = if (self.descending_flag)
                self.makeSub(null, .{ .key = from, .inc = inc })
            else
                self.makeSub(.{ .key = from, .inc = inc }, null);
            return r catch unreachable;
        }
    };
}
