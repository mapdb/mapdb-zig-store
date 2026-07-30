//! Map-backed navigable set (Java `DB.treeSet`) built on a `BTreeMap` whose value
//! format serializes nothing (`NoValueFormat`). Only the `TreeSet` catalog row is
//! written; the value format is implicit and has no descriptor.
//! Ported from `mapdb-rust-store/src/db/set.rs`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const ser = @import("../ser/mod.zig");
const btree = @import("../btree/mod.zig");

/// The element serializer for the absent value: reads/writes zero bytes.
pub const NoValueSer = struct {
    pub const Elem = void;
    pub const instance: NoValueSer = .{};

    pub fn serialize(_: NoValueSer, _: *DataOutput2, _: void) DbError!void {}
    pub fn deserialize(_: NoValueSer, _: Allocator, _: *DataInput2, _: ?usize) DbError!void {
        return {};
    }
    pub fn cloneElem(_: NoValueSer, _: Allocator, _: void) DbError!void {
        return {};
    }
    pub fn deinitElem(_: NoValueSer, _: Allocator, _: void) void {}
    pub fn compare(_: NoValueSer, _: void, _: void) Order {
        return .eq;
    }
    pub fn equals(_: NoValueSer, _: void, _: void) bool {
        return true;
    }
    pub fn fixedSize(_: NoValueSer) ?usize {
        return 0;
    }
    pub fn naturalOrder(_: NoValueSer) bool {
        return true;
    }
    pub fn equalsBySerializedBytes(_: NoValueSer) bool {
        return true;
    }
};

/// A value group format that serializes to zero bytes (Java map-backed set's
/// no-value format). Built on the fixed-stride template with a zero-width element.
pub const NoValueFormat = ser.FixedStrideFormat(NoValueSer);

/// A navigable set backed by `BTreeMap(S, KF, NoValueFormat)` (Java `DB.treeSet`).
pub fn NavigableSet(comptime S: type, comptime KF: type) type {
    const Map = btree.BTreeMap(S, KF, NoValueFormat);
    return struct {
        const Self = @This();
        pub const Key = KF.Elem;
        map: Map,

        pub fn fromMap(map: Map) Self {
            return .{ .map = map };
        }
        pub fn deinit(self: Self) void {
            self.map.deinit();
        }
        /// Atomic last-ref release of the backing map. `true` if this
        /// was the last reference (freed); `false` if a derived clone still owns it.
        pub fn closeIfLast(self: Self) bool {
            return self.map.closeIfLast();
        }
        /// Release + destroy the fresh (never-published) backing map records.
        /// Error-path use only.
        pub fn deinitAndDestroy(self: Self) void {
            self.map.deinitAndDestroy();
        }
        /// A SCOPED BORROW of the backing map (review C6): the returned handle
        /// SHARES this set's `Inner` WITHOUT bumping the refcount, so the caller
        /// must NOT `deinit` it and must not let it outlive the set. Use it only
        /// for read/navigation within the set's lifetime.
        pub fn backingMap(self: Self) Map {
            return self.map;
        }
        /// Free a key returned by a navigation/poll method (owned by the set's
        /// allocator). A no-op for zero-management key formats (e.g. `LONG`).
        pub fn deinitKey(self: Self, k: Key) void {
            self.map.kf().deinitElem(self.map.a(), k);
        }
        pub fn counterRecid(self: Self) u64 {
            return self.map.counterRecid();
        }
        pub fn rootRecidRecid(self: Self) u64 {
            return self.map.rootRecidRecid();
        }
        /// Add `element` (BORROWED by-value key); true if it was newly inserted.
        pub fn add(self: Self, element: Key) DbError!bool {
            const prev = try self.map.putIfAbsent(element, {});
            if (prev) |_| return false;
            return true;
        }
        pub fn contains(self: Self, element: *const Key) DbError!bool {
            return self.map.containsKey(element);
        }
        pub fn remove(self: Self, element: *const Key) DbError!bool {
            return self.map.removeOnly(element);
        }
        pub fn sizeLong(self: Self) DbError!u64 {
            return self.map.sizeLong();
        }
        pub fn isEmpty(self: Self) DbError!bool {
            return self.map.isEmpty();
        }
        pub fn clear(self: Self) DbError!void {
            return self.map.clear();
        }
        pub fn isClosed(self: Self) bool {
            return self.map.isClosed();
        }

        // -------- navigation: each returns an OWNED key (free via `deinitKey`) --------

        fn keyOf(self: Self, e: ?Map.Entry) ?Key {
            _ = self;
            return if (e) |x| x.key else null; // val is void — nothing to free
        }

        /// The least element, or `null` (Java `first`).
        pub fn first(self: Self) DbError!?Key {
            return self.keyOf(try self.map.firstEntry());
        }
        /// The greatest element, or `null` (Java `last`).
        pub fn last(self: Self) DbError!?Key {
            return self.keyOf(try self.map.lastEntry());
        }
        /// The greatest element `< k` (Java `lower`).
        pub fn lower(self: Self, k: *const Key) DbError!?Key {
            return self.keyOf(try self.map.lowerEntry(k));
        }
        /// The greatest element `<= k` (Java `floor`).
        pub fn floor(self: Self, k: *const Key) DbError!?Key {
            return self.keyOf(try self.map.floorEntry(k));
        }
        /// The least element `>= k` (Java `ceiling`).
        pub fn ceiling(self: Self, k: *const Key) DbError!?Key {
            return self.keyOf(try self.map.ceilingEntry(k));
        }
        /// The least element `> k` (Java `higher`).
        pub fn higher(self: Self, k: *const Key) DbError!?Key {
            return self.keyOf(try self.map.higherEntry(k));
        }
        /// Remove and return the least element, or `null` (Java `pollFirst`).
        pub fn pollFirst(self: Self) DbError!?Key {
            return self.keyOf(try self.map.popFirst());
        }
        /// Remove and return the greatest element, or `null` (Java `pollLast`).
        pub fn pollLast(self: Self) DbError!?Key {
            return self.keyOf(try self.map.popLast());
        }

        /// Ascending snapshot of the elements (owned slice; free each key via
        /// `deinitKey`, then free the slice).
        pub fn toSlice(self: Self) DbError![]Key {
            return self.collectKeys(try self.map.entries());
        }
        /// Descending snapshot of the elements (owned; same ownership as `toSlice`).
        pub fn toSliceDescending(self: Self) DbError![]Key {
            return self.collectKeys(try self.map.descendingEntries(null, true, null, true));
        }

        /// Move the keys out of an owned entry slice into a fresh key slice, then
        /// free the entry slice itself (the void values need no teardown).
        fn collectKeys(self: Self, es: []Map.Entry) DbError![]Key {
            const alloc = self.map.a();
            defer alloc.free(es);
            const keys = alloc.alloc(Key, es.len) catch |e| {
                for (es) |x| self.map.kf().deinitElem(alloc, x.key);
                return e;
            };
            for (es, 0..) |x, i| keys[i] = x.key; // key ownership moves to `keys`
            return keys;
        }
    };
}

// ------------------------------------------------------------------- tests

const testing = std.testing;
const StoreByteArray = @import("../store/mod.zig").StoreByteArray;
const LongFormat = @import("../ser/long.zig").LongFormat;

test "NoValueFormat is a valid group format" {
    ser.checkGroupFormat(NoValueFormat);
}

test "map-backed set add/contains/remove/size" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    const Set = NavigableSet(StoreByteArray, LongFormat);
    const map = try btree.BTreeMap(StoreByteArray, LongFormat, NoValueFormat).createCounter(a, &s, LongFormat.instance, NoValueFormat.instance, 16, true);
    const set = Set.fromMap(map);
    defer set.deinit();

    try testing.expect(try set.add(5));
    try testing.expect(try set.add(3));
    try testing.expect(!(try set.add(5))); // duplicate
    try testing.expectEqual(@as(u64, 2), try set.sizeLong());
    try testing.expect(try set.contains(&@as(i64, 3)));
    try testing.expect(!(try set.contains(&@as(i64, 9))));
    try testing.expect(try set.remove(&@as(i64, 3)));
    try testing.expectEqual(@as(u64, 1), try set.sizeLong());
}

test "navigable set first/last/floor/ceiling/poll + ascending/descending" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    const Set = NavigableSet(StoreByteArray, LongFormat);
    const map = try btree.BTreeMap(StoreByteArray, LongFormat, NoValueFormat).createCounter(a, &s, LongFormat.instance, NoValueFormat.instance, 4, true);
    const set = Set.fromMap(map);
    defer set.deinit();

    for ([_]i64{ 10, 20, 30, 40, 50 }) |k| try testing.expect(try set.add(k));
    try testing.expectEqual(@as(?i64, 10), try set.first());
    try testing.expectEqual(@as(?i64, 50), try set.last());
    try testing.expectEqual(@as(?i64, 20), try set.floor(&@as(i64, 25)));
    try testing.expectEqual(@as(?i64, 30), try set.ceiling(&@as(i64, 25)));
    try testing.expectEqual(@as(?i64, 20), try set.lower(&@as(i64, 30)));
    try testing.expectEqual(@as(?i64, 40), try set.higher(&@as(i64, 30)));

    const asc = try set.toSlice();
    defer a.free(asc);
    try testing.expectEqualSlices(i64, &.{ 10, 20, 30, 40, 50 }, asc);
    const desc = try set.toSliceDescending();
    defer a.free(desc);
    try testing.expectEqualSlices(i64, &.{ 50, 40, 30, 20, 10 }, desc);

    try testing.expectEqual(@as(?i64, 10), try set.pollFirst());
    try testing.expectEqual(@as(?i64, 50), try set.pollLast());
    try testing.expectEqual(@as(u64, 3), try set.sizeLong());
}
