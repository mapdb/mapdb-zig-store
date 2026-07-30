//! BTreeMap behavioural + concurrency + view/columnar + crafted-corruption
//! suites, ported from `mapdb-rust-store/tests/btree_{smoke,concurrent,view,wal}.rs`
//! and `mapdb-rust-store/src/btree/tests.rs`.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;

const store_mod = @import("../store/mod.zig");
const StoreOnHeap = store_mod.StoreOnHeap;
const StoreByteArray = store_mod.StoreByteArray;
const StoreDirect = store_mod.StoreDirect;
const StoreWAL = store_mod.StoreWAL;
const LeaseTable = store_mod.LeaseTable;
const RecordRead = store_mod.RecordRead;

const long = @import("../ser/long.zig");
const LongFormat = long.LongFormat;
const serializers = @import("../ser/serializers.zig");
const LONG = serializers.LongSer.instance;
const columnar = @import("../ser/columnar.zig");
const ColumnarValueFormat = columnar.ColumnarValueFormat;
const ColumnType = columnar.ColumnType;
const Value = @import("../ser/value.zig").Value;

const nodemod = @import("node.zig");
const Node = nodemod.Node;
const NodeSerializer = nodemod.NodeSerializer;
const DIR = nodemod.DIR;
const LEFT = nodemod.LEFT;
const RIGHT = nodemod.RIGHT;

const mapmod = @import("map.zig");
const BTreeMap = mapmod.BTreeMap;
const BTreeMapExternal = mapmod.BTreeMapExternal;
const string_group = @import("../ser/string_group.zig");
const StringGroupFormat = string_group.StringGroupFormat;
const listenermod = @import("../listener.zig");
const io_mod = @import("../io.zig");
const DataOutput2 = io_mod.DataOutput2;
const StringSer = serializers.StringSer;

fn Map(comptime S: type) type {
    return BTreeMap(S, LongFormat, LongFormat);
}

fn isCorrupt(r: anytype) bool {
    if (r) |_| {
        return false;
    } else |e| {
        return e == error.DataCorruption;
    }
}

// ============================================================ smoke

test "smoke: put/get/remove basic" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 8);
    defer map.deinit();

    try testing.expectEqual(@as(?i64, null), try map.get(&@as(i64, 1)));
    try testing.expectEqual(@as(?i64, null), try map.put(1, 100));
    try testing.expectEqual(@as(?i64, null), try map.put(2, 200));
    try testing.expectEqual(@as(?i64, 100), try map.get(&@as(i64, 1)));
    try testing.expectEqual(@as(?i64, 200), try map.get(&@as(i64, 2)));
    try testing.expectEqual(@as(?i64, 100), try map.put(1, 111)); // overwrite returns old
    try testing.expectEqual(@as(?i64, 111), try map.get(&@as(i64, 1)));
    try testing.expect(try map.containsKey(&@as(i64, 1)));
    try testing.expect(!try map.containsKey(&@as(i64, 99)));
    try testing.expectEqual(@as(?i64, 111), try map.remove(&@as(i64, 1)));
    try testing.expectEqual(@as(?i64, null), try map.get(&@as(i64, 1)));
    try testing.expectEqual(@as(?i64, null), try map.remove(&@as(i64, 1)));
    try testing.expectEqual(@as(u64, 1), try map.sizeLong());
}

test "smoke: many ascending splits" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 4);
    defer map.deinit();

    var i: i64 = 0;
    while (i < 1000) : (i += 1) try testing.expectEqual(@as(?i64, null), try map.put(i, i * 10));
    i = 0;
    while (i < 1000) : (i += 1) try testing.expectEqual(@as(?i64, i * 10), try map.get(&i));
    try testing.expectEqual(@as(u64, 1000), try map.sizeLong());
    const es = try map.entries();
    defer map.deinitEntries(es);
    try testing.expectEqual(@as(usize, 1000), es.len);
    for (es, 0..) |e, idx| {
        try testing.expectEqual(@as(i64, @intCast(idx)), e.key);
        try testing.expectEqual(@as(i64, @intCast(idx)) * 10, e.val);
    }
}

test "smoke: many descending inserts" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 4);
    defer map.deinit();

    var i: i64 = 499;
    while (i >= 0) : (i -= 1) _ = try map.put(i, i);
    i = 0;
    while (i < 500) : (i += 1) try testing.expectEqual(@as(?i64, i), try map.get(&i));
    const es = try map.entries();
    defer map.deinitEntries(es);
    var prev: i64 = -1;
    for (es) |e| {
        try testing.expect(prev < e.key);
        prev = e.key;
    }
}

test "smoke: random ops vs model" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 6);
    defer map.deinit();

    var model = std.AutoHashMap(i64, i64).init(a);
    defer model.deinit();
    var x: u64 = 0x1234_5678;
    var n: usize = 0;
    while (n < 5000) : (n += 1) {
        x = x *% 6364136223846793005 +% 1442695040888963407;
        const k = @as(i64, @intCast(@as(u64, @intCast(x >> 33)) % 300));
        const op = (x >> 20) & 3;
        switch (op) {
            0, 1 => {
                const v = k * 7;
                const got = try map.put(k, v);
                const prev = try model.fetchPut(k, v);
                try testing.expectEqual(if (prev) |p| @as(?i64, p.value) else null, got);
            },
            2 => {
                const got = try map.remove(&k);
                const prev = model.fetchRemove(k);
                try testing.expectEqual(if (prev) |p| @as(?i64, p.value) else null, got);
            },
            else => {
                const got = try map.get(&k);
                try testing.expectEqual(model.get(k), got);
            },
        }
    }
    const es = try map.entries();
    defer map.deinitEntries(es);
    try testing.expectEqual(@as(usize, model.count()), es.len);
    for (es) |e| try testing.expectEqual(@as(?i64, e.val), model.get(e.key));
}

test "smoke: CAS ops" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 8);
    defer map.deinit();

    _ = try map.put(1, 10);
    try testing.expectEqual(@as(?i64, 10), try map.putIfAbsent(1, 999)); // present, no change
    try testing.expectEqual(@as(?i64, 10), try map.get(&@as(i64, 1)));
    try testing.expectEqual(@as(?i64, null), try map.putIfAbsent(2, 20)); // inserted
    try testing.expectEqual(@as(?i64, 20), try map.get(&@as(i64, 2)));
    try testing.expectEqual(@as(?i64, 10), try map.replace(&@as(i64, 1), 11));
    try testing.expectEqual(@as(?i64, null), try map.replace(&@as(i64, 99), 1)); // absent
    try testing.expect(try map.replaceIf(&@as(i64, 1), &@as(i64, 11), 12));
    try testing.expect(!try map.replaceIf(&@as(i64, 1), &@as(i64, 11), 13)); // old mismatch
    try testing.expectEqual(@as(?i64, 12), try map.get(&@as(i64, 1)));
    try testing.expect(!try map.removeIf(&@as(i64, 1), &@as(i64, 99))); // value mismatch
    try testing.expect(try map.removeIf(&@as(i64, 1), &@as(i64, 12)));
    try testing.expectEqual(@as(?i64, null), try map.get(&@as(i64, 1)));
}

fn collectKeys(a: Allocator, map: anytype, lo: ?i64, lo_i: bool, hi: ?i64, hi_i: bool) ![]i64 {
    var it = try map.entryIter(lo, lo_i, hi, hi_i);
    defer it.deinit();
    var out: std.ArrayListUnmanaged(i64) = .empty;
    errdefer out.deinit(a);
    while (try it.next()) |e| try out.append(a, e.key);
    return out.toOwnedSlice(a);
}

test "smoke: bounded iteration" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 4);
    defer map.deinit();
    var i: i64 = 0;
    while (i < 100) : (i += 1) _ = try map.put(i, i);

    const c1 = try collectKeys(a, &map, 10, true, 15, true);
    defer a.free(c1);
    try testing.expectEqualSlices(i64, &.{ 10, 11, 12, 13, 14, 15 }, c1);
    const c2 = try collectKeys(a, &map, 10, false, 15, false);
    defer a.free(c2);
    try testing.expectEqualSlices(i64, &.{ 11, 12, 13, 14 }, c2);
    const c3 = try collectKeys(a, &map, 95, true, null, true);
    defer a.free(c3);
    try testing.expectEqual(@as(usize, 5), c3.len);
    const c4 = try collectKeys(a, &map, null, true, 4, true);
    defer a.free(c4);
    try testing.expectEqualSlices(i64, &.{ 0, 1, 2, 3, 4 }, c4);
    // descending
    const desc = try map.descendingEntries(10, true, 13, true);
    defer map.deinitEntries(desc);
    try testing.expectEqual(@as(usize, 4), desc.len);
    try testing.expectEqual(@as(i64, 13), desc[0].key);
    try testing.expectEqual(@as(i64, 10), desc[3].key);
}

test "smoke: poll entries" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 4);
    defer map.deinit();
    var i: i64 = 0;
    while (i < 20) : (i += 1) _ = try map.put(i, i);

    const f = try map.pollFirstEntry(null, true, null, true);
    try testing.expectEqual(@as(i64, 0), f.?.key);
    const l = try map.pollLastEntry(null, true, null, true);
    try testing.expectEqual(@as(i64, 19), l.?.key);
    try testing.expectEqual(@as(u64, 18), try map.sizeLong());
}

const PairIter = struct {
    items: []const [2]i64,
    idx: usize = 0,
    pub fn next(self: *PairIter) ?struct { key: i64, val: i64 } {
        if (self.idx >= self.items.len) return null;
        const p = self.items[self.idx];
        self.idx += 1;
        return .{ .key = p[0], .val = p[1] };
    }
};

test "smoke: pump bulk build" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var items: [2000][2]i64 = undefined;
    for (&items, 0..) |*it, i| it.* = .{ @intCast(i), @as(i64, @intCast(i)) * 2 };
    var iter = PairIter{ .items = &items };
    var map = try Map(StoreOnHeap).createFromSorted(a, &store, .{}, .{}, 16, &iter);
    defer map.deinit();
    try testing.expectEqual(@as(u64, 2000), try map.sizeLong());
    for (items) |it| try testing.expectEqual(@as(?i64, it[1]), try map.get(&it[0]));
    _ = try map.put(10000, 42);
    try testing.expectEqual(@as(?i64, 42), try map.get(&@as(i64, 10000)));
    const es = try map.entries();
    defer map.deinitEntries(es);
    try testing.expectEqual(@as(usize, 2001), es.len);
}

test "smoke: pump rejects unsorted" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var items = [_][2]i64{ .{ 1, 1 }, .{ 3, 3 }, .{ 2, 2 } };
    var iter = PairIter{ .items = &items };
    try testing.expectError(error.NotSorted, Map(StoreOnHeap).createFromSorted(a, &store, .{}, .{}, 8, &iter));
}

test "smoke: pump empty source" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var items = [_][2]i64{};
    var iter = PairIter{ .items = &items };
    var map = try Map(StoreOnHeap).createFromSorted(a, &store, .{}, .{}, 8, &iter);
    defer map.deinit();
    try testing.expectEqual(@as(u64, 0), try map.sizeLong());
    _ = try map.put(5, 5);
    try testing.expectEqual(@as(?i64, 5), try map.get(&@as(i64, 5)));
}

test "smoke: reopen persists root" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var rrr: u64 = undefined;
    {
        var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 4);
        defer map.deinit();
        var i: i64 = 0;
        while (i < 200) : (i += 1) _ = try map.put(i, i * 3);
        rrr = map.rootRecidRecid();
    }
    var map2 = try Map(StoreOnHeap).open(a, &store, rrr, .{}, .{}, 4);
    defer map2.deinit();
    var i: i64 = 0;
    while (i < 200) : (i += 1) try testing.expectEqual(@as(?i64, i * 3), try map2.get(&i));
}

test "smoke: duplicate open rejected" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 8);
    const rrr = map.rootRecidRecid();
    try testing.expectError(error.AlreadyOpen, Map(StoreOnHeap).open(a, &store, rrr, .{}, .{}, 8));
    map.deinit();
    var m2 = try Map(StoreOnHeap).open(a, &store, rrr, .{}, .{}, 8);
    m2.deinit();
}

test "smoke: verify after ops" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 4);
    defer map.deinit();
    var i: i64 = 0;
    while (i < 300) : (i += 1) {
        _ = try map.put(i, i);
        if (@rem(i, 3) == 0) _ = try map.remove(&@as(i64, @divTrunc(i, 2)));
    }
    try store.verify();
}

// ============================================================ view

fn filled(a: Allocator, store: *StoreOnHeap, max: usize, n: i64) !Map(StoreOnHeap) {
    var map = try Map(StoreOnHeap).create(a, store, .{}, .{}, max);
    var i: i64 = 0;
    while (i < n) : (i += 1) _ = try map.put(i, i * 10);
    return map;
}

fn expectEntry(e: ?Map(StoreOnHeap).Entry, k: i64, v: i64) !void {
    try testing.expect(e != null);
    try testing.expectEqual(k, e.?.key);
    try testing.expectEqual(v, e.?.val);
}

test "view: navigation entries" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try filled(a, &store, 4, 100);
    defer m.deinit();
    try expectEntry(try m.firstEntry(), 0, 0);
    try expectEntry(try m.lastEntry(), 99, 990);
    try expectEntry(try m.floorEntry(&@as(i64, 50)), 50, 500);
    try expectEntry(try m.floorEntry(&@as(i64, 999)), 99, 990);
    try expectEntry(try m.ceilingEntry(&@as(i64, 50)), 50, 500);
    try testing.expect((try m.ceilingEntry(&@as(i64, 999))) == null);
    try expectEntry(try m.lowerEntry(&@as(i64, 50)), 49, 490);
    try expectEntry(try m.higherEntry(&@as(i64, 50)), 51, 510);
    try testing.expect((try m.lowerEntry(&@as(i64, 0))) == null);
    try testing.expect((try m.higherEntry(&@as(i64, 99))) == null);
}

test "view: navigation on gaps" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 4);
    defer m.deinit();
    for ([_]i64{ 10, 20, 30, 40, 50 }) |k| _ = try m.put(k, k);
    try expectEntry(try m.floorEntry(&@as(i64, 25)), 20, 20);
    try expectEntry(try m.ceilingEntry(&@as(i64, 25)), 30, 30);
    try expectEntry(try m.lowerEntry(&@as(i64, 30)), 20, 20);
    try expectEntry(try m.higherEntry(&@as(i64, 30)), 40, 40);
    try testing.expect((try m.floorEntry(&@as(i64, 5))) == null);
    try testing.expect((try m.ceilingEntry(&@as(i64, 55))) == null);
}

test "view: sub_map bounds" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try filled(a, &store, 4, 100);
    defer m.deinit();
    const r = m.range(20, 30); // [20,30)
    const es = try r.entries();
    defer r.deinitEntries(es);
    try testing.expectEqual(@as(usize, 10), es.len);
    try testing.expectEqual(@as(i64, 20), es[0].key);
    try testing.expectEqual(@as(i64, 29), es[9].key);
    try testing.expectEqual(@as(u64, 10), try r.sizeLong());
    try expectEntry(try r.firstEntry(), 20, 200);
    try expectEntry(try r.lastEntry(), 29, 290);
    try testing.expectEqual(@as(?i64, null), try r.get(15));
    try testing.expectEqual(@as(?i64, 250), try r.get(25));
    try testing.expectEqual(@as(?i64, null), try r.get(30)); // exclusive upper
    const ri = m.subMap(20, true, 30, true);
    try expectEntry(try ri.lastEntry(), 30, 300);
}

test "view: head/tail map" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try filled(a, &store, 4, 50);
    defer m.deinit();
    const head = m.headMap(10, false); // keys < 10
    const hes = try head.entries();
    defer head.deinitEntries(hes);
    try testing.expectEqual(@as(usize, 10), hes.len);
    try expectEntry(try head.lastEntry(), 9, 90);
    const tail = m.tailMap(45, true); // keys >= 45
    const tk = try tail.entries();
    defer tail.deinitEntries(tk);
    try testing.expectEqual(@as(usize, 5), tk.len);
    try testing.expectEqual(@as(i64, 45), tk[0].key);
    try testing.expectEqual(@as(i64, 49), tk[4].key);
}

test "view: descending" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try filled(a, &store, 4, 20);
    defer m.deinit();
    const d = m.descending();
    const es = try d.entries();
    defer d.deinitEntries(es);
    try testing.expectEqual(@as(usize, 20), es.len);
    try testing.expectEqual(@as(i64, 19), es[0].key);
    try testing.expectEqual(@as(i64, 0), es[19].key);
    try expectEntry(try d.firstEntry(), 19, 190);
    try expectEntry(try d.lastEntry(), 0, 0);
    try expectEntry(try d.floorEntry(10), 10, 100);
    try expectEntry(try d.ceilingEntry(10), 10, 100);
    try expectEntry(try d.higherEntry(10), 9, 90); // next smaller
    try expectEntry(try d.lowerEntry(10), 11, 110); // prev larger
    const dd = d.descending();
    try testing.expect(!dd.isDescending());
}

test "view: descending sub_map" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try filled(a, &store, 4, 100);
    defer m.deinit();
    const d = m.descending();
    const sub = d.subMap(80, true, 70, false); // backing (70, 80]
    const es = try sub.entries();
    defer sub.deinitEntries(es);
    const want = [_]i64{ 80, 79, 78, 77, 76, 75, 74, 73, 72, 71 };
    try testing.expectEqual(want.len, es.len);
    for (want, es) |w, e| try testing.expectEqual(w, e.key);
}

test "view: nested sub_map never widens" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try filled(a, &store, 4, 100);
    defer m.deinit();
    const outer = m.subMap(20, true, 60, false); // [20,60)
    const inner = outer.subMap(20, true, 60, false);
    try expectEntry(try inner.firstEntry(), 20, 200);
    try expectEntry(try inner.lastEntry(), 59, 590);
}

test "view: poll via view" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try filled(a, &store, 4, 10);
    defer m.deinit();
    try expectEntry(try m.popFirst(), 0, 0);
    try expectEntry(try m.popLast(), 9, 90);
    const r = m.subMap(2, true, 8, true);
    try expectEntry(try r.pollFirstEntry(), 2, 20);
    try expectEntry(try r.pollLastEntry(), 8, 80);
    const d = m.descending();
    try expectEntry(try d.pollFirstEntry(), 7, 70); // backing greatest remaining
}

test "view: clear bounded" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try filled(a, &store, 4, 50);
    defer m.deinit();
    const r = m.subMap(10, true, 20, false);
    try r.clear();
    try testing.expectEqual(@as(?i64, 90), try m.get(&@as(i64, 9)));
    try testing.expectEqual(@as(?i64, null), try m.get(&@as(i64, 10)));
    try testing.expectEqual(@as(?i64, null), try m.get(&@as(i64, 19)));
    try testing.expectEqual(@as(?i64, 200), try m.get(&@as(i64, 20)));
    try testing.expectEqual(@as(u64, 40), try m.sizeLong());
}

test "view: empty and inverted ranges" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try filled(a, &store, 4, 20);
    defer m.deinit();
    const r = m.subMap(5, false, 5, false);
    try testing.expect(try r.isEmpty());
    try testing.expectEqual(@as(u64, 0), try r.sizeLong());
    try testing.expect((try r.firstEntry()) == null);
}

// ============================================================ columnar (byte store)

const ColMap = BTreeMap(StoreDirect, LongFormat, ColumnarValueFormat);

fn colRow(a: Allocator, l: i64, i: i32, s: i16) ![]Value {
    const row = try a.alloc(Value, 3);
    row[0] = .{ .long = l };
    row[1] = .{ .int = i };
    row[2] = .{ .short = s };
    return row;
}

const ColCtx = struct {
    a: Allocator,
    keys: *std.ArrayListUnmanaged(i64),
    cells: *std.ArrayListUnmanaged(Value),
    fn cb(self: *ColCtx, k: *const i64, cell: *const Value) void {
        self.keys.append(self.a, k.*) catch unreachable;
        self.cells.append(self.a, cell.*) catch unreachable;
    }
};

test "columnar: single column scan (byte store)" {
    const a = testing.allocator;
    var store = try StoreDirect.init(a, true);
    defer store.deinit();
    const vf = ColumnarValueFormat.of(&.{ .long, .int, .short });
    var map = try ColMap.create(a, &store, .{}, vf, 4);
    defer map.deinit();

    var i: i64 = 0;
    while (i < 200) : (i += 1) {
        const row = try colRow(a, i * 100, @intCast(i), @intCast(@rem(i, 7)));
        defer a.free(row);
        const old = try map.put(i, row);
        if (old) |o| a.free(o);
    }

    // scan column 1 (Int) over [50, 60]
    {
        var keys: std.ArrayListUnmanaged(i64) = .empty;
        defer keys.deinit(a);
        var cells: std.ArrayListUnmanaged(Value) = .empty;
        defer cells.deinit(a);
        var ctx = ColCtx{ .a = a, .keys = &keys, .cells = &cells };
        try map.forEachValueColumn(50, true, 60, true, 1, &ctx, ColCtx.cb);
        try testing.expectEqual(@as(usize, 11), keys.items.len);
        for (keys.items, cells.items, 0..) |k, c, idx| {
            try testing.expectEqual(@as(i64, 50 + @as(i64, @intCast(idx))), k);
            try testing.expectEqual(@as(i32, @intCast(k)), c.int);
        }
    }
    // full scan of column 0 (Long) sums
    {
        var keys: std.ArrayListUnmanaged(i64) = .empty;
        defer keys.deinit(a);
        var cells: std.ArrayListUnmanaged(Value) = .empty;
        defer cells.deinit(a);
        var ctx = ColCtx{ .a = a, .keys = &keys, .cells = &cells };
        try map.forEachValueColumn(null, true, null, true, 0, &ctx, ColCtx.cb);
        var sum: i64 = 0;
        for (cells.items) |c| sum += c.long;
        var want: i64 = 0;
        i = 0;
        while (i < 200) : (i += 1) want += i * 100;
        try testing.expectEqual(want, sum);
    }
    // exclusive bounds on column 2
    {
        var keys: std.ArrayListUnmanaged(i64) = .empty;
        defer keys.deinit(a);
        var cells: std.ArrayListUnmanaged(Value) = .empty;
        defer cells.deinit(a);
        var ctx = ColCtx{ .a = a, .keys = &keys, .cells = &cells };
        try map.forEachValueColumn(10, false, 14, false, 2, &ctx, ColCtx.cb);
        try testing.expectEqualSlices(i64, &.{ 11, 12, 13 }, keys.items);
    }
    try store.verify();
}

// ============================================================ byte store (StoreDirect on_bytes)

test "bytestore: put/get splits + binary search" {
    const a = testing.allocator;
    var store = try StoreDirect.init(a, true);
    defer store.deinit();
    var map = try Map(StoreDirect).create(a, &store, .{}, .{}, 4);
    defer map.deinit();
    var i: i64 = 0;
    while (i < 2000) : (i += 1) _ = try map.put(i * 3, i);
    i = 0;
    while (i < 2000) : (i += 1) {
        try testing.expectEqual(@as(?i64, i), try map.get(&@as(i64, i * 3)));
        try testing.expectEqual(@as(?i64, null), try map.get(&@as(i64, i * 3 + 1)));
    }
    try testing.expectEqual(@as(u64, 2000), try map.sizeLong());
    try store.verify();
}

test "bytestore: reopen and pump" {
    const a = testing.allocator;
    var store = try StoreDirect.init(a, true);
    defer store.deinit();
    var items: [3000][2]i64 = undefined;
    for (&items, 0..) |*it, k| it.* = .{ @intCast(k), @as(i64, @intCast(k)) + 1 };
    var iter = PairIter{ .items = &items };
    var rrr: u64 = undefined;
    {
        var map = try Map(StoreDirect).createFromSorted(a, &store, .{}, .{}, 16, &iter);
        defer map.deinit();
        rrr = map.rootRecidRecid();
        var i: i64 = 0;
        while (i < 3000) : (i += 1) try testing.expectEqual(@as(?i64, i + 1), try map.get(&i));
    }
    var m2 = try Map(StoreDirect).open(a, &store, rrr, .{}, .{}, 16);
    defer m2.deinit();
    try testing.expectEqual(@as(?i64, 1501), try m2.get(&@as(i64, 1500)));
    _ = try m2.put(99999, 7);
    try testing.expectEqual(@as(?i64, 7), try m2.get(&@as(i64, 99999)));
    try store.verify();
}

// ============================================================ concurrency

const Worker = struct {
    fn disjoint(map: Map(StoreOnHeap), t: usize, per: i64) void {
        var i: i64 = 0;
        while (i < per) : (i += 1) {
            const k = @as(i64, @intCast(t)) * per + i;
            _ = map.put(k, k * 2) catch unreachable;
        }
    }
};

test "concurrent: disjoint writers" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 8);
    defer map.deinit();
    const threads = 8;
    const per: i64 = 4000;
    var handles: [threads]std.Thread = undefined;
    for (&handles, 0..) |*h, t| h.* = try std.Thread.spawn(.{}, Worker.disjoint, .{ map, t, per });
    for (&handles) |*h| h.join();

    const total = @as(u64, threads) * @as(u64, per);
    try testing.expectEqual(total, try map.sizeLong());
    const es = try map.entries();
    defer map.deinitEntries(es);
    try testing.expectEqual(@as(usize, total), es.len);
    for (es, 0..) |e, idx| {
        try testing.expectEqual(@as(i64, @intCast(idx)), e.key);
        try testing.expectEqual(@as(i64, @intCast(idx)) * 2, e.val);
    }
    try store.verify();
}

const MixWorker = struct {
    fn run(map: Map(StoreOnHeap), t: usize) void {
        var x: u64 = 0x9E3779B9 ^ (@as(u64, t) << 32);
        var n: usize = 0;
        while (n < 8000) : (n += 1) {
            x = x *% 6364136223846793005 +% 1;
            const k = @as(i64, @intCast(@as(u64, @intCast(x >> 33)) % 2000));
            switch ((x >> 20) & 3) {
                0, 1 => _ = map.put(k, k) catch unreachable,
                2 => _ = map.remove(&k) catch unreachable,
                else => {
                    if (map.get(&k) catch unreachable) |v| std.debug.assert(v == k);
                },
            }
        }
    }
};

test "concurrent: mixed ops invariants" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 6);
    defer map.deinit();
    const threads = 6;
    var handles: [threads]std.Thread = undefined;
    for (&handles, 0..) |*h, t| h.* = try std.Thread.spawn(.{}, MixWorker.run, .{ map, t });
    for (&handles) |*h| h.join();
    try store.verify();
    const es = try map.entries();
    defer map.deinitEntries(es);
    var prev: ?i64 = null;
    for (es) |e| {
        try testing.expectEqual(e.key, e.val);
        if (prev) |p| try testing.expect(p < e.key);
        prev = e.key;
    }
    try testing.expectEqual(@as(u64, es.len), try map.sizeLong());
}

const GrowWorker = struct {
    fn run(map: Map(StoreOnHeap), n: i64) void {
        var k: i64 = 0;
        while (k < n) : (k += 1) _ = map.put(k, k) catch unreachable;
    }
};

test "concurrent: root grow contention" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const a = testing.allocator;
    var round: usize = 0;
    while (round < 12) : (round += 1) {
        var store = try StoreOnHeap.init(a, true);
        defer store.deinit();
        var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 4);
        defer map.deinit();
        const n: i64 = 600;
        var handles: [12]std.Thread = undefined;
        for (&handles) |*h| h.* = try std.Thread.spawn(.{}, GrowWorker.run, .{ map, n });
        for (&handles) |*h| h.join();
        try store.verify();
        const es = try map.entries();
        defer map.deinitEntries(es);
        try testing.expectEqual(@as(usize, @intCast(n)), es.len);
        for (es, 0..) |e, i| {
            try testing.expectEqual(@as(i64, @intCast(i)), e.key);
            try testing.expectEqual(@as(i64, @intCast(i)), e.val);
        }
    }
}

// Debug-only: the zero-held node-lock checker (map.zig `zeroHeldPreAcquire`/
// `zeroHeldRecord`/`zeroHeldRelease`) must not trip under contention, and no
// thread may hold a node lock once its ops complete. A violation aborts inside
// the offending thread (the checker's asserts); here we additionally pin the
// drain-to-zero invariant on BOTH the workers (their own TLS) and the spawner.
const ZeroHeldWorker = struct {
    fn run(map: Map(StoreOnHeap), t: usize, per: i64) void {
        var i: i64 = 0;
        while (i < per) : (i += 1) {
            const k = @as(i64, @intCast(t)) * per + i;
            _ = map.put(k, k * 2) catch unreachable;
        }
        // This worker thread must hold no node lock on return (its own TLS).
        std.debug.assert(mapmod.debugHeldLockCount() == 0);
    }
};

test "concurrent: zero-held node-lock checker stays quiet + drains" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    if (@import("builtin").mode != .Debug) return error.SkipZigTest;
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 4); // small node ⇒ splits/root-grow
    defer map.deinit();

    // Single-threaded ops on this thread: nothing left held between/after.
    var i: i64 = 0;
    while (i < 200) : (i += 1) _ = try map.put(i, i * 2);
    try testing.expectEqual(@as(usize, 0), mapmod.debugHeldLockCount());
    i = 0;
    while (i < 100) : (i += 1) _ = try map.remove(&i);
    try testing.expectEqual(@as(usize, 0), mapmod.debugHeldLockCount());

    // Contended split/root-grow: any zero-held violation aborts inside a worker,
    // and each worker asserts it drained its own TLS before returning.
    const threads = 8;
    const per: i64 = 2000;
    var handles: [threads]std.Thread = undefined;
    for (&handles, 0..) |*h, t| h.* = try std.Thread.spawn(.{}, ZeroHeldWorker.run, .{ map, threads + t, per });
    for (&handles) |*h| h.join();

    // This (spawning) thread never acquired a node lock and released none.
    try testing.expectEqual(@as(usize, 0), mapmod.debugHeldLockCount());
    try store.verify();
}

// Positive nesting: the deadlock-freedom contract permits an acyclic Bind chain
// of ANY depth — one lock in each of N DISTINCT tables held at once. Pins the
// UNBOUNDED-tracker fix (no fixed cap can abort valid input).
test "zero-held checker: five distinct tables nest without tripping" {
    if (@import("builtin").mode != .Debug) return error.SkipZigTest;
    const a = testing.allocator;
    const H = mapmod.testHooks;
    var t0 = try H.initTable(a);
    var t1 = try H.initTable(a);
    var t2 = try H.initTable(a);
    var t3 = try H.initTable(a);
    var t4 = try H.initTable(a);
    defer {
        H.deinitTable(&t0);
        H.deinitTable(&t1);
        H.deinitTable(&t2);
        H.deinitTable(&t3);
        H.deinitTable(&t4);
    }
    try testing.expectEqual(@as(usize, 0), H.heldCount());
    try H.lock(&t0, 10);
    try H.lock(&t1, 11);
    try H.lock(&t2, 12);
    try H.lock(&t3, 13);
    try H.lock(&t4, 14); // fifth distinct table — a HELD_MAX=4 cap would abort here
    try testing.expectEqual(@as(usize, 5), H.heldCount());
    // Release in reverse; drains exactly to zero.
    H.unlock(&t4, 14);
    H.unlock(&t3, 13);
    H.unlock(&t2, 12);
    H.unlock(&t1, 11);
    H.unlock(&t0, 10);
    try testing.expectEqual(@as(usize, 0), H.heldCount());
}

// The same-table pre-acquire predicate the `lock` assert is built on: true when
// this thread already holds a lock of THAT table, false for any other table.
test "zero-held checker: same-table pre-acquire predicate" {
    if (@import("builtin").mode != .Debug) return error.SkipZigTest;
    const a = testing.allocator;
    const H = mapmod.testHooks;
    var t0 = try H.initTable(a);
    var t1 = try H.initTable(a);
    defer {
        H.deinitTable(&t0);
        H.deinitTable(&t1);
    }
    try testing.expect(!H.wouldViolate(&t0)); // nothing held
    try H.lock(&t0, 5);
    try testing.expect(H.wouldViolate(&t0)); // same table already held ⇒ violation
    try testing.expect(!H.wouldViolate(&t1)); // different table ⇒ ok
    H.unlock(&t0, 5);
    try testing.expect(!H.wouldViolate(&t0));
    try testing.expectEqual(@as(usize, 0), H.heldCount());
}

const ReadWorker = struct {
    fn writer(map: Map(StoreOnHeap)) void {
        var i: i64 = 1000;
        while (i < 10000) : (i += 1) _ = map.put(i, i) catch unreachable;
    }
    fn reader(map: Map(StoreOnHeap)) void {
        var n: usize = 0;
        while (n < 20000) : (n += 1) {
            for ([_]i64{ 0, 500, 999 }) |k| {
                const v = map.get(&k) catch unreachable;
                std.debug.assert(v.? == k);
            }
        }
    }
};

test "concurrent: readers during writes" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try Map(StoreOnHeap).create(a, &store, .{}, .{}, 8);
    defer map.deinit();
    var i: i64 = 0;
    while (i < 1000) : (i += 1) _ = try map.put(i, i);
    var w = try std.Thread.spawn(.{}, ReadWorker.writer, .{map});
    var rs: [4]std.Thread = undefined;
    for (&rs) |*h| h.* = try std.Thread.spawn(.{}, ReadWorker.reader, .{map});
    w.join();
    for (&rs) |*h| h.join();
    try store.verify();
}

const DirectWorker = struct {
    fn run(map: Map(StoreDirect), t: usize) void {
        var i: i64 = 0;
        while (i < 3000) : (i += 1) {
            const k = @as(i64, @intCast(t)) * 3000 + i;
            _ = map.put(k, k) catch unreachable;
        }
    }
};

test "bytestore: concurrent" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const a = testing.allocator;
    var store = try StoreDirect.init(a, true);
    defer store.deinit();
    var map = try Map(StoreDirect).create(a, &store, .{}, .{}, 8);
    defer map.deinit();
    var handles: [4]std.Thread = undefined;
    for (&handles, 0..) |*h, t| h.* = try std.Thread.spawn(.{}, DirectWorker.run, .{ map, t });
    for (&handles) |*h| h.join();
    try testing.expectEqual(@as(u64, 12000), try map.sizeLong());
    for ([_]i64{ 0, 5000, 11999 }) |k| try testing.expectEqual(@as(?i64, k), try map.get(&k));
    try store.verify();
}

// ============================================================ crafted corruption

const LNode = Node(LongFormat, LongFormat);
const LSer = NodeSerializer(LongFormat, LongFormat);

fn writeHeap(store: *StoreOnHeap, a: Allocator, recid: u64, node: LNode) !void {
    try store.update(LNode, a, recid, node, LSer.init(.{}, .{}));
}
fn writeDirect(store: *StoreDirect, a: Allocator, recid: u64, node: LNode) !void {
    try store.update(LNode, a, recid, node, LSer.init(.{}, .{}));
}

test "crafted: zero root pointer open errors" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    const rrr = try store.put(i64, a, 0, LONG);
    try testing.expect(isCorrupt(Map(StoreOnHeap).open(a, &store, rrr, .{}, .{}, 8)));
}

test "crafted: zero root_recid_recid open errors" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    try testing.expect(isCorrupt(Map(StoreOnHeap).open(a, &store, 0, .{}, .{}, 8)));
}

test "crafted: self-cyclic root dir open errors" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    const d = try store.preallocate();
    var keys = [_]i64{5};
    var kids = [_]u64{ d, d };
    try writeHeap(&store, a, d, .{ .flags = DIR | LEFT | RIGHT, .link = 0, .keys = &keys, .body = .{ .dir = &kids } });
    const rrr = try store.put(i64, a, @intCast(d), LONG);
    try testing.expect(isCorrupt(Map(StoreOnHeap).open(a, &store, rrr, .{}, .{}, 8)));
}

fn mapWithLeafCycle(a: Allocator, store: *StoreOnHeap) !Map(StoreOnHeap) {
    const leaf_a = try store.preallocate();
    const leaf_b = try store.preallocate();
    const root = try store.preallocate();
    var ka = [_]i64{1};
    var va = [_]i64{10};
    var fa = [_]i64{100};
    try writeHeap(store, a, leaf_a, .{ .flags = LEFT, .link = leaf_b, .keys = &ka, .body = .{ .leaf = .{ .values = &va, .fence = &fa } } });
    var kb = [_]i64{200};
    var vb = [_]i64{20};
    var fb = [_]i64{200};
    try writeHeap(store, a, leaf_b, .{ .flags = 0, .link = leaf_a, .keys = &kb, .body = .{ .leaf = .{ .values = &vb, .fence = &fb } } }); // cycle
    var kr = [_]i64{100};
    var kids = [_]u64{ leaf_a, leaf_b };
    try writeHeap(store, a, root, .{ .flags = DIR | LEFT | RIGHT, .link = 0, .keys = &kr, .body = .{ .dir = &kids } });
    const rrr = try store.put(i64, a, @intCast(root), LONG);
    return Map(StoreOnHeap).open(a, store, rrr, .{}, .{}, 8);
}

test "crafted: get through leaf cycle errors not hangs" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try mapWithLeafCycle(a, &store);
    defer map.deinit();
    try testing.expect(isCorrupt(map.get(&@as(i64, 300)))); // routed to leafB → move-right cycle
}

test "crafted: iteration through leaf cycle errors not hangs" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try mapWithLeafCycle(a, &store);
    defer map.deinit();
    var it = try map.iter();
    defer it.deinit();
    var saw_err = false;
    var count: u64 = 0;
    while (true) {
        const r = it.next();
        if (r) |maybe| {
            if (maybe) |e| {
                map.deinitEntry(e);
                count += 1;
                try testing.expect(count < 5_000_000);
            } else break;
        } else |_| {
            saw_err = true;
            break;
        }
    }
    try testing.expect(saw_err);
}

test "crafted: byte path rejects empty non-right dir" {
    const a = testing.allocator;
    var store = try StoreDirect.init(a, true);
    defer store.deinit();
    const good_leaf = try store.preallocate();
    const bad_dir = try store.preallocate();
    const root = try store.preallocate();
    var kl = [_]i64{1};
    var vl = [_]i64{10};
    var fl = [_]i64{50};
    try writeDirect(&store, a, good_leaf, .{ .flags = LEFT, .link = bad_dir, .keys = &kl, .body = .{ .leaf = .{ .values = &vl, .fence = &fl } } });
    var kbad = [_]i64{};
    var kids_bad = [_]u64{};
    try writeDirect(&store, a, bad_dir, .{ .flags = DIR, .link = good_leaf, .keys = &kbad, .body = .{ .dir = &kids_bad } });
    var kr = [_]i64{50};
    var kids = [_]u64{ good_leaf, bad_dir };
    try writeDirect(&store, a, root, .{ .flags = DIR | LEFT | RIGHT, .link = 0, .keys = &kr, .body = .{ .dir = &kids } });
    const rrr = try store.put(i64, a, @intCast(root), LONG);
    var map = try Map(StoreDirect).open(a, &store, rrr, .{}, .{}, 8);
    defer map.deinit();
    try testing.expect(isCorrupt(map.get(&@as(i64, 100))));
}

test "crafted: fake root descendant does not replace root" {
    const a = testing.allocator;
    var store = try StoreDirect.init(a, true);
    defer store.deinit();
    const na = try store.preallocate();
    const nc = try store.preallocate();
    const root = try store.preallocate();
    var ka = [_]i64{ 10, 20, 30, 40 };
    var va = [_]i64{ 100, 200, 300, 400 };
    try writeDirect(&store, a, na, .{ .flags = LEFT | RIGHT, .link = 0, .keys = &ka, .body = .{ .leaf = .{ .values = &va, .fence = null } } });
    var kc = [_]i64{100};
    var vc = [_]i64{1000};
    try writeDirect(&store, a, nc, .{ .flags = RIGHT, .link = 0, .keys = &kc, .body = .{ .leaf = .{ .values = &vc, .fence = null } } });
    var kr = [_]i64{50};
    var kids = [_]u64{ na, nc };
    try writeDirect(&store, a, root, .{ .flags = DIR | LEFT | RIGHT, .link = 0, .keys = &kr, .body = .{ .dir = &kids } });
    const rrr = try store.put(i64, a, @intCast(root), LONG);
    var map = try Map(StoreDirect).open(a, &store, rrr, .{}, .{}, 4);
    defer map.deinit();

    _ = try map.put(45, 450); // routed to A → overflow → split; must NOT replace root
    try testing.expectEqual(@as(?i64, 1000), try map.get(&@as(i64, 100))); // sibling C not orphaned
    try testing.expectEqual(@as(?i64, 100), try map.get(&@as(i64, 10)));
    try testing.expectEqual(@as(?i64, 400), try map.get(&@as(i64, 40)));
    try testing.expectEqual(@as(?i64, 450), try map.get(&@as(i64, 45)));
    try testing.expectEqual(rrr, map.rootRecidRecid());
}

test "crafted: get routed to null child errors not absent" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    const child0 = try store.preallocate();
    const null_child = try store.preallocate(); // never written → stays null
    const root = try store.preallocate();
    var k0 = [_]i64{10};
    var v0 = [_]i64{100};
    try writeHeap(&store, a, child0, .{ .flags = LEFT | RIGHT, .link = 0, .keys = &k0, .body = .{ .leaf = .{ .values = &v0, .fence = null } } });
    var kr = [_]i64{50};
    var kids = [_]u64{ child0, null_child };
    try writeHeap(&store, a, root, .{ .flags = DIR | LEFT | RIGHT, .link = 0, .keys = &kr, .body = .{ .dir = &kids } });
    const rrr = try store.put(i64, a, @intCast(root), LONG);
    var map = try Map(StoreOnHeap).open(a, &store, rrr, .{}, .{}, 16);
    defer map.deinit();
    try testing.expectEqual(@as(?i64, 100), try map.get(&@as(i64, 10)));
    try testing.expect(isCorrupt(map.get(&@as(i64, 100))));
}

// ---- root-grow failure poison (wrapper store) ----

const FailUpdateStore = struct {
    const Self = @This();
    inner: StoreOnHeap,
    fail_recid: std.atomic.Value(u64),
    leases: LeaseTable,

    fn init(a: Allocator) !Self {
        return .{ .inner = try StoreOnHeap.init(a, true), .fail_recid = std.atomic.Value(u64).init(0), .leases = LeaseTable.init(a) };
    }
    fn deinit(self: *Self) void {
        self.inner.deinit();
        self.leases.deinit();
    }
    fn arm(self: *Self, r: u64) void {
        self.fail_recid.store(r, .seq_cst);
    }
    pub fn preallocate(self: *Self) DbError!u64 {
        return self.inner.preallocate();
    }
    pub fn put(self: *Self, comptime R: type, a: Allocator, v: R, ser: anytype) DbError!u64 {
        return self.inner.put(R, a, v, ser);
    }
    pub fn get(self: *Self, comptime R: type, a: Allocator, recid: u64, ser: anytype) DbError!?R {
        return self.inner.get(R, a, recid, ser);
    }
    pub fn read(self: *Self, recid: u64, action: RecordRead) DbError!i64 {
        return self.inner.read(recid, action);
    }
    pub fn update(self: *Self, comptime R: type, a: Allocator, recid: u64, v: ?R, ser: anytype) DbError!void {
        const f = self.fail_recid.load(.seq_cst);
        if (f != 0 and f == recid) return error.DataCorruption;
        return self.inner.update(R, a, recid, v, ser);
    }
    pub fn compareAndSwap(self: *Self, comptime R: type, a: Allocator, recid: u64, expect: ?R, new: ?R, ser: anytype) DbError!bool {
        return self.inner.compareAndSwap(R, a, recid, expect, new, ser);
    }
    pub fn delete(self: *Self, recid: u64) DbError!void {
        return self.inner.delete(recid);
    }
    pub fn isThreadSafe(_: *Self) bool {
        return true;
    }
    pub fn isTx(_: *Self) bool {
        return false;
    }
    pub fn leaseTable(self: *Self) *LeaseTable {
        return &self.leases;
    }
};

test "crafted: root-grow failure poisons, not hangs" {
    const a = testing.allocator;
    var store = try FailUpdateStore.init(a);
    defer store.deinit();
    var map = try Map(FailUpdateStore).create(a, &store, .{}, .{}, 4);
    const rrr = map.rootRecidRecid();
    // The root-pointer record is updated ONLY on a root grow → fail that update.
    store.arm(rrr);
    var hit_err = false;
    var i: i64 = 0;
    while (i < 10) : (i += 1) {
        if (map.put(i, i)) |_| {} else |_| {
            hit_err = true;
            break;
        }
    }
    try testing.expect(hit_err);
    // poisoned: later ops fail fast, never park forever in leftEdge.
    try testing.expect(isCorrupt(map.put(1000, 1000)));
    try testing.expect(isCorrupt(map.get(&@as(i64, 0))));
    map.deinit(); // release the lease before reopening

    // reopen after a failed root-grow must report corruption (LEFT-only root).
    store.fail_recid.store(0, .seq_cst); // disarm; damage already persisted
    try testing.expect(isCorrupt(Map(FailUpdateStore).open(a, &store, rrr, .{}, .{}, 4)));
}

// ============================================================ owned-slice keys/values

// Exercises the deep-clone CoW paths + pump/value ownership fixes with a format
// whose elements own memory (`[]const u8`), which the scalar tests never reach.

const ByteArrayFormat = @import("../ser/bytearray.zig").ByteArrayFormat;
const BAMap = BTreeMap(StoreOnHeap, ByteArrayFormat, ByteArrayFormat);

fn keyStr(a: Allocator, i: usize) ![]const u8 {
    return std.fmt.allocPrint(a, "key-{d:0>6}", .{i});
}
fn valStr(a: Allocator, i: usize) ![]const u8 {
    return std.fmt.allocPrint(a, "val-{d:0>6}", .{i});
}

test "owned-slice: put/get/remove/CAS + splits (deep-clone CoW)" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var map = try BAMap.create(a, &store, .{}, .{}, 4);
    defer map.deinit();

    var i: usize = 0;
    while (i < 400) : (i += 1) {
        const k = try keyStr(a, i);
        defer a.free(k);
        const v = try valStr(a, i);
        defer a.free(v);
        const old = try map.put(k, v); // borrows k/v (clones in)
        try testing.expect(old == null);
        if (old) |o| a.free(o);
    }
    // read back (owned results freed by caller)
    i = 0;
    while (i < 400) : (i += 1) {
        const k = try keyStr(a, i);
        defer a.free(k);
        const got = (try map.get(&k)).?;
        defer a.free(got);
        const want = try valStr(a, i);
        defer a.free(want);
        try testing.expectEqualSlices(u8, want, got);
    }
    // CAS: replaceIf with matching then non-matching old value
    {
        const k = try keyStr(a, 42);
        defer a.free(k);
        const old_v = try valStr(a, 42);
        defer a.free(old_v);
        const new_v = try valStr(a, 999999);
        defer a.free(new_v);
        try testing.expect(try map.replaceIf(&k, &old_v, new_v));
        try testing.expect(!try map.replaceIf(&k, &old_v, new_v)); // now mismatches
        const got = (try map.get(&k)).?;
        defer a.free(got);
        try testing.expectEqualSlices(u8, new_v, got);
    }
    // removeIf mismatch then match
    {
        const k = try keyStr(a, 100);
        defer a.free(k);
        const wrong = try valStr(a, 0);
        defer a.free(wrong);
        try testing.expect(!try map.removeIf(&k, &wrong));
        const right = try valStr(a, 100);
        defer a.free(right);
        try testing.expect(try map.removeIf(&k, &right));
        try testing.expect((try map.get(&k)) == null);
    }
    try testing.expectEqual(@as(u64, 399), try map.sizeLong());

    // ascending order + entries ownership
    const es = try map.entries();
    defer map.deinitEntries(es);
    try testing.expectEqual(@as(usize, 399), es.len);
    var prev: ?[]const u8 = null;
    for (es) |e| {
        if (prev) |p| try testing.expect(std.mem.order(u8, p, e.key) == .lt);
        prev = e.key;
    }
    try store.verify();
}

// Iterator that yields freshly-allocated (OWNED) string entries; the pump takes
// ownership of each (validates the value-ownership + separator fixes).
const OwnedPairIter = struct {
    a: Allocator,
    n: usize,
    idx: usize = 0,
    pub fn next(self: *OwnedPairIter) ?struct { key: []const u8, val: []const u8 } {
        if (self.idx >= self.n) return null;
        const k = keyStr(self.a, self.idx) catch unreachable;
        const v = valStr(self.a, self.idx) catch unreachable;
        self.idx += 1;
        return .{ .key = k, .val = v };
    }
};

test "owned-slice: pump bulk build (moves owned entries)" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var iter = OwnedPairIter{ .a = a, .n = 1000 };
    var map = try BAMap.createFromSorted(a, &store, .{}, .{}, 8, &iter);
    defer map.deinit();
    try testing.expectEqual(@as(u64, 1000), try map.sizeLong());
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const k = try keyStr(a, i);
        defer a.free(k);
        const got = (try map.get(&k)).?;
        defer a.free(got);
        const want = try valStr(a, i);
        defer a.free(want);
        try testing.expectEqualSlices(u8, want, got);
    }
    try store.verify();
}

// ============================================================ OOM atomicity

test "oom: put/split is leak-free under a failing allocator sweep" {
    const a = testing.allocator;
    var idx: usize = 0;
    while (idx < 250) : (idx += 1) {
        var store = try StoreOnHeap.init(a, true); // store uses the real allocator
        defer store.deinit();
        var fa = testing.FailingAllocator.init(a, .{ .fail_index = idx });
        // The map's own allocations (node CoW, splits, left_edges, guards) run on
        // the failing allocator; an OOM at any publication point must leave no
        // leak (testing.allocator underneath is leak-checked) and never a hang.
        var map = Map(StoreOnHeap).create(fa.allocator(), &store, .{}, .{}, 4) catch continue;
        defer map.deinit();
        var i: i64 = 0;
        while (i < 40) : (i += 1) {
            _ = map.put(i, i) catch break;
        }
    }
}

// ============================================================ WAL (tx store)

fn walTmpPath(a: Allocator, tmp: *std.testing.TmpDir, name: []const u8) ![]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realpath(".", &buf);
    return std.fs.path.join(a, &.{ dir, name });
}

test "wal: rollback then regrow keeps left_edges consistent" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try walTmpPath(a, &tmp, "bt.wal");
    defer a.free(p);

    var rrr: u64 = undefined;
    {
        var store = try StoreWAL.open(a, p, true);
        defer store.deinit();
        var map = try Map(StoreWAL).create(a, &store, .{}, .{}, 4);
        defer map.deinit();
        try store.commit(); // committed baseline: empty map, height 1

        const n: i64 = 200;
        var k: i64 = 0;
        while (k < n) : (k += 1) _ = try map.put(k, k);
        try testing.expectEqual(@as(u64, @intCast(n)), try map.sizeLong());

        try store.rollback();
        try testing.expectEqual(@as(u64, 0), try map.sizeLong());

        k = 0;
        while (k < n) : (k += 1) _ = try map.put(k, k * 10);
        try testing.expectEqual(@as(u64, @intCast(n)), try map.sizeLong());
        const es = try map.entries();
        defer map.deinitEntries(es);
        for (es, 0..) |e, i| {
            try testing.expectEqual(@as(i64, @intCast(i)), e.key);
            try testing.expectEqual(@as(i64, @intCast(i)) * 10, e.val);
        }
        try store.commit();
        rrr = map.rootRecidRecid();
        try store.close();
    }
    var store2 = try StoreWAL.open(a, p, true);
    defer store2.deinit();
    var m2 = try Map(StoreWAL).open(a, &store2, rrr, .{}, .{}, 4);
    defer m2.deinit();
    try testing.expectEqual(@as(u64, 200), try m2.sizeLong());
    var k: i64 = 0;
    while (k < 200) : (k += 1) try testing.expectEqual(@as(?i64, k * 10), try m2.get(&k));
    try store2.close();
}

test "wal: repeated rollback cycles advance generation" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const p = try walTmpPath(a, &tmp, "bt2.wal");
    defer a.free(p);

    var rrr: u64 = undefined;
    {
        var store = try StoreWAL.open(a, p, true);
        defer store.deinit();
        var map = try Map(StoreWAL).create(a, &store, .{}, .{}, 4);
        defer map.deinit();
        try store.commit();

        var cycle: i64 = 0;
        while (cycle < 4) : (cycle += 1) {
            const n = 80 + cycle * 40;
            var k: i64 = 0;
            while (k < n) : (k += 1) _ = try map.put(k, k);
            try testing.expectEqual(@as(u64, @intCast(n)), try map.sizeLong());
            try store.rollback();
            try testing.expectEqual(@as(u64, 0), try map.sizeLong());
        }
        const n: i64 = 300;
        var k: i64 = 0;
        while (k < n) : (k += 1) _ = try map.put(k, k + 7);
        try store.commit();
        try testing.expectEqual(@as(u64, @intCast(n)), try map.sizeLong());
        rrr = map.rootRecidRecid();
        try store.close();
    }
    var store2 = try StoreWAL.open(a, p, true);
    defer store2.deinit();
    var m2 = try Map(StoreWAL).open(a, &store2, rrr, .{}, .{}, 4);
    defer m2.deinit();
    try testing.expectEqual(@as(u64, 300), try m2.sizeLong());
    var k: i64 = 0;
    while (k < 300) : (k += 1) try testing.expectEqual(@as(?i64, k + 7), try m2.get(&k));
    try store2.close();
}

// ============================================================ counter + listeners + external

const LLMap = BTreeMap(StoreOnHeap, LongFormat, LongFormat);

// ---- listener recorders ----

const LongEvent = struct { key: i64, old: ?i64, new: ?i64 };

const LongRecorder = struct {
    a: Allocator,
    events: std.ArrayListUnmanaged(LongEvent) = .empty,
    fn modify(ctx: *anyopaque, key: i64, old: ?i64, new: ?i64, triggered: bool) DbError!void {
        _ = triggered;
        const self: *LongRecorder = @ptrCast(@alignCast(ctx));
        try self.events.append(self.a, .{ .key = key, .old = old, .new = new });
    }
    fn deinit(self: *LongRecorder) void {
        self.events.deinit(self.a);
    }
    fn listener(self: *LongRecorder) listenermod.MapModificationListener(i64, i64) {
        return listenermod.MapModificationListener(i64, i64).init(self, modify);
    }
};

const AtomicCounter = struct {
    n: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    saw_nonnull_old: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    fn modify(ctx: *anyopaque, key: i64, old: ?i64, new: ?i64, triggered: bool) DbError!void {
        _ = key;
        _ = new;
        _ = triggered;
        const self: *AtomicCounter = @ptrCast(@alignCast(ctx));
        if (old != null) self.saw_nonnull_old.store(true, .seq_cst);
        _ = self.n.fetchAdd(1, .seq_cst);
    }
    fn listener(self: *AtomicCounter) listenermod.MapModificationListener(i64, i64) {
        return listenermod.MapModificationListener(i64, i64).init(self, modify);
    }
};

fn traversalCount(map: anytype) !u64 {
    var it = try map.iter();
    defer it.deinit();
    var c: u64 = 0;
    while (try it.next()) |e| {
        map.deinitEntry(e);
        c += 1;
    }
    return c;
}

// ---- counter: sequential ----

test "counter: disabled by default" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.create(a, &store, .{}, .{}, 8);
    defer m.deinit();
    try testing.expectEqual(@as(u64, 0), m.counterRecid());
    _ = try m.put(1, 1);
    try testing.expectEqual(@as(u64, 1), try m.sizeLong()); // traversal fallback
}

test "counter: enabled exposes recid, starts at 0" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.createCounter(a, &store, .{}, .{}, 8, true);
    defer m.deinit();
    try testing.expect(m.counterRecid() > 0);
    try testing.expectEqual(@as(u64, 0), try m.sizeLong());
}

test "counter: insert/update/remove/clear tracking" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.createCounter(a, &store, .{}, .{}, 6, true);
    defer m.deinit();

    var i: i64 = 0;
    while (i < 100) : (i += 1) {
        try testing.expectEqual(@as(?i64, null), try m.put(i, i));
        try testing.expectEqual(@as(u64, @intCast(i + 1)), try m.sizeLong());
    }
    try testing.expectEqual(@as(u64, 100), try m.sizeLong());
    try testing.expectEqual(try traversalCount(&m), try m.sizeLong());

    // updates do NOT change the counter
    i = 0;
    while (i < 100) : (i += 1) try testing.expectEqual(@as(?i64, i), try m.put(i, i * 10));
    try testing.expectEqual(@as(u64, 100), try m.sizeLong());

    // putIfAbsent present: no change; absent: +1
    try testing.expectEqual(@as(?i64, 0), try m.putIfAbsent(0, 999));
    try testing.expectEqual(@as(u64, 100), try m.sizeLong());
    try testing.expectEqual(@as(?i64, null), try m.putIfAbsent(1000, 1));
    try testing.expectEqual(@as(u64, 101), try m.sizeLong());
    _ = try m.remove(&@as(i64, 1000));
    try testing.expectEqual(@as(u64, 100), try m.sizeLong());

    // replace present: no change; absent: no change
    try testing.expectEqual(@as(?i64, 0), try m.replace(&@as(i64, 0), 7));
    try testing.expectEqual(@as(u64, 100), try m.sizeLong());
    try testing.expectEqual(@as(?i64, null), try m.replace(&@as(i64, 5000), 1));
    try testing.expectEqual(@as(u64, 100), try m.sizeLong());

    // removes
    i = 0;
    while (i < 50) : (i += 1) {
        const want: i64 = if (i == 0) 7 else i * 10;
        try testing.expectEqual(@as(?i64, want), try m.remove(&i));
        try testing.expectEqual(@as(u64, @intCast(100 - (i + 1))), try m.sizeLong());
    }
    try testing.expectEqual(@as(u64, 50), try m.sizeLong());
    try testing.expectEqual(try traversalCount(&m), try m.sizeLong());
    try testing.expectEqual(@as(?i64, null), try m.remove(&@as(i64, 0)));
    try testing.expectEqual(@as(u64, 50), try m.sizeLong());

    try m.clear();
    try testing.expectEqual(@as(u64, 0), try m.sizeLong());
    try testing.expectEqual(@as(u64, 0), try traversalCount(&m));
}

test "counter: matches traversal after mixed random ops (many splits)" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.createCounter(a, &store, .{}, .{}, 4, true);
    defer m.deinit();
    var prng = std.Random.DefaultPrng.init(42);
    const rnd = prng.random();
    var ref = std.AutoHashMap(i64, void).init(a);
    defer ref.deinit();
    var n: usize = 0;
    while (n < 5000) : (n += 1) {
        const k: i64 = rnd.intRangeLessThan(i64, 0, 500);
        if (rnd.boolean()) {
            const prev = try m.put(k, k);
            const was = ref.contains(k);
            try ref.put(k, {});
            try testing.expectEqual(was, prev != null);
        } else {
            const prev = try m.remove(&k);
            const was = ref.remove(k);
            try testing.expectEqual(was, prev != null);
        }
        try testing.expectEqual(@as(u64, ref.count()), try m.sizeLong());
    }
    try testing.expectEqual(try traversalCount(&m), try m.sizeLong());
}

// ---- counter: concurrent ----

const CountWorker = struct {
    fn disjoint(map: LLMap, base: i64, per: i64, insert: bool) void {
        var i: i64 = 0;
        while (i < per) : (i += 1) {
            if (insert) {
                _ = map.put(base + i, base + i) catch unreachable;
            } else {
                _ = map.remove(&(base + i)) catch unreachable;
            }
        }
    }
};

test "counter concurrent: disjoint inserts stay exact" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.createCounter(a, &store, .{}, .{}, 8, true);
    defer m.deinit();
    const threads = 8;
    const per: i64 = 4000;
    var handles: [threads]std.Thread = undefined;
    for (&handles, 0..) |*h, t| h.* = try std.Thread.spawn(.{}, CountWorker.disjoint, .{ m, @as(i64, @intCast(t)) * per, per, true });
    for (&handles) |*h| h.join();
    try testing.expectEqual(@as(u64, threads * per), try m.sizeLong());
    try testing.expectEqual(try traversalCount(&m), try m.sizeLong());
}

const PutRemoveWorker = struct {
    fn run(map: LLMap, seed: u64, keyspace: i64, ops: usize) void {
        var prng = std.Random.DefaultPrng.init(seed);
        const rnd = prng.random();
        var i: usize = 0;
        while (i < ops) : (i += 1) {
            const k = rnd.intRangeLessThan(i64, 0, keyspace);
            if (rnd.boolean()) {
                _ = map.put(k, k) catch unreachable;
            } else {
                _ = map.remove(&k) catch unreachable;
            }
        }
    }
};

test "counter concurrent: put/remove same keyspace equals traversal" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.createCounter(a, &store, .{}, .{}, 6, true);
    defer m.deinit();
    const keyspace: i64 = 2000;
    var k: i64 = 0;
    while (k < keyspace) : (k += 2) _ = try m.put(k, k);
    const threads = 8;
    var handles: [threads]std.Thread = undefined;
    for (&handles, 0..) |*h, t| h.* = try std.Thread.spawn(.{}, PutRemoveWorker.run, .{ m, @as(u64, t), keyspace, 12000 });
    for (&handles) |*h| h.join();
    try testing.expectEqual(try traversalCount(&m), try m.sizeLong());
}

test "counter concurrent: insert then remove to empty" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.createCounter(a, &store, .{}, .{}, 6, true);
    defer m.deinit();
    const threads = 6;
    const per: i64 = 4000;
    var h1: [threads]std.Thread = undefined;
    for (&h1, 0..) |*h, t| h.* = try std.Thread.spawn(.{}, CountWorker.disjoint, .{ m, @as(i64, @intCast(t)) * per, per, true });
    for (&h1) |*h| h.join();
    try testing.expectEqual(@as(u64, threads * per), try m.sizeLong());
    try testing.expectEqual(try traversalCount(&m), try m.sizeLong());
    var h2: [threads]std.Thread = undefined;
    for (&h2, 0..) |*h, t| h.* = try std.Thread.spawn(.{}, CountWorker.disjoint, .{ m, @as(i64, @intCast(t)) * per, per, false });
    for (&h2) |*h| h.join();
    try testing.expectEqual(@as(u64, 0), try m.sizeLong());
    try testing.expectEqual(@as(u64, 0), try traversalCount(&m));
}

// ---- listeners ----

test "listener: insert/update/remove events" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.create(a, &store, .{}, .{}, 8);
    defer m.deinit();
    var rec = LongRecorder{ .a = a };
    defer rec.deinit();
    try m.modificationListenerAdd(rec.listener());

    _ = try m.put(5, 50);
    _ = try m.put(5, 60);
    try testing.expectEqual(@as(?i64, 60), try m.remove(&@as(i64, 5)));

    try testing.expectEqual(@as(usize, 3), rec.events.items.len);
    try testing.expectEqual(LongEvent{ .key = 5, .old = null, .new = 50 }, rec.events.items[0]);
    try testing.expectEqual(LongEvent{ .key = 5, .old = 50, .new = 60 }, rec.events.items[1]);
    try testing.expectEqual(LongEvent{ .key = 5, .old = 60, .new = null }, rec.events.items[2]);
}

test "listener: replace + conditional ops fire correctly" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.create(a, &store, .{}, .{}, 8);
    defer m.deinit();
    var rec = LongRecorder{ .a = a };
    defer rec.deinit();
    try m.modificationListenerAdd(rec.listener());

    _ = try m.put(1, 10); // insert
    _ = try m.replace(&@as(i64, 1), 20); // update
    _ = try m.replaceIf(&@as(i64, 1), &@as(i64, 20), 30); // update
    _ = try m.replaceIf(&@as(i64, 1), &@as(i64, 999), 40); // mismatch: nothing
    _ = try m.replace(&@as(i64, 2), 5); // absent: nothing
    _ = try m.putIfAbsent(1, 77); // present: nothing
    _ = try m.removeIf(&@as(i64, 1), &@as(i64, 999)); // mismatch: nothing
    _ = try m.putIfAbsent(2, 22); // insert
    try testing.expect(try m.removeIf(&@as(i64, 2), &@as(i64, 22))); // remove

    try testing.expectEqual(@as(usize, 5), rec.events.items.len);
    try testing.expectEqual(LongEvent{ .key = 1, .old = null, .new = 10 }, rec.events.items[0]);
    try testing.expectEqual(LongEvent{ .key = 1, .old = 10, .new = 20 }, rec.events.items[1]);
    try testing.expectEqual(LongEvent{ .key = 1, .old = 20, .new = 30 }, rec.events.items[2]);
    try testing.expectEqual(LongEvent{ .key = 2, .old = null, .new = 22 }, rec.events.items[3]);
    try testing.expectEqual(LongEvent{ .key = 2, .old = 22, .new = null }, rec.events.items[4]);
}

test "listener: clear fires a removal for every entry" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.createCounter(a, &store, .{}, .{}, 4, true);
    defer m.deinit();
    var i: i64 = 0;
    while (i < 25) : (i += 1) _ = try m.put(i, i * 10);
    var rec = LongRecorder{ .a = a };
    defer rec.deinit();
    try m.modificationListenerAdd(rec.listener());
    try m.clear();
    try testing.expectEqual(@as(usize, 25), rec.events.items.len);
    // clear snapshots keys ascending, so removals fire in ascending order
    for (rec.events.items, 0..) |e, idx| {
        try testing.expectEqual(@as(i64, @intCast(idx)), e.key);
        try testing.expectEqual(@as(?i64, @as(i64, @intCast(idx)) * 10), e.old);
        try testing.expectEqual(@as(?i64, null), e.new);
    }
    try testing.expectEqual(@as(u64, 0), try m.sizeLong());
}

test "listener: multiple listeners all fire, remove works" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.create(a, &store, .{}, .{}, 8);
    defer m.deinit();
    var r1 = AtomicCounter{};
    var r2 = AtomicCounter{};
    try m.modificationListenerAdd(r1.listener());
    try m.modificationListenerAdd(r2.listener());
    _ = try m.put(1, 1);
    _ = try m.put(1, 2);
    _ = try m.remove(&@as(i64, 1));
    try testing.expectEqual(@as(u64, 3), r1.n.load(.seq_cst));
    try testing.expectEqual(@as(u64, 3), r2.n.load(.seq_cst));
    // duplicate add is ignored; remove drops it
    try m.modificationListenerAdd(r1.listener());
    try testing.expect(m.modificationListenerRemove(r1.listener()));
    _ = try m.put(2, 2);
    try testing.expectEqual(@as(u64, 3), r1.n.load(.seq_cst)); // unchanged
    try testing.expectEqual(@as(u64, 4), r2.n.load(.seq_cst));
}

const ListenWorker = struct {
    fn run(map: LLMap, base: i64, per: i64) void {
        var i: i64 = 0;
        while (i < per) : (i += 1) _ = map.put(base + i, base + i) catch unreachable;
    }
};

test "listener concurrent: event count matches disjoint inserts" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.createCounter(a, &store, .{}, .{}, 6, true);
    defer m.deinit();
    var rec = AtomicCounter{};
    try m.modificationListenerAdd(rec.listener());
    const threads = 6;
    const per: i64 = 3000;
    var handles: [threads]std.Thread = undefined;
    for (&handles, 0..) |*h, t| h.* = try std.Thread.spawn(.{}, ListenWorker.run, .{ m, @as(i64, @intCast(t)) * per, per });
    for (&handles) |*h| h.join();
    try testing.expectEqual(@as(u64, threads * per), rec.n.load(.seq_cst));
    try testing.expect(!rec.saw_nonnull_old.load(.seq_cst)); // all inserts
    try testing.expectEqual(@as(u64, threads * per), try m.sizeLong());
}

// ---- bulk build + reopen counter ----

const PairIter2 = struct {
    items: []const [2]i64,
    idx: usize = 0,
    pub fn next(self: *PairIter2) ?struct { key: i64, val: i64 } {
        if (self.idx >= self.items.len) return null;
        const it = self.items[self.idx];
        self.idx += 1;
        return .{ .key = it[0], .val = it[1] };
    }
};

test "bulk build: counter enabled + keeps tracking" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    const n = 3000;
    var items: [n][2]i64 = undefined;
    for (&items, 0..) |*it, k| it.* = .{ @intCast(k), @as(i64, @intCast(k)) * 2 };
    var iter = PairIter2{ .items = &items };
    var m = try LLMap.createFromSortedCounter(a, &store, .{}, .{}, 16, &iter, true);
    defer m.deinit();
    try testing.expect(m.counterRecid() > 0);
    try testing.expectEqual(@as(u64, n), try m.sizeLong());
    try testing.expectEqual(try traversalCount(&m), try m.sizeLong());
    try testing.expectEqual(@as(?i64, null), try m.put(n, 1));
    try testing.expectEqual(@as(u64, n + 1), try m.sizeLong());
    _ = try m.remove(&@as(i64, 0));
    try testing.expectEqual(@as(u64, n), try m.sizeLong());
}

test "bulk build: no counter falls back to traversal" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var items: [100][2]i64 = undefined;
    for (&items, 0..) |*it, k| it.* = .{ @intCast(k), @intCast(k) };
    var iter = PairIter2{ .items = &items };
    var m = try LLMap.createFromSorted(a, &store, .{}, .{}, 16, &iter);
    defer m.deinit();
    try testing.expectEqual(@as(u64, 0), m.counterRecid());
    try testing.expectEqual(@as(u64, 100), try m.sizeLong());
}

test "bulk build: empty counter starts at zero, tracks later writes" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var items: [0][2]i64 = undefined;
    var iter = PairIter2{ .items = &items };
    var m = try LLMap.createFromSortedCounter(a, &store, .{}, .{}, 16, &iter, true);
    defer m.deinit();
    try testing.expect(m.counterRecid() > 0);
    try testing.expectEqual(@as(u64, 0), try m.sizeLong());
    _ = try m.put(1, 10);
    try testing.expectEqual(@as(u64, 1), try m.sizeLong());
}

test "reopen with counter recid persists the count" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var rrr: u64 = undefined;
    var cr: u64 = undefined;
    {
        var m = try LLMap.createCounter(a, &store, .{}, .{}, 8, true);
        defer m.deinit(); // release the RW lease before reopening (Zig no-double-open)
        var i: i64 = 0;
        while (i < 200) : (i += 1) _ = try m.put(i, i);
        rrr = m.rootRecidRecid();
        cr = m.counterRecid();
        try testing.expectEqual(@as(u64, 200), try m.sizeLong());
    }
    var re = try LLMap.openCounter(a, &store, rrr, .{}, .{}, 8, cr);
    defer re.deinit();
    try testing.expectEqual(@as(u64, 200), try re.sizeLong());
    _ = try re.put(200, 200);
    try testing.expectEqual(@as(u64, 201), try re.sizeLong());
}

// ---- external values ----

fn ExtMap(comptime S: type) type {
    return BTreeMapExternal(S, LongFormat, StringGroupFormat);
}

fn expectStrEq(expected: []const u8, actual: ?[]const u8) !void {
    try testing.expect(actual != null);
    try testing.expectEqualStrings(expected, actual.?);
}

test "external values: ops/views/reopen across stores" {
    const a = testing.allocator;
    // StoreOnHeap
    {
        var store = try StoreOnHeap.init(a, true);
        defer store.deinit();
        try externalOps(a, StoreOnHeap, &store);
    }
    // StoreByteArray
    {
        var store = try StoreByteArray.init(a, true);
        defer store.deinit();
        try externalOps(a, StoreByteArray, &store);
    }
    // StoreDirect
    {
        var store = try StoreDirect.init(a, true);
        defer store.deinit();
        try externalOps(a, StoreDirect, &store);
    }
}

fn externalOps(a: Allocator, comptime S: type, store: *S) !void {
    const M = ExtMap(S);
    var map = try M.createCounter(a, store, .{}, .{}, 4, true);
    var done = false;
    defer if (!done) map.deinit();
    try testing.expect(!map.valueInline());

    var buf: [16]u8 = undefined;
    var i: i64 = 0;
    while (i < 40) : (i += 1) {
        const v = try std.fmt.bufPrint(&buf, "v{d}", .{i});
        try testing.expectEqual(@as(?[]const u8, null), try map.put(i, v));
    }
    {
        const old = try map.put(5, "updated");
        try expectStrEq("v5", old);
        a.free(old.?);
    }
    {
        const g = try map.get(&@as(i64, 5));
        try expectStrEq("updated", g);
        a.free(g.?);
    }
    {
        const old = try map.replace(&@as(i64, 6), "six");
        try expectStrEq("v6", old);
        a.free(old.?);
    }
    try testing.expect(try map.replaceIf(&@as(i64, 7), &@as([]const u8, "v7"), "seven"));
    try testing.expect(!try map.replaceIf(&@as(i64, 7), &@as([]const u8, "v7"), "wrong"));
    try testing.expect(try map.removeIf(&@as(i64, 8), &@as([]const u8, "v8")));
    {
        // subMap [9,12) remove 9
        const sub = map.subMap(9, true, 12, false);
        const r = try sub.remove(9);
        try expectStrEq("v9", r);
        a.free(r.?);
    }
    {
        const first = try map.popFirst();
        try testing.expect(first != null);
        try testing.expectEqual(@as(i64, 0), first.?.key);
        try expectStrEq("v0", first.?.val);
        map.deinitEntry(first.?);
    }
    try testing.expectEqual(@as(u64, 37), try map.sizeLong());

    const rrr = map.rootRecidRecid();
    const cr = map.counterRecid();
    map.deinit();
    done = true;

    var re = try M.openCounter(a, store, rrr, .{}, .{}, 4, cr);
    defer re.deinit();
    {
        const g5 = try re.get(&@as(i64, 5));
        try expectStrEq("updated", g5);
        a.free(g5.?);
        const g7 = try re.get(&@as(i64, 7));
        try expectStrEq("seven", g7);
        a.free(g7.?);
    }
    try testing.expectEqual(@as(u64, 37), try re.sizeLong());
    // iterate all
    {
        const es = try re.entries();
        defer re.deinitEntries(es);
        try testing.expectEqual(@as(usize, 37), es.len);
    }
    try re.clear();
    try testing.expect(try re.isEmpty());
    try testing.expectEqual(@as(u64, 0), try re.sizeLong());
    try store.verify();
}

fn recidCount(a: Allocator, store: anytype) !usize {
    const recids = try store.getAllRecids(a);
    defer a.free(recids);
    return recids.len;
}

const ExtReader = struct {
    map: ExtMap(StoreDirect),
    stop: *std.atomic.Value(bool),
    failed: *std.atomic.Value(bool),
    fn run(self: ExtReader) void {
        var iters: usize = 0;
        while (!self.stop.load(.acquire) and iters < 200_000) : (iters += 1) {
            const v = self.map.get(&@as(i64, 1)) catch {
                self.failed.store(true, .release);
                return;
            };
            if (v) |val| {
                if (!std.mem.eql(u8, val, "one")) self.failed.store(true, .release);
                self.map.a().free(val);
            }
        }
    }
};

test "external values: reader never observes a reused value recid under churn" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const a = testing.allocator;
    var store = try StoreDirect.init(a, true);
    defer store.deinit();
    const M = ExtMap(StoreDirect);
    var map = try M.createCounter(a, &store, .{}, .{}, 8, false);
    defer map.deinit();
    _ = try map.put(1, "one");
    const baseline = try recidCount(a, &store);

    var stop = std.atomic.Value(bool).init(false);
    var failed = std.atomic.Value(bool).init(false);
    const reader = try std.Thread.spawn(.{}, ExtReader.run, .{ExtReader{ .map = map, .stop = &stop, .failed = &failed }});

    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        _ = try map.removeOnly(&@as(i64, 1));
        try map.putOnly(2, "unrelated");
        _ = try map.removeOnly(&@as(i64, 2));
        try map.putOnly(1, "one");
    }
    stop.store(true, .release);
    reader.join();
    try testing.expect(!failed.load(.acquire));
    try testing.expect(try recidCount(a, &store) <= baseline + 2);
}

const ChurnWorker = struct {
    map: ExtMap(StoreDirect),
    tid: usize,
    keys: i64,
    iters: usize,
    fn run(self: ChurnWorker) void {
        var prng = std.Random.DefaultPrng.init(self.tid);
        const rnd = prng.random();
        var buf: [24]u8 = undefined;
        var i: usize = 0;
        while (i < self.iters) : (i += 1) {
            const key = rnd.intRangeLessThan(i64, 0, self.keys);
            switch (i & 3) {
                0 => {
                    const v = std.fmt.bufPrint(&buf, "t{d}v{d}", .{ self.tid, i }) catch unreachable;
                    self.map.putOnly(key, v) catch unreachable;
                },
                1 => {
                    if (self.map.get(&key) catch unreachable) |val| self.map.a().free(val);
                },
                2 => _ = self.map.removeOnly(&key) catch unreachable,
                else => {
                    var it = self.map.iter() catch unreachable;
                    defer it.deinit();
                    var seen: usize = 0;
                    while (seen < 32) : (seen += 1) {
                        const e = it.next() catch unreachable;
                        if (e) |ent| self.map.deinitEntry(ent) else break;
                    }
                },
            }
        }
    }
};

test "external values: hi-bounded scan frees the loaded node" {
    // Regression for the advanceExternal hi-bound exit that returned `null`
    // without freeing the leaf node it had loaded (keys + packed-recid group +
    // fence). This whole test runs under testing.allocator, so any leak on a
    // bounded-scan exit fails it. Before the `defer if (node_live) node.deinit`
    // fix this leaked ~3 allocations per bounded navigation call.
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    const M = ExtMap(StoreOnHeap);
    var map = try M.createCounter(a, &store, .{}, .{}, 4, true);
    defer map.deinit();
    var buf: [16]u8 = undefined;
    var i: i64 = 0;
    while (i < 20) : (i += 1) {
        const v = try std.fmt.bufPrint(&buf, "v{d}", .{i});
        try testing.expectEqual(@as(?[]const u8, null), try map.put(i, v));
    }
    // A range count that terminates AT the hi bound.
    try testing.expectEqual(@as(u64, 4), try map.sizeLongRange(@as(?i64, 5), true, @as(?i64, 8), true));
    // floorEntry expands a value and scans to a hi bound (largest key <= k) on
    // every call — the exact bounded value-returning path that leaked. Call it
    // repeatedly across several interior bounds.
    for ([_]i64{ 3, 8, 12, 19 }) |k| {
        if (try map.floorEntry(&k)) |fe| {
            try testing.expectEqual(k, fe.key);
            map.deinitEntry(fe);
        }
    }
}

test "external values: concurrent churn leaks no value recids" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const a = testing.allocator;
    var store = try StoreDirect.init(a, true);
    defer store.deinit();
    const M = ExtMap(StoreDirect);
    var map = try M.createCounter(a, &store, .{}, .{}, 8, false);
    defer map.deinit();
    const baseline = try recidCount(a, &store);
    const key_count: i64 = 256;
    const threads = 6;
    var handles: [threads]std.Thread = undefined;
    for (&handles, 0..) |*h, t| h.* = try std.Thread.spawn(.{}, ChurnWorker.run, .{ChurnWorker{ .map = map, .tid = t, .keys = key_count, .iters = 6000 }});
    for (&handles) |*h| h.join();
    var key: i64 = 0;
    while (key < key_count) : (key += 1) {
        if (try map.remove(&key)) |v| a.free(v);
    }
    try store.verify();
    // structural leaf/dir nodes stay (no merge on remove) but every VALUE recid
    // must be freed — a value leak would scale with the thousands of churn ops.
    const bound: usize = baseline + @as(usize, @intCast(key_count));
    try testing.expect(try recidCount(a, &store) <= bound);
}

// ---- sync listeners (throw-safety) ----

/// A synchronous listener that throws once when armed, then disarms — drives the
/// throw-safe fire points without leaking the covering node lock or desyncing the
/// counter (Java BTreeMapSyncListenerTest.ArmedThrow).
const ArmedThrow = struct {
    armed: bool = false,
    fn modify(ctx: *anyopaque, key: i64, old: ?[]const u8, new: ?[]const u8, triggered: bool) DbError!void {
        _ = key;
        _ = old;
        _ = new;
        _ = triggered;
        const self: *ArmedThrow = @ptrCast(@alignCast(ctx));
        if (self.armed) {
            self.armed = false;
            return error.DataCorruption; // stand-in for IllegalStateException("boom")
        }
    }
    fn listener(self: *ArmedThrow) listenermod.MapModificationListener(i64, []const u8) {
        return listenermod.MapModificationListener(i64, []const u8).initSynchronous(self, modify);
    }
};

fn assertConsistent(map: anytype, expected: u64) !void {
    try testing.expectEqual(expected, try map.sizeLong());
    var it = try map.iter();
    defer it.deinit();
    var n: u64 = 0;
    while (try it.next()) |e| {
        map.deinitEntry(e);
        n += 1;
    }
    try testing.expectEqual(expected, n);
}

fn getStr(map: anytype, a: Allocator, k: i64) !?[]const u8 {
    const v = try map.get(&k);
    _ = a;
    return v;
}

fn syncListenerDrill(a: Allocator, comptime external: bool) !void {
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    const M = if (external) BTreeMapExternal(StoreOnHeap, LongFormat, StringGroupFormat) else BTreeMap(StoreOnHeap, LongFormat, StringGroupFormat);
    var map = try M.createCounter(a, &store, .{}, .{}, 4, true);
    defer map.deinit();

    var lst = ArmedThrow{};
    try map.modificationListenerAdd(lst.listener());

    try map.putOnly(0, "v0");
    try map.putOnly(1, "v1");

    // non-split insert throws, tree stays usable, SAME leaf op completes
    lst.armed = true;
    try testing.expectError(error.DataCorruption, map.put(2, "v2"));
    {
        const g = try map.get(&@as(i64, 2));
        try expectStrEq("v2", g);
        a.free(g.?);
    }
    try assertConsistent(&map, 3);
    try map.putOnly(2, "v2b"); // same leaf: node lock must not be leaked
    {
        const g = try map.get(&@as(i64, 2));
        try expectStrEq("v2b", g);
        a.free(g.?);
    }

    // put over an existing key (update branch)
    lst.armed = true;
    try testing.expectError(error.DataCorruption, map.put(0, "v0b"));
    {
        const g = try map.get(&@as(i64, 0));
        try expectStrEq("v0b", g);
        a.free(g.?);
    }
    try assertConsistent(&map, 3);
    try map.putOnly(0, "v0c");

    // SPLITTING insert: 5th key overflows maxNodeSize=4 and splits the root leaf.
    // The listener throws, but separator/root propagation must still complete so a
    // LATER split of the right half does not spin forever in leftEdge.
    try map.putOnly(3, "v3");
    lst.armed = true;
    try testing.expectError(error.DataCorruption, map.put(4, "v4"));
    {
        const g = try map.get(&@as(i64, 4));
        try expectStrEq("v4", g);
        a.free(g.?);
    }
    try assertConsistent(&map, 5);
    try map.putOnly(5, "v5"); // fills the right half
    try map.putOnly(6, "v6"); // overflows it: forces its own split + propagation
    try map.putOnly(7, "v7");
    try assertConsistent(&map, 8);
    _ = try map.removeOnly(&@as(i64, 6));
    _ = try map.removeOnly(&@as(i64, 7));
    try assertConsistent(&map, 6);

    // remove throws
    lst.armed = true;
    try testing.expectError(error.DataCorruption, map.remove(&@as(i64, 5)));
    try testing.expectEqual(@as(?[]const u8, null), try map.get(&@as(i64, 5)));
    try assertConsistent(&map, 5);
    try map.putOnly(5, "back");
    try assertConsistent(&map, 6);

    // replace throws
    lst.armed = true;
    try testing.expectError(error.DataCorruption, map.replace(&@as(i64, 1), "v1b"));
    {
        const g = try map.get(&@as(i64, 1));
        try expectStrEq("v1b", g);
        a.free(g.?);
    }
    try assertConsistent(&map, 6);
    _ = try map.removeOnly(&@as(i64, 1));
    try assertConsistent(&map, 5);

    try store.verify();
}

test "sync listener: throwing listener leaves inline map usable" {
    try syncListenerDrill(testing.allocator, false);
}

test "sync listener: throwing listener leaves external-value map usable" {
    try syncListenerDrill(testing.allocator, true);
}

const OrderRecorder = struct {
    a: Allocator,
    out: std.ArrayListUnmanaged([]u8) = .empty,
    sync: bool,
    fn modify(ctx: *anyopaque, key: i64, old: ?[]const u8, new: ?[]const u8, triggered: bool) DbError!void {
        _ = triggered;
        const self: *OrderRecorder = @ptrCast(@alignCast(ctx));
        const s = std.fmt.allocPrint(self.a, "{d}:{s}:{s}", .{
            key,
            old orelse "null",
            new orelse "null",
        }) catch return error.OutOfMemory;
        self.out.append(self.a, s) catch return error.OutOfMemory;
    }
    fn deinit(self: *OrderRecorder) void {
        for (self.out.items) |s| self.a.free(s);
        self.out.deinit(self.a);
    }
    fn listener(self: *OrderRecorder) listenermod.MapModificationListener(i64, []const u8) {
        return if (self.sync)
            listenermod.MapModificationListener(i64, []const u8).initSynchronous(self, modify)
        else
            listenermod.MapModificationListener(i64, []const u8).init(self, modify);
    }
};

const AlwaysThrowSync = struct {
    fn modify(_: *anyopaque, _: i64, _: ?[]const u8, _: ?[]const u8, _: bool) DbError!void {
        return error.DataCorruption;
    }
    fn listener(self: *AlwaysThrowSync) listenermod.MapModificationListener(i64, []const u8) {
        return listenermod.MapModificationListener(i64, []const u8).initSynchronous(self, modify);
    }
    fn listenerDeferred(self: *AlwaysThrowSync) listenermod.MapModificationListener(i64, []const u8) {
        return listenermod.MapModificationListener(i64, []const u8).init(self, modify);
    }
};

test "sync listener: a throwing listener still delivers to a later listener" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    const M = BTreeMap(StoreOnHeap, LongFormat, StringGroupFormat);
    var map = try M.create(a, &store, .{}, .{}, 4);
    defer map.deinit();
    var thrower = AlwaysThrowSync{};
    var later = OrderRecorder{ .a = a, .sync = true };
    defer later.deinit();
    try map.modificationListenerAdd(thrower.listener());
    try map.modificationListenerAdd(later.listener());
    try testing.expectError(error.DataCorruption, map.put(1, "v1"));
    try testing.expectEqual(@as(usize, 1), later.out.items.len);
    try testing.expectEqualStrings("1:null:v1", later.out.items[0]);
    const g = try map.get(&@as(i64, 1));
    try expectStrEq("v1", g);
    a.free(g.?);
}

test "deferred listener: a throwing listener still delivers to a later listener" {
    const a = testing.allocator;
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    const M = BTreeMap(StoreOnHeap, LongFormat, StringGroupFormat);
    var map = try M.create(a, &store, .{}, .{}, 4);
    defer map.deinit();
    var thrower = AlwaysThrowSync{};
    var later = OrderRecorder{ .a = a, .sync = false };
    defer later.deinit();
    try map.modificationListenerAdd(thrower.listenerDeferred());
    try map.modificationListenerAdd(later.listener());
    try testing.expectError(error.DataCorruption, map.put(1, "v1"));
    try testing.expectEqual(@as(usize, 1), later.out.items.len);
    try testing.expectEqualStrings("1:null:v1", later.out.items[0]);
    const g = try map.get(&@as(i64, 1));
    try expectStrEq("v1", g);
    a.free(g.?);
}

// ---- golden bytes (Java byte-compat) ----

fn serBytes(a: Allocator, ser: anytype, comptime R: type, v: R) ![]u8 {
    var out = DataOutput2.init(a);
    defer out.deinit();
    try ser.serialize(&out, v);
    return out.copyBytes(a);
}

test "golden: counter record is an 8-byte big-endian long" {
    const a = testing.allocator;
    // The counter record content is exactly LongSer.serialize(count) (Java Serializers.LONG).
    const bytes = try serBytes(a, LONG, i64, 42);
    defer a.free(bytes);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 42 }, bytes);

    // And the live counter record round-trips through the store.
    var store = try StoreOnHeap.init(a, true);
    defer store.deinit();
    var m = try LLMap.createCounter(a, &store, .{}, .{}, 4, true);
    defer m.deinit();
    var i: i64 = 0;
    while (i < 42) : (i += 1) _ = try m.put(i, i);
    const raw = (try store.get(i64, a, m.counterRecid(), LONG)).?;
    const raw_bytes = try serBytes(a, LONG, i64, raw);
    defer a.free(raw_bytes);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 42 }, raw_bytes);
}

test "golden: external value record is the String element encoding" {
    const a = testing.allocator;
    // Java `store.put(value, valueFormat.element())`: packInt(len) then UTF-8 bytes.
    // "hello" -> packInt(5)=0x85, then 'h','e','l','l','o'.
    const bytes = try serBytes(a, StringSer.instance, []const u8, "hello");
    defer a.free(bytes);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x85, 'h', 'e', 'l', 'l', 'o' }, bytes);

    // The external map writes exactly this record and reads it back.
    var store = try StoreByteArray.init(a, true);
    defer store.deinit();
    const M = BTreeMapExternal(StoreByteArray, LongFormat, StringGroupFormat);
    var m = try M.createCounter(a, &store, .{}, .{}, 4, false);
    defer m.deinit();
    _ = try m.put(1, "hello");
    const g = try m.get(&@as(i64, 1));
    try expectStrEq("hello", g);
    a.free(g.?);
}
