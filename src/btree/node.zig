//! B-link tree node model + wire format, ported from
//! `mapdb-rust-store/src/btree/node.rs` (Java `BTreeMap.Node`/`NodeSerializer`),
//! byte-for-byte.
//!
//! Wire format (mapdb3 lineage): `packInt(keysLen<<4 | flags)`,
//! `[packLong(link)]` unless RIGHT, key group, then child recids (dir, packed
//! longs) or value group + optional 1-element fence group **last** (leaf). The
//! fence sits last so the read path never decodes it.
//!
//! `NodeSerializer(KF, VF)` is a `Serializer` for `Node(KF, VF)`. It carries the
//! key/value formats by value; when both formats are zero-sized (all scalar
//! formats) the serializer is itself zero-sized, so `StoreOnHeap` accepts it and
//! reconstructs it from its `instance` decl (the map is the only node writer, so
//! `compare`/`equals` are never reached). A stateful value format (columnar) makes
//! the serializer stateful → it may then only be used over a byte store (which
//! does not require a stateless serializer); the map's columnar tests use a byte
//! store, matching the Rust byte-path coverage.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;

pub const DIR: i32 = 8;
pub const LEFT: i32 = 4;
pub const RIGHT: i32 = 2;

/// Immutable / copy-on-write node. Holds only the packed groups (never the
/// formats). `link == 0` ⇔ RIGHT flag (rightmost, no right sibling).
pub fn Node(comptime KF: type, comptime VF: type) type {
    return struct {
        const Self = @This();

        flags: i32,
        link: u64,
        keys: KF.Group,
        body: Body,

        pub const Leaf = struct {
            values: VF.Group,
            /// Non-rightmost leaf only: a 1-element key group holding the leaf's
            /// inclusive high bound. `null` on rightmost leaves.
            fence: ?KF.Group,
        };
        pub const Body = union(enum) {
            dir: []u64,
            leaf: Leaf,
        };

        pub inline fn isDir(self: *const Self) bool {
            return self.flags & DIR != 0;
        }
        pub inline fn isRight(self: *const Self) bool {
            return self.flags & RIGHT != 0;
        }

        /// Dir children (asserts on a leaf — internal invariant).
        pub inline fn children(self: *const Self) []const u64 {
            return switch (self.body) {
                .dir => |c| c,
                .leaf => unreachable,
            };
        }

        /// Free the node's owned groups/children. `kf`/`vf` are the formats the
        /// node was materialized with.
        pub fn deinit(self: *Self, alloc: Allocator, kf: KF, vf: VF) void {
            kf.deinitGroup(alloc, self.keys);
            switch (self.body) {
                .dir => |c| alloc.free(c),
                .leaf => |l| {
                    vf.deinitGroup(alloc, l.values);
                    if (l.fence) |f| kf.deinitGroup(alloc, f);
                },
            }
        }
    };
}

/// `Serializer<Node>` bound to a pair of formats. `max_node_size` is not stored
/// (Zig byte stores size the output buffer dynamically; no `size_hint` needed).
pub fn NodeSerializer(comptime KF: type, comptime VF: type) type {
    return struct {
        const Self = @This();
        pub const Elem = Node(KF, VF);
        const NodeT = Node(KF, VF);

        kf: KF,
        vf: VF,

        /// Lazily evaluated: only referenced by `StoreOnHeap` (stateless
        /// serializers). For zero-sized formats it yields the correct zero-sized
        /// serializer; for a stateful format it is never evaluated (byte store).
        pub const instance: Self = .{ .kf = fmtInstance(KF), .vf = fmtInstance(VF) };

        pub fn init(kf: KF, vf: VF) Self {
            return .{ .kf = kf, .vf = vf };
        }

        // -------- Serializer surface --------

        pub fn serialize(self: Self, out: *DataOutput2, n: NodeT) DbError!void {
            const keys_len = self.kf.size(&n.keys);
            try out.packInt((@as(i32, @intCast(keys_len)) << 4) | n.flags);
            if (n.flags & RIGHT == 0) try out.packLong(n.link);
            try self.kf.serializeGroup(out, &n.keys);
            switch (n.body) {
                .dir => |cs| for (cs) |c| try out.packLong(c),
                .leaf => |l| {
                    try self.vf.serializeGroup(out, &l.values);
                    if (n.flags & RIGHT == 0) {
                        const f = l.fence.?; // non-rightmost leaf always has a fence
                        try self.kf.serializeGroup(out, &f);
                    }
                },
            }
        }

        pub fn deserialize(self: Self, alloc: Allocator, input: *DataInput2, size: ?usize) DbError!NodeT {
            // Record start: a valid node uses every content byte with no slack
            // (D5). A crafted header under-reporting keysLen shifts the key/value
            // boundary while leaving the record locally decodable — the leftover
            // trailing bytes are the tell.
            const start = input.pos;
            const h = try input.unpackInt();
            const flags = h & 0xF;
            const keys_len: usize = @as(u32, @bitCast(h)) >> 4;
            // Every key occupies >= 1 serialized byte, so keysLen > size is corrupt.
            if (size) |sz| {
                if (keys_len > sz) return error.DataCorruption;
            }
            // Non-rightmost node MUST carry a nonzero right link (no false 0 sentinel).
            const link: u64 = if (flags & RIGHT != 0) 0 else blk: {
                const l = try input.unpackLong();
                if (l == 0) return error.DataCorruption;
                break :blk l;
            };
            const keys = try self.kf.deserializeGroup(alloc, input, keys_len);
            errdefer self.kf.deinitGroup(alloc, keys);
            // Search/routing/fence math assume strictly-increasing keys.
            try self.checkSorted(alloc, &keys);

            if (flags & DIR != 0) {
                const child_count = keys_len + @as(usize, if (flags & RIGHT != 0) 1 else 0);
                if (child_count == 0) return error.DataCorruption;
                const cs = try alloc.alloc(u64, child_count);
                errdefer alloc.free(cs);
                for (cs) |*slot| {
                    const c = try input.unpackLong();
                    if (c == 0) return error.DataCorruption;
                    slot.* = c;
                }
                try self.requireConsumed(size, start, input);
                return .{ .flags = flags, .link = link, .keys = keys, .body = .{ .dir = cs } };
            }

            const values = try self.vf.deserializeGroup(alloc, input, keys_len);
            errdefer self.vf.deinitGroup(alloc, values);
            var fence: ?KF.Group = null;
            if (flags & RIGHT == 0) {
                const f = try self.kf.deserializeGroup(alloc, input, 1);
                errdefer self.kf.deinitGroup(alloc, f);
                // The fence is the inclusive high bound: it must be >= the greatest
                // live key, else a writer treats an in-leaf key as beyond the leaf.
                if (keys_len > 0) {
                    const last = try self.kf.get(alloc, &keys, keys_len - 1);
                    defer self.kf.deinitElem(alloc, last);
                    const bound = try self.kf.get(alloc, &f, 0);
                    defer self.kf.deinitElem(alloc, bound);
                    if (self.kf.compare(last, bound) == .gt) return error.DataCorruption;
                }
                fence = f;
            }
            try self.requireConsumed(size, start, input);
            return .{ .flags = flags, .link = link, .keys = keys, .body = .{ .leaf = .{ .values = values, .fence = fence } } };
        }

        fn requireConsumed(_: Self, size: ?usize, start: usize, input: *DataInput2) DbError!void {
            if (size) |sz| {
                if (input.pos - start != sz) return error.DataCorruption;
            }
        }

        /// Reject unsorted / duplicate keys under the key format's order.
        fn checkSorted(self: Self, alloc: Allocator, keys: *const KF.Group) DbError!void {
            const n = self.kf.size(keys);
            if (n < 2) return;
            var prev = try self.kf.get(alloc, keys, 0);
            var i: usize = 1;
            while (i < n) : (i += 1) {
                const cur = self.kf.get(alloc, keys, i) catch |e| {
                    self.kf.deinitElem(alloc, prev);
                    return e;
                };
                const bad = self.kf.compare(prev, cur) != .lt;
                self.kf.deinitElem(alloc, prev);
                if (bad) {
                    self.kf.deinitElem(alloc, cur);
                    return error.DataCorruption;
                }
                prev = cur;
            }
            self.kf.deinitElem(alloc, prev);
        }

        pub fn cloneElem(self: Self, alloc: Allocator, n: NodeT) DbError!NodeT {
            const keys = try self.kf.cloneGroup(alloc, &n.keys);
            errdefer self.kf.deinitGroup(alloc, keys);
            switch (n.body) {
                .dir => |cs| {
                    const children = try alloc.dupe(u64, cs);
                    return .{ .flags = n.flags, .link = n.link, .keys = keys, .body = .{ .dir = children } };
                },
                .leaf => |l| {
                    const values = try self.vf.cloneGroup(alloc, &l.values);
                    errdefer self.vf.deinitGroup(alloc, values);
                    var fence: ?KF.Group = null;
                    if (l.fence) |f| fence = try self.kf.cloneGroup(alloc, &f);
                    return .{ .flags = n.flags, .link = n.link, .keys = keys, .body = .{ .leaf = .{ .values = values, .fence = fence } } };
                },
            }
        }

        pub fn deinitElem(self: Self, alloc: Allocator, n: NodeT) void {
            var m = n;
            m.deinit(alloc, self.kf, self.vf);
        }

        // Nodes are never compared or CAS'd by value; the map is the only writer.
        pub fn compare(_: Self, _: NodeT, _: NodeT) Order {
            return .eq;
        }
        pub fn equals(_: Self, _: NodeT, _: NodeT) bool {
            return false;
        }
        pub fn fixedSize(_: Self) ?usize {
            return null;
        }
        pub fn equalsBySerializedBytes(_: Self) bool {
            return false;
        }
    };
}

/// Reconstruct a format instance for the (zero-sized) `NodeSerializer.instance`.
fn fmtInstance(comptime F: type) F {
    if (@hasDecl(F, "instance")) return F.instance;
    return .{};
}

// ------------------------------------------------------------------- tests

const testing = std.testing;
const LongFormat = @import("../ser/long.zig").LongFormat;

const LNode = Node(LongFormat, LongFormat);
const LSer = NodeSerializer(LongFormat, LongFormat);

fn lser() LSer {
    return LSer.init(.{}, .{});
}

fn serBytes(alloc: Allocator, node: LNode) ![]u8 {
    var out = DataOutput2.init(alloc);
    defer out.deinit();
    try lser().serialize(&out, node);
    return out.copyBytes(alloc);
}

fn be(v: i64) [8]u8 {
    return @bitCast(std.mem.nativeToBig(i64, v));
}

fn leafNode(flags: i32, link: u64, keys: []i64, values: []i64, fence: ?[]i64) LNode {
    return .{ .flags = flags, .link = link, .keys = keys, .body = .{ .leaf = .{ .values = values, .fence = fence } } };
}

test "golden: empty rightmost leaf" {
    const a = testing.allocator;
    var keys = [_]i64{};
    var vals = [_]i64{};
    const bytes = try serBytes(a, leafNode(LEFT | RIGHT, 0, &keys, &vals, null));
    defer a.free(bytes);
    try testing.expectEqualSlices(u8, &.{0x86}, bytes);
}

test "golden: non-rightmost leaf (fence last)" {
    const a = testing.allocator;
    var keys = [_]i64{ 5, 7 };
    var vals = [_]i64{ 50, 70 };
    var fence = [_]i64{7};
    const bytes = try serBytes(a, leafNode(LEFT, 9, &keys, &vals, &fence));
    defer a.free(bytes);
    var want = std.ArrayList(u8){};
    defer want.deinit(a);
    try want.appendSlice(a, &.{ 0xA4, 0x89 });
    try want.appendSlice(a, &be(5));
    try want.appendSlice(a, &be(7));
    try want.appendSlice(a, &be(50));
    try want.appendSlice(a, &be(70));
    try want.appendSlice(a, &be(7));
    try testing.expectEqualSlices(u8, want.items, bytes);
}

test "golden: rightmost dir" {
    const a = testing.allocator;
    var keys = [_]i64{5};
    var kids = [_]u64{ 100, 200 };
    const node: LNode = .{ .flags = DIR | LEFT | RIGHT, .link = 0, .keys = &keys, .body = .{ .dir = &kids } };
    const bytes = try serBytes(a, node);
    defer a.free(bytes);
    var want = std.ArrayList(u8){};
    defer want.deinit(a);
    try want.append(a, 0x9E);
    try want.appendSlice(a, &be(5));
    try want.appendSlice(a, &.{ 0xE4, 0x01, 0xC8 });
    try testing.expectEqualSlices(u8, want.items, bytes);
}

test "golden: non-rightmost dir" {
    const a = testing.allocator;
    var keys = [_]i64{ 3, 9 };
    var kids = [_]u64{ 7, 8 };
    const node: LNode = .{ .flags = DIR, .link = 42, .keys = &keys, .body = .{ .dir = &kids } };
    const bytes = try serBytes(a, node);
    defer a.free(bytes);
    var want = std.ArrayList(u8){};
    defer want.deinit(a);
    try want.appendSlice(a, &.{ 0xA8, 0xAA });
    try want.appendSlice(a, &be(3));
    try want.appendSlice(a, &be(9));
    try want.appendSlice(a, &.{ 0x87, 0x88 });
    try testing.expectEqualSlices(u8, want.items, bytes);
}

fn deser(a: Allocator, bytes: []const u8) DbError!LNode {
    var input = DataInput2.init(bytes);
    return lser().deserialize(a, &input, bytes.len);
}

test "roundtrip determinism (all shapes)" {
    const a = testing.allocator;
    var k0 = [_]i64{};
    var v0 = [_]i64{};
    var k1 = [_]i64{ 5, 7, 11 };
    var v1 = [_]i64{ 50, 70, 110 };
    var f1 = [_]i64{11};
    var k3 = [_]i64{100};
    var v3 = [_]i64{1000};
    var f3 = [_]i64{100};
    const nodes = [_]LNode{
        leafNode(LEFT | RIGHT, 0, &k0, &v0, null),
        leafNode(LEFT, 9, &k1, &v1, &f1),
        leafNode(0, 77, &k3, &v3, &f3),
    };
    for (nodes) |node| {
        const bytes = try serBytes(a, node);
        defer a.free(bytes);
        var decoded = try deser(a, bytes);
        defer decoded.deinit(a, .{}, .{});
        const re = try serBytes(a, decoded);
        defer a.free(re);
        try testing.expectEqualSlices(u8, bytes, re);
    }
    // rightmost dir
    var kd = [_]i64{ 5, 9 };
    var kids = [_]u64{ 100, 200, 300 };
    const dir: LNode = .{ .flags = DIR | LEFT | RIGHT, .link = 0, .keys = &kd, .body = .{ .dir = &kids } };
    const dbytes = try serBytes(a, dir);
    defer a.free(dbytes);
    var ddec = try deser(a, dbytes);
    defer ddec.deinit(a, .{}, .{});
    const dre = try serBytes(a, ddec);
    defer a.free(dre);
    try testing.expectEqualSlices(u8, dbytes, dre);
}

fn isCorrupt(r: anytype) bool {
    if (r) |_| {
        return false;
    } else |e| {
        return e == error.DataCorruption;
    }
}

test "corrupt: keysLen exceeds size" {
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try out.packInt((200 << 4) | (LEFT | RIGHT));
    var input = DataInput2.init(out.bytes());
    try testing.expect(isCorrupt(lser().deserialize(a, &input, out.bytes().len)));
}

test "corrupt: non-rightmost node zero link" {
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try out.packInt((1 << 4) | LEFT);
    try out.packLong(0);
    var input = DataInput2.init(out.bytes());
    try testing.expect(isCorrupt(lser().deserialize(a, &input, out.bytes().len)));
}

test "corrupt: directory zero child" {
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try out.packInt((1 << 4) | (DIR | LEFT | RIGHT));
    try out.writeI64(5);
    try out.packLong(100);
    try out.packLong(0);
    var input = DataInput2.init(out.bytes());
    try testing.expect(isCorrupt(lser().deserialize(a, &input, out.bytes().len)));
}

test "corrupt: empty non-rightmost dir" {
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try out.packInt(0 << 4 | DIR);
    try out.packLong(5);
    var input = DataInput2.init(out.bytes());
    try testing.expect(isCorrupt(lser().deserialize(a, &input, out.bytes().len)));
}

test "corrupt: forged keysLen leaves trailing bytes" {
    const a = testing.allocator;
    var keys = [_]i64{ 1, 2 };
    var vals = [_]i64{ 10, 20 };
    const bytes = try serBytes(a, leafNode(LEFT | RIGHT, 0, &keys, &vals, null));
    defer a.free(bytes);
    try testing.expectEqual(@as(u8, 0xA6), bytes[0]);
    bytes[0] = 0x96; // forge keysLen 2 -> 1
    try testing.expect(isCorrupt(deser(a, bytes)));
}

test "corrupt: unsorted / duplicate keys" {
    const a = testing.allocator;
    var kd = [_]i64{ 2, 1 };
    var vd = [_]i64{ 20, 10 };
    const b1 = try serBytes(a, leafNode(LEFT | RIGHT, 0, &kd, &vd, null));
    defer a.free(b1);
    try testing.expect(isCorrupt(deser(a, b1)));
    var kdup = [_]i64{ 5, 5 };
    var vdup = [_]i64{ 50, 51 };
    const b2 = try serBytes(a, leafNode(LEFT | RIGHT, 0, &kdup, &vdup, null));
    defer a.free(b2);
    try testing.expect(isCorrupt(deser(a, b2)));
}

test "corrupt: leaf fence below last key" {
    const a = testing.allocator;
    var keys = [_]i64{ 1, 2 };
    var vals = [_]i64{ 10, 20 };
    var fence = [_]i64{1};
    const bytes = try serBytes(a, leafNode(LEFT, 77, &keys, &vals, &fence));
    defer a.free(bytes);
    try testing.expect(isCorrupt(deser(a, bytes)));
}
