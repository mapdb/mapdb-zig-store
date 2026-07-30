//! `ObjectArrayFormat(Ser)` — generic fallback group format over any element
//! serializer (Java `ObjectArrayFormat`). `supportsBinary() == false`: callers
//! must deserialize before searching (no silent fallback, rule R6). Ported from
//! `mapdb-rust-store/src/ser/object_array.rs`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const mod = @import("mod.zig");
const SearchResult = mod.SearchResult;

/// Group backed by `[]Ser.Elem`, elements encoded by the element serializer.
pub fn ObjectArrayFormat(comptime Ser: type) type {
    return struct {
        const Self = @This();
        pub const Elem = Ser.Elem;
        pub const Group = []Ser.Elem;
        pub const Cursor = NeverCursor;

        element: Ser,

        pub fn init(element: Ser) Self {
            return .{ .element = element };
        }

        fn cmp(ser: Ser, a: Elem, b: Elem) Order {
            return ser.compare(a, b);
        }

        /// Zero-length groups are allocator-owned: freeable by `deinitGroup`.
        pub fn empty(_: Self, alloc: Allocator) DbError!Group {
            return alloc.alloc(std.meta.Child(Group), 0);
        }
        pub fn size(_: Self, g: *const Group) usize {
            return g.len;
        }
        pub fn compare(self: Self, a: Elem, b: Elem) Order {
            return self.element.compare(a, b);
        }
        pub fn cloneElem(self: Self, alloc: Allocator, v: Elem) DbError!Elem {
            return self.element.cloneElem(alloc, v);
        }
        pub fn deinitElem(self: Self, alloc: Allocator, v: Elem) void {
            self.element.deinitElem(alloc, v);
        }
        pub fn get(self: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Elem {
            return self.element.cloneElem(alloc, g.*[pos]);
        }
        pub fn search(self: Self, g: *const Group, key: Elem) SearchResult {
            return mod.bsearch(Elem, g.*, key, self.element, cmp);
        }
        pub fn insert(self: Self, alloc: Allocator, g: *const Group, pos: usize, v: Elem) DbError!Group {
            return mod.deepInsert(Elem, alloc, self.element, g.*, pos, v);
        }
        pub fn set(self: Self, alloc: Allocator, g: *const Group, pos: usize, v: Elem) DbError!Group {
            return mod.deepSet(Elem, alloc, self.element, g.*, pos, v);
        }
        pub fn delete(self: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Group {
            return mod.deepDelete(Elem, alloc, self.element, g.*, pos);
        }
        pub fn copyRange(self: Self, alloc: Allocator, g: *const Group, from: usize, to: usize) DbError!Group {
            return mod.deepCopyRange(Elem, alloc, self.element, g.*, from, to);
        }
        pub fn fromSlice(self: Self, alloc: Allocator, values: []const Elem) DbError!Group {
            return mod.deepClone(Elem, alloc, self.element, values);
        }
        pub fn cloneGroup(self: Self, alloc: Allocator, g: *const Group) DbError!Group {
            return mod.deepClone(Elem, alloc, self.element, g.*);
        }
        pub fn deinitGroup(self: Self, alloc: Allocator, g: Group) void {
            mod.deepDeinit(Elem, alloc, self.element, g);
        }
        pub fn serializeGroup(self: Self, out: *DataOutput2, g: *const Group) DbError!void {
            for (g.*) |e| try self.element.serialize(out, e);
        }
        pub fn deserializeGroup(self: Self, alloc: Allocator, input: *DataInput2, count: usize) DbError!Group {
            // Bound the allocation by the actual input BEFORE allocating: every
            // element encoding is >= 1 byte (fixed scalars or a packInt-framed
            // payload), so count > remaining is corruption, not OOM.
            const min_elem = if (self.element.fixedSize()) |w| @max(w, 1) else 1;
            if (try mod.ckMul(count, min_elem) > input.remaining()) return error.DataCorruption;
            const r = try alloc.alloc(Elem, count);
            var n: usize = 0;
            errdefer {
                for (r[0..n]) |e| self.element.deinitElem(alloc, e);
                alloc.free(r);
            }
            while (n < count) : (n += 1) r[n] = try self.element.deserialize(alloc, input, null);
            return r;
        }
        pub fn supportsBinary(_: Self) bool {
            return false;
        }
        pub fn binarySearch(_: Self, _: Allocator, _: Elem, _: *DataInput2, _: usize) DbError!SearchResult {
            return error.DataCorruption; // no binary access (no silent fallback)
        }
        pub fn binaryGet(_: Self, _: Allocator, _: *DataInput2, _: usize, _: usize) DbError!Elem {
            return error.DataCorruption;
        }
        pub fn rangeCursor(_: Self, _: Allocator, _: *DataInput2, _: usize, _: usize, _: usize) DbError!Cursor {
            return error.DataCorruption; // no range cursor
        }

        /// Placeholder cursor type (never constructed; `rangeCursor` errors).
        pub const NeverCursor = struct {
            pub fn next(_: *NeverCursor) DbError!bool {
                return false;
            }
            pub fn index(_: *const NeverCursor) usize {
                return 0;
            }
            pub fn value(_: *const NeverCursor, _: Allocator) DbError!Elem {
                return error.DataCorruption;
            }
            pub fn deinit(_: *NeverCursor) void {}
        };
    };
}

// ------------------------------------------------------------------- tests

const testing = std.testing;
const serializers = @import("serializers.zig");

test "object array non-binary round-trip + search" {
    const a = testing.allocator;
    const F = ObjectArrayFormat(serializers.LongSer);
    const f = F.init(serializers.LongSer.instance);
    var g = [_]i64{ 1, 2, 3, 10, 20 };
    var group: F.Group = &g;

    var out = DataOutput2.init(a);
    defer out.deinit();
    try f.serializeGroup(&out, &group);
    var inp = DataInput2.init(out.bytes());
    const back = try f.deserializeGroup(a, &inp, g.len);
    defer f.deinitGroup(a, back);
    try testing.expectEqualSlices(i64, &g, back);

    try testing.expect(!f.supportsBinary());
    var inp2 = DataInput2.init(out.bytes());
    try testing.expectError(error.DataCorruption, f.binarySearch(a, 3, &inp2, g.len));
    try testing.expect(f.search(&group, 10).eql(.{ .found = 3 }));
    try testing.expect(f.search(&group, 4).eql(.{ .insert = 3 }));
}

test "object array over owned-slice elements deep-clones" {
    const a = testing.allocator;
    const F = ObjectArrayFormat(serializers.StringSer);
    const f = F.init(serializers.StringSer.instance);
    var src = [_][]const u8{ "apple", "banana" };
    const g = try f.fromSlice(a, &src);
    defer f.deinitGroup(a, g);
    // insert borrows; original untouched, new group deep-owns
    const g2 = try f.insert(a, &g, 1, "avocado");
    defer f.deinitGroup(a, g2);
    try testing.expectEqual(@as(usize, 3), g2.len);
    try testing.expectEqualStrings("avocado", g2[1]);
    try testing.expect(g2[0].ptr != g[0].ptr); // deep clone
}
