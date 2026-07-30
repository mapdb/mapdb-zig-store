//! `ser` layer aggregator + comptime interface contracts.
//!
//! Two central duck-typed contracts (decl-name + associated-type checks
//! only; representative compile probes validate the real call surface):
//! - **Serializer**: element codec + ordering + logical equality + ownership.
//! - **GroupFormat**: the packed key/value array of one node, owning both the
//!   representation (`Group`) and the access algorithm, in an OBJECT side
//!   (materialized, copy-on-write) and a BYTE side (search/get on serialized
//!   bytes). `Elem`/`Group` are associated types for full monomorphization.
//!
//! Deviation from the Rust `Box<dyn GroupCursor>` cursor: Zig consumers are
//! comptime-generic, so each format exposes a concrete `pub const Cursor`
//! struct returned by value from `rangeCursor` — no type erasure, no boxing.
//!
//! Ownership: every returned `Group` — INCLUDING the zero-length group
//! from `empty(self, alloc)` — is allocator-owned and freed by `deinitGroup`.
//! `empty` therefore takes an `Allocator` and is fallible (a deviation from the
//! Rust `fn empty(&self) -> Group`, forced by "no static literal as an owned
//! value"). Deserializers validate the declared group extent against the actual
//! input BEFORE any count-proportional allocation (tainted count → clean
//! `error.DataCorruption`, never attacker-induced OOM).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const DataInput2 = @import("../io.zig").DataInput2;
const DataOutput2 = @import("../io.zig").DataOutput2;

// ---- submodules ----
pub const utf8 = @import("utf8.zig");
pub const value = @import("value.zig");
pub const serializers = @import("serializers.zig");
pub const arrays = @import("arrays.zig");
pub const bignum = @import("bignum.zig");
pub const compression = @import("compression.zig");
pub const scalar = @import("scalar.zig");
pub const long = @import("long.zig");
pub const int = @import("int.zig");
pub const string_group = @import("string_group.zig");
pub const string_prefix = @import("string_prefix.zig");
pub const bytearray = @import("bytearray.zig");
pub const object_array = @import("object_array.zig");
pub const tuple = @import("tuple.zig");
pub const columnar = @import("columnar.zig");
pub const probes = @import("probes.zig");

pub const Value = value.Value;
pub const Tuple = value.Tuple;

/// Result of a binary search: `.found` with the index, or `.insert` with the
/// insertion point. Replaces Java's `-(ins+1)` JDK convention.
pub const SearchResult = union(enum) {
    found: usize,
    insert: usize,

    pub fn eql(a: SearchResult, b: SearchResult) bool {
        return switch (a) {
            .found => |x| switch (b) {
                .found => |y| x == y,
                .insert => false,
            },
            .insert => |x| switch (b) {
                .found => false,
                .insert => |y| x == y,
            },
        };
    }
};

/// Encode a [`SearchResult`] into the Java `int` convention (`index`/`-(ins+1)`).
pub fn searchToJava(r: SearchResult) i64 {
    return switch (r) {
        .found => |i| @intCast(i),
        .insert => |ins| -@as(i64, @intCast(ins)) - 1,
    };
}

// -------------------------------------------------------- comptime contracts

/// Validate that `S` looks like a `Serializer` for `Elem` (decl names +
/// associated `Elem` type). Full signatures are checked by compile probes.
///
/// ## Serializer contract (the interface you implement)
/// A Serializer for `T` is any (usually zero-sized) type declaring:
/// - `pub const Elem = T;` — the materialized element type.
/// - `serialize(self, out: *DataOutput2, v: Elem) DbError!void` — append the
///   wire encoding; `out` owns its buffer. `v` is BORROWED (not freed).
/// - `deserialize(self, alloc, in: *DataInput2, size: ?usize) DbError!Elem` —
///   decode one element; the result is OWNED by `alloc` (caller frees via
///   `deinitElem`). `size` is the record length when known (Java −1 → `null`).
///   Every read is bounds-checked → `error.DataCorruption`, never a crash.
/// - `cloneElem(self, alloc, v: Elem) DbError!Elem` — deep copy `v` (borrowed)
///   into a fresh `alloc`-owned value. The deep-clone half of the ownership ruling; without it
///   StoreOnHeap/CAS would alias slice ownership → double free.
/// - `deinitElem(self, alloc, v: Elem) void` — free an `alloc`-owned element
///   (no-op for scalars). Must tolerate a zero-length slice.
/// - `compare(self, a, b) std.math.Order` — total order used for search/sort
///   (both borrowed).
/// - `equals(self, a, b) bool` — LOGICAL equality for CAS (D1); may differ from
///   byte equality (e.g. UTF-8 canonicalization).
/// - `fixedSize(self) ?usize` — the fixed wire width, or `null` if variable.
/// - `equalsBySerializedBytes(self) bool` — `true` iff `equals` is exactly a
///   byte compare of the encodings (lets byte stores skip a decode).
/// Ownership rule of thumb: inputs are borrowed; anything the callee returns is
/// owned by the passed `alloc`; the serializer itself retains nothing.
pub fn checkSerializer(comptime S: type, comptime Elem: type) void {
    comptime {
        if (!@hasDecl(S, "Elem")) @compileError("serializer " ++ @typeName(S) ++ " missing `pub const Elem`");
        if (S.Elem != Elem)
            @compileError("serializer " ++ @typeName(S) ++ " Elem=" ++ @typeName(S.Elem) ++ " != expected " ++ @typeName(Elem));
        const decls = [_][]const u8{
            "serialize", "deserialize", "cloneElem", "deinitElem",
            "compare",   "equals",      "fixedSize", "equalsBySerializedBytes",
        };
        for (decls) |name| {
            if (!@hasDecl(S, name))
                @compileError("serializer " ++ @typeName(S) ++ " missing decl `" ++ name ++ "`");
        }
    }
}

/// Validate that `F` looks like a `GroupFormat` (decl names + `Elem`/`Group`/
/// `Cursor` associated types). Full signatures are checked by compile probes.
///
/// ## GroupFormat contract (the interface you implement)
/// A GroupFormat owns the packed key/value array of ONE btree node — both the
/// in-memory representation (`Group`, opaque to callers) and the access
/// algorithm — in an OBJECT side (materialized, copy-on-write) and a BYTE side
/// (search/get directly on serialized bytes). Associated types: `Elem` (element),
/// `Group` (the packed array), `Cursor` (concrete forward cursor, by value).
///
/// Ownership: EVERY returned `Group` — including `empty`'s zero-length one —
/// is `alloc`-owned and freed by `deinitGroup`; every returned `Elem` is
/// `alloc`-owned and freed by `deinitElem`. Object-side mutators are pure
/// copy-on-write: the input `Group` is BORROWED and untouched, a fresh `Group`
/// is returned, and on error every partial output is freed (strong guarantee).
///
/// Object side:
/// - `empty(self, alloc) DbError!Group` — a fresh empty group.
/// - `size(self, g) usize` — element count.
/// - `get(self, alloc, g, pos) DbError!Elem` — owned clone of element `pos`.
/// - `search(self, g, key) SearchResult` — `.found`/`.insert` (no allocation).
/// - `insert/set/delete(self, alloc, g, pos, ...) DbError!Group` — CoW edit.
/// - `copyRange(self, alloc, g, from, to)` / `fromSlice(self, alloc, values)` /
///   `cloneGroup(self, alloc, g)` — CoW builders.
/// - `deinitGroup(self, alloc, g) void` — free an owned group.
/// - `compare(self, a, b) std.math.Order` — element order.
///
/// Byte side (positioning is load-bearing):
/// - `serializeGroup(self, out, g) DbError!void` — element count stored EXTERNALLY.
/// - `deserializeGroup(self, alloc, in, count) DbError!Group` — validates the
///   declared extent against the real input BEFORE any count-proportional
///   allocation (tainted count → `DataCorruption`, never OOM).
/// - `supportsBinary(self) bool`.
/// - `binarySearch(self, alloc, key, in: *DataInput2, count) DbError!SearchResult`
///   and `binaryGet(self, alloc, in, count, pos) DbError!Elem`: enter at group
///   START, MUST leave `in` at group END (whether found or not).
/// - `rangeCursor(self, alloc, in, count, from, to) DbError!Cursor` — a forward
///   cursor; on exhaustion it leaves `in` at group end. `cursor.value(alloc)`
///   returns an owned clone.
/// Additive btree hooks (not in the Rust trait): `equalsElem` (logical element
/// equality for CAS) and `naturalOrder` (JDK null-comparator ordering).
pub fn checkGroupFormat(comptime F: type) void {
    comptime {
        const types = [_][]const u8{ "Elem", "Group", "Cursor" };
        for (types) |name| {
            if (!@hasDecl(F, name))
                @compileError("group format " ++ @typeName(F) ++ " missing `pub const " ++ name ++ "`");
        }
        const decls = [_][]const u8{
            "empty",            "size",        "get",            "search",
            "insert",           "set",         "delete",         "copyRange",
            "fromSlice",        "deinitGroup", "cloneGroup",     "serializeGroup",
            "deserializeGroup", "compare",     "supportsBinary", "binarySearch",
            "binaryGet",        "rangeCursor",
        };
        for (decls) |name| {
            if (!@hasDecl(F, name))
                @compileError("group format " ++ @typeName(F) ++ " missing decl `" ++ name ++ "`");
        }
    }
}

// ---------------------------------------------------- generic byte-side cursor

/// Default forward cursor built on `binaryGet` (O(n·binaryGet) full scan). A
/// correctness fallback for formats with random byte-side access but no special
/// sequential layout (the fixed-stride and offset-table formats use it). Formats
/// with sequential wire layouts (delta, columnar) provide their own cursor.
///
/// Positioning contract: on exhaustion (after `next` first returns `false`) the
/// input is left at group end — including for an empty group/range.
pub fn BinaryGetCursor(comptime F: type) type {
    return struct {
        const Self = @This();
        pub const Elem = F.Elem;

        fmt: F,
        input: *DataInput2,
        alloc: Allocator,
        group_start: usize,
        count: usize,
        to: usize,
        idx: usize,
        started: bool = false,
        cur: ?F.Elem = null,
        exhausted: bool = false,

        /// `input` must be at group start; `from<=to<=count` (validated by caller).
        pub fn init(fmt: F, alloc: Allocator, input: *DataInput2, count: usize, from: usize, to: usize) Self {
            return .{
                .fmt = fmt,
                .input = input,
                .alloc = alloc,
                .group_start = input.pos,
                .count = count,
                .to = to,
                .idx = from,
            };
        }

        fn freeCur(self: *Self) void {
            if (self.cur) |c| self.fmt.deinitElem(self.alloc, c);
            self.cur = null;
        }

        pub fn next(self: *Self) DbError!bool {
            if (self.exhausted) return false;
            if (self.started) {
                self.idx += 1;
            } else {
                self.started = true;
            }
            if (self.idx >= self.to) {
                self.exhausted = true;
                self.freeCur();
                self.input.setPos(self.group_start);
                if (self.count == 0) {
                    const g = try self.fmt.deserializeGroup(self.alloc, self.input, 0);
                    self.fmt.deinitGroup(self.alloc, g);
                } else {
                    const e = try self.fmt.binaryGet(self.alloc, self.input, self.count, self.count - 1);
                    self.fmt.deinitElem(self.alloc, e);
                }
                return false;
            }
            self.input.setPos(self.group_start);
            self.freeCur();
            self.cur = try self.fmt.binaryGet(self.alloc, self.input, self.count, self.idx);
            return true;
        }

        pub fn index(self: *const Self) usize {
            return self.idx;
        }

        /// Owned clone of the current element (valid after `next()==true`).
        pub fn value(self: *const Self, alloc: Allocator) DbError!F.Elem {
            return self.fmt.cloneElem(alloc, self.cur.?);
        }

        pub fn deinit(self: *Self) void {
            self.freeCur();
        }
    };
}

/// Checked `a + b` / `a * b` mapping overflow → `error.DataCorruption` (torn
/// values must fail fast rather than wrap — D4).
pub fn ckAdd(a: usize, b: usize) DbError!usize {
    return std.math.add(usize, a, b) catch return error.DataCorruption;
}
pub fn ckMul(a: usize, b: usize) DbError!usize {
    return std.math.mul(usize, a, b) catch return error.DataCorruption;
}

/// `base + idx*width`, checked against overflow (a torn/oversize node must fail
/// fast rather than wrap — D4). Used by every fixed-stride/offset-table format.
pub fn elemOff(base: usize, idx: usize, width: usize) DbError!usize {
    const off = std.math.mul(usize, idx, width) catch return error.DataCorruption;
    return std.math.add(usize, base, off) catch return error.DataCorruption;
}

// -------------------------------------------------- shared object-side helpers

/// `Arrays.binarySearch` over a sorted slice using a context-carrying compare.
/// `cmpFn(ctx, stored, key)` returns `stored <=> key`.
pub fn bsearch(
    comptime T: type,
    g: []const T,
    key: T,
    ctx: anytype,
    comptime cmpFn: fn (@TypeOf(ctx), T, T) Order,
) SearchResult {
    var lo: isize = 0;
    var hi: isize = @as(isize, @intCast(g.len)) - 1;
    while (lo <= hi) {
        const mid: usize = @intCast(@divTrunc(lo + hi, 2));
        switch (cmpFn(ctx, g[mid], key)) {
            .eq => return .{ .found = mid },
            .lt => lo = @as(isize, @intCast(mid)) + 1,
            .gt => hi = @as(isize, @intCast(mid)) - 1,
        }
    }
    return .{ .insert = @intCast(lo) };
}

/// Fixed-stride scalar group format factory (Long/Int/Short/Char/Uuid). `Ser`
/// is a fixed-size scalar element serializer (its `fixedSize()` is the stride);
/// the byte side does O(log n) true binary search over the packed BE cells.
/// `binarySearch` reads cells through `Ser.deserialize`, which is allocation-
/// free for every scalar serializer (safe to call with an unused allocator).
pub fn FixedStrideFormat(comptime Ser: type) type {
    return struct {
        const Self = @This();
        pub const Elem = Ser.Elem;
        pub const Group = []Ser.Elem;
        pub const Cursor = BinaryGetCursor(Self);
        pub const instance: Self = .{};
        /// Element serializer type (Java `GroupFormat.element()`): used by
        /// external-value BTree maps to encode each value as its own store record.
        pub const ElementSer = Ser;
        const width: usize = Ser.instance.fixedSize().?;

        /// The single-element `Serializer` backing this group (Java
        /// `GroupFormat.element()`).
        pub fn element(_: Self) Ser {
            return Ser.instance;
        }

        fn cmp(_: void, a: Elem, b: Elem) Order {
            return Ser.instance.compare(a, b);
        }

        /// Zero-length groups are allocator-owned: freeable by `deinitGroup`.
        pub fn empty(_: Self, alloc: Allocator) DbError!Group {
            return alloc.alloc(Elem, 0);
        }
        pub fn size(_: Self, g: *const Group) usize {
            return g.len;
        }
        pub fn compare(_: Self, a: Elem, b: Elem) Order {
            return Ser.instance.compare(a, b);
        }
        /// Logical element equality (delegates to the element serializer). Used
        /// by btree CAS ops. Additive to the Rust GroupFormat surface.
        pub fn equalsElem(_: Self, a: Elem, b: Elem) bool {
            return Ser.instance.equals(a, b);
        }
        /// True iff elements order by their natural ordering (JDK null-comparator).
        pub fn naturalOrder(_: Self) bool {
            return Ser.instance.naturalOrder();
        }
        pub fn cloneElem(_: Self, alloc: Allocator, v: Elem) DbError!Elem {
            return Ser.instance.cloneElem(alloc, v);
        }
        pub fn deinitElem(_: Self, alloc: Allocator, v: Elem) void {
            Ser.instance.deinitElem(alloc, v);
        }
        pub fn get(_: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Elem {
            return Ser.instance.cloneElem(alloc, g.*[pos]);
        }
        pub fn search(_: Self, g: *const Group, key: Elem) SearchResult {
            return bsearch(Elem, g.*, key, {}, cmp);
        }
        pub fn insert(_: Self, alloc: Allocator, g: *const Group, pos: usize, v: Elem) DbError!Group {
            return sliceInsert(Elem, alloc, g.*, pos, v);
        }
        pub fn set(_: Self, alloc: Allocator, g: *const Group, pos: usize, v: Elem) DbError!Group {
            const r = try alloc.dupe(Elem, g.*);
            r[pos] = v;
            return r;
        }
        pub fn delete(_: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Group {
            return sliceDelete(Elem, alloc, g.*, pos);
        }
        pub fn copyRange(_: Self, alloc: Allocator, g: *const Group, from: usize, to: usize) DbError!Group {
            return sliceCopyRange(Elem, alloc, g.*, from, to);
        }
        pub fn fromSlice(_: Self, alloc: Allocator, values: []const Elem) DbError!Group {
            return alloc.dupe(Elem, values);
        }
        pub fn cloneGroup(_: Self, alloc: Allocator, g: *const Group) DbError!Group {
            return alloc.dupe(Elem, g.*);
        }
        pub fn deinitGroup(_: Self, alloc: Allocator, g: Group) void {
            alloc.free(g);
        }
        pub fn serializeGroup(_: Self, out: *DataOutput2, g: *const Group) DbError!void {
            for (g.*) |v| try Ser.instance.serialize(out, v);
        }
        pub fn deserializeGroup(_: Self, alloc: Allocator, input: *DataInput2, count: usize) DbError!Group {
            // Bound the allocation by the actual input BEFORE allocating: a
            // tainted count must fail as corruption, never as OOM.
            if (try ckMul(count, width) > input.remaining()) return error.DataCorruption;
            const r = try alloc.alloc(Elem, count);
            errdefer alloc.free(r);
            for (r) |*slot| slot.* = try Ser.instance.deserialize(alloc, input, null);
            return r;
        }
        pub fn supportsBinary(_: Self) bool {
            return true;
        }
        pub fn binarySearch(_: Self, _: Allocator, key: Elem, input: *DataInput2, count: usize) DbError!SearchResult {
            // Rust guard ported: an isize-overflowing count is corruption, not
            // a ReleaseSafe @intCast panic.
            if (count > std.math.maxInt(isize)) return error.DataCorruption;
            const start = input.pos;
            var lo: isize = 0;
            var hi: isize = @as(isize, @intCast(count)) - 1;
            var found: ?usize = null;
            while (lo <= hi) {
                const mid: usize = @intCast(@divTrunc(lo + hi, 2));
                try input.seek(try elemOff(start, mid, width));
                const v = try Ser.instance.deserialize(undefined, input, null);
                switch (Ser.instance.compare(v, key)) {
                    .eq => {
                        found = mid;
                        break;
                    },
                    .lt => lo = @as(isize, @intCast(mid)) + 1,
                    .gt => hi = @as(isize, @intCast(mid)) - 1,
                }
            }
            try input.seek(try elemOff(start, count, width));
            if (found) |i| return .{ .found = i };
            return .{ .insert = @intCast(lo) };
        }
        pub fn binaryGet(_: Self, alloc: Allocator, input: *DataInput2, count: usize, pos: usize) DbError!Elem {
            const start = input.pos;
            if (pos >= count) return error.DataCorruption;
            try input.seek(try elemOff(start, pos, width));
            const v = try Ser.instance.deserialize(alloc, input, null);
            try input.seek(try elemOff(start, count, width));
            return v;
        }
        pub fn rangeCursor(self: Self, alloc: Allocator, input: *DataInput2, count: usize, from: usize, to: usize) DbError!Cursor {
            if (from > to or to > count) return error.DataCorruption;
            return Cursor.init(self, alloc, input, count, from, to);
        }
    };
}

/// Insert `v` at `pos` into a fresh slice (copy elements; caller owns).
pub fn sliceInsert(comptime T: type, alloc: Allocator, g: []const T, pos: usize, v: T) DbError![]T {
    const r = try alloc.alloc(T, g.len + 1);
    @memcpy(r[0..pos], g[0..pos]);
    r[pos] = v;
    @memcpy(r[pos + 1 ..], g[pos..]);
    return r;
}

/// Delete element at `pos`, returning a fresh slice (caller owns).
pub fn sliceDelete(comptime T: type, alloc: Allocator, g: []const T, pos: usize) DbError![]T {
    const r = try alloc.alloc(T, g.len - 1);
    @memcpy(r[0..pos], g[0..pos]);
    @memcpy(r[pos..], g[pos + 1 ..]);
    return r;
}

/// `g[from..to]` copied into a fresh slice (caller owns).
pub fn sliceCopyRange(comptime T: type, alloc: Allocator, g: []const T, from: usize, to: usize) DbError![]T {
    return alloc.dupe(T, g[from..to]);
}

// ------------------------------------------- deep copy-on-write over a codec
//
// For groups whose elements own memory (`[]const u8` strings/bytes, `[]Value`
// rows) a shallow slice copy would alias ownership → double free. These builders
// DEEP-clone every retained element through `codec.cloneElem(alloc, e)` (inputs
// are borrowed), with strong exception safety: on any failure every element
// cloned so far and the output slice are freed, leaving the input untouched.

pub fn deepDeinit(comptime Elem: type, alloc: Allocator, codec: anytype, g: []const Elem) void {
    for (g) |e| codec.deinitElem(alloc, e);
    alloc.free(g);
}

pub fn deepClone(comptime Elem: type, alloc: Allocator, codec: anytype, g: []const Elem) DbError![]Elem {
    const r = try alloc.alloc(Elem, g.len);
    var n: usize = 0;
    errdefer {
        for (r[0..n]) |e| codec.deinitElem(alloc, e);
        alloc.free(r);
    }
    while (n < g.len) : (n += 1) r[n] = try codec.cloneElem(alloc, g[n]);
    return r;
}

pub fn deepInsert(comptime Elem: type, alloc: Allocator, codec: anytype, g: []const Elem, pos: usize, v: Elem) DbError![]Elem {
    const r = try alloc.alloc(Elem, g.len + 1);
    var n: usize = 0;
    errdefer {
        for (r[0..n]) |e| codec.deinitElem(alloc, e);
        alloc.free(r);
    }
    while (n < pos) : (n += 1) r[n] = try codec.cloneElem(alloc, g[n]);
    r[n] = try codec.cloneElem(alloc, v);
    n += 1;
    while (n < g.len + 1) : (n += 1) r[n] = try codec.cloneElem(alloc, g[n - 1]);
    return r;
}

pub fn deepSet(comptime Elem: type, alloc: Allocator, codec: anytype, g: []const Elem, pos: usize, v: Elem) DbError![]Elem {
    const r = try alloc.alloc(Elem, g.len);
    var n: usize = 0;
    errdefer {
        for (r[0..n]) |e| codec.deinitElem(alloc, e);
        alloc.free(r);
    }
    while (n < g.len) : (n += 1) {
        r[n] = if (n == pos) try codec.cloneElem(alloc, v) else try codec.cloneElem(alloc, g[n]);
    }
    return r;
}

pub fn deepDelete(comptime Elem: type, alloc: Allocator, codec: anytype, g: []const Elem, pos: usize) DbError![]Elem {
    const r = try alloc.alloc(Elem, g.len - 1);
    var n: usize = 0;
    errdefer {
        for (r[0..n]) |e| codec.deinitElem(alloc, e);
        alloc.free(r);
    }
    var j: usize = 0;
    while (j < g.len) : (j += 1) {
        if (j == pos) continue;
        r[n] = try codec.cloneElem(alloc, g[j]);
        n += 1;
    }
    return r;
}

pub fn deepCopyRange(comptime Elem: type, alloc: Allocator, codec: anytype, g: []const Elem, from: usize, to: usize) DbError![]Elem {
    return deepClone(Elem, alloc, codec, g[from..to]);
}

// ------------------------------------------------------------------- tests

test {
    std.testing.refAllDecls(@This());
}

test "SearchResult eql / searchToJava" {
    const f = SearchResult{ .found = 3 };
    const ins = SearchResult{ .insert = 2 };
    try std.testing.expect(f.eql(.{ .found = 3 }));
    try std.testing.expect(!f.eql(ins));
    try std.testing.expectEqual(@as(i64, 3), searchToJava(f));
    try std.testing.expectEqual(@as(i64, -3), searchToJava(ins));
}
