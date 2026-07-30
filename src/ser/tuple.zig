//! `TupleFormat` — binary-capable group format for composite/tuple keys (Java
//! `TupleFormat` + `TupleComponent`). Each tuple is encoded to an ORDER-
//! PRESERVING (memcomparable) `[]u8` by its component schema, so the UNSIGNED
//! byte order of the encodings equals the logical tuple order. The group is then
//! stored/searched like a `byte[][]` group (blob + i32 offset table, unsigned
//! in-place compare with a length tie-break → `(a) < (a,b)`). Ported from
//! `mapdb-rust-store/src/ser/tuple.rs`.
//!
//! Per-component encoding:
//! - Int/Long: fixed-width big-endian with the sign bit flipped (`v ^ MIN`).
//! - Str/Bytes: `0x00`→`0x00 0xFF` escape, `0x00 0x00` terminator. STRING order
//!   is UTF-8 (code-point) order (deliberately ≠ `String.compareTo`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const mod = @import("mod.zig");
const utf8 = @import("utf8.zig");
const value = @import("value.zig");
const Value = value.Value;
const serializers = @import("serializers.zig");
const SearchResult = mod.SearchResult;
const byteCodec = serializers.ByteArrayUnsignedSer.instance;

const I32_MIN: i32 = std.math.minInt(i32);
const I64_MIN: i64 = std.math.minInt(i64);

/// A typed component of a composite key providing a memcomparable codec.
pub const TupleComponent = enum {
    int,
    long,
    str,
    bytes,

    fn encode(self: TupleComponent, out: *DataOutput2, v: Value) DbError!void {
        switch (self) {
            .int => try out.writeI32(v.int ^ I32_MIN),
            .long => try out.writeI64(v.long ^ I64_MIN),
            .str => try writeEscaped(out, v.str),
            .bytes => try writeEscaped(out, v.bytes),
        }
    }

    fn compareVal(self: TupleComponent, a: Value, b: Value) Order {
        return switch (self) {
            .int => std.math.order(a.int, b.int),
            .long => std.math.order(a.long, b.long),
            // UTF-8 unsigned byte order == code-point order.
            .str => utf8.compareUnsignedBytes(a.str, b.str),
            .bytes => utf8.compareUnsignedBytes(a.bytes, b.bytes),
        };
    }

    fn equalTo(self: TupleComponent, a: Value, b: Value) bool {
        return self.compareVal(a, b) == .eq;
    }
};

// ---- escaped-terminated codec for variable-length components ----

fn writeEscaped(out: *DataOutput2, payload: []const u8) DbError!void {
    for (payload) |b| {
        if (b == 0x00) {
            try out.writeU8(0x00);
            try out.writeU8(0xFF);
        } else {
            try out.writeU8(b);
        }
    }
    try out.writeU8(0x00);
    try out.writeU8(0x00);
}

fn readEscaped(alloc: Allocator, input: *DataInput2, end: usize) DbError![]u8 {
    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(alloc);
    while (true) {
        if (input.pos >= end) return error.DataCorruption;
        const b = try input.readU8();
        if (b == 0x00) {
            if (input.pos >= end) return error.DataCorruption;
            const b2 = try input.readU8();
            if (b2 == 0x00) break; // terminator
            if (b2 != 0xFF) return error.DataCorruption;
            try buf.append(alloc, 0x00);
        } else {
            try buf.append(alloc, b);
        }
    }
    return buf.toOwnedSlice(alloc);
}

// ---- per-tuple memcomparable codec ----

fn encodeTuple(alloc: Allocator, schema: []const TupleComponent, tuple: []const Value) DbError![]u8 {
    std.debug.assert(tuple.len <= schema.len);
    var out = DataOutput2.init(alloc);
    errdefer out.deinit();
    for (tuple, 0..) |v, i| try schema[i].encode(&out, v);
    return out.toOwnedSlice();
}

fn decodeTuple(alloc: Allocator, schema: []const TupleComponent, enc: []const u8) DbError!value.Tuple {
    const end = enc.len;
    var input = DataInput2.init(enc);
    var r = std.ArrayList(Value){};
    errdefer {
        for (r.items) |v| v.deinit(alloc);
        r.deinit(alloc);
    }
    var i: usize = 0;
    while (input.pos < end) {
        if (i == schema.len) return error.DataCorruption; // more components than schema
        const v = try decodeComponent(alloc, schema[i], &input, end);
        errdefer v.deinit(alloc);
        try r.append(alloc, v);
        i += 1;
    }
    return r.toOwnedSlice(alloc);
}

fn decodeComponent(alloc: Allocator, comp: TupleComponent, input: *DataInput2, end: usize) DbError!Value {
    switch (comp) {
        .int => {
            if (input.pos + 4 > end) return error.DataCorruption;
            return .{ .int = (try input.readI32()) ^ I32_MIN };
        },
        .long => {
            if (input.pos + 8 > end) return error.DataCorruption;
            return .{ .long = (try input.readI64()) ^ I64_MIN };
        },
        .str => {
            const raw = try readEscaped(alloc, input, end);
            errdefer alloc.free(raw);
            const lossy = try utf8.utf8Lossy(alloc, raw);
            alloc.free(raw);
            return .{ .str = lossy };
        },
        .bytes => return .{ .bytes = try readEscaped(alloc, input, end) },
    }
}

fn compareTuple(schema: []const TupleComponent, a: []const Value, b: []const Value) Order {
    const min = @min(a.len, b.len);
    var i: usize = 0;
    while (i < min) : (i += 1) {
        const c = schema[i].compareVal(a[i], b[i]);
        if (c != .eq) return c;
    }
    return std.math.order(a.len, b.len);
}

/// Compare a stored ENCODED tuple against a structured key tuple, in place (no
/// allocation) — used by object-side `search`. Returns `stored <=> key`. Agrees
/// with the unsigned byte order of the encodings (the memcomparable invariant).
fn compareEncodedToTuple(schema: []const TupleComponent, stored: []const u8, key: []const Value) DbError!Order {
    var in = DataInput2.init(stored);
    const end = stored.len;
    var i: usize = 0;
    while (in.pos < end) {
        if (i >= key.len) return .gt; // stored has more components → longer → greater
        const c = try compareComponentInPlace(schema[i], &in, end, key[i]);
        if (c != .eq) return c;
        i += 1;
    }
    if (i < key.len) return .lt; // stored is a prefix of key → shorter → less
    return .eq;
}

fn compareComponentInPlace(comp: TupleComponent, in: *DataInput2, end: usize, keyval: Value) DbError!Order {
    switch (comp) {
        .int => {
            if (in.pos + 4 > end) return error.DataCorruption;
            const sv = (try in.readI32()) ^ I32_MIN;
            return std.math.order(sv, keyval.int);
        },
        .long => {
            if (in.pos + 8 > end) return error.DataCorruption;
            const sv = (try in.readI64()) ^ I64_MIN;
            return std.math.order(sv, keyval.long);
        },
        .str => return compareEscapedInPlace(in, end, keyval.str),
        .bytes => return compareEscapedInPlace(in, end, keyval.bytes),
    }
}

/// Unsigned compare of the (unescaped) stored variable-length component against
/// `key`, consuming exactly the component's bytes on equality.
fn compareEscapedInPlace(in: *DataInput2, end: usize, key: []const u8) DbError!Order {
    var j: usize = 0;
    while (true) {
        if (in.pos >= end) return error.DataCorruption; // unterminated
        const b = try in.readU8();
        var sb: u8 = undefined;
        if (b == 0x00) {
            if (in.pos >= end) return error.DataCorruption;
            const b2 = try in.readU8();
            if (b2 == 0x00) return std.math.order(j, key.len); // terminator
            if (b2 != 0xFF) return error.DataCorruption;
            sb = 0x00;
        } else {
            sb = b;
        }
        if (j >= key.len) return .gt; // stored longer than key
        if (sb != key[j]) return std.math.order(sb, key[j]);
        j += 1;
    }
}

/// Unsigned-lexicographic compare of stored ENCODED element `idx` against the
/// pre-encoded `probe`, in place — the byte side (agrees with object side).
fn compareStoredTo(input: *DataInput2, off_base: usize, blob_base: usize, blob_len: usize, count: usize, idx: usize, probe: []const u8) DbError!Order {
    try input.seek(try mod.elemOff(off_base, idx, 4));
    const s = try input.readI32();
    const e = if (idx + 1 < count) try input.readI32() else @as(i32, @intCast(blob_len));
    if (s < 0 or e < s or @as(usize, @intCast(e)) > blob_len) return error.DataCorruption;
    const stored_len: usize = @intCast(e - s);
    try input.seek(try mod.ckAdd(blob_base, @as(usize, @intCast(s))));
    const n = @min(stored_len, probe.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const c: i32 = @as(i32, try input.readU8()) - @as(i32, probe[i]);
        if (c != 0) return if (c < 0) Order.lt else Order.gt;
    }
    return std.math.order(stored_len, probe.len);
}

/// A tuple format over an ordered component schema (arity = length). The schema
/// slice is BORROWED (caller keeps it alive); no allocation held by the format.
pub const TupleFormat = struct {
    const Self = @This();
    pub const Elem = value.Tuple;
    /// Group holds each tuple's memcomparable encoding (== Java's `byte[][]`).
    pub const Group = [][]const u8;
    pub const Cursor = mod.BinaryGetCursor(Self);

    schema: []const TupleComponent,
    element_ser: TupleSerializer,

    pub fn of(components: []const TupleComponent) Self {
        std.debug.assert(components.len >= 1);
        return .{ .schema = components, .element_ser = .{ .schema = components } };
    }

    pub fn element(self: Self) TupleSerializer {
        return self.element_ser;
    }

    /// Defensive copy of this format's persisted component schema (Java
    /// `TupleFormat.schema()` — `schema.clone()`; renamed `schemaCopy` here
    /// because the port keeps the borrowed schema in a field of the same name).
    /// Duplicated into a fresh `alloc`-owned slice the caller frees.
    pub fn schemaCopy(self: Self, alloc: Allocator) DbError![]TupleComponent {
        return alloc.dupe(TupleComponent, self.schema);
    }

    /// Zero-length groups are allocator-owned: freeable by `deinitGroup`.
    pub fn empty(_: Self, alloc: Allocator) DbError!Group {
        return alloc.alloc(std.meta.Child(Group), 0);
    }
    pub fn size(_: Self, g: *const Group) usize {
        return g.len;
    }
    pub fn compare(self: Self, a: Elem, b: Elem) Order {
        return compareTuple(self.schema, a, b);
    }
    pub fn cloneElem(_: Self, alloc: Allocator, v: Elem) DbError!Elem {
        return value.cloneTuple(alloc, v);
    }
    pub fn deinitElem(_: Self, alloc: Allocator, v: Elem) void {
        value.deinitTuple(alloc, v);
    }
    pub fn get(self: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Elem {
        return decodeTuple(alloc, self.schema, g.*[pos]);
    }
    pub fn search(self: Self, g: *const Group, key: Elem) SearchResult {
        var lo: isize = 0;
        var hi: isize = @as(isize, @intCast(g.len)) - 1;
        while (lo <= hi) {
            const mid: usize = @intCast(@divTrunc(lo + hi, 2));
            // stored group is well-formed (our own encoding); corruption →
            // treat as insertion point (never happens in practice).
            const c = compareEncodedToTuple(self.schema, g.*[mid], key) catch return .{ .insert = @intCast(mid) };
            switch (c) {
                .eq => return .{ .found = mid },
                .lt => lo = @as(isize, @intCast(mid)) + 1,
                .gt => hi = @as(isize, @intCast(mid)) - 1,
            }
        }
        return .{ .insert = @intCast(lo) };
    }
    pub fn insert(self: Self, alloc: Allocator, g: *const Group, pos: usize, v: Elem) DbError!Group {
        const enc = try encodeTuple(alloc, self.schema, v);
        defer alloc.free(enc);
        return mod.deepInsert([]const u8, alloc, byteCodec, g.*, pos, enc);
    }
    pub fn set(self: Self, alloc: Allocator, g: *const Group, pos: usize, v: Elem) DbError!Group {
        const enc = try encodeTuple(alloc, self.schema, v);
        defer alloc.free(enc);
        return mod.deepSet([]const u8, alloc, byteCodec, g.*, pos, enc);
    }
    pub fn delete(_: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Group {
        return mod.deepDelete([]const u8, alloc, byteCodec, g.*, pos);
    }
    pub fn copyRange(_: Self, alloc: Allocator, g: *const Group, from: usize, to: usize) DbError!Group {
        return mod.deepCopyRange([]const u8, alloc, byteCodec, g.*, from, to);
    }
    pub fn fromSlice(self: Self, alloc: Allocator, values: []const Elem) DbError!Group {
        const r = try alloc.alloc([]const u8, values.len);
        var n: usize = 0;
        errdefer {
            for (r[0..n]) |e| alloc.free(e);
            alloc.free(r);
        }
        while (n < values.len) : (n += 1) r[n] = try encodeTuple(alloc, self.schema, values[n]);
        return r;
    }
    pub fn cloneGroup(_: Self, alloc: Allocator, g: *const Group) DbError!Group {
        return mod.deepClone([]const u8, alloc, byteCodec, g.*);
    }
    pub fn deinitGroup(_: Self, alloc: Allocator, g: Group) void {
        mod.deepDeinit([]const u8, alloc, byteCodec, g);
    }

    pub fn serializeGroup(_: Self, out: *DataOutput2, g: *const Group) DbError!void {
        var blob_len: usize = 0;
        for (g.*) |e| blob_len += e.len;
        try out.writeI32(@intCast(blob_len));
        var off: i32 = 0;
        for (g.*) |e| {
            try out.writeI32(off);
            off += @intCast(e.len);
        }
        for (g.*) |e| try out.writeAll(e);
    }
    pub fn deserializeGroup(_: Self, alloc: Allocator, input: *DataInput2, count: usize) DbError!Group {
        const blob_len_i = try input.readI32();
        if (blob_len_i < 0) return error.DataCorruption;
        const blob_len: usize = @intCast(blob_len_i);
        // Validate the whole declared extent (offset table + blob) against the
        // actual input BEFORE allocating from the tainted count.
        if (try mod.ckAdd(try mod.ckMul(count, 4), blob_len) > input.remaining()) return error.DataCorruption;
        const off = try alloc.alloc(i32, count);
        defer alloc.free(off);
        for (off) |*slot| slot.* = try input.readI32();
        const blob = try input.takeBytes(blob_len);
        const r = try alloc.alloc([]const u8, count);
        var n: usize = 0;
        errdefer {
            for (r[0..n]) |e| alloc.free(e);
            alloc.free(r);
        }
        while (n < count) : (n += 1) {
            const s = off[n];
            const e = if (n + 1 < count) off[n + 1] else blob_len_i;
            if (s < 0 or e < s or @as(usize, @intCast(e)) > blob_len) return error.DataCorruption;
            r[n] = try alloc.dupe(u8, blob[@intCast(s)..@intCast(e)]);
        }
        return r;
    }

    pub fn supportsBinary(_: Self) bool {
        return true;
    }
    pub fn binarySearch(self: Self, alloc: Allocator, key: Elem, input: *DataInput2, count: usize) DbError!SearchResult {
        const probe = try encodeTuple(alloc, self.schema, key);
        defer alloc.free(probe);
        const start = input.pos;
        const blob_len_i = try input.readI32();
        if (blob_len_i < 0) return error.DataCorruption;
        const blob_len: usize = @intCast(blob_len_i);
        const off_base = try mod.ckAdd(start, 4);
        const blob_base = try mod.elemOff(off_base, count, 4);
        const blob_end = try mod.ckAdd(blob_base, blob_len);
        var lo: isize = 0;
        var hi: isize = @as(isize, @intCast(count)) - 1;
        var found: ?usize = null;
        while (lo <= hi) {
            const mid: usize = @intCast(@divTrunc(lo + hi, 2));
            switch (try compareStoredTo(input, off_base, blob_base, blob_len, count, mid, probe)) {
                .eq => {
                    found = mid;
                    break;
                },
                .lt => lo = @as(isize, @intCast(mid)) + 1,
                .gt => hi = @as(isize, @intCast(mid)) - 1,
            }
        }
        try input.seek(blob_end);
        if (found) |i| return .{ .found = i };
        return .{ .insert = @intCast(lo) };
    }
    pub fn binaryGet(self: Self, alloc: Allocator, input: *DataInput2, count: usize, pos: usize) DbError!Elem {
        const start = input.pos;
        const blob_len_i = try input.readI32();
        if (blob_len_i < 0) return error.DataCorruption;
        const blob_len: usize = @intCast(blob_len_i);
        if (pos >= count) return error.DataCorruption;
        const off_base = try mod.ckAdd(start, 4);
        const blob_base = try mod.elemOff(off_base, count, 4);
        const blob_end = try mod.ckAdd(blob_base, blob_len);
        try input.seek(try mod.elemOff(off_base, pos, 4));
        const s = try input.readI32();
        const e = if (pos + 1 < count) try input.readI32() else blob_len_i;
        if (s < 0 or e < s or @as(usize, @intCast(e)) > blob_len) return error.DataCorruption;
        try input.seek(try mod.ckAdd(blob_base, @as(usize, @intCast(s))));
        const raw = try input.takeBytes(@intCast(e - s));
        const t = try decodeTuple(alloc, self.schema, raw);
        errdefer value.deinitTuple(alloc, t);
        try input.seek(blob_end);
        return t;
    }
    pub fn rangeCursor(self: Self, alloc: Allocator, input: *DataInput2, count: usize, from: usize, to: usize) DbError!Cursor {
        if (from > to or to > count) return error.DataCorruption;
        return Cursor.init(self, alloc, input, count, from, to);
    }
};

/// Self-delimiting standalone codec for a single tuple: `packInt(len)+encoded`.
pub const TupleSerializer = struct {
    pub const Elem = value.Tuple;
    schema: []const TupleComponent,

    pub fn serialize(self: TupleSerializer, out: *DataOutput2, v: Elem) DbError!void {
        const e = try encodeTuple(out.alloc, self.schema, v);
        defer out.alloc.free(e);
        try out.packInt(@intCast(e.len));
        try out.writeAll(e);
    }
    pub fn deserialize(self: TupleSerializer, alloc: Allocator, input: *DataInput2, _: ?usize) DbError!Elem {
        const len = try input.unpackInt();
        if (len < 0) return error.DataCorruption;
        const raw = try input.takeBytes(@intCast(len));
        return decodeTuple(alloc, self.schema, raw);
    }
    pub fn cloneElem(_: TupleSerializer, alloc: Allocator, v: Elem) DbError!Elem {
        return value.cloneTuple(alloc, v);
    }
    pub fn deinitElem(_: TupleSerializer, alloc: Allocator, v: Elem) void {
        value.deinitTuple(alloc, v);
    }
    pub fn compare(self: TupleSerializer, a: Elem, b: Elem) Order {
        return compareTuple(self.schema, a, b);
    }
    pub fn equals(self: TupleSerializer, a: Elem, b: Elem) bool {
        if (a.len != b.len) return false;
        for (a, b, 0..) |x, y, i| {
            if (!self.schema[i].equalTo(x, y)) return false;
        }
        return true;
    }
    pub fn fixedSize(_: TupleSerializer) ?usize {
        return null;
    }
    pub fn naturalOrder(_: TupleSerializer) bool {
        return false;
    }
    pub fn equalsBySerializedBytes(_: TupleSerializer) bool {
        return true; // memcomparable encoding is canonical
    }
};

// ------------------------------------------------------------------- tests

const testing = std.testing;

fn v_i(x: i32) Value {
    return .{ .int = x };
}
fn v_l(x: i64) Value {
    return .{ .long = x };
}
fn v_s(x: []const u8) Value {
    return .{ .str = x };
}
fn v_b(x: []const u8) Value {
    return .{ .bytes = x };
}

test "tuple prefix ordering (a) < (a,b) + coherence" {
    const a = testing.allocator;
    const f = TupleFormat.of(&.{ .int, .int });
    // sorted: [], (5), (5,-1), (5,0), (6)
    var t0 = [_]Value{};
    var t1 = [_]Value{v_i(5)};
    var t2 = [_]Value{ v_i(5), v_i(-1) };
    var t3 = [_]Value{ v_i(5), v_i(0) };
    var t4 = [_]Value{v_i(6)};
    const sorted = [_]value.Tuple{ &t0, &t1, &t2, &t3, &t4 };
    const g = try f.fromSlice(a, &sorted);
    defer f.deinitGroup(a, g);

    var out = DataOutput2.init(a);
    defer out.deinit();
    var group: TupleFormat.Group = g;
    try f.serializeGroup(&out, &group);
    const bytes = out.bytes();

    var p5x = [_]Value{ v_i(5), v_i(1) }; // not present
    var p7 = [_]Value{v_i(7)}; // not present
    const probes = [_]value.Tuple{ &t0, &t1, &t2, &t3, &p5x, &t4, &p7 };
    for (probes) |key| {
        const obj = f.search(&group, key);
        var inp = DataInput2.init(bytes);
        const byte_res = try f.binarySearch(a, key, &inp, g.len);
        try testing.expect(obj.eql(byte_res));
        try testing.expectEqual(bytes.len, inp.pos);
    }
    for (0..g.len) |pos| {
        var ig = DataInput2.init(bytes);
        const got = try f.binaryGet(a, &ig, g.len, pos);
        defer f.deinitElem(a, got);
        try testing.expect(f.element().equals(got, sorted[pos]));
        try testing.expectEqual(bytes.len, ig.pos);
    }
}

test "tuple str/bytes 0x00 escaping round-trips" {
    const a = testing.allocator;
    const f = TupleFormat.of(&.{ .bytes, .int });
    var t = [_]Value{ v_b(&[_]u8{ 0x00, 0xFF, 0x00 }), v_i(4) };
    const one = [_]value.Tuple{&t};
    const g = try f.fromSlice(a, &one);
    defer f.deinitGroup(a, g);
    const got = try f.get(a, &g, 0);
    defer f.deinitElem(a, got);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0xFF, 0x00 }, got[0].bytes);
    try testing.expectEqual(@as(i32, 4), got[1].int);
}

test "tuple element serializer self-delimits + empty components" {
    const a = testing.allocator;
    const f = TupleFormat.of(&.{ .str, .bytes });
    const ser = f.element();
    var t = [_]Value{ v_s(""), v_b(&.{}) };
    var out = DataOutput2.init(a);
    defer out.deinit();
    try ser.serialize(&out, &t);
    var inp = DataInput2.init(out.bytes());
    const back = try ser.deserialize(a, &inp, null);
    defer ser.deinitElem(a, back);
    try testing.expectEqual(out.bytes().len, inp.pos);
    try testing.expect(ser.equals(&t, back));
    // (s"", b[]) encodes to two terminators = 4 zero bytes
    const enc = try encodeTuple(a, f.schema, &t);
    defer a.free(enc);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, enc);
}

test "tuple string order is code-point (utf-8), not utf-16" {
    const f = TupleFormat.of(&.{.str});
    var bmp = [_]Value{v_s("\u{FF61}")};
    var supp = [_]Value{v_s("\u{10000}")};
    // code-point: U+FF61 < U+10000 (reverse of UTF-16)
    try testing.expectEqual(Order.lt, f.compare(&bmp, &supp));
}
