//! `ColumnarValueFormat` — column-major (Arrow-style) group format over a fixed
//! schema of fixed-width integral columns (Java `ColumnarValueFormat`, rule R7).
//! A group of `n` fixed-arity rows is stored COLUMN-BY-COLUMN so a scan over one
//! column reads only that column's contiguous byte run. Schema is NOT on the
//! wire. Ported from `mapdb-rust-store/src/ser/columnar.rs`.
//!
//! Wire (`n` rows external, widths `w0,w1,..`):
//!   `[col0: n*w0][col1: n*w1] ... [col(C-1): n*w(C-1)]`, each cell big-endian.
//! Cell `(row i, col c)` lives at `start + n*cumWidth[c] + i*w_c`; group ends at
//! `start + n*row_width`. Byte side DECODES each probed cell and compares with
//! the SIGNED per-column order (raw memcmp would misorder negatives).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const mod = @import("mod.zig");
const vmod = @import("value.zig");
const Value = vmod.Value;
const SearchResult = mod.SearchResult;

/// Fixed-width integral column type: big-endian on the wire, signed order.
pub const ColumnType = enum {
    long,
    int,
    short,
    byte,

    pub fn width(self: ColumnType) usize {
        return switch (self) {
            .long => 8,
            .int => 4,
            .short => 2,
            .byte => 1,
        };
    }
};

/// Row deep-clone codec (rows are owned `[]Value`).
const RowCodec = struct {
    pub fn cloneElem(_: RowCodec, alloc: Allocator, v: []Value) DbError![]Value {
        return vmod.cloneTuple(alloc, v);
    }
    pub fn deinitElem(_: RowCodec, alloc: Allocator, v: []Value) void {
        vmod.deinitTuple(alloc, v);
    }
};
const rowCodec = RowCodec{};

fn cellI64(v: Value) i64 {
    return switch (v) {
        .long => |x| x,
        .int => |x| x,
        .short => |x| x,
        .byte => |x| x,
        .str, .bytes => unreachable, // caller schema error (columns are integral)
    };
}

fn cellAs(t: ColumnType, v: Value) i64 {
    const n = cellI64(v);
    return switch (t) {
        .long => n,
        .int => @as(i32, @truncate(n)),
        .short => @as(i16, @truncate(n)),
        .byte => @as(i8, @truncate(n)),
    };
}

fn writeCell(out: *DataOutput2, t: ColumnType, v: Value) DbError!void {
    const n = cellI64(v);
    switch (t) {
        .long => try out.writeI64(n),
        .int => try out.writeI32(@truncate(n)),
        .short => try out.writeI16(@truncate(n)),
        .byte => try out.writeU8(@bitCast(@as(i8, @truncate(n)))),
    }
}

fn readCell(input: *DataInput2, t: ColumnType) DbError!Value {
    return switch (t) {
        .long => .{ .long = try input.readI64() },
        .int => .{ .int = try input.readI32() },
        .short => .{ .short = try input.readI16() },
        .byte => .{ .byte = try input.readI8() },
    };
}

fn compareCell(t: ColumnType, a: Value, b: Value) Order {
    return std.math.order(cellAs(t, a), cellAs(t, b));
}

/// Columnar value format over a fixed schema. Element = full-arity row
/// (`[]Value`), group = `[][]Value`. Schema slice is BORROWED (no owned alloc).
pub const ColumnarValueFormat = struct {
    const Self = @This();
    pub const Elem = vmod.Tuple;
    pub const Group = [][]Value;
    pub const Cursor = RowCursor;

    schema: []const ColumnType,
    row_ser: RowSerializer,

    pub fn of(columns: []const ColumnType) Self {
        std.debug.assert(columns.len >= 1);
        return .{ .schema = columns, .row_ser = .{ .schema = columns, .row_width = rowWidthOf(columns) } };
    }

    pub fn columnCount(self: Self) usize {
        return self.schema.len;
    }
    pub fn columnType(self: Self, col: usize) ColumnType {
        return self.schema[col];
    }
    pub fn rowWidth(self: Self) usize {
        return self.row_ser.row_width;
    }
    pub fn element(self: Self) RowSerializer {
        return self.row_ser;
    }

    fn cumWidthBefore(self: Self, col: usize) usize {
        var s: usize = 0;
        for (self.schema[0..col]) |c| s += c.width();
        return s;
    }
    fn cellOffset(self: Self, start: usize, nrows: usize, col: usize, row: usize) DbError!usize {
        const cols_before = std.math.mul(usize, nrows, self.cumWidthBefore(col)) catch return error.DataCorruption;
        const within = std.math.mul(usize, row, self.schema[col].width()) catch return error.DataCorruption;
        const p = std.math.add(usize, start, cols_before) catch return error.DataCorruption;
        return std.math.add(usize, p, within) catch return error.DataCorruption;
    }
    fn groupEnd(self: Self, start: usize, nrows: usize) DbError!usize {
        const bytes = std.math.mul(usize, nrows, self.rowWidth()) catch return error.DataCorruption;
        return std.math.add(usize, start, bytes) catch return error.DataCorruption;
    }
    fn checkArity(self: Self, row: []const Value) void {
        std.debug.assert(row.len == self.schema.len);
    }
    fn compareRows(self: Self, a: []const Value, b: []const Value) Order {
        self.checkArity(a);
        self.checkArity(b);
        for (self.schema, 0..) |t, c| {
            const cmp = compareCell(t, a[c], b[c]);
            if (cmp != .eq) return cmp;
        }
        return .eq;
    }
    fn compareRowAt(self: Self, input: *DataInput2, start: usize, nrows: usize, row: usize, key: []const Value) DbError!Order {
        for (self.schema, 0..) |t, c| {
            try input.seek(try self.cellOffset(start, nrows, c, row));
            const cell = try readCell(input, t);
            const cmp = compareCell(t, cell, key[c]);
            if (cmp != .eq) return cmp;
        }
        return .eq;
    }

    /// Zero-length groups are allocator-owned: freeable by `deinitGroup`.
    pub fn empty(_: Self, alloc: Allocator) DbError!Group {
        return alloc.alloc(std.meta.Child(Group), 0);
    }
    pub fn size(_: Self, g: *const Group) usize {
        return g.len;
    }
    pub fn compare(self: Self, a: Elem, b: Elem) Order {
        return self.compareRows(a, b);
    }
    /// Logical row equality (btree CAS ops).
    pub fn equalsElem(self: Self, a: Elem, b: Elem) bool {
        return self.compareRows(a, b) == .eq;
    }
    /// Columnar rows use a per-column composite order, not element natural order.
    pub fn naturalOrder(_: Self) bool {
        return false;
    }
    pub fn cloneElem(_: Self, alloc: Allocator, v: Elem) DbError!Elem {
        return vmod.cloneTuple(alloc, v);
    }
    pub fn deinitElem(_: Self, alloc: Allocator, v: Elem) void {
        vmod.deinitTuple(alloc, v);
    }
    pub fn get(_: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Elem {
        return vmod.cloneTuple(alloc, g.*[pos]);
    }
    pub fn search(self: Self, g: *const Group, key: Elem) SearchResult {
        self.checkArity(key);
        var lo: isize = 0;
        var hi: isize = @as(isize, @intCast(g.len)) - 1;
        while (lo <= hi) {
            const mid: usize = @intCast(@divTrunc(lo + hi, 2));
            switch (self.compareRows(g.*[mid], key)) {
                .eq => return .{ .found = mid },
                .lt => lo = @as(isize, @intCast(mid)) + 1,
                .gt => hi = @as(isize, @intCast(mid)) - 1,
            }
        }
        return .{ .insert = @intCast(lo) };
    }
    pub fn insert(self: Self, alloc: Allocator, g: *const Group, pos: usize, v: Elem) DbError!Group {
        self.checkArity(v);
        return mod.deepInsert([]Value, alloc, rowCodec, g.*, pos, v);
    }
    pub fn set(self: Self, alloc: Allocator, g: *const Group, pos: usize, v: Elem) DbError!Group {
        self.checkArity(v);
        return mod.deepSet([]Value, alloc, rowCodec, g.*, pos, v);
    }
    pub fn delete(_: Self, alloc: Allocator, g: *const Group, pos: usize) DbError!Group {
        return mod.deepDelete([]Value, alloc, rowCodec, g.*, pos);
    }
    pub fn copyRange(_: Self, alloc: Allocator, g: *const Group, from: usize, to: usize) DbError!Group {
        return mod.deepCopyRange([]Value, alloc, rowCodec, g.*, from, to);
    }
    pub fn fromSlice(self: Self, alloc: Allocator, values: []const Elem) DbError!Group {
        for (values) |row| self.checkArity(row);
        return mod.deepClone([]Value, alloc, rowCodec, values);
    }
    pub fn cloneGroup(_: Self, alloc: Allocator, g: *const Group) DbError!Group {
        return mod.deepClone([]Value, alloc, rowCodec, g.*);
    }
    pub fn deinitGroup(_: Self, alloc: Allocator, g: Group) void {
        mod.deepDeinit([]Value, alloc, rowCodec, g);
    }

    pub fn serializeGroup(self: Self, out: *DataOutput2, g: *const Group) DbError!void {
        for (self.schema, 0..) |t, c| {
            for (g.*) |row| try writeCell(out, t, row[c]);
        }
    }
    pub fn deserializeGroup(self: Self, alloc: Allocator, input: *DataInput2, count: usize) DbError!Group {
        // Bound the allocation by the known group extent (count * row_width)
        // BEFORE allocating from the tainted count.
        if (try mod.ckMul(count, self.rowWidth()) > input.remaining()) return error.DataCorruption;
        const rows = try alloc.alloc([]Value, count);
        var built: usize = 0;
        errdefer {
            for (rows[0..built]) |r| alloc.free(r);
            alloc.free(rows);
        }
        while (built < count) : (built += 1) {
            rows[built] = try alloc.alloc(Value, self.schema.len);
            for (rows[built]) |*slot| slot.* = .{ .byte = 0 }; // placeholders (integral, no owned mem)
        }
        for (self.schema, 0..) |t, c| {
            for (rows) |row| row[c] = try readCell(input, t);
        }
        return rows;
    }

    pub fn supportsBinary(_: Self) bool {
        return true;
    }
    pub fn binaryGet(self: Self, alloc: Allocator, input: *DataInput2, count: usize, pos: usize) DbError!Elem {
        if (pos >= count) return error.DataCorruption;
        const start = input.pos;
        const row = try alloc.alloc(Value, self.schema.len);
        errdefer alloc.free(row);
        for (self.schema, 0..) |t, c| {
            try input.seek(try self.cellOffset(start, count, c, pos));
            row[c] = try readCell(input, t);
        }
        try input.seek(try self.groupEnd(start, count));
        return row;
    }
    pub fn binarySearch(self: Self, _: Allocator, key: Elem, input: *DataInput2, count: usize) DbError!SearchResult {
        if (key.len != self.schema.len) return error.DataCorruption;
        // Rust guard ported: an isize-overflowing count is corruption, not a
        // ReleaseSafe @intCast panic.
        if (count > std.math.maxInt(isize)) return error.DataCorruption;
        const start = input.pos;
        var lo: isize = 0;
        var hi: isize = @as(isize, @intCast(count)) - 1;
        var found: ?usize = null;
        while (lo <= hi) {
            const mid: usize = @intCast(@divTrunc(lo + hi, 2));
            switch (try self.compareRowAt(input, start, count, mid, key)) {
                .eq => {
                    found = mid;
                    break;
                },
                .lt => lo = @as(isize, @intCast(mid)) + 1,
                .gt => hi = @as(isize, @intCast(mid)) - 1,
            }
        }
        try input.seek(try self.groupEnd(start, count));
        if (found) |i| return .{ .found = i };
        return .{ .insert = @intCast(lo) };
    }
    pub fn rangeCursor(self: Self, alloc: Allocator, input: *DataInput2, count: usize, from: usize, to: usize) DbError!Cursor {
        if (from > to or to > count) return error.DataCorruption;
        return .{ .fmt = self, .input = input, .alloc = alloc, .start = input.pos, .count = count, .to = to, .idx = from };
    }

    /// Cursor over ONE column's values for rows `[from, to)`: reads only that
    /// column's contiguous byte run, never the whole group. On exhaustion the
    /// input is left at group end.
    pub fn columnCursor(self: Self, alloc: Allocator, input: *DataInput2, nrows: usize, col: usize, from: usize, to: usize) DbError!ColumnCursor {
        if (col >= self.schema.len) return error.DataCorruption;
        if (from > to or to > nrows) return error.DataCorruption;
        return .{ .fmt = self, .input = input, .alloc = alloc, .start = input.pos, .count = nrows, .col = col, .t = self.schema[col], .to = to, .idx = from };
    }
};

fn rowWidthOf(columns: []const ColumnType) usize {
    var s: usize = 0;
    for (columns) |c| s += c.width();
    return s;
}

/// Whole-row cursor: one decode (seek each column cell) per row.
pub const RowCursor = struct {
    fmt: ColumnarValueFormat,
    input: *DataInput2,
    alloc: Allocator,
    start: usize,
    count: usize,
    to: usize,
    idx: usize,
    started: bool = false,
    cur: ?[]Value = null,
    exhausted: bool = false,

    fn freeCur(self: *RowCursor) void {
        if (self.cur) |c| vmod.deinitTuple(self.alloc, c);
        self.cur = null;
    }
    pub fn next(self: *RowCursor) DbError!bool {
        if (self.exhausted) return false;
        if (self.started) {
            self.idx += 1;
        } else {
            self.started = true;
        }
        if (self.idx >= self.to) {
            self.exhausted = true;
            self.freeCur();
            try self.input.seek(try self.fmt.groupEnd(self.start, self.count));
            return false;
        }
        self.freeCur();
        const row = try self.alloc.alloc(Value, self.fmt.schema.len);
        errdefer self.alloc.free(row);
        for (self.fmt.schema, 0..) |t, c| {
            try self.input.seek(try self.fmt.cellOffset(self.start, self.count, c, self.idx));
            row[c] = try readCell(self.input, t);
        }
        self.cur = row;
        return true;
    }
    pub fn index(self: *const RowCursor) usize {
        return self.idx;
    }
    pub fn value(self: *const RowCursor, alloc: Allocator) DbError![]Value {
        return vmod.cloneTuple(alloc, self.cur.?);
    }
    pub fn deinit(self: *RowCursor) void {
        self.freeCur();
    }
};

/// Single-column cursor: reads only column `col`'s contiguous run.
pub const ColumnCursor = struct {
    fmt: ColumnarValueFormat,
    input: *DataInput2,
    alloc: Allocator,
    start: usize,
    count: usize,
    col: usize,
    t: ColumnType,
    to: usize,
    idx: usize,
    started: bool = false,
    cur: ?Value = null,
    exhausted: bool = false,

    pub fn next(self: *ColumnCursor) DbError!bool {
        if (self.exhausted) return false;
        if (self.started) {
            self.idx += 1;
        } else {
            self.started = true;
        }
        if (self.idx >= self.to) {
            self.exhausted = true;
            self.cur = null;
            try self.input.seek(try self.fmt.groupEnd(self.start, self.count));
            return false;
        }
        try self.input.seek(try self.fmt.cellOffset(self.start, self.count, self.col, self.idx));
        self.cur = try readCell(self.input, self.t);
        return true;
    }
    pub fn index(self: *const ColumnCursor) usize {
        return self.idx;
    }
    /// Cells are integral (no owned memory) so this is a plain copy.
    pub fn value(self: *const ColumnCursor, _: Allocator) DbError!Value {
        return self.cur.?;
    }
    pub fn deinit(_: *ColumnCursor) void {}
};

/// Standalone single-row codec (row-major fixed-width cells).
pub const RowSerializer = struct {
    pub const Elem = vmod.Tuple;
    schema: []const ColumnType,
    row_width: usize,

    pub fn serialize(self: RowSerializer, out: *DataOutput2, v: Elem) DbError!void {
        std.debug.assert(v.len == self.schema.len);
        for (self.schema, 0..) |t, c| try writeCell(out, t, v[c]);
    }
    pub fn deserialize(self: RowSerializer, alloc: Allocator, input: *DataInput2, _: ?usize) DbError!Elem {
        const row = try alloc.alloc(Value, self.schema.len);
        errdefer alloc.free(row);
        for (self.schema, 0..) |t, c| row[c] = try readCell(input, t);
        return row;
    }
    pub fn cloneElem(_: RowSerializer, alloc: Allocator, v: Elem) DbError!Elem {
        return vmod.cloneTuple(alloc, v);
    }
    pub fn deinitElem(_: RowSerializer, alloc: Allocator, v: Elem) void {
        vmod.deinitTuple(alloc, v);
    }
    pub fn compare(self: RowSerializer, a: Elem, b: Elem) Order {
        std.debug.assert(a.len == self.schema.len and b.len == self.schema.len);
        for (self.schema, 0..) |t, c| {
            const cmp = compareCell(t, a[c], b[c]);
            if (cmp != .eq) return cmp;
        }
        return .eq;
    }
    pub fn equals(self: RowSerializer, a: Elem, b: Elem) bool {
        return self.compare(a, b) == .eq;
    }
    pub fn fixedSize(self: RowSerializer) ?usize {
        return self.row_width;
    }
    pub fn naturalOrder(_: RowSerializer) bool {
        return false;
    }
    pub fn equalsBySerializedBytes(_: RowSerializer) bool {
        return true;
    }
};

// ------------------------------------------------------------------- tests

const testing = std.testing;

fn vL(x: i64) Value {
    return .{ .long = x };
}
fn vI(x: i32) Value {
    return .{ .int = x };
}
fn vS(x: i16) Value {
    return .{ .short = x };
}
fn vB(x: i8) Value {
    return .{ .byte = x };
}

test "columnar column-major wire layout + round-trip" {
    const a = testing.allocator;
    const f = ColumnarValueFormat.of(&.{ .long, .short });
    var r0 = [_]Value{ vL(1), vS(10) };
    var r1 = [_]Value{ vL(2), vS(20) };
    var r2 = [_]Value{ vL(3), vS(30) };
    var rows = [_][]Value{ &r0, &r1, &r2 };
    var group: ColumnarValueFormat.Group = &rows;

    var out = DataOutput2.init(a);
    defer out.deinit();
    try f.serializeGroup(&out, &group);
    const bytes = out.bytes();
    try testing.expectEqual(@as(usize, 30), bytes.len); // 3*8 + 3*2
    try testing.expectEqualSlices(u8, &std.mem.toBytes(std.mem.nativeToBig(i64, 1)), bytes[0..8]);
    try testing.expectEqualSlices(u8, &std.mem.toBytes(std.mem.nativeToBig(i16, 30)), bytes[28..30]);

    var inp = DataInput2.init(bytes);
    const back = try f.deserializeGroup(a, &inp, 3);
    defer f.deinitGroup(a, back);
    try testing.expectEqual(@as(i64, 2), back[1][0].long);
    try testing.expectEqual(@as(i16, 30), back[2][1].short);
    try testing.expectEqual(bytes.len, inp.pos);
}

fn serGroup(f: ColumnarValueFormat, a: Allocator, rows: [][]Value) ![]u8 {
    var out = DataOutput2.init(a);
    defer out.deinit();
    var group: ColumnarValueFormat.Group = rows;
    try f.serializeGroup(&out, &group);
    return out.copyBytes(a);
}

test "columnar signed order coherence all widths" {
    const a = testing.allocator;
    const f = ColumnarValueFormat.of(&.{ .long, .int, .short, .byte });
    var rows_buf = [_][4]Value{
        .{ vL(std.math.minInt(i64)), vI(0), vS(0), vB(0) },
        .{ vL(-1), vI(std.math.minInt(i32)), vS(-1), vB(-128) },
        .{ vL(-1), vI(std.math.minInt(i32)), vS(-1), vB(-1) },
        .{ vL(-1), vI(-1), vS(std.math.minInt(i16)), vB(0) },
        .{ vL(0), vI(0), vS(0), vB(0) },
        .{ vL(1), vI(-1), vS(-1), vB(-1) },
        .{ vL(std.math.maxInt(i64)), vI(std.math.maxInt(i32)), vS(std.math.maxInt(i16)), vB(127) },
    };
    var rows: [rows_buf.len][]Value = undefined;
    for (&rows_buf, 0..) |*rb, i| rows[i] = rb;
    std.mem.sort([]Value, &rows, f, struct {
        fn lt(fmt: ColumnarValueFormat, x: []Value, y: []Value) bool {
            return fmt.compareRows(x, y) == .lt;
        }
    }.lt);
    var group: ColumnarValueFormat.Group = &rows;
    const bytes = try serGroup(f, a, &rows);
    defer a.free(bytes);

    var p0 = [_]Value{ vL(std.math.minInt(i64)), vI(0), vS(0), vB(0) };
    var p1 = [_]Value{ vL(-1), vI(std.math.minInt(i32)), vS(-1), vB(-1) };
    var p2 = [_]Value{ vL(-1), vI(-2), vS(0), vB(0) };
    var p3 = [_]Value{ vL(0), vI(0), vS(0), vB(1) };
    const probes = [_][]Value{ &p0, &p1, &p2, &p3 };
    for (probes) |key| {
        const obj = f.search(&group, key);
        var inp = DataInput2.init(bytes);
        const byte_res = try f.binarySearch(a, key, &inp, rows.len);
        try testing.expect(obj.eql(byte_res));
        try testing.expectEqual(bytes.len, inp.pos);
    }
    for (0..rows.len) |pos| {
        var ig = DataInput2.init(bytes);
        const got = try f.binaryGet(a, &ig, rows.len, pos);
        defer f.deinitElem(a, got);
        try testing.expect(f.compare(got, rows[pos]) == .eq);
        try testing.expectEqual(bytes.len, ig.pos);
    }
}

test "columnar column cursor reads only its column" {
    const a = testing.allocator;
    const f = ColumnarValueFormat.of(&.{ .long, .int, .short });
    var rb = [_][3]Value{
        .{ vL(1000), vI(0), vS(0) },
        .{ vL(1001), vI(-1), vS(7) },
        .{ vL(1002), vI(-2), vS(14) },
        .{ vL(1003), vI(-3), vS(21) },
        .{ vL(1004), vI(-4), vS(28) },
    };
    var rows: [rb.len][]Value = undefined;
    for (&rb, 0..) |*r, i| rows[i] = r;
    const bytes = try serGroup(f, a, &rows);
    defer a.free(bytes);
    try testing.expectEqual(@as(usize, 5 * 14), bytes.len);

    var inp = DataInput2.init(bytes);
    var cur = try f.columnCursor(a, &inp, 5, 1, 0, 5);
    defer cur.deinit();
    var got = std.ArrayList(i32){};
    defer got.deinit(a);
    while (try cur.next()) {
        const v = try cur.value(a);
        try got.append(a, v.int);
    }
    try testing.expectEqualSlices(i32, &.{ 0, -1, -2, -3, -4 }, got.items);
    try testing.expectEqual(bytes.len, inp.pos);
}
