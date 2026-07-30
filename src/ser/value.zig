//! Heterogeneous row/cell value (Rust `ser/value.rs`, decision D3). Java
//! `Object[]` of boxed primitives / String / byte[] → a closed tagged union.
//! Used by TupleFormat rows and ColumnarValueFormat cells.
//!
//! Ownership: the `str`/`bytes` variants hold OWNED slices. `clone` deep
//! copies (allocating for slices), `deinit` frees them. `Tuple = []Value` is an
//! owned slice of owned values; `cloneTuple`/`deinitTuple` handle it with strong
//! exception safety (a partial clone that later fails is fully freed).

const std = @import("std");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;

/// A single tuple component or columnar cell.
pub const Value = union(enum) {
    long: i64,
    int: i32,
    short: i16,
    byte: i8,
    /// Owned UTF-8 bytes.
    str: []const u8,
    /// Owned raw bytes.
    bytes: []const u8,

    /// Deep clone into `alloc` (slices are duplicated; scalars are copied).
    pub fn clone(self: Value, alloc: Allocator) DbError!Value {
        return switch (self) {
            .str => |s| .{ .str = try alloc.dupe(u8, s) },
            .bytes => |b| .{ .bytes = try alloc.dupe(u8, b) },
            else => self,
        };
    }

    /// Free any owned slice held by this value.
    pub fn deinit(self: Value, alloc: Allocator) void {
        switch (self) {
            .str => |s| alloc.free(s),
            .bytes => |b| alloc.free(b),
            else => {},
        }
    }

    pub fn asLong(self: Value) ?i64 {
        return switch (self) {
            .long => |v| v,
            else => null,
        };
    }
    pub fn asInt(self: Value) ?i32 {
        return switch (self) {
            .int => |v| v,
            else => null,
        };
    }
    pub fn asStr(self: Value) ?[]const u8 {
        return switch (self) {
            .str => |s| s,
            else => null,
        };
    }
    pub fn asBytes(self: Value) ?[]const u8 {
        return switch (self) {
            .bytes => |b| b,
            else => null,
        };
    }
};

/// Prefix-capable tuple: an owned slice of owned values (arity 0..=schema.len).
pub const Tuple = []Value;

/// Deep-clone a tuple into `alloc`. Strong exception safety: on any element
/// clone failure every already-cloned element and the outer slice are freed.
pub fn cloneTuple(alloc: Allocator, t: []const Value) DbError!Tuple {
    const out = try alloc.alloc(Value, t.len);
    var n: usize = 0;
    errdefer {
        for (out[0..n]) |v| v.deinit(alloc);
        alloc.free(out);
    }
    while (n < t.len) : (n += 1) {
        out[n] = try t[n].clone(alloc);
    }
    return out;
}

/// Free a tuple and every value it owns.
pub fn deinitTuple(alloc: Allocator, t: []const Value) void {
    for (t) |v| v.deinit(alloc);
    alloc.free(t);
}

const testing = std.testing;

test "value clone/deinit round-trips owned slices" {
    const a = testing.allocator;
    const v = Value{ .str = "hello" };
    const c = try v.clone(a);
    defer c.deinit(a);
    try testing.expectEqualStrings("hello", c.str);
    try testing.expect(c.str.ptr != v.str.ptr);

    const scalar = Value{ .long = 42 };
    const sc = try scalar.clone(a);
    sc.deinit(a); // no-op
    try testing.expectEqual(@as(i64, 42), sc.long);
}

test "cloneTuple/deinitTuple" {
    const a = testing.allocator;
    var src = [_]Value{ .{ .int = 1 }, .{ .str = "x" }, .{ .bytes = "\x00\x01" } };
    const t = try cloneTuple(a, &src);
    defer deinitTuple(a, t);
    try testing.expectEqual(@as(usize, 3), t.len);
    try testing.expectEqualStrings("x", t[1].str);
}
