//! The DB name catalog — a `Map<String,String>` stored at recid 1, byte-for-byte
//! compatible with Java `DB.CATALOG_SER`. Ported from the
//! Rust port `mapdb-rust-store/src/db/catalog.rs`; the golden byte vectors are the
//! same Rust-verified-against-Java values.
//!
//! ## Wire format ("MDBC" v1)
//! ```text
//! magic:   u32 big-endian  0x4D444243 ("MDBC")
//! version: u32 big-endian  1
//! repr:    u8              0            (REPR_INLINE)
//! count:   packInt         number of entries
//! entries: count × (key, value)         sorted ascending by key
//!   each string = packInt(utf8-byte-len) ++ utf8 bytes  (Serializers.STRING)
//! ```
//! `packInt`/`packLong` put 7 data bits per byte, most-significant group first,
//! and set the high bit `0x80` on the TERMINAL byte (NOT LEB128). An empty
//! catalog is exactly the 10 bytes `4D 44 42 43 00 00 00 01 00 80`.
//!
//! [`NameCatalog`] keeps its pairs sorted ascending by key (unsigned byte order),
//! which equals Java `TreeMap` natural (`String.compareTo`, UTF-16) order because
//! all catalog keys are restricted ASCII (`[A-Za-z0-9._-]#…`). Sorting on insert
//! keeps `serialize` allocation-free (the Serializer contract passes no allocator
//! to `serialize`).
//!
//! The decoder is defensive: it rejects records shorter than
//! 10 bytes, a bad magic/version/representation, a count over the max, a string
//! crossing the record end, duplicate keys, and any trailing or short bytes;
//! it bounds every length before allocating.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;

/// Reserved recid holding the name catalog (Java `DB.RECID_CATALOG`).
pub const RECID_CATALOG: u64 = 1;

const CATALOG_MAGIC: u32 = 0x4D44_4243; // "MDBC"
const CATALOG_VERSION: i32 = 1;
const REPR_INLINE: u8 = 0;
const MAX_CATALOG_ENTRIES: u64 = 10_000_000;
/// magic(4) + version(4) + repr(1) + at least one count byte.
const MIN_CATALOG_LEN: usize = 10;

/// A sorted `name#param -> value` string map, owned by one allocator. Every key
/// and value is an allocator-owned copy; `deinit` frees them all.
pub const NameCatalog = struct {
    pub const Pair = struct { key: []const u8, value: []const u8 };

    pairs: std.ArrayListUnmanaged(Pair) = .empty,

    pub fn init() NameCatalog {
        return .{};
    }

    pub fn deinit(self: *NameCatalog, alloc: Allocator) void {
        for (self.pairs.items) |p| {
            alloc.free(p.key);
            alloc.free(p.value);
        }
        self.pairs.deinit(alloc);
    }

    pub fn len(self: *const NameCatalog) usize {
        return self.pairs.items.len;
    }

    /// Binary-search for `key`; `.found` = index, `.insert` = insertion point.
    fn find(self: *const NameCatalog, key: []const u8) union(enum) { found: usize, insert: usize } {
        var lo: usize = 0;
        var hi: usize = self.pairs.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, self.pairs.items[mid].key, key)) {
                .eq => return .{ .found = mid },
                .lt => lo = mid + 1,
                .gt => hi = mid,
            }
        }
        return .{ .insert = lo };
    }

    /// Borrowed value for `key`, or null.
    pub fn get(self: *const NameCatalog, key: []const u8) ?[]const u8 {
        return switch (self.find(key)) {
            .found => |i| self.pairs.items[i].value,
            .insert => null,
        };
    }

    pub fn contains(self: *const NameCatalog, key: []const u8) bool {
        return self.get(key) != null;
    }

    /// Insert or replace `key -> value` (copies both). Replaces the value if the
    /// key exists (freeing the old value); keeps the pairs sorted.
    pub fn put(self: *NameCatalog, alloc: Allocator, key: []const u8, value: []const u8) DbError!void {
        switch (self.find(key)) {
            .found => |i| {
                const nv = try alloc.dupe(u8, value);
                alloc.free(self.pairs.items[i].value);
                self.pairs.items[i].value = nv;
            },
            .insert => |i| {
                const k = try alloc.dupe(u8, key);
                errdefer alloc.free(k);
                const v = try alloc.dupe(u8, value);
                errdefer alloc.free(v);
                try self.pairs.insert(alloc, i, .{ .key = k, .value = v });
            },
        }
    }

    /// Remove `key`; true if it was present.
    pub fn remove(self: *NameCatalog, alloc: Allocator, key: []const u8) bool {
        switch (self.find(key)) {
            .found => |i| {
                const p = self.pairs.orderedRemove(i);
                alloc.free(p.key);
                alloc.free(p.value);
                return true;
            },
            .insert => return false,
        }
    }

    /// Remove every pair whose key starts with `prefix`; returns the count.
    pub fn removePrefix(self: *NameCatalog, alloc: Allocator, prefix: []const u8) usize {
        var removed: usize = 0;
        var i: usize = 0;
        while (i < self.pairs.items.len) {
            if (std.mem.startsWith(u8, self.pairs.items[i].key, prefix)) {
                const p = self.pairs.orderedRemove(i);
                alloc.free(p.key);
                alloc.free(p.value);
                removed += 1;
            } else i += 1;
        }
        return removed;
    }

    /// A deep copy owned by `alloc`.
    pub fn clone(self: *const NameCatalog, alloc: Allocator) DbError!NameCatalog {
        var out = NameCatalog.init();
        errdefer out.deinit(alloc);
        try out.pairs.ensureTotalCapacity(alloc, self.pairs.items.len);
        for (self.pairs.items) |p| {
            const k = try alloc.dupe(u8, p.key);
            errdefer alloc.free(k);
            const v = try alloc.dupe(u8, p.value);
            out.pairs.appendAssumeCapacity(.{ .key = k, .value = v });
        }
        return out;
    }

    pub fn eql(self: *const NameCatalog, other: *const NameCatalog) bool {
        if (self.pairs.items.len != other.pairs.items.len) return false;
        for (self.pairs.items, other.pairs.items) |a, b| {
            if (!std.mem.eql(u8, a.key, b.key) or !std.mem.eql(u8, a.value, b.value)) return false;
        }
        return true;
    }
};

/// Read a `packInt`-framed UTF-8 string bounded by `end` (a record offset). The
/// length is a `u32`-domain value (these fields were written with `packInt`); a
/// larger packed value is corruption, not a truncated length.
fn readBoundedString(alloc: Allocator, input: *DataInput2, end: usize) DbError![]const u8 {
    const raw = try readBoundedPacked(input, end);
    if (raw > std.math.maxInt(u32)) return error.DataCorruption;
    const strlen: usize = @intCast(raw);
    const stop = std.math.add(usize, input.pos, strlen) catch return error.DataCorruption;
    if (stop > end) return error.DataCorruption;
    const src = try input.takeBytes(strlen);
    return alloc.dupe(u8, src);
}

/// A valid packed `u64` occupies at most `ceil(64/7) == 10` bytes; a longer run
/// is corruption, not a value whose high bits we may silently discard.
const MAX_PACKED_BYTES: usize = 10;

/// Decode a packed varint bounded so it cannot read past `end` (Java
/// `DB.readBoundedPackedLong`). Same MSB-first bit layout as `unpackLong`, but —
/// mirroring the hardened Rust decoder — rejects a non-canonical leading
/// zero group, an overlong (>10-byte / unterminated) run, and any value that
/// overflows 64 bits, instead of silently wrapping.
fn readBoundedPacked(input: *DataInput2, end: usize) DbError!u64 {
    var ret: u64 = 0;
    var i: usize = 0;
    while (i < MAX_PACKED_BYTES) : (i += 1) {
        if (input.pos >= end) return error.DataCorruption;
        const v = try input.readU8();
        const group: u64 = v & 0x7F;
        const terminal = (v & 0x80) != 0;
        // An MSB-first packed value never begins with an all-zero group unless
        // the value IS zero (a single terminal byte).
        if (i == 0 and group == 0 and !terminal) return error.DataCorruption;
        // Checked accumulation on EVERY byte (MSB-first: overflow can land on any
        // byte): a run whose value exceeds 64 bits is corruption.
        ret = std.math.mul(u64, ret, 128) catch return error.DataCorruption;
        ret = std.math.add(u64, ret, group) catch return error.DataCorruption;
        if (terminal) return ret;
    }
    return error.DataCorruption; // overlong / unterminated
}

/// The catalog codec (Java `DB.CATALOG_SER`): a zero-sized element serializer
/// with `Elem == NameCatalog`, used only at recid 1 by the DB facade.
pub const CatalogSer = struct {
    pub const Elem = NameCatalog;
    pub const instance: CatalogSer = .{};

    pub fn serialize(_: CatalogSer, out: *DataOutput2, cat: NameCatalog) DbError!void {
        try out.writeU32(CATALOG_MAGIC);
        try out.writeI32(CATALOG_VERSION);
        try out.writeU8(REPR_INLINE);
        try out.packInt(@intCast(cat.pairs.items.len));
        // Already sorted ascending by key == Java TreeMap natural order.
        for (cat.pairs.items) |p| {
            try out.packInt(@intCast(p.key.len));
            try out.writeAll(p.key);
            try out.packInt(@intCast(p.value.len));
            try out.writeAll(p.value);
        }
    }

    pub fn deserialize(_: CatalogSer, alloc: Allocator, input: *DataInput2, size: ?usize) DbError!NameCatalog {
        // The framed record size is REQUIRED — the catalog is a bounded record,
        // and `input.len()` is wrong whenever `input.pos > 0` (N4). Recid-1 reads
        // always supply it.
        const total = size orelse return error.DataCorruption;
        if (total < MIN_CATALOG_LEN) return error.DataCorruption;
        const start = input.pos;
        const end = std.math.add(usize, start, total) catch return error.DataCorruption;
        if (end > input.len()) return error.DataCorruption;

        const magic: u32 = @bitCast(try input.readI32());
        if (magic != CATALOG_MAGIC) return error.DataCorruption;
        const version = try input.readI32();
        if (version != CATALOG_VERSION) return error.DataCorruption;
        const repr = try input.readU8();
        if (repr != REPR_INLINE) return error.DataCorruption;
        const count = try readBoundedPacked(input, end);
        if (count > MAX_CATALOG_ENTRIES) return error.DataCorruption;

        var cat = NameCatalog.init();
        errdefer cat.deinit(alloc);
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            const key = try readBoundedString(alloc, input, end);
            errdefer alloc.free(key);
            const value = try readBoundedString(alloc, input, end);
            errdefer alloc.free(value);
            // Duplicate keys are corruption (the sorted map rejects a re-insert).
            switch (cat.find(key)) {
                .found => return error.DataCorruption,
                .insert => |ins| try cat.pairs.insert(alloc, ins, .{ .key = key, .value = value }),
            }
        }
        // No trailing or short bytes (Java asserts pos == start+size).
        if (input.pos != end) return error.DataCorruption;
        return cat;
    }

    pub fn cloneElem(_: CatalogSer, alloc: Allocator, cat: NameCatalog) DbError!NameCatalog {
        return cat.clone(alloc);
    }
    pub fn deinitElem(_: CatalogSer, alloc: Allocator, cat: NameCatalog) void {
        var c = cat;
        c.deinit(alloc);
    }
    pub fn compare(_: CatalogSer, _: NameCatalog, _: NameCatalog) Order {
        return .eq; // never used as a key
    }
    pub fn equals(_: CatalogSer, a: NameCatalog, b: NameCatalog) bool {
        return a.eql(&b);
    }
    pub fn fixedSize(_: CatalogSer) ?usize {
        return null;
    }
    pub fn equalsBySerializedBytes(_: CatalogSer) bool {
        return true;
    }
};

// ------------------------------------------------------------------- tests

const testing = std.testing;

fn encode(alloc: Allocator, cat: *const NameCatalog) ![]u8 {
    var out = DataOutput2.init(alloc);
    defer out.deinit();
    try CatalogSer.instance.serialize(&out, cat.*);
    return out.copyBytes(alloc);
}

fn decode(alloc: Allocator, bytes: []const u8) DbError!NameCatalog {
    var input = DataInput2.init(bytes);
    return CatalogSer.instance.deserialize(alloc, &input, bytes.len);
}

test "empty catalog golden bytes (Java 10-byte header)" {
    const a = testing.allocator;
    var cat = NameCatalog.init();
    defer cat.deinit(a);
    const got = try encode(a, &cat);
    defer a.free(got);
    try testing.expectEqualSlices(u8, &.{ 0x4D, 0x44, 0x42, 0x43, 0x00, 0x00, 0x00, 0x01, 0x00, 0x80 }, got);
}

test "single entry golden bytes (al#type=AtomicLong)" {
    const a = testing.allocator;
    var cat = NameCatalog.init();
    defer cat.deinit(a);
    try cat.put(a, "al#type", "AtomicLong");
    // Laid out one catalog record per line: header, then `len key`, then
    // `len value`. The formatter's column packing hides that structure.
    // zig fmt: off
    const expected = [_]u8{
        0x4D, 0x44, 0x42, 0x43, 0x00, 0x00, 0x00, 0x01, 0x00, 0x81,
        0x87, 'a', 'l', '#', 't', 'y', 'p', 'e',
        0x8A, 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'n', 'g',
    };
    // zig fmt: on
    const got = try encode(a, &cat);
    defer a.free(got);
    try testing.expectEqualSlices(u8, &expected, got);
    var back = try decode(a, got);
    defer back.deinit(a);
    try testing.expect(back.eql(&cat));
}

test "entries serialize in sorted order regardless of insertion order" {
    const a = testing.allocator;
    var x = NameCatalog.init();
    defer x.deinit(a);
    try x.put(a, "b", "2");
    try x.put(a, "a", "1");
    var y = NameCatalog.init();
    defer y.deinit(a);
    try y.put(a, "a", "1");
    try y.put(a, "b", "2");
    const bx = try encode(a, &x);
    defer a.free(bx);
    const by = try encode(a, &y);
    defer a.free(by);
    try testing.expectEqualSlices(u8, by, bx);
    // "a" (0x61) sorts before "b" (0x62); first key byte after count.
    try testing.expectEqual(@as(u8, 0x81), bx[10]);
    try testing.expectEqual(@as(u8, 'a'), bx[11]);
}

test "realistic TreeMap row round-trips" {
    const a = testing.allocator;
    var cat = NameCatalog.init();
    defer cat.deinit(a);
    try cat.put(a, "t#type", "TreeMap");
    try cat.put(a, "t#keySerializer", "LONG");
    try cat.put(a, "t#valueSerializer", "STRING");
    try cat.put(a, "t#rootRecidRecid", "2");
    try cat.put(a, "t#maxNodeSize", "32");
    try cat.put(a, "t#counterRecid", "0");
    try cat.put(a, "t#valueInline", "true");
    const bytes = try encode(a, &cat);
    defer a.free(bytes);
    var back = try decode(a, bytes);
    defer back.deinit(a);
    try testing.expect(back.eql(&cat));
}

test "decoder rejects malformed records" {
    const a = testing.allocator;
    try testing.expectError(error.DataCorruption, decode(a, &.{ 0x4D, 0x44, 0x42 })); // short
    try testing.expectError(error.DataCorruption, decode(a, &.{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x80 })); // bad magic
    try testing.expectError(error.DataCorruption, decode(a, &.{ 0x4D, 0x44, 0x42, 0x43, 0x00, 0x00, 0x00, 0x09, 0x00, 0x80 })); // bad version
    // trailing byte
    try testing.expectError(error.DataCorruption, decode(a, &.{ 0x4D, 0x44, 0x42, 0x43, 0x00, 0x00, 0x00, 0x01, 0x00, 0x80, 0xFF }));
    // string crossing record end: count 1, key len 50 but no bytes
    try testing.expectError(error.DataCorruption, decode(a, &.{ 0x4D, 0x44, 0x42, 0x43, 0x00, 0x00, 0x00, 0x01, 0x00, 0x81, 0xB2 }));
    // duplicate keys
    try testing.expectError(error.DataCorruption, decode(a, &.{
        0x4D, 0x44, 0x42, 0x43, 0x00, 0x00, 0x00, 0x01, 0x00, 0x82,
        0x81, 'a',  0x81, 'x',  0x81, 'a',  0x81, 'y',
    }));
}

test "decoder rejects non-canonical / overlong / overflowing packed ints" {
    const a = testing.allocator;
    // count encoded as two-byte zero `00 80` is non-canonical (canonical is `80`).
    try testing.expectError(error.DataCorruption, decode(a, &.{ 0x4D, 0x44, 0x42, 0x43, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x80 }));
    // overlong / unterminated packed count: 11 continuation bytes, no terminator.
    {
        var bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer bytes.deinit(a);
        try bytes.appendSlice(a, &.{ 0x4D, 0x44, 0x42, 0x43, 0x00, 0x00, 0x00, 0x01, 0x00 });
        try bytes.appendNTimes(a, 0x00, 11);
        try testing.expectError(error.DataCorruption, decode(a, bytes.items));
    }
    // packed count overflowing 64 bits: 9 × 0x7F continuation then a terminal.
    {
        var bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer bytes.deinit(a);
        try bytes.appendSlice(a, &.{ 0x4D, 0x44, 0x42, 0x43, 0x00, 0x00, 0x00, 0x01, 0x00 });
        try bytes.appendNTimes(a, 0x7F, 9);
        try bytes.append(a, 0xFF);
        try testing.expectError(error.DataCorruption, decode(a, bytes.items));
    }
    // unterminated packed string length (count 1 then 11 continuation bytes).
    {
        var bytes: std.ArrayListUnmanaged(u8) = .empty;
        defer bytes.deinit(a);
        try bytes.appendSlice(a, &.{ 0x4D, 0x44, 0x42, 0x43, 0x00, 0x00, 0x00, 0x01, 0x00, 0x81 });
        try bytes.appendNTimes(a, 0x00, 11);
        try testing.expectError(error.DataCorruption, decode(a, bytes.items));
    }
}

test "NameCatalog put/get/remove/prefix" {
    const a = testing.allocator;
    var cat = NameCatalog.init();
    defer cat.deinit(a);
    try cat.put(a, "q#type", "Queue");
    try cat.put(a, "q#headerRecid", "5");
    try cat.put(a, "q#serializer", "STRING");
    try cat.put(a, "q#type", "Stack"); // replace
    try testing.expectEqualStrings("Stack", cat.get("q#type").?);
    try testing.expect(cat.contains("q#serializer"));
    try testing.expectEqual(@as(usize, 3), cat.removePrefix(a, "q#"));
    try testing.expectEqual(@as(usize, 0), cat.len());
}
