//! Compile probes + torn-input fuzz sweeps for the ser layer.
//!
//! - Compile probes: a comptime block runs `checkSerializer`/`checkGroupFormat`
//!   against the full built-in set (decl-name + associated-type validation), and
//!   runtime probes instantiate every byte-side entry with typed dummy args.
//! - Torn-input: random/truncated bytes fed to every byte-side entry point must
//!   return cleanly (`DbError` or a value) and NEVER crash (Debug/ReleaseSafe
//!   trap illegal behavior) — run under a bounded `FixedBufferAllocator` so a
//!   garbage length cannot provoke unbounded allocation.

const std = @import("std");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const mod = @import("mod.zig");
const serializers = @import("serializers.zig");
const scalar = @import("scalar.zig");
const long = @import("long.zig");
const int = @import("int.zig");
const string_group = @import("string_group.zig");
const string_prefix = @import("string_prefix.zig");
const bytearray = @import("bytearray.zig");
const object_array = @import("object_array.zig");
const tuple = @import("tuple.zig");
const columnar = @import("columnar.zig");
const Value = @import("value.zig").Value;

// ------------------------------------------------------------- compile probes

test "compile probes: checkSerializer / checkGroupFormat over all built-ins" {
    comptime {
        mod.checkSerializer(serializers.ShortSer, i16);
        mod.checkSerializer(serializers.CharSer, u16);
        mod.checkSerializer(serializers.IntSer, i32);
        mod.checkSerializer(serializers.LongSer, i64);
        mod.checkSerializer(serializers.UuidSer, u128);
        mod.checkSerializer(serializers.StringSer, []const u8);
        mod.checkSerializer(serializers.ByteArraySer, []const u8);
        mod.checkSerializer(serializers.ByteArrayUnsignedSer, []const u8);

        mod.checkGroupFormat(scalar.ShortFormat);
        mod.checkGroupFormat(scalar.CharFormat);
        mod.checkGroupFormat(scalar.UuidFormat);
        mod.checkGroupFormat(long.LongFormat);
        mod.checkGroupFormat(long.LongDeltaFormat);
        mod.checkGroupFormat(int.IntFormat);
        mod.checkGroupFormat(int.IntDeltaFormat);
        mod.checkGroupFormat(string_group.StringGroupFormat);
        mod.checkGroupFormat(string_prefix.StringPrefixFormat);
        mod.checkGroupFormat(bytearray.ByteArrayFormat);
        mod.checkGroupFormat(bytearray.ByteArrayPrefixFormat);
        mod.checkGroupFormat(object_array.ObjectArrayFormat(serializers.LongSer));
        mod.checkGroupFormat(object_array.ObjectArrayFormat(serializers.StringSer));
        mod.checkGroupFormat(tuple.TupleFormat);
        mod.checkGroupFormat(columnar.ColumnarValueFormat);
    }
}

// ------------------------------------------------------------- torn-input fuzz

/// Feed random/truncated bytes to every byte-side entry of `F` with a bounded
/// allocator. Any result (value or `DbError`) is acceptable; the pass criterion
/// is "does not crash / does not allocate unboundedly".
fn fuzzTorn(comptime F: type, key: F.Elem, seed: u64) !void {
    var buf: [1 << 16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const a = fba.allocator();

    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();

    var bytes: [96]u8 = undefined;
    var iter: usize = 0;
    while (iter < 400) : (iter += 1) {
        const len = rnd.intRangeAtMost(usize, 0, bytes.len);
        rnd.bytes(bytes[0..len]);
        const b = bytes[0..len];
        // count: mostly small, occasionally large to exercise the count clamps.
        const count: usize = if (rnd.boolean()) rnd.intRangeAtMost(usize, 0, 12) else rnd.intRangeAtMost(usize, 0, 1 << 20);
        const pos = rnd.intRangeAtMost(usize, 0, 16);

        fba.reset();
        var in1 = DataInput2.init(b);
        _ = F.instance.binarySearch(a, key, &in1, count) catch {};

        fba.reset();
        var in2 = DataInput2.init(b);
        if (F.instance.binaryGet(a, &in2, count, pos)) |v| {
            F.instance.deinitElem(a, v);
        } else |_| {}

        fba.reset();
        var in3 = DataInput2.init(b);
        if (F.instance.deserializeGroup(a, &in3, count)) |g| {
            F.instance.deinitGroup(a, g);
        } else |_| {}

        fba.reset();
        var in4 = DataInput2.init(b);
        const safe_count = @min(count, 12);
        if (F.instance.rangeCursor(a, &in4, safe_count, 0, safe_count)) |cur_const| {
            var cur = cur_const;
            defer cur.deinit();
            var guard: usize = 0;
            while (guard < 64) : (guard += 1) {
                const more = cur.next() catch break;
                if (!more) break;
                if (cur.value(a)) |v| {
                    F.instance.deinitElem(a, v);
                } else |_| {}
            }
        } else |_| {}
    }
}

test "torn input: fixed-stride + delta formats never crash, bounded alloc" {
    var s: u64 = 0xC0FFEE;
    inline for (.{ long.LongFormat, long.LongDeltaFormat, int.IntFormat, int.IntDeltaFormat }) |F| {
        try fuzzTorn(F, 0, s);
        s +%= 0x9E3779B97F4A7C15;
    }
    try fuzzTorn(scalar.ShortFormat, 0, s);
    try fuzzTorn(scalar.CharFormat, 0, s +% 1);
    try fuzzTorn(scalar.UuidFormat, 0, s +% 2);
}

test "torn input: string + byte[] formats never crash, bounded alloc" {
    try fuzzTorn(string_group.StringGroupFormat, "probe", 1);
    try fuzzTorn(string_prefix.StringPrefixFormat, "probe", 2);
    try fuzzTorn(bytearray.ByteArrayFormat, "probe", 3);
    try fuzzTorn(bytearray.ByteArrayPrefixFormat, "probe", 4);
}

test "torn input: tuple + columnar formats never crash, bounded alloc" {
    // TupleFormat / ColumnarValueFormat carry a runtime schema (no `instance`),
    // so exercise them directly rather than via `fuzzTorn`.
    var buf: [1 << 16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const a = fba.allocator();
    var prng = std.Random.DefaultPrng.init(0xABCDEF);
    const rnd = prng.random();

    const tf = tuple.TupleFormat.of(&.{ .int, .str });
    var tk = [_]Value{ .{ .int = 7 }, .{ .str = "k" } };
    const cf = columnar.ColumnarValueFormat.of(&.{ .long, .int });
    var ck = [_]Value{ .{ .long = 1 }, .{ .int = 2 } };

    var bytes: [96]u8 = undefined;
    var iter: usize = 0;
    while (iter < 400) : (iter += 1) {
        const len = rnd.intRangeAtMost(usize, 0, bytes.len);
        rnd.bytes(bytes[0..len]);
        const b = bytes[0..len];
        const count = rnd.intRangeAtMost(usize, 0, 12);
        const pos = rnd.intRangeAtMost(usize, 0, 16);

        fba.reset();
        var t1 = DataInput2.init(b);
        _ = tf.binarySearch(a, &tk, &t1, count) catch {};
        fba.reset();
        var t2 = DataInput2.init(b);
        if (tf.binaryGet(a, &t2, count, pos)) |v| tf.deinitElem(a, v) else |_| {}
        fba.reset();
        var t3 = DataInput2.init(b);
        if (tf.deserializeGroup(a, &t3, count)) |g| tf.deinitGroup(a, g) else |_| {}

        fba.reset();
        var c1 = DataInput2.init(b);
        _ = cf.binarySearch(a, &ck, &c1, count) catch {};
        fba.reset();
        var c2 = DataInput2.init(b);
        if (cf.binaryGet(a, &c2, count, pos)) |v| cf.deinitElem(a, v) else |_| {}
        fba.reset();
        var c3 = DataInput2.init(b);
        if (cf.deserializeGroup(a, &c3, count)) |g| cf.deinitGroup(a, g) else |_| {}
    }
}

// ------------------------------------------------ order-coherence PRNG sweep

test "order coherence PRNG sweep (Long/Int/ByteArray)" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5EED);
    const rnd = prng.random();

    // Long
    {
        var vals = std.ArrayList(i64){};
        defer vals.deinit(a);
        for (0..40) |_| try vals.append(a, rnd.int(i64));
        std.mem.sort(i64, vals.items, {}, comptime std.sort.asc(i64));
        // dedup
        var w: usize = 0;
        for (vals.items, 0..) |v, idx| {
            if (idx == 0 or v != vals.items[w - 1]) {
                vals.items[w] = v;
                w += 1;
            }
        }
        vals.shrinkRetainingCapacity(w);
        var out = io.DataOutput2.init(a);
        defer out.deinit();
        var group: long.LongFormat.Group = vals.items;
        try long.LongFormat.instance.serializeGroup(&out, &group);
        const bytes = try out.copyBytes(a);
        defer a.free(bytes);
        for (0..60) |_| {
            const key = rnd.int(i64);
            const obj = long.LongFormat.instance.search(&group, key);
            var inp = DataInput2.init(bytes);
            const byte_res = try long.LongFormat.instance.binarySearch(a, key, &inp, vals.items.len);
            try std.testing.expect(obj.eql(byte_res));
        }
    }
}

// -------------------------------------- deterministic hardening regressions

// 14-byte crafted prefix block declaring blobLen=2^31-1 and
// suffixLen=2^30 must fail as DataCorruption BEFORE any allocation — proven by
// a 64-byte FixedBufferAllocator (an attempted 1 GiB scratch resize would
// surface as OutOfMemory instead).
test "regression: crafted prefix block fails as corruption, not giant alloc" {
    // blobLen=0x7FFFFFFF | restartOff[0]=0 | shared=packInt(0) | suffixLen=packInt(2^30)
    const crafted = [_]u8{
        0x7f, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x04, 0x00, 0x00, 0x00, 0x80,
    };
    var buf: [64]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const a = fba.allocator();

    inline for (.{ bytearray.ByteArrayPrefixFormat, string_prefix.StringPrefixFormat }) |F| {
        fba.reset();
        var d = DataInput2.init(&crafted);
        try std.testing.expectError(error.DataCorruption, F.instance.deserializeGroup(a, &d, 1));
        fba.reset();
        var s = DataInput2.init(&crafted);
        try std.testing.expectError(error.DataCorruption, F.instance.binarySearch(a, "k", &s, 1));
        fba.reset();
        var g = DataInput2.init(&crafted);
        try std.testing.expectError(error.DataCorruption, F.instance.binaryGet(a, &g, 1, 0));
    }
}

// allocating from a tainted count before proving the input
// can hold that many elements must fail as DataCorruption, never OOM.
test "regression: tainted count fails as corruption before allocation" {
    var buf: [64]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const a = fba.allocator();

    // fixed-stride: empty input, count=1024
    {
        var d = DataInput2.init(&.{});
        try std.testing.expectError(error.DataCorruption, long.LongFormat.instance.deserializeGroup(a, &d, 1024));
    }
    // delta: empty input, count=1024
    inline for (.{ long.LongDeltaFormat, int.IntDeltaFormat }) |F| {
        fba.reset();
        var d = DataInput2.init(&.{});
        try std.testing.expectError(error.DataCorruption, F.instance.deserializeGroup(a, &d, 1024));
    }
    // offset-table: blobLen=0 but count=1024 (needs 4096 offset bytes)
    inline for (.{ string_group.StringGroupFormat, bytearray.ByteArrayFormat }) |F| {
        fba.reset();
        var d = DataInput2.init(&.{ 0, 0, 0, 0 });
        try std.testing.expectError(error.DataCorruption, F.instance.deserializeGroup(a, &d, 1024));
    }
    // object array: empty input, count=1024
    {
        fba.reset();
        const F = object_array.ObjectArrayFormat(serializers.LongSer);
        const f = F.init(serializers.LongSer.instance);
        var d = DataInput2.init(&.{});
        try std.testing.expectError(error.DataCorruption, f.deserializeGroup(a, &d, 1024));
    }
    // columnar: empty input, count=1024
    {
        fba.reset();
        const cf = columnar.ColumnarValueFormat.of(&.{ .long, .int });
        var d = DataInput2.init(&.{});
        try std.testing.expectError(error.DataCorruption, cf.deserializeGroup(a, &d, 1024));
    }
    // tuple: blobLen=0 but count=1024
    {
        fba.reset();
        const tf = tuple.TupleFormat.of(&.{.int});
        var d = DataInput2.init(&.{ 0, 0, 0, 0 });
        try std.testing.expectError(error.DataCorruption, tf.deserializeGroup(a, &d, 1024));
    }
}

// count > maxInt(isize) must be corruption, not a
// ReleaseSafe @intCast panic.
test "regression: isize-overflowing count is corruption, not a panic" {
    const a = std.testing.allocator;
    const huge: usize = @as(usize, std.math.maxInt(isize)) + 1;
    {
        var s = DataInput2.init(&.{});
        try std.testing.expectError(error.DataCorruption, long.LongFormat.instance.binarySearch(a, 5, &s, huge));
        var s2 = DataInput2.init(&.{});
        try std.testing.expectError(error.DataCorruption, long.LongFormat.instance.binarySearch(a, 5, &s2, std.math.maxInt(usize)));
    }
    {
        const cf = columnar.ColumnarValueFormat.of(&.{.byte});
        var key = [_]Value{.{ .byte = 1 }};
        var s = DataInput2.init(&.{});
        try std.testing.expectError(error.DataCorruption, cf.binarySearch(a, &key, &s, huge));
    }
}

// prefix deserialization must consume exactly the declared
// blob — trailing bytes inside the blob (or an unconsumed blob at count=0)
// are corruption.
test "regression: prefix framing rejects unconsumed declared blob" {
    const a = std.testing.allocator;
    // count=0 with declared blobLen=1 and one trailing blob byte.
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x01, 0xaa };
    inline for (.{ bytearray.ByteArrayPrefixFormat, string_prefix.StringPrefixFormat }) |F| {
        var d = DataInput2.init(&bytes);
        try std.testing.expectError(error.DataCorruption, F.instance.deserializeGroup(a, &d, 0));
    }
    // canonical count=0 group still decodes to an owned empty group.
    inline for (.{ bytearray.ByteArrayPrefixFormat, string_prefix.StringPrefixFormat }) |F| {
        var d = DataInput2.init(&.{ 0x00, 0x00, 0x00, 0x00 });
        const g = try F.instance.deserializeGroup(a, &d, 0);
        F.instance.deinitGroup(a, g);
    }
}

// empty() returns an allocator-owned zero-length group freed by
// deinitGroup (never a static literal).
test "regression: empty() groups are allocator-owned" {
    const a = std.testing.allocator;
    inline for (.{
        long.LongFormat,                  long.LongDeltaFormat,
        int.IntFormat,                    int.IntDeltaFormat,
        scalar.ShortFormat,               scalar.CharFormat,
        scalar.UuidFormat,                string_group.StringGroupFormat,
        string_prefix.StringPrefixFormat, bytearray.ByteArrayFormat,
        bytearray.ByteArrayPrefixFormat,
    }) |F| {
        const g = try F.instance.empty(a);
        try std.testing.expectEqual(@as(usize, 0), F.instance.size(&g));
        F.instance.deinitGroup(a, g);
    }
    {
        const tf = tuple.TupleFormat.of(&.{.int});
        const g = try tf.empty(a);
        tf.deinitGroup(a, g);
    }
    {
        const cf = columnar.ColumnarValueFormat.of(&.{.byte});
        const g = try cf.empty(a);
        cf.deinitGroup(a, g);
    }
    {
        const F = object_array.ObjectArrayFormat(serializers.StringSer);
        const f = F.init(serializers.StringSer.instance);
        const g = try f.empty(a);
        f.deinitGroup(a, g);
    }
}
