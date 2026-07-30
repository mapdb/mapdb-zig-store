//! Generic store TCK, ported from `mapdb-rust-store/tests/store_tck.rs`.
//! `verify()` runs after every mutation; exact `DbError` identities are asserted.
//! Run against `StoreOnHeap` AND `StoreByteArray` (delta suite for delta stores).

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const mod = @import("mod.zig");
const RecordRead = mod.RecordRead;
const TypeId = mod.TypeId;
const AppendResult = mod.AppendResult;
const sers = @import("../ser/serializers.zig");
const LongSer = sers.LongSer;
const IntSer = sers.IntSer;
const ByteArraySer = sers.ByteArraySer;

const StoreOnHeap = @import("heap.zig").StoreOnHeap;
const StoreByteArray = @import("bytearray.zig").StoreByteArray;
const StoreDirect = @import("direct.zig").StoreDirect;
const StoreWAL = @import("wal.zig").StoreWAL;

// ---------------------------------------------------------------- fixtures

/// Deterministic pseudo-random byte block (Java `Fixtures.bytes`), returned by
/// value so callers need no allocation.
fn bytes(seed: u64, comptime len: usize) [len]u8 {
    var x = seed *% 0x9E37_79B9_7F4A_7C15 +% 1;
    var out: [len]u8 = undefined;
    for (&out) |*b| {
        x = x *% 6364136223846793005 +% 1442695040888963407;
        b.* = @truncate(x >> 33);
    }
    return out;
}

/// Size-driven raw-bytes serializer (Java `Fixtures.RAW`): content == value, so
/// appended delta bytes are observable. Used by the delta TCK.
const RawSer = struct {
    pub const Elem = []const u8;
    pub const instance: RawSer = .{};
    pub fn serialize(_: RawSer, out: *DataOutput2, v: []const u8) DbError!void {
        try out.writeAll(v);
    }
    pub fn deserialize(_: RawSer, alloc: Allocator, input: *DataInput2, size: ?usize) DbError![]const u8 {
        const n = size orelse return error.DataCorruption;
        const b = try alloc.alloc(u8, n);
        errdefer alloc.free(b);
        try input.readFully(b);
        return b;
    }
    pub fn cloneElem(_: RawSer, alloc: Allocator, v: []const u8) DbError![]const u8 {
        return alloc.dupe(u8, v);
    }
    pub fn deinitElem(_: RawSer, alloc: Allocator, v: []const u8) void {
        alloc.free(v);
    }
    pub fn equals(_: RawSer, a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
    pub fn compare(_: RawSer, a: []const u8, b: []const u8) std.math.Order {
        return std.mem.order(u8, a, b);
    }
    pub fn fixedSize(_: @This()) ?usize {
        return null;
    }
    pub fn equalsBySerializedBytes(_: @This()) bool {
        return true;
    }
};

/// A serializer whose LOGICAL equality is ASCII case-insensitive, to prove CAS
/// uses `ser.equals` (a NON-canonical-encoding case: "HELLO" bytes ≠ "Hello"
/// bytes but are logically equal). Wire format = `ByteArraySer`.
const CaseInsensitiveSer = struct {
    pub const Elem = []const u8;
    pub const instance: CaseInsensitiveSer = .{};
    pub fn serialize(_: CaseInsensitiveSer, out: *DataOutput2, v: []const u8) DbError!void {
        return ByteArraySer.instance.serialize(out, v);
    }
    pub fn deserialize(_: CaseInsensitiveSer, alloc: Allocator, input: *DataInput2, size: ?usize) DbError![]const u8 {
        return ByteArraySer.instance.deserialize(alloc, input, size);
    }
    pub fn cloneElem(_: CaseInsensitiveSer, alloc: Allocator, v: []const u8) DbError![]const u8 {
        return alloc.dupe(u8, v);
    }
    pub fn deinitElem(_: CaseInsensitiveSer, alloc: Allocator, v: []const u8) void {
        alloc.free(v);
    }
    pub fn equals(_: CaseInsensitiveSer, a: []const u8, b: []const u8) bool {
        return std.ascii.eqlIgnoreCase(a, b);
    }
    pub fn compare(_: CaseInsensitiveSer, a: []const u8, b: []const u8) std.math.Order {
        return std.mem.order(u8, a, b);
    }
    pub fn fixedSize(_: @This()) ?usize {
        return null;
    }
    pub fn equalsBySerializedBytes(_: @This()) bool {
        return false; // logical (case-insensitive) equality ≠ byte equality
    }
};

/// Push-down read action: decodes an i64 from bytes (byte stores) or downcasts a
/// boxed i64 (heap store), recording which branch ran. onObject enforces the
/// type token (a wrong-token record → `error.DataCorruption`).
const ReadProbe = struct {
    saw_null: bool = false,
    value: ?i64 = null,

    fn onBytes(ctx: *anyopaque, input: *DataInput2, size: usize) DbError!i64 {
        _ = size;
        const self: *ReadProbe = @ptrCast(@alignCast(ctx));
        const v = try input.readI64();
        self.value = v;
        return v;
    }
    fn onObject(ctx: *anyopaque, obj: *const anyopaque, token: TypeId) DbError!i64 {
        const self: *ReadProbe = @ptrCast(@alignCast(ctx));
        if (token != mod.typeToken(i64)) return error.DataCorruption;
        const p: *const i64 = @ptrCast(@alignCast(obj));
        self.value = p.*;
        return p.*;
    }
    fn onNull(ctx: *anyopaque) DbError!i64 {
        const self: *ReadProbe = @ptrCast(@alignCast(ctx));
        self.saw_null = true;
        return 0;
    }
    const vtable = RecordRead.VTable{ .onBytes = onBytes, .onObject = onObject, .onNull = onNull };
    fn action(self: *ReadProbe) RecordRead {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

fn containsRecid(slice: []const u64, r: u64) bool {
    return std.mem.indexOfScalar(u64, slice, r) != null;
}

fn expectContent(comptime S: type, s: *S, alloc: Allocator, recid: u64, ser: anytype, expected: []const u8) !void {
    const g = (try s.get([]const u8, alloc, recid, ser)).?;
    defer ser.deinitElem(alloc, g);
    try testing.expectEqualSlices(u8, expected, g);
}

// ------------------------------------------------------------- core states

fn tckStates(comptime S: type, s: *S, alloc: Allocator) !void {
    const L = LongSer.instance;
    try s.verify();

    // Void: never-allocated recid → GetVoid on read/get/delete.
    const void_recid: u64 = 999_999;
    try testing.expectError(error.GetVoid, s.get(i64, alloc, void_recid, L));
    try testing.expectError(error.GetVoid, s.delete(void_recid));

    // put → Live
    const r1 = try s.put(i64, alloc, @as(i64, 42), L);
    try s.verify();
    try testing.expectEqual(@as(i64, 42), (try s.get(i64, alloc, r1, L)).?);
    {
        var p = ReadProbe{};
        try testing.expectEqual(@as(i64, 42), try s.read(r1, p.action()));
        try testing.expectEqual(@as(i64, 42), p.value.?);
    }

    // preallocate → Preallocated: get → null; excluded from getAllRecids
    const rp = try s.preallocate();
    try s.verify();
    try testing.expect((try s.get(i64, alloc, rp, L)) == null);
    {
        var p = ReadProbe{};
        _ = try s.read(rp, p.action());
        try testing.expect(p.saw_null);
    }
    {
        const all = try s.getAllRecids(alloc);
        defer alloc.free(all);
        try testing.expect(!containsRecid(all, rp));
        try testing.expect(containsRecid(all, r1));
    }

    // update preallocated → Live
    try s.update(i64, alloc, rp, @as(i64, 7), L);
    try s.verify();
    try testing.expectEqual(@as(i64, 7), (try s.get(i64, alloc, rp, L)).?);
    {
        const all = try s.getAllRecids(alloc);
        defer alloc.free(all);
        try testing.expect(containsRecid(all, rp));
    }

    // update Live → null content: get → null but record still exists
    try s.update(i64, alloc, r1, null, L);
    try s.verify();
    try testing.expect((try s.get(i64, alloc, r1, L)) == null);
    {
        var p = ReadProbe{};
        _ = try s.read(r1, p.action());
        try testing.expect(p.saw_null);
    }

    // delete → Deleted: get/read → GetVoid
    try s.delete(r1);
    try s.verify();
    try testing.expectError(error.GetVoid, s.get(i64, alloc, r1, L));
    {
        var p = ReadProbe{};
        try testing.expectError(error.GetVoid, s.read(r1, p.action()));
    }
    // update of a deleted recid → GetVoid
    try testing.expectError(error.GetVoid, s.update(i64, alloc, r1, @as(i64, 1), L));
}

fn tckCas(comptime S: type, s: *S, alloc: Allocator) !void {
    const L = LongSer.instance;
    const r = try s.put(i64, alloc, @as(i64, 100), L);
    // wrong expected → false, no change
    try testing.expect(!try s.compareAndSwap(i64, alloc, r, @as(i64, 5), @as(i64, 6), L));
    try testing.expectEqual(@as(i64, 100), (try s.get(i64, alloc, r, L)).?);
    // right expected → swap
    try testing.expect(try s.compareAndSwap(i64, alloc, r, @as(i64, 100), @as(i64, 200), L));
    try testing.expectEqual(@as(i64, 200), (try s.get(i64, alloc, r, L)).?);
    try s.verify();
    // swap Live → Null
    try testing.expect(try s.compareAndSwap(i64, alloc, r, @as(i64, 200), null, L));
    try testing.expect((try s.get(i64, alloc, r, L)) == null);
    // Null matches null expected → swap back to Live
    try testing.expect(try s.compareAndSwap(i64, alloc, r, null, @as(i64, 9), L));
    try testing.expectEqual(@as(i64, 9), (try s.get(i64, alloc, r, L)).?);
    // expecting null on a live value → false
    try testing.expect(!try s.compareAndSwap(i64, alloc, r, null, @as(i64, 1), L));
    try s.verify();
}

fn tckReuseClose(comptime S: type, s: *S, alloc: Allocator) !void {
    const L = LongSer.instance;
    const a = try s.put(i64, alloc, @as(i64, 1), L);
    try s.delete(a);
    // a is free; Void until reused
    try testing.expectError(error.GetVoid, s.get(i64, alloc, a, L));
    try s.verify();
    try s.close();
    try testing.expect(s.isClosed());
    try testing.expectError(error.StoreClosed, s.get(i64, alloc, a, L));
}

/// Nested owned-slice record type ([]const u8) exercising clone/deinit/CAS paths.
fn tckOwnedSlice(comptime S: type, s: *S, alloc: Allocator) !void {
    const B = ByteArraySer.instance;
    const v1: []const u8 = "hello world, a longer owned slice";
    const r = try s.put([]const u8, alloc, v1, B);
    try s.verify();
    try expectContent(S, s, alloc, r, B, v1);

    const v2: []const u8 = "another owned value entirely";
    try s.update([]const u8, alloc, r, v2, B);
    try s.verify();
    try expectContent(S, s, alloc, r, B, v2);

    // logical CAS on a slice value (byte-equality here)
    try testing.expect(try s.compareAndSwap([]const u8, alloc, r, v2, @as([]const u8, "third"), B));
    try expectContent(S, s, alloc, r, B, "third");
    try s.verify();

    try s.delete(r);
    try s.verify();
    try testing.expectError(error.GetVoid, s.get([]const u8, alloc, r, B));
}

/// Logical CAS with a NON-canonical encoding: expected bytes differ from stored
/// bytes yet `ser.equals` (case-insensitive) matches.
fn tckLogicalCas(comptime S: type, s: *S, alloc: Allocator) !void {
    const CI = CaseInsensitiveSer.instance;
    const r = try s.put([]const u8, alloc, @as([]const u8, "Hello"), CI);
    try s.verify();
    // "HELLO" (different bytes) logically matches stored "Hello"
    try testing.expect(try s.compareAndSwap([]const u8, alloc, r, @as([]const u8, "HELLO"), @as([]const u8, "world"), CI));
    try expectContent(S, s, alloc, r, CI, "world");
    // a non-matching logical value → false
    try testing.expect(!try s.compareAndSwap([]const u8, alloc, r, @as([]const u8, "nope"), @as([]const u8, "x"), CI));
    try s.verify();
    try s.delete(r);
}

// ------------------------------------------------------------- delta suite

fn tckDelta(comptime S: type, s: *S, alloc: Allocator) !void {
    const R = RawSer.instance;

    // --- append grows content byte-exactly within provisioned capacity ---
    {
        const base = bytes(1, 12);
        const bs: []const u8 = &base;
        const r = try s.put([]const u8, alloc, bs, R);
        try s.updateWithHeadroom([]const u8, alloc, r, bs, R, 64);
        try s.verify();
        const d1 = [_]u8{ 10, 11, 12 };
        const d2 = [_]u8{ 20, 21 };
        const d3 = [_]u8{30};
        try testing.expect((try s.append(r, &d1)).eql(.{ .new_size = 15 }));
        try testing.expect((try s.append(r, &d2)).eql(.{ .new_size = 17 }));
        try testing.expect((try s.append(r, &d3)).eql(.{ .new_size = 18 }));
        try s.verify();
        const merged = try std.mem.concat(alloc, u8, &.{ bs, &d1, &d2, &d3 });
        defer alloc.free(merged);
        try expectContent(S, s, alloc, r, R, merged);
    }

    // --- refused at the capacity boundary; REFUSED leaves content intact ---
    {
        const base = bytes(2, 8);
        const bs: []const u8 = &base;
        const rb = try s.put([]const u8, alloc, bs, R);
        try s.updateWithHeadroom([]const u8, alloc, rb, bs, R, 40);
        try s.commit();
        const cap_rem = try s.capacityRemaining(rb);
        try testing.expect(cap_rem >= 40);
        const fill = try alloc.alloc(u8, cap_rem);
        defer alloc.free(fill);
        for (fill, 0..) |*b, i| b.* = @truncate(i + 1);
        try testing.expect((try s.append(rb, fill)).eql(.{ .new_size = 8 + cap_rem }));
        try testing.expectEqual(@as(usize, 0), try s.capacityRemaining(rb));
        const bmerged = try std.mem.concat(alloc, u8, &.{ bs, fill });
        defer alloc.free(bmerged);
        try testing.expect((try s.append(rb, &[_]u8{99})).eql(.refused));
        try testing.expectEqual(@as(usize, 0), try s.capacityRemaining(rb));
        try expectContent(S, s, alloc, rb, R, bmerged);
        try s.verify();
    }

    // --- append on a preallocated record establishes it with delta content ---
    {
        const rp = try s.preallocate();
        try testing.expect((try s.get([]const u8, alloc, rp, R)) == null);
        {
            const all = try s.getAllRecids(alloc);
            defer alloc.free(all);
            try testing.expect(!containsRecid(all, rp));
        }
        const d = bytes(3, 14);
        try testing.expect((try s.append(rp, &d)).eql(.{ .new_size = 14 }));
        try s.verify();
        try expectContent(S, s, alloc, rp, R, &d);
        {
            const all = try s.getAllRecids(alloc);
            defer alloc.free(all);
            try testing.expect(containsRecid(all, rp));
        }
        try s.commit();
        try expectContent(S, s, alloc, rp, R, &d);
    }

    // --- update resets the appended region ---
    {
        const base = bytes(4, 8);
        const bs: []const u8 = &base;
        const ru = try s.put([]const u8, alloc, bs, R);
        try s.updateWithHeadroom([]const u8, alloc, ru, bs, R, 32);
        _ = try s.append(ru, &[_]u8{ 7, 7, 7, 7 });
        const m1 = try std.mem.concat(alloc, u8, &.{ bs, &[_]u8{ 7, 7, 7, 7 } });
        defer alloc.free(m1);
        try expectContent(S, s, alloc, ru, R, m1);
        const base2 = bytes(40, 10);
        try s.update([]const u8, alloc, ru, @as([]const u8, &base2), R);
        try expectContent(S, s, alloc, ru, R, &base2);
        try s.verify();
    }

    // --- update_with_headroom guarantees the headroom is appendable ---
    {
        const H: usize = 48;
        const base = bytes(5, 6);
        const bs: []const u8 = &base;
        const rh = try s.put([]const u8, alloc, bs, R);
        try s.updateWithHeadroom([]const u8, alloc, rh, bs, R, H);
        try testing.expect((try s.capacityRemaining(rh)) >= H);
        const block = try alloc.alloc(u8, H);
        defer alloc.free(block);
        for (block, 0..) |*b, i| b.* = @truncate(i);
        try testing.expect((try s.append(rh, block)).eql(.{ .new_size = 6 + H }));
        const m = try std.mem.concat(alloc, u8, &.{ bs, block });
        defer alloc.free(m);
        try expectContent(S, s, alloc, rh, R, m);
        try s.verify();
    }

    // --- delete after appends → GetVoid on every delta op ---
    {
        const base = bytes(6, 8);
        const bs: []const u8 = &base;
        const rd = try s.put([]const u8, alloc, bs, R);
        try s.updateWithHeadroom([]const u8, alloc, rd, bs, R, 32);
        _ = try s.append(rd, &[_]u8{ 1, 2, 3 });
        try s.delete(rd);
        try s.verify();
        try testing.expectError(error.GetVoid, s.get([]const u8, alloc, rd, R));
        try testing.expectError(error.GetVoid, s.append(rd, &[_]u8{1}));
        try testing.expectError(error.GetVoid, s.capacityRemaining(rd));
        try testing.expectError(error.GetVoid, s.update([]const u8, alloc, rd, bs, R));
        try testing.expectError(error.GetVoid, s.updateWithHeadroom([]const u8, alloc, rd, bs, R, 8));
        try testing.expectError(error.GetVoid, s.compareAndSwap([]const u8, alloc, rd, bs, bs, R));
        try s.verify();
    }

    // --- zero-length append is a no-op returning the current size ---
    {
        const base = bytes(7, 13);
        const bs: []const u8 = &base;
        const rz = try s.put([]const u8, alloc, bs, R);
        try testing.expect((try s.append(rz, &[_]u8{})).eql(.{ .new_size = 13 }));
        try expectContent(S, s, alloc, rz, R, bs);
        try testing.expect((try s.append(rz, &[_]u8{})).eql(.{ .new_size = 13 }));
        try expectContent(S, s, alloc, rz, R, bs);
        try s.verify();
    }

    // --- CAS after appends compares the merged logical value ---
    {
        const base = bytes(8, 8);
        const bs: []const u8 = &base;
        const rc = try s.put([]const u8, alloc, bs, R);
        try s.updateWithHeadroom([]const u8, alloc, rc, bs, R, 64);
        const d1 = [_]u8{ 40, 41, 42 };
        const d2 = [_]u8{ 50, 51 };
        _ = try s.append(rc, &d1);
        _ = try s.append(rc, &d2);
        const merged = try std.mem.concat(alloc, u8, &.{ bs, &d1, &d2 });
        defer alloc.free(merged);
        try expectContent(S, s, alloc, rc, R, merged);
        // CAS against the base-only (pre-append) image must fail.
        const repl_fail = bytes(80, 5);
        try testing.expect(!try s.compareAndSwap([]const u8, alloc, rc, bs, @as([]const u8, &repl_fail), R));
        // CAS against the merged image must succeed.
        const replacement = bytes(82, 7);
        try testing.expect(try s.compareAndSwap([]const u8, alloc, rc, merged, @as([]const u8, &replacement), R));
        try expectContent(S, s, alloc, rc, R, &replacement);
        try s.verify();
    }
}

// ----------------------------------------------------------------- runners

fn runCore(comptime S: type, alloc: Allocator) !void {
    inline for ([_]bool{ true, false }) |ts| {
        {
            var s = try S.init(alloc, ts);
            defer s.deinit();
            try tckStates(S, &s, alloc);
        }
        {
            var s = try S.init(alloc, ts);
            defer s.deinit();
            try tckCas(S, &s, alloc);
        }
        {
            var s = try S.init(alloc, ts);
            defer s.deinit();
            try tckReuseClose(S, &s, alloc);
        }
        {
            var s = try S.init(alloc, ts);
            defer s.deinit();
            try tckOwnedSlice(S, &s, alloc);
        }
        {
            var s = try S.init(alloc, ts);
            defer s.deinit();
            try tckLogicalCas(S, &s, alloc);
        }
        if (comptime mod.supportsDelta(S)) {
            var s = try S.init(alloc, ts);
            defer s.deinit();
            try tckDelta(S, &s, alloc);
        }
    }
}

// ------------------------------------------------------------------- tests

test "TCK: StoreOnHeap" {
    try runCore(StoreOnHeap, testing.allocator);
}

test "TCK: StoreByteArray (incl. delta)" {
    try runCore(StoreByteArray, testing.allocator);
}

test "TCK: StoreDirect heap volume (incl. delta)" {
    try runCore(StoreDirect, testing.allocator);
}

test "TCK: StoreWAL (transactional, staged-until-commit; incl. delta)" {
    // StoreWAL.init opens a fresh unique temp WAL file in cwd, removed on deinit:
    // the generic TCK passes because reads merge staged
    // mutations over the inner committed image.
    try runCore(StoreWAL, testing.allocator);
}

test "StoreByteArray: verify() races free-list churn" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const alloc = testing.allocator;
    var s = try StoreByteArray.init(alloc, true);
    defer s.deinit();

    const N_WORKERS = 4;
    const ROUNDS = 60;
    const BATCH = 32;

    // Workers put a batch then delete it all: the free list repeatedly grows
    // by BATCH recids (forcing appends/reallocation) and shrinks again while
    // verify() scans it.
    const Worker = struct {
        fn run(st: *StoreByteArray) void {
            const L = LongSer.instance;
            var recs: [BATCH]u64 = undefined;
            var round: usize = 0;
            while (round < ROUNDS) : (round += 1) {
                for (&recs, 0..) |*r, i|
                    r.* = st.put(i64, testing.allocator, @as(i64, @intCast(i)), L) catch @panic("put failed");
                for (recs) |r| st.delete(r) catch @panic("delete failed");
            }
        }
    };
    const Verifier = struct {
        fn run(st: *StoreByteArray, stop: *std.atomic.Value(bool)) void {
            while (!stop.load(.acquire)) {
                st.verify() catch @panic("verify failed under concurrent churn");
                std.Thread.yield() catch {};
            }
        }
    };

    var stop = std.atomic.Value(bool).init(false);
    const ver_t = try std.Thread.spawn(.{}, Verifier.run, .{ &s, &stop });
    var workers: [N_WORKERS]std.Thread = undefined;
    for (&workers) |*t| t.* = try std.Thread.spawn(.{}, Worker.run, .{&s});
    for (&workers) |*t| t.join();
    stop.store(true, .release);
    ver_t.join();
    try s.verify();
}

test "StoreOnHeap: onObject push-down read + wrong-token" {
    const alloc = testing.allocator;
    var s = try StoreOnHeap.init(alloc, true);
    defer s.deinit();
    const L = LongSer.instance;

    const r = try s.put(i64, alloc, @as(i64, 42), L);
    var p = ReadProbe{};
    try testing.expectEqual(@as(i64, 42), try s.read(r, p.action()));
    try testing.expectEqual(@as(i64, 42), p.value.?);

    // wrong-token via the store's get() token check
    try testing.expectError(error.DataCorruption, s.get(i32, alloc, r, IntSer.instance));

    // wrong-token via the action's onObject: an i32 record read by an
    // i64-expecting probe → DataCorruption.
    const ri = try s.put(i32, alloc, @as(i32, 7), IntSer.instance);
    var p2 = ReadProbe{};
    try testing.expectError(error.DataCorruption, s.read(ri, p2.action()));
}
