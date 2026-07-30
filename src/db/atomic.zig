//! Atomic scalar cells over a Store record (Java `org.mapdb.db.Atomic`). Ported
//! from `mapdb-rust-store/src/db/atomic.rs`.
//!
//! Each atomic is a single store record read/written through the record's logical
//! CAS. All are cheap value handles (they carry `*S`, a recid, and the map's
//! allocator), so a second facade open of the same name is rejected by the DB's
//! lease/handle model, not by an instance cache (Zig no-cache deviation).
//!
//! `AtomicLong`/`AtomicInteger`/`AtomicBoolean` hold a non-null primitive record;
//! `AtomicString`/`AtomicVar` are nullable (a null record decodes to `null`).
//! Catalog rows: `type=AtomicLong|AtomicInteger|AtomicBoolean|AtomicString|AtomicVar`,
//! `recid=<decimal>`, and for `AtomicVar` additionally `serializer=<descriptor>`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Order = std.math.Order;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const serializers = @import("../ser/serializers.zig");

const LONG = serializers.LongSer.instance;
const INT = serializers.IntSer.instance;
const BOOL = serializers.BoolSer.instance;
const STRING = serializers.StringSer.instance;

fn missing() DbError {
    return error.DataCorruption;
}

/// Nullable-string codec (Java `Serializers.STRING_NULLABLE`): a presence byte
/// (`0x00` = null, `0x01` = present) then the ordinary `STRING` encoding when
/// present. `AtomicString` always writes a (non-null) record whose CONTENT
/// encodes null-ness, so `get()` on a fresh `atomicString` returns `null`.
pub const NullableStringSer = struct {
    pub const Elem = ?[]const u8;
    pub const instance: NullableStringSer = .{};

    pub fn serialize(_: NullableStringSer, out: *DataOutput2, v: ?[]const u8) DbError!void {
        if (v) |s| {
            try out.writeU8(1);
            try STRING.serialize(out, s);
        } else {
            try out.writeU8(0);
        }
    }
    pub fn deserialize(_: NullableStringSer, alloc: Allocator, input: *DataInput2, _: ?usize) DbError!?[]const u8 {
        const present = try input.readU8();
        if (present == 0) return null;
        return try STRING.deserialize(alloc, input, null);
    }
    pub fn cloneElem(_: NullableStringSer, alloc: Allocator, v: ?[]const u8) DbError!?[]const u8 {
        return if (v) |s| try alloc.dupe(u8, s) else null;
    }
    pub fn deinitElem(_: NullableStringSer, alloc: Allocator, v: ?[]const u8) void {
        if (v) |s| alloc.free(s);
    }
    pub fn compare(_: NullableStringSer, a: ?[]const u8, b: ?[]const u8) Order {
        if (a == null and b == null) return .eq;
        if (a == null) return .lt;
        if (b == null) return .gt;
        return STRING.compare(a.?, b.?);
    }
    pub fn equals(_: NullableStringSer, a: ?[]const u8, b: ?[]const u8) bool {
        if (a == null and b == null) return true;
        if (a == null or b == null) return false;
        return std.mem.eql(u8, a.?, b.?);
    }
    pub fn fixedSize(_: NullableStringSer) ?usize {
        return null;
    }
    pub fn equalsBySerializedBytes(_: NullableStringSer) bool {
        return true;
    }
};

pub const STRING_NULLABLE = NullableStringSer.instance;

/// Factory for the three non-null numeric atomics (Long/Integer/Boolean). `Ser`
/// is a scalar serializer with `Elem == P`.
fn NumericAtomic(comptime S: type, comptime P: type, comptime Ser: anytype) type {
    return struct {
        const Self = @This();
        store: *S,
        alloc: Allocator,
        recid: u64,

        pub fn init(store: *S, alloc: Allocator, recid: u64) Self {
            return .{ .store = store, .alloc = alloc, .recid = recid };
        }
        pub fn getRecid(self: Self) u64 {
            return self.recid;
        }
        pub fn get(self: Self) DbError!P {
            return (try self.store.get(P, self.alloc, self.recid, Ser)) orelse missing();
        }
        pub fn set(self: Self, value: P) DbError!void {
            return self.store.update(P, self.alloc, self.recid, value, Ser);
        }
        pub fn compareAndSet(self: Self, expect: P, new: P) DbError!bool {
            return self.store.compareAndSwap(P, self.alloc, self.recid, @as(?P, expect), @as(?P, new), Ser);
        }
        pub fn getAndSet(self: Self, new: P) DbError!P {
            while (true) {
                const cur = try self.get();
                if (try self.compareAndSet(cur, new)) return cur;
            }
        }
    };
}

/// Add numeric increment/decrement helpers to a `NumericAtomic` (Long/Integer).
fn NumericAtomicWithMath(comptime S: type, comptime P: type, comptime Ser: anytype) type {
    const Base = NumericAtomic(S, P, Ser);
    return struct {
        const Self = @This();
        base: Base,

        pub fn init(store: *S, alloc: Allocator, recid: u64) Self {
            return .{ .base = Base.init(store, alloc, recid) };
        }
        pub fn getRecid(self: Self) u64 {
            return self.base.recid;
        }
        pub fn get(self: Self) DbError!P {
            return self.base.get();
        }
        pub fn set(self: Self, value: P) DbError!void {
            return self.base.set(value);
        }
        pub fn compareAndSet(self: Self, expect: P, new: P) DbError!bool {
            return self.base.compareAndSet(expect, new);
        }
        pub fn getAndSet(self: Self, new: P) DbError!P {
            return self.base.getAndSet(new);
        }
        pub fn addAndGet(self: Self, delta: P) DbError!P {
            while (true) {
                const cur = try self.base.get();
                const next = cur +% delta; // Java long/int overflow wraps
                if (try self.base.compareAndSet(cur, next)) return next;
            }
        }
        pub fn getAndAdd(self: Self, delta: P) DbError!P {
            while (true) {
                const cur = try self.base.get();
                const next = cur +% delta;
                if (try self.base.compareAndSet(cur, next)) return cur;
            }
        }
        pub fn incrementAndGet(self: Self) DbError!P {
            return self.addAndGet(1);
        }
        pub fn getAndIncrement(self: Self) DbError!P {
            return self.getAndAdd(1);
        }
        pub fn decrementAndGet(self: Self) DbError!P {
            return self.addAndGet(-1);
        }
        pub fn getAndDecrement(self: Self) DbError!P {
            return self.getAndAdd(-1);
        }
    };
}

pub fn AtomicLong(comptime S: type) type {
    return NumericAtomicWithMath(S, i64, LONG);
}
pub fn AtomicInteger(comptime S: type) type {
    return NumericAtomicWithMath(S, i32, INT);
}
pub fn AtomicBoolean(comptime S: type) type {
    return NumericAtomic(S, bool, BOOL);
}

/// A nullable atomic string (Java `Atomic.String`). Returned strings are owned by
/// the map allocator (free with the allocator). A null record decodes to `null`.
pub fn AtomicString(comptime S: type) type {
    return struct {
        const Self = @This();
        store: *S,
        alloc: Allocator,
        recid: u64,

        pub fn init(store: *S, alloc: Allocator, recid: u64) Self {
            return .{ .store = store, .alloc = alloc, .recid = recid };
        }
        pub fn getRecid(self: Self) u64 {
            return self.recid;
        }
        /// `null` when the stored value is null; otherwise an OWNED string.
        pub fn get(self: Self) DbError!?[]const u8 {
            const outer = try self.store.get(?[]const u8, self.alloc, self.recid, STRING_NULLABLE);
            // outer is ?(?[]const u8): the record is always present, so unwrap once.
            return outer orelse null;
        }
        pub fn set(self: Self, value: ?[]const u8) DbError!void {
            return self.store.update(?[]const u8, self.alloc, self.recid, value, STRING_NULLABLE);
        }
        pub fn compareAndSet(self: Self, expect: ?[]const u8, new: ?[]const u8) DbError!bool {
            return self.store.compareAndSwap(?[]const u8, self.alloc, self.recid, @as(??[]const u8, expect), @as(??[]const u8, new), STRING_NULLABLE);
        }
        /// Atomically set to `new` and return the OWNED previous value (Java
        /// `getAndSet`). A losing CAS — OR a CAS that ERRORS mid-loop (StoreClosed /
        /// I/O) — frees the fetched value first, so `cur` never leaks.
        pub fn getAndSet(self: Self, new: ?[]const u8) DbError!?[]const u8 {
            while (true) {
                const cur = try self.get();
                const swapped = self.compareAndSet(cur, new) catch |e| {
                    if (cur) |c| self.alloc.free(c);
                    return e;
                };
                if (swapped) return cur;
                if (cur) |c| self.alloc.free(c);
            }
        }
    };
}

/// A nullable atomic cell over an arbitrary element serializer (Java
/// `Atomic.Var<E>`). `Se` may be a STATEFUL element serializer (e.g. a
/// `CompressionSerializer`), so the handle stores the serializer VALUE `se` and
/// passes it to every store op / descriptor generation rather than a
/// non-existent `Se.instance`; `E == Se.Elem`.
pub fn AtomicVar(comptime S: type, comptime Se: type) type {
    const E = Se.Elem;
    return struct {
        const Self = @This();
        store: *S,
        alloc: Allocator,
        recid: u64,
        se: Se,

        pub fn init(store: *S, alloc: Allocator, recid: u64, se: Se) Self {
            return .{ .store = store, .alloc = alloc, .recid = recid, .se = se };
        }
        pub fn getRecid(self: Self) u64 {
            return self.recid;
        }
        /// `null` when the record is null; otherwise an OWNED `E`.
        pub fn get(self: Self) DbError!?E {
            return self.store.get(E, self.alloc, self.recid, self.se);
        }
        pub fn set(self: Self, value: ?E) DbError!void {
            return self.store.update(E, self.alloc, self.recid, value, self.se);
        }
        pub fn compareAndSet(self: Self, expect: ?E, new: ?E) DbError!bool {
            return self.store.compareAndSwap(E, self.alloc, self.recid, expect, new, self.se);
        }
        /// Atomically set to `new`, returning the OWNED previous value (Java
        /// `getAndSet`). A losing CAS — OR a CAS that ERRORS mid-loop — frees the
        /// fetched value first, so `cur` never leaks.
        pub fn getAndSet(self: Self, new: ?E) DbError!?E {
            while (true) {
                const cur = try self.get();
                const swapped = self.compareAndSet(cur, new) catch |e| {
                    if (cur) |c| self.se.deinitElem(self.alloc, c);
                    return e;
                };
                if (swapped) return cur;
                if (cur) |c| self.se.deinitElem(self.alloc, c);
            }
        }
    };
}

// ------------------------------------------------------------------- tests

const testing = std.testing;
const StoreByteArray = @import("../store/mod.zig").StoreByteArray;

test "STRING_NULLABLE presence byte round-trips null and value" {
    const a = testing.allocator;
    var out = DataOutput2.init(a);
    defer out.deinit();
    try STRING_NULLABLE.serialize(&out, null);
    try testing.expectEqualSlices(u8, &.{0x00}, out.bytes());
    var out2 = DataOutput2.init(a);
    defer out2.deinit();
    try STRING_NULLABLE.serialize(&out2, "hi");
    // presence 1, then STRING("hi") = 0x82 'h' 'i'
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x82, 'h', 'i' }, out2.bytes());
    var inp = DataInput2.init(out2.bytes());
    const back = try STRING_NULLABLE.deserialize(a, &inp, null);
    defer STRING_NULLABLE.deinitElem(a, back);
    try testing.expectEqualStrings("hi", back.?);
}

test "AtomicLong increment/CAS over a byte store" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    const recid = try s.put(i64, a, @as(i64, 10), LONG);
    const al = AtomicLong(StoreByteArray).init(&s, a, recid);
    try testing.expectEqual(@as(i64, 10), try al.get());
    try testing.expectEqual(@as(i64, 11), try al.incrementAndGet());
    try testing.expectEqual(@as(i64, 11), try al.getAndAdd(5));
    try testing.expectEqual(@as(i64, 16), try al.get());
    try testing.expect(try al.compareAndSet(16, 100));
    try testing.expect(!(try al.compareAndSet(16, 200)));
}

test "AtomicString null then value" {
    const a = testing.allocator;
    var s = try StoreByteArray.init(a, true);
    defer s.deinit();
    const recid = try s.put(?[]const u8, a, null, STRING_NULLABLE);
    const as = AtomicString(StoreByteArray).init(&s, a, recid);
    try testing.expect((try as.get()) == null);
    try as.set("hello");
    const v = try as.get();
    defer if (v) |x| a.free(x);
    try testing.expectEqualStrings("hello", v.?);
}
