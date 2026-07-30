//! Map modification listeners + the `ModificationAwareMap` / `MapExtra` shape
//! contracts (Java `org.mapdb.MapModificationListener`,
//! `SynchronousMapModificationListener`, `ModificationAwareMap`, `MapExtra`).
//!
//! Idiom: a listener is a `ptr` + `modifyFn` vtable pair (the
//! `std.mem.Allocator` style), monomorphized over the map's `(K, V)`. Java's
//! `SynchronousMapModificationListener` marker — "deliver SYNCHRONOUSLY, under
//! the covering leaf/segment lock, preserving per-key event order" — is carried
//! as a `synchronous: bool` flag rather than a separate type, since Zig has no
//! interface-marker refinement.
//!
//! These types are consumed by BTreeMap: the map owns
//! a [`ListenerRegistry`], fires async listeners AFTER releasing the covering
//! lock and synchronous ones UNDER it, both POST-mutation. Throw-safety: a
//! failing listener must not corrupt the tree or skip split propagation; the
//! registry fires ALL listeners and surfaces the FIRST error (Java rethrows the
//! first throwable with the rest attached as suppressed — Zig errors carry no
//! payload, so the remainder are dropped after still being delivered).

const std = @import("std");
const Allocator = std.mem.Allocator;
const DbError = @import("errors.zig").DbError;

/// Runtime map-mutation callback (Java `MapModificationListener`). `old_value`
/// is `null` on insert, `new_value` is `null` on remove. `triggered` is `true`
/// for automatic expiry/eviction and `false` for user-requested mutations.
/// Keys/values are BORROWED for the duration of the call (never retained).
pub fn MapModificationListener(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();

        pub const ModifyFn = *const fn (
            ctx: *anyopaque,
            key: K,
            old_value: ?V,
            new_value: ?V,
            triggered: bool,
        ) DbError!void;

        ctx: *anyopaque,
        modifyFn: ModifyFn,
        /// `true` requests synchronous, under-lock delivery (Java
        /// `SynchronousMapModificationListener`); `false` is deferred delivery.
        synchronous: bool = false,

        pub fn init(ctx: *anyopaque, modifyFn: ModifyFn) Self {
            return .{ .ctx = ctx, .modifyFn = modifyFn, .synchronous = false };
        }

        /// A synchronous (under-lock, order-preserving) listener.
        pub fn initSynchronous(ctx: *anyopaque, modifyFn: ModifyFn) Self {
            return .{ .ctx = ctx, .modifyFn = modifyFn, .synchronous = true };
        }

        pub fn modify(self: Self, key: K, old_value: ?V, new_value: ?V, triggered: bool) DbError!void {
            return self.modifyFn(self.ctx, key, old_value, new_value, triggered);
        }

        pub fn eql(self: Self, other: Self) bool {
            return self.ctx == other.ctx and self.modifyFn == other.modifyFn;
        }
    };
}

/// A registry of modification listeners owned by a `ModificationAwareMap`.
/// Not internally synchronized: the owning map guards add/remove/fire with its
/// own structure lock (Java registers/fires under the map lock).
pub fn ListenerRegistry(comptime K: type, comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Listener = MapModificationListener(K, V);

        listeners: std.ArrayListUnmanaged(Listener) = .empty,

        pub fn deinit(self: *Self, alloc: Allocator) void {
            self.listeners.deinit(alloc);
        }

        pub fn add(self: *Self, alloc: Allocator, listener: Listener) DbError!void {
            try self.listeners.append(alloc, listener);
        }

        /// Remove the first registered listener equal (ctx+fn) to `listener`.
        /// Returns `true` if one was removed.
        pub fn remove(self: *Self, listener: Listener) bool {
            for (self.listeners.items, 0..) |l, i| {
                if (l.eql(listener)) {
                    _ = self.listeners.orderedRemove(i);
                    return true;
                }
            }
            return false;
        }

        pub fn isEmpty(self: *const Self) bool {
            return self.listeners.items.len == 0;
        }

        pub fn count(self: *const Self) usize {
            return self.listeners.items.len;
        }

        pub fn hasSynchronous(self: *const Self) bool {
            for (self.listeners.items) |l| if (l.synchronous) return true;
            return false;
        }

        /// Fire every listener whose `synchronous` flag matches `synchronous`,
        /// in registration order. ALL matching listeners are invoked even if one
        /// fails; the FIRST error is returned afterwards (throw-safe delivery).
        pub fn fire(
            self: *const Self,
            synchronous: bool,
            key: K,
            old_value: ?V,
            new_value: ?V,
            triggered: bool,
        ) DbError!void {
            var first_err: ?DbError = null;
            for (self.listeners.items) |l| {
                if (l.synchronous != synchronous) continue;
                l.modify(key, old_value, new_value, triggered) catch |e| {
                    if (first_err == null) first_err = e;
                };
            }
            if (first_err) |e| return e;
        }
    };
}

/// Comptime shape check for `ModificationAwareMap` (Java): the map exposes
/// `modificationListenerAdd` / `modificationListenerRemove`. Names-only (like
/// `store.checkStore`); generic signatures are validated by instantiation.
pub fn checkModificationAwareMap(comptime M: type) void {
    comptime {
        for ([_][]const u8{ "modificationListenerAdd", "modificationListenerRemove" }) |name| {
            if (!@hasDecl(M, name))
                @compileError("ModificationAwareMap " ++ @typeName(M) ++ " missing decl `" ++ name ++ "`");
        }
    }
}

/// Comptime shape check for `MapExtra` (Java): a persistent concurrent map that
/// is also `ModificationAwareMap` and exposes `sizeLong` / `isClosed` /
/// `keySerializer` / `valueSerializer`.
pub fn checkMapExtra(comptime M: type) void {
    comptime {
        checkModificationAwareMap(M);
        for ([_][]const u8{ "sizeLong", "isClosed", "keySerializer", "valueSerializer" }) |name| {
            if (!@hasDecl(M, name))
                @compileError("MapExtra " ++ @typeName(M) ++ " missing decl `" ++ name ++ "`");
        }
    }
}

// ------------------------------------------------------------------- tests

const testing = std.testing;

const Recorder = struct {
    hits: usize = 0,
    last_key: i64 = 0,
    last_old: ?i64 = null,
    last_new: ?i64 = null,
    last_triggered: bool = false,
    fail: bool = false,

    fn modify(ctx: *anyopaque, key: i64, old_value: ?i64, new_value: ?i64, triggered: bool) DbError!void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        self.hits += 1;
        self.last_key = key;
        self.last_old = old_value;
        self.last_new = new_value;
        self.last_triggered = triggered;
        if (self.fail) return error.DataCorruption;
    }
};

test "listener fires with borrowed key/values and triggered flag" {
    const L = MapModificationListener(i64, i64);
    var rec = Recorder{};
    const l = L.init(&rec, Recorder.modify);
    try l.modify(7, null, 99, false);
    try testing.expectEqual(@as(usize, 1), rec.hits);
    try testing.expectEqual(@as(i64, 7), rec.last_key);
    try testing.expectEqual(@as(?i64, null), rec.last_old);
    try testing.expectEqual(@as(?i64, 99), rec.last_new);
    try testing.expect(!rec.last_triggered);
}

test "registry add/remove/fire sync vs async partition + throw-safety" {
    const a = testing.allocator;
    const L = MapModificationListener(i64, i64);
    var reg = ListenerRegistry(i64, i64){};
    defer reg.deinit(a);

    var async_rec = Recorder{};
    var sync_rec = Recorder{ .fail = true };
    var sync_rec2 = Recorder{};

    const la = L.init(&async_rec, Recorder.modify);
    try reg.add(a, la);
    try reg.add(a, L.initSynchronous(&sync_rec, Recorder.modify));
    try reg.add(a, L.initSynchronous(&sync_rec2, Recorder.modify));
    try testing.expect(reg.hasSynchronous());
    try testing.expectEqual(@as(usize, 3), reg.count());

    // async fire hits only the async listener
    try reg.fire(false, 1, 10, 20, false);
    try testing.expectEqual(@as(usize, 1), async_rec.hits);
    try testing.expectEqual(@as(usize, 0), sync_rec.hits);

    // sync fire hits both sync listeners even though the first fails; the
    // first error is surfaced afterwards.
    try testing.expectError(error.DataCorruption, reg.fire(true, 2, 30, 40, true));
    try testing.expectEqual(@as(usize, 1), sync_rec.hits);
    try testing.expectEqual(@as(usize, 1), sync_rec2.hits); // still delivered
    try testing.expect(sync_rec2.last_triggered);

    // remove the async listener
    try testing.expect(reg.remove(la));
    try testing.expectEqual(@as(usize, 2), reg.count());
    try reg.fire(false, 3, 0, 0, false);
    try testing.expectEqual(@as(usize, 1), async_rec.hits); // unchanged
}
