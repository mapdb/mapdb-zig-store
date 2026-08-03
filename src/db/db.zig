//! The `Db` facade (Java `org.mapdb.db.DB`): the name catalog at recid 1, typed
//! comptime collection makers, the lease-based double-open rejection (Zig no-cache
//! deviation), and the close/deinit teardown-order lifecycle. Ported from
//! `mapdb-rust-store/src/db/db.rs` with these Zig-specific rulings: `Db(comptime S)` with
//! comptime-typed makers, NO instance cache (a second writable open returns
//! `error.AlreadyOpen`), `close()` enforces no-outstanding-handles
//! (`error.HandlesOpen`), and `deinit` asserts close succeeded in safe modes.
//!
//! ## Administrative lifecycle (review C4/C5)
//! `admin_mu` is THE lifecycle serialization point: every admin/maker/read
//! operation acquires it via [`lockAdmin`] and rechecks `state` UNDER the lock, so
//! an operation that queued behind an in-flight `close`/`rollback` observes
//! `StoreClosed` once it wins the lock. `close()` holds `admin_mu` across the
//! store close + cleanup, so a concurrent second closer blocks and returns only
//! after the close has actually completed (never an early success that lets a
//! caller `deinit()` a still-closing store).
//!
//! ## Catalog staging (review C3)
//! Every create/rename/delete mutates a DEEP CLONE of the live catalog, persists
//! the clone to recid 1, and swaps it into `self.catalog` only after the store
//! update succeeds ([`swapCatalog`]); a failed/partial save therefore never
//! corrupts the in-memory catalog.
//!
//! ## Handle lifecycle (Zig no-cache model)
//! Every successful maker `open`/`create` increments an outstanding-handle count
//! and returns a RAW collection handle. The caller tears a handle down through
//! the matching `Db.close*` helper. `closeMap`/`closeSet` are FALLIBLE and refuse
//! to release the name's handle count while a derived clone still owns the tree
//! (review C6). `Db.close()` fails `error.HandlesOpen` while any handle remains.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const storemod = @import("../store/mod.zig");
const btree = @import("../btree/mod.zig");
const blocking = @import("../queue/blocking.zig");
const catalogmod = @import("catalog.zig");
const descriptor = @import("descriptor.zig");
const atomicmod = @import("atomic.zig");
const setmod = @import("set.zig");
const serializers = @import("../ser/serializers.zig");

const NameCatalog = catalogmod.NameCatalog;
const CatalogSer = catalogmod.CatalogSer;
const RECID_CATALOG = catalogmod.RECID_CATALOG;

const LONG = serializers.LongSer.instance;
const INT = serializers.IntSer.instance;
const BOOL = serializers.BoolSer.instance;
const STRING_NULLABLE = atomicmod.STRING_NULLABLE;

const MIN_MNS = btree.map.MIN_MAX_NODE_SIZE;
const MAX_MNS = btree.map.MAX_MAX_NODE_SIZE;

// DB lifecycle states (stored in the atomic `state`).
const OPEN: u8 = 0;
const CLOSED: u8 = 2;

/// Validate a collection name: non-empty, only `[A-Za-z0-9._-]` (Java `checkName`).
/// `#` is forbidden (it separates a name from a parameter).
pub fn validateName(name: []const u8) DbError!void {
    if (name.len == 0) return error.WrongConfiguration;
    for (name) |c| {
        const ok = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or c == '.' or c == '_' or c == '-';
        if (!ok) return error.WrongConfiguration;
    }
}

/// A create-time `maxNodeSize` outside the legal range is wrong CONFIGURATION
/// (review C2); a persisted one is `DataCorruption` (checked in `openFromCatalog`
/// and `validateCatalog`).
fn validateMaxNodeSize(n: usize) DbError!void {
    if (n < MIN_MNS or n > MAX_MNS) return error.WrongConfiguration;
}

fn parseRecid(cat: *const NameCatalog, alloc: Allocator, name: []const u8, suffix: []const u8) DbError!u64 {
    const key = try keyName(alloc, name, suffix);
    defer alloc.free(key);
    const s = cat.get(key) orelse return error.DataCorruption;
    const v = std.fmt.parseInt(u64, s, 10) catch return error.DataCorruption;
    if (v < 1) return error.DataCorruption;
    return v;
}

fn parseRecidDefault0(cat: *const NameCatalog, alloc: Allocator, name: []const u8, suffix: []const u8) DbError!u64 {
    const key = try keyName(alloc, name, suffix);
    defer alloc.free(key);
    const s = cat.get(key) orelse return 0; // legacy default (absent counterRecid → 0)
    return std.fmt.parseInt(u64, s, 10) catch return error.DataCorruption;
}

fn keyName(alloc: Allocator, name: []const u8, suffix: []const u8) DbError![]u8 {
    return std.fmt.allocPrint(alloc, "{s}#{s}", .{ name, suffix });
}

/// `<path>.ckpt` — the Java WAL checkpoint sidecar.
fn ckptPath(alloc: Allocator, path: []const u8) DbError![]u8 {
    return std.fmt.allocPrint(alloc, "{s}.ckpt", .{path});
}

// ============================================================ catalog validation

/// Fully validate a decoded name catalog beyond MDBC syntax:
/// group by the first `#`, require a legal name and a known `#type`,
/// require the EXACT required/allowed field set per type (reject unknown fields),
/// validate codec descriptors, parse recids (`≥ 1`; `counterRecid == 0` allowed),
/// booleans, and the `maxNodeSize` range. Called at open, after a rollback
/// reload, and before rename/delete — before any collection is built over it.
/// Mirrors Rust `validate_catalog`.
pub fn validateCatalog(alloc: Allocator, cat: *const NameCatalog) DbError!void {
    // Group `name#param -> value` by name into a temporary owned structure.
    const Fields = std.StringHashMapUnmanaged([]const u8);
    var groups = std.StringHashMapUnmanaged(Fields){};
    defer {
        var it = groups.valueIterator();
        while (it.next()) |f| f.deinit(alloc);
        groups.deinit(alloc);
    }
    for (cat.pairs.items) |p| {
        const hash = std.mem.indexOfScalar(u8, p.key, '#') orelse return error.DataCorruption;
        const name = p.key[0..hash];
        const param = p.key[hash + 1 ..];
        if (std.mem.indexOfScalar(u8, param, '#') != null) return error.DataCorruption; // >1 '#'
        const gop = try groups.getOrPut(alloc, name);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.put(alloc, param, p.value);
    }

    var git = groups.iterator();
    while (git.next()) |g| {
        const name = g.key_ptr.*;
        const fields = g.value_ptr;
        validateName(name) catch return error.DataCorruption;
        const ty = fields.get("type") orelse return error.DataCorruption;
        if (std.mem.eql(u8, ty, "TreeMap")) {
            try checkFields(fields, &.{ "keySerializer", "valueSerializer", "rootRecidRecid", "maxNodeSize" }, &.{ "counterRecid", "valueInline" });
            try checkGroupDesc(alloc, fields, "keySerializer");
            try checkGroupDesc(alloc, fields, "valueSerializer");
            try checkRecidGe1(fields, "rootRecidRecid");
            try checkCounter(fields, "counterRecid");
            try checkMaxNode(fields);
            try checkBool(fields, "valueInline");
        } else if (std.mem.eql(u8, ty, "TreeSet")) {
            try checkFields(fields, &.{ "serializer", "rootRecidRecid", "maxNodeSize" }, &.{"counterRecid"});
            try checkGroupDesc(alloc, fields, "serializer");
            try checkRecidGe1(fields, "rootRecidRecid");
            try checkCounter(fields, "counterRecid");
            try checkMaxNode(fields);
        } else if (std.mem.eql(u8, ty, "AtomicLong") or std.mem.eql(u8, ty, "AtomicInteger") or
            std.mem.eql(u8, ty, "AtomicBoolean") or std.mem.eql(u8, ty, "AtomicString"))
        {
            try checkFields(fields, &.{"recid"}, &.{});
            try checkRecidGe1(fields, "recid");
        } else if (std.mem.eql(u8, ty, "AtomicVar")) {
            try checkFields(fields, &.{ "recid", "serializer" }, &.{});
            try checkSerDesc(alloc, fields, "serializer");
            try checkRecidGe1(fields, "recid");
        } else if (std.mem.eql(u8, ty, "Queue") or std.mem.eql(u8, ty, "Stack") or std.mem.eql(u8, ty, "CircularQueue")) {
            try checkFields(fields, &.{ "headerRecid", "serializer" }, &.{});
            try checkSerDesc(alloc, fields, "serializer");
            try checkRecidGe1(fields, "headerRecid");
        } else {
            return error.DataCorruption; // unknown #type
        }
    }
}

const FieldsT = std.StringHashMapUnmanaged([]const u8);

fn checkFields(fields: *const FieldsT, required: []const []const u8, optional: []const []const u8) DbError!void {
    for (required) |r| if (!fields.contains(r)) return error.DataCorruption;
    var it = fields.keyIterator();
    while (it.next()) |k| {
        const key = k.*;
        if (std.mem.eql(u8, key, "type")) continue;
        var ok = false;
        for (required) |r| if (std.mem.eql(u8, key, r)) {
            ok = true;
        };
        for (optional) |o| if (std.mem.eql(u8, key, o)) {
            ok = true;
        };
        if (!ok) return error.DataCorruption; // unknown field
    }
}

fn checkGroupDesc(alloc: Allocator, fields: *const FieldsT, field: []const u8) DbError!void {
    if (fields.get(field)) |v| if (!(try descriptor.isValidGroupDescriptor(alloc, v))) return error.DataCorruption;
}
fn checkSerDesc(alloc: Allocator, fields: *const FieldsT, field: []const u8) DbError!void {
    if (fields.get(field)) |v| if (!(try descriptor.isValidSerDescriptor(alloc, v))) return error.DataCorruption;
}
fn checkRecidGe1(fields: *const FieldsT, field: []const u8) DbError!void {
    if (fields.get(field)) |v| {
        const r = std.fmt.parseInt(u64, v, 10) catch return error.DataCorruption;
        if (r < 1) return error.DataCorruption;
    }
}
fn checkCounter(fields: *const FieldsT, field: []const u8) DbError!void {
    if (fields.get(field)) |v| {
        _ = std.fmt.parseInt(u64, v, 10) catch return error.DataCorruption; // 0 allowed
    }
}
fn checkMaxNode(fields: *const FieldsT) DbError!void {
    if (fields.get("maxNodeSize")) |v| {
        const m = std.fmt.parseInt(usize, v, 10) catch return error.DataCorruption;
        if (m < MIN_MNS or m > MAX_MNS) return error.DataCorruption;
    }
}
fn checkBool(fields: *const FieldsT, field: []const u8) DbError!void {
    if (fields.get(field)) |v| {
        if (!std.mem.eql(u8, v, "true") and !std.mem.eql(u8, v, "false")) return error.DataCorruption;
    }
}

// ============================================================ Db

/// The DB facade over a store `S`. Not copyable after construction (makers keep
/// `*Db`); keep it at a stable address (`var db = ...`).
pub fn Db(comptime S: type) type {
    return struct {
        const Self = @This();

        alloc: Allocator,
        store: *S,
        /// Whether `deinit` frees `store` (true for maker-constructed DBs).
        owns_store: bool,
        /// Optional backing store for a read-only wrapper (`StoreReadOnlyWrapper`
        /// owns only its delegate pointer; the DB frees the delegate here).
        ro_backing: ?*anyopaque = null,
        ro_backing_deinit: ?*const fn (Allocator, *anyopaque) void = null,
        catalog: NameCatalog,
        admin_mu: std.Thread.Mutex = .{},
        open_handles: usize = 0,
        /// Lifecycle state (atomic; also always transitioned under `admin_mu`).
        state: std.atomic.Value(u8) = std.atomic.Value(u8).init(OPEN),
        /// Files removed after close (temp DB / delete-after-close); both `<path>`
        /// and `<path>.ckpt` are deleted, if present. Owned strings.
        cleanup_paths: std.ArrayListUnmanaged([]const u8) = .empty,

        // -------------------------------------------------- construction

        /// Wrap `store`, initializing or validating the name catalog at recid 1.
        /// `owns_store` transfers store ownership to the DB (`deinit` frees it).
        /// On failure the caller retains store ownership (this does not free it).
        pub fn init(alloc: Allocator, store: *S, owns_store: bool) DbError!Self {
            var self = Self{
                .alloc = alloc,
                .store = store,
                .owns_store = owns_store,
                .catalog = NameCatalog.init(),
            };
            try self.initCatalog();
            return self;
        }

        fn initCatalog(self: *Self) DbError!void {
            const recids = try self.store.getAllRecids(self.alloc);
            const is_empty = recids.len == 0;
            self.alloc.free(recids);
            if (is_empty) {
                if (storemod.isReadOnly(S, self.store)) return error.WrongConfiguration;
                var empty = NameCatalog.init();
                errdefer empty.deinit(self.alloc);
                const recid = try self.store.put(NameCatalog, self.alloc, empty, CatalogSer.instance);
                if (recid != RECID_CATALOG) {
                    self.store.delete(recid) catch {};
                    return error.WrongConfiguration;
                }
                // The sole hidden facade commit: persist the fresh empty catalog.
                try self.store.commit();
                self.catalog = empty; // ownership moves into the DB
            } else {
                const got = self.store.get(NameCatalog, self.alloc, RECID_CATALOG, CatalogSer.instance) catch |e| switch (e) {
                    error.GetVoid => return error.WrongConfiguration, // recid 1 not allocated
                    else => return e,
                };
                var loaded = got orelse return error.WrongConfiguration; // null record = wrong store
                // Reject a hostile / malformed catalog at open, before any
                // collection can be built over it.
                validateCatalog(self.alloc, &loaded) catch |e| {
                    loaded.deinit(self.alloc);
                    return e;
                };
                self.catalog = loaded;
            }
        }

        pub fn registerCleanup(self: *Self, path: []const u8) DbError!void {
            const owned = try self.alloc.dupe(u8, path);
            errdefer self.alloc.free(owned);
            try self.cleanup_paths.append(self.alloc, owned);
        }

        // -------------------------------------------------- admin / catalog

        /// Acquire `admin_mu`, THEN recheck lifecycle (review C5): an operation
        /// that queued behind an in-flight `close`/`rollback` observes
        /// `StoreClosed` once it wins the lock. On success the lock is HELD (the
        /// caller must `defer self.admin_mu.unlock()`); on `StoreClosed` it is
        /// released before returning.
        fn lockAdmin(self: *Self) DbError!void {
            self.admin_mu.lock();
            if (self.state.load(.acquire) != OPEN) {
                self.admin_mu.unlock();
                return error.StoreClosed;
            }
        }

        /// Persist a candidate catalog to recid 1 (Java DB does NOT auto-commit
        /// named-object catalog edits).
        fn saveCatalog(self: *Self, staged: *const NameCatalog) DbError!void {
            try self.store.update(NameCatalog, self.alloc, RECID_CATALOG, staged.*, CatalogSer.instance);
        }

        /// Persist `staged` to recid 1 and, ONLY on success, swap it into
        /// `self.catalog` (freeing the old catalog). `staged` is moved out — the
        /// caller's `errdefer staged.deinit` then frees an empty catalog (no-op)
        /// on the success path (review C3). On save failure `self.catalog` is
        /// untouched and `staged` stays owned by the caller's errdefer.
        fn swapCatalog(self: *Self, staged: *NameCatalog) DbError!void {
            try self.saveCatalog(staged);
            var old = self.catalog;
            self.catalog = staged.*;
            staged.* = NameCatalog.init();
            old.deinit(self.alloc);
        }

        /// A snapshot copy of the whole name catalog (Java `getNameCatalog`); owned.
        pub fn getNameCatalog(self: *Self) DbError!NameCatalog {
            try self.lockAdmin();
            defer self.admin_mu.unlock();
            return self.catalog.clone(self.alloc);
        }

        /// True if a named object exists (Java `exists`). Errors `StoreClosed` on a
        /// closed DB.
        pub fn exists(self: *Self, name: []const u8) DbError!bool {
            try self.lockAdmin();
            defer self.admin_mu.unlock();
            const key = try keyName(self.alloc, name, "type");
            defer self.alloc.free(key);
            return self.catalog.contains(key);
        }

        /// The stored `#type` of `name` as an OWNED copy (caller frees), or null
        /// (Java `getType`). Errors `StoreClosed` on a closed DB.
        pub fn getType(self: *Self, name: []const u8) DbError!?[]u8 {
            try self.lockAdmin();
            defer self.admin_mu.unlock();
            const key = try keyName(self.alloc, name, "type");
            defer self.alloc.free(key);
            const t = self.catalog.get(key) orelse return null;
            return try self.alloc.dupe(u8, t);
        }

        /// Commit the backing store (Java `commit`). No-op on a read-only store.
        /// Serialized with catalog mutation / close via `admin_mu` (review C5).
        pub fn commit(self: *Self) DbError!void {
            try self.lockAdmin();
            defer self.admin_mu.unlock();
            if (storemod.isReadOnly(S, self.store)) return;
            try self.store.commit();
        }

        /// Roll back the backing store (Java `rollback`); fails `Unsupported` on a
        /// non-transactional store. Rejects `HandlesOpen` while any facade handle
        /// is live (the no-cache model cannot invalidate a live handle safely —
        /// review C4). After a successful rollback the catalog is reloaded from
        /// recid 1 and REVALIDATED before it is installed.
        pub fn rollback(self: *Self) DbError!void {
            try self.lockAdmin();
            defer self.admin_mu.unlock();
            if (self.open_handles != 0) return error.HandlesOpen;
            if (comptime storemod.supportsTx(S)) {
                try self.store.rollback();
            } else return error.Unsupported;
            // The store has now reverted. From here ANY failure to reload+validate
            // the catalog leaves stale in-memory metadata over a moved store, so we
            // POISON the facade: close the store and transition to a terminal state
            // (no later maker/admin op may act on the stale catalog).
            self.reloadCatalogAfterRollback() catch |e| {
                self.store.close() catch {};
                self.state.store(CLOSED, .release);
                return e;
            };
        }

        fn reloadCatalogAfterRollback(self: *Self) DbError!void {
            // An initialized DB ALWAYS has a committed recid-1 catalog, so a missing
            // or null record after rollback is corruption, not an empty catalog.
            const got = self.store.get(NameCatalog, self.alloc, RECID_CATALOG, CatalogSer.instance) catch |e| switch (e) {
                error.GetVoid => return error.DataCorruption,
                else => return e,
            };
            var reloaded = got orelse return error.DataCorruption;
            errdefer reloaded.deinit(self.alloc);
            try validateCatalog(self.alloc, &reloaded);
            var old = self.catalog;
            self.catalog = reloaded;
            reloaded = NameCatalog.init(); // ownership transferred; errdefer no-ops
            old.deinit(self.alloc);
        }

        pub fn compact(self: *Self) DbError!void {
            try self.lockAdmin();
            defer self.admin_mu.unlock();
            try self.store.compact();
        }

        pub fn isClosed(self: *Self) bool {
            return self.state.load(.acquire) != OPEN;
        }

        /// The backing store pointer. Errors `StoreClosed` once the DB has closed
        /// (do not hand out a store the DB may free — review N3).
        pub fn storePtr(self: *Self) DbError!*S {
            try self.lockAdmin();
            defer self.admin_mu.unlock();
            return self.store;
        }

        // -------------------------------------------------- rename / delete

        /// Rename a named object (Java `rename`): `old` must exist, `new#type` must
        /// not; rewrites every `old#…` key to `new#…` on a staged catalog clone,
        /// saves once, and swaps. Java does NOT commit. Rejects a rename while ANY
        /// handle is open (the no-cache model cannot rebind a live handle — M10).
        pub fn rename(self: *Self, old: []const u8, new: []const u8) DbError!void {
            try validateName(old);
            try validateName(new);
            try self.lockAdmin();
            defer self.admin_mu.unlock();
            if (self.open_handles != 0) return error.HandlesOpen;
            try validateCatalog(self.alloc, &self.catalog);
            const old_type = try keyName(self.alloc, old, "type");
            defer self.alloc.free(old_type);
            const new_type = try keyName(self.alloc, new, "type");
            defer self.alloc.free(new_type);
            if (!self.catalog.contains(old_type)) return error.WrongConfiguration;
            if (self.catalog.contains(new_type)) return error.WrongConfiguration;
            const old_prefix = try std.fmt.allocPrint(self.alloc, "{s}#", .{old});
            defer self.alloc.free(old_prefix);

            var staged = try self.catalog.clone(self.alloc);
            errdefer staged.deinit(self.alloc);
            // Collect the moved pairs (own copies), remove old, insert renamed.
            var moved: std.ArrayListUnmanaged(struct { suffix: []u8, value: []u8 }) = .empty;
            defer {
                for (moved.items) |m| {
                    self.alloc.free(m.suffix);
                    self.alloc.free(m.value);
                }
                moved.deinit(self.alloc);
            }
            for (staged.pairs.items) |p| {
                if (std.mem.startsWith(u8, p.key, old_prefix)) {
                    const suffix = try self.alloc.dupe(u8, p.key[old_prefix.len..]);
                    errdefer self.alloc.free(suffix);
                    const value = try self.alloc.dupe(u8, p.value);
                    errdefer self.alloc.free(value);
                    try moved.append(self.alloc, .{ .suffix = suffix, .value = value });
                }
            }
            _ = staged.removePrefix(self.alloc, old_prefix);
            for (moved.items) |m| {
                const nk = try std.fmt.allocPrint(self.alloc, "{s}#{s}", .{ new, m.suffix });
                defer self.alloc.free(nk);
                try staged.put(self.alloc, nk, m.value);
            }
            try self.swapCatalog(&staged);
        }

        /// Delete a named object (Java `delete`): capture the object's data recids,
        /// unlink all `name#…` catalog keys on a staged clone and save FIRST, then
        /// best-effort free the known structural records (review N2). Rejects a
        /// delete while any handle is open. Returns false if the name did not
        /// exist. A teardown failure leaves an unlinked leak, never a catalog
        /// pointer to destroyed data.
        pub fn delete(self: *Self, name: []const u8) DbError!bool {
            try self.lockAdmin();
            defer self.admin_mu.unlock();
            if (self.open_handles != 0) return error.HandlesOpen;
            try validateCatalog(self.alloc, &self.catalog);
            const type_key = try keyName(self.alloc, name, "type");
            defer self.alloc.free(type_key);
            if (!self.catalog.contains(type_key)) return false;
            // Capture validated teardown metadata BEFORE unlinking (review N2).
            const recid = try self.optRecid(name, "recid");
            const root_recid_recid = try self.optRecid(name, "rootRecidRecid");
            const counter_recid = try self.optRecid(name, "counterRecid");
            const header_recid = try self.optRecid(name, "headerRecid");
            const prefix = try std.fmt.allocPrint(self.alloc, "{s}#", .{name});
            defer self.alloc.free(prefix);

            var staged = try self.catalog.clone(self.alloc);
            errdefer staged.deinit(self.alloc);
            _ = staged.removePrefix(self.alloc, prefix);
            try self.swapCatalog(&staged);
            // Unlinked and durable. Best-effort free of the known data records
            // (already unlinked, so a failure only leaks — never a catalog pointer
            // to freed data). NOTE: interior tree nodes and queue node records are
            // NOT reclaimed here (the no-instance-cache facade has no typed handle
            // to clear them) and store `compact` PACKS live records but is not
            // reachability GC, so those nodes leak until the store is rebuilt —
            // gap-listed. Java/Rust clear entries via a cached handle at delete time.
            if (recid) |r| self.store.delete(r) catch {};
            if (root_recid_recid) |r| self.store.delete(r) catch {};
            if (counter_recid) |r| if (r != 0) self.store.delete(r) catch {};
            if (header_recid) |r| self.store.delete(r) catch {};
            return true;
        }

        fn optRecid(self: *Self, name: []const u8, suffix: []const u8) DbError!?u64 {
            const key = try keyName(self.alloc, name, suffix);
            defer self.alloc.free(key);
            const s = self.catalog.get(key) orelse return null;
            return std.fmt.parseInt(u64, s, 10) catch null;
        }

        // -------------------------------------------------- handle counting

        /// Bump the open-handle count. Caller MUST hold `admin_mu` (makers do).
        fn incHandle(self: *Self) void {
            self.open_handles += 1;
        }
        fn decHandle(self: *Self) void {
            self.admin_mu.lock();
            defer self.admin_mu.unlock();
            std.debug.assert(self.open_handles > 0);
            self.open_handles -= 1;
        }

        /// Tear down a tree map / tree set backing map and release its handle.
        /// FALLIBLE: the ATOMIC `closeIfLast` frees the tree ONLY if this is the
        /// last reference and, only then, this decrements the handle count; a
        /// derived clone racing the close either keeps the tree alive (returns
        /// `error.HandlesOpen`, nothing freed) or is itself invalidated — no
        /// check-then-free TOCTOU. Close every derived clone (via
        /// `map.deinit()`) FIRST, then close the original here.
        pub fn closeMap(self: *Self, map: anytype) DbError!void {
            if (!map.closeIfLast()) return error.HandlesOpen;
            self.decHandle();
        }
        /// Tear down a navigable set (same atomic last-owner rule as `closeMap`).
        pub fn closeSet(self: *Self, set: anytype) DbError!void {
            if (!set.closeIfLast()) return error.HandlesOpen;
            self.decHandle();
        }
        /// Release an atomic handle (atomics own no resources).
        pub fn closeAtomic(self: *Self) void {
            self.decHandle();
        }
        /// Wake+join blocked waiters, free the heap-boxed queue, release its handle.
        pub fn closeQueue(self: *Self, q: anytype) void {
            q.closeHandle();
            self.alloc.destroy(q);
            self.decHandle();
        }

        // -------------------------------------------------- makers

        pub fn treeMap(self: *Self, name: []const u8, key_format: anytype, value_format: anytype) TreeMapMaker(S, @TypeOf(key_format), @TypeOf(value_format), true) {
            return .{ .db = self, .name = name, .kf = key_format, .vf = value_format };
        }
        pub fn treeMapExternal(self: *Self, name: []const u8, key_format: anytype, value_format: anytype) TreeMapMaker(S, @TypeOf(key_format), @TypeOf(value_format), false) {
            return .{ .db = self, .name = name, .kf = key_format, .vf = value_format };
        }
        pub fn treeSet(self: *Self, name: []const u8, key_format: anytype) TreeSetMaker(S, @TypeOf(key_format)) {
            return .{ .db = self, .name = name, .kf = key_format };
        }
        pub fn atomicLong(self: *Self, name: []const u8) AtomicNumMaker(S, i64, LONG, "AtomicLong", atomicmod.AtomicLong(S)) {
            return .{ .db = self, .name = name, .initial = 0 };
        }
        pub fn atomicInteger(self: *Self, name: []const u8) AtomicNumMaker(S, i32, INT, "AtomicInteger", atomicmod.AtomicInteger(S)) {
            return .{ .db = self, .name = name, .initial = 0 };
        }
        pub fn atomicBoolean(self: *Self, name: []const u8) AtomicNumMaker(S, bool, BOOL, "AtomicBoolean", atomicmod.AtomicBoolean(S)) {
            return .{ .db = self, .name = name, .initial = false };
        }
        pub fn atomicString(self: *Self, name: []const u8) AtomicStringMaker(S) {
            return .{ .db = self, .name = name, .initial = null };
        }
        /// `se` is the element serializer VALUE (may be stateful).
        pub fn atomicVar(self: *Self, name: []const u8, se: anytype, initial: ?@TypeOf(se).Elem) AtomicVarMaker(S, @TypeOf(se)) {
            return .{ .db = self, .name = name, .se = se, .initial = initial };
        }
        pub fn queue(self: *Self, name: []const u8, se: anytype) QueueMaker(S, @TypeOf(se)) {
            return .{ .db = self, .name = name, .se = se, .mode = .fifo, .catalog_type = "Queue", .capacity = std.math.maxInt(i64) };
        }
        pub fn stack(self: *Self, name: []const u8, se: anytype) QueueMaker(S, @TypeOf(se)) {
            return .{ .db = self, .name = name, .se = se, .mode = .lifo, .catalog_type = "Stack", .capacity = std.math.maxInt(i64) };
        }
        pub fn circularQueue(self: *Self, name: []const u8, se: anytype, capacity: u64) QueueMaker(S, @TypeOf(se)) {
            return .{ .db = self, .name = name, .se = se, .mode = .circular, .catalog_type = "CircularQueue", .capacity = capacity };
        }

        // -------------------------------------------------- close / deinit

        /// Close the DB (Java `close`): fails `error.HandlesOpen` if any facade
        /// handle remains (Zig teardown order). Idempotent once closed. Holds
        /// `admin_mu` across store close + cleanup, so a concurrent second closer
        /// blocks and returns only after the close actually completed (review C5).
        /// NO auto-commit — a WAL's uncommitted changes are intentionally
        /// discarded. Store close error is PRIMARY; a cleanup error is returned
        /// only when store close succeeded (Zig errors carry no payload — N1).
        pub fn close(self: *Self) DbError!void {
            self.admin_mu.lock();
            defer self.admin_mu.unlock();
            if (self.state.load(.acquire) == CLOSED) return; // idempotent
            if (self.open_handles != 0) return error.HandlesOpen;
            const store_res = self.store.close();
            const cleanup_res = self.runCleanup();
            self.state.store(CLOSED, .release);
            try store_res; // store-close error is primary
            try cleanup_res;
        }

        fn runCleanup(self: *Self) DbError!void {
            var first_err: ?DbError = null;
            for (self.cleanup_paths.items) |path| {
                deleteIfPresent(path) catch |e| {
                    if (first_err == null) first_err = e;
                };
                const ck = ckptPath(self.alloc, path) catch {
                    if (first_err == null) first_err = error.OutOfMemory;
                    continue;
                };
                defer self.alloc.free(ck);
                deleteIfPresent(ck) catch |e| {
                    if (first_err == null) first_err = e;
                };
            }
            if (first_err) |e| return e;
        }

        /// Free the DB (Java `Drop`). Asserts close succeeded in safe modes; then
        /// frees the catalog, cleanup paths, and (if owned) the store allocation.
        pub fn deinit(self: *Self) void {
            if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
                std.debug.assert(self.state.load(.acquire) == CLOSED); // close() must run first
                std.debug.assert(self.open_handles == 0);
            }
            self.catalog.deinit(self.alloc);
            for (self.cleanup_paths.items) |p| self.alloc.free(p);
            self.cleanup_paths.deinit(self.alloc);
            if (self.owns_store) {
                self.store.deinit();
                self.alloc.destroy(self.store);
            }
            if (self.ro_backing) |p| {
                if (self.ro_backing_deinit) |f| f(self.alloc, p);
            }
        }
    };
}

fn deleteIfPresent(path: []const u8) DbError!void {
    std.fs.cwd().deleteFile(path) catch |e| switch (e) {
        error.FileNotFound => {},
        else => return error.Io,
    };
}

// ============================================================ TreeMap maker

pub fn TreeMapMaker(comptime S: type, comptime KF: type, comptime VF: type, comptime inline_values: bool) type {
    const Map = if (inline_values) btree.BTreeMap(S, KF, VF) else btree.BTreeMapExternal(S, KF, VF);
    return struct {
        const Self = @This();
        db: *Db(S),
        name: []const u8,
        kf: KF,
        vf: VF,
        max_node_size: usize = 32,
        counter_enable: bool = false,

        pub fn maxNodeSize(self: Self, n: usize) Self {
            var s = self;
            s.max_node_size = n;
            return s;
        }
        pub fn counterEnable(self: Self) Self {
            var s = self;
            s.counter_enable = true;
            return s;
        }

        fn buildMap(self: Self) DbError!Map {
            return Map.createCounter(self.db.alloc, self.db.store, self.kf, self.vf, self.max_node_size, self.counter_enable);
        }

        fn writeCatalog(self: Self, cat: *NameCatalog, map: *const Map) DbError!void {
            const a = self.db.alloc;
            const n = self.name;
            try putKV(cat, a, n, "type", "TreeMap");
            const kd = try descriptor.groupDescriptorOrCustom(a, self.kf);
            defer a.free(kd);
            try putKV(cat, a, n, "keySerializer", kd);
            const vd = try descriptor.groupDescriptorOrCustom(a, self.vf);
            defer a.free(vd);
            try putKV(cat, a, n, "valueSerializer", vd);
            try putKVDecimal(cat, a, n, "rootRecidRecid", map.rootRecidRecid());
            try putKVDecimal(cat, a, n, "maxNodeSize", self.max_node_size);
            try putKVDecimal(cat, a, n, "counterRecid", map.counterRecid());
            try putKV(cat, a, n, "valueInline", if (inline_values) "true" else "false");
        }

        fn verifyCatalog(self: Self) DbError!void {
            const a = self.db.alloc;
            const t = try getKV(&self.db.catalog, a, self.name, "type") orelse return error.WrongConfiguration;
            if (!std.mem.eql(u8, t, "TreeMap")) return error.WrongType;
            const kd = try getKV(&self.db.catalog, a, self.name, "keySerializer") orelse return error.DataCorruption;
            try descriptor.verifyGroup(a, kd, self.kf);
            const vd = try getKV(&self.db.catalog, a, self.name, "valueSerializer") orelse return error.DataCorruption;
            try descriptor.verifyGroup(a, vd, self.vf);
            // valueInline must match this maker's inline/external kind.
            const vi = try getKV(&self.db.catalog, a, self.name, "valueInline");
            const stored_inline = if (vi) |v| std.mem.eql(u8, v, "true") else true;
            if (stored_inline != inline_values) return error.WrongType;
        }

        fn openFromCatalog(self: Self) DbError!Map {
            const a = self.db.alloc;
            const root = try parseRecid(&self.db.catalog, a, self.name, "rootRecidRecid");
            const mns = blk: {
                const s = try getKV(&self.db.catalog, a, self.name, "maxNodeSize") orelse return error.DataCorruption;
                const m = std.fmt.parseInt(usize, s, 10) catch return error.DataCorruption;
                if (m < MIN_MNS or m > MAX_MNS) return error.DataCorruption; // review C2
                break :blk m;
            };
            const counter = try parseRecidDefault0(&self.db.catalog, a, self.name, "counterRecid");
            return Map.openCounter(a, self.db.store, root, self.kf, self.vf, mns, counter);
        }

        pub fn create(self: Self) DbError!Map {
            try validateName(self.name);
            try validateMaxNodeSize(self.max_node_size);
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            return self.createLocked();
        }

        fn createLocked(self: Self) DbError!Map {
            if (try existsType(&self.db.catalog, self.db.alloc, self.name)) return error.WrongConfiguration;
            const map = try self.buildMap();
            // On a pre-publication failure, destroy the fresh (never-published)
            // root/root-pointer/counter records so they don't leak in the store.
            errdefer map.deinitAndDestroy();
            var staged = try self.db.catalog.clone(self.db.alloc);
            errdefer staged.deinit(self.db.alloc);
            try self.writeCatalog(&staged, &map);
            try self.db.swapCatalog(&staged);
            self.db.incHandle();
            return map;
        }

        fn openLocked(self: Self) DbError!Map {
            try self.verifyCatalog();
            const map = try self.openFromCatalog();
            self.db.incHandle();
            return map;
        }

        pub fn open(self: Self) DbError!Map {
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            return self.openLocked();
        }

        pub fn createOrOpen(self: Self) DbError!Map {
            try validateName(self.name);
            try validateMaxNodeSize(self.max_node_size);
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            if (try existsType(&self.db.catalog, self.db.alloc, self.name)) return self.openLocked();
            return self.createLocked();
        }
    };
}

// ============================================================ TreeSet maker

pub fn TreeSetMaker(comptime S: type, comptime KF: type) type {
    const NVF = setmod.NoValueFormat;
    const Map = btree.BTreeMap(S, KF, NVF);
    const Set = setmod.NavigableSet(S, KF);
    return struct {
        const Self = @This();
        db: *Db(S),
        name: []const u8,
        kf: KF,
        max_node_size: usize = 32,
        counter_enable: bool = false,

        pub fn maxNodeSize(self: Self, n: usize) Self {
            var s = self;
            s.max_node_size = n;
            return s;
        }
        pub fn counterEnable(self: Self) Self {
            var s = self;
            s.counter_enable = true;
            return s;
        }

        fn writeCatalog(self: Self, cat: *NameCatalog, map: *const Map) DbError!void {
            const a = self.db.alloc;
            const n = self.name;
            try putKV(cat, a, n, "type", "TreeSet");
            const sd = try descriptor.groupDescriptorOrCustom(a, self.kf);
            defer a.free(sd);
            try putKV(cat, a, n, "serializer", sd);
            try putKVDecimal(cat, a, n, "rootRecidRecid", map.rootRecidRecid());
            try putKVDecimal(cat, a, n, "maxNodeSize", self.max_node_size);
            try putKVDecimal(cat, a, n, "counterRecid", map.counterRecid());
        }

        fn verifyCatalog(self: Self) DbError!void {
            const a = self.db.alloc;
            const t = try getKV(&self.db.catalog, a, self.name, "type") orelse return error.WrongConfiguration;
            if (!std.mem.eql(u8, t, "TreeSet")) return error.WrongType;
            const sd = try getKV(&self.db.catalog, a, self.name, "serializer") orelse return error.DataCorruption;
            try descriptor.verifyGroup(a, sd, self.kf);
        }

        fn openFromCatalog(self: Self) DbError!Set {
            const a = self.db.alloc;
            const root = try parseRecid(&self.db.catalog, a, self.name, "rootRecidRecid");
            const mns = blk: {
                const s = try getKV(&self.db.catalog, a, self.name, "maxNodeSize") orelse return error.DataCorruption;
                const m = std.fmt.parseInt(usize, s, 10) catch return error.DataCorruption;
                if (m < MIN_MNS or m > MAX_MNS) return error.DataCorruption; // review C2
                break :blk m;
            };
            const counter = try parseRecidDefault0(&self.db.catalog, a, self.name, "counterRecid");
            const map = try Map.openCounter(a, self.db.store, root, self.kf, NVF.instance, mns, counter);
            return Set.fromMap(map);
        }

        fn buildSet(self: Self) DbError!Set {
            const map = try Map.createCounter(self.db.alloc, self.db.store, self.kf, NVF.instance, self.max_node_size, self.counter_enable);
            return Set.fromMap(map);
        }

        fn createLocked(self: Self) DbError!Set {
            if (try existsType(&self.db.catalog, self.db.alloc, self.name)) return error.WrongConfiguration;
            const set = try self.buildSet();
            errdefer set.deinitAndDestroy(); // destroy fresh records on failure
            var staged = try self.db.catalog.clone(self.db.alloc);
            errdefer staged.deinit(self.db.alloc);
            try self.writeCatalog(&staged, &set.map);
            try self.db.swapCatalog(&staged);
            self.db.incHandle();
            return set;
        }

        fn openLocked(self: Self) DbError!Set {
            try self.verifyCatalog();
            const set = try self.openFromCatalog();
            self.db.incHandle();
            return set;
        }

        pub fn create(self: Self) DbError!Set {
            try validateName(self.name);
            try validateMaxNodeSize(self.max_node_size);
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            return self.createLocked();
        }

        pub fn open(self: Self) DbError!Set {
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            return self.openLocked();
        }

        pub fn createOrOpen(self: Self) DbError!Set {
            try validateName(self.name);
            try validateMaxNodeSize(self.max_node_size);
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            if (try existsType(&self.db.catalog, self.db.alloc, self.name)) return self.openLocked();
            return self.createLocked();
        }
    };
}

// ============================================================ atomic makers

fn AtomicNumMaker(comptime S: type, comptime P: type, comptime Ser: anytype, comptime type_str: []const u8, comptime Atomic: type) type {
    return struct {
        const Self = @This();
        db: *Db(S),
        name: []const u8,
        initial: P,

        pub fn initialValue(self: Self, v: P) Self {
            var s = self;
            s.initial = v;
            return s;
        }

        fn createLocked(self: Self) DbError!Atomic {
            if (try existsType(&self.db.catalog, self.db.alloc, self.name)) return error.WrongConfiguration;
            const recid = try self.db.store.put(P, self.db.alloc, self.initial, Ser);
            errdefer self.db.store.delete(recid) catch {};
            var staged = try self.db.catalog.clone(self.db.alloc);
            errdefer staged.deinit(self.db.alloc);
            try putKV(&staged, self.db.alloc, self.name, "type", type_str);
            try putKVDecimal(&staged, self.db.alloc, self.name, "recid", recid);
            try self.db.swapCatalog(&staged);
            self.db.incHandle();
            return Atomic.init(self.db.store, self.db.alloc, recid);
        }
        fn openLocked(self: Self) DbError!Atomic {
            try verifyType(&self.db.catalog, self.db.alloc, self.name, type_str);
            const recid = try parseRecid(&self.db.catalog, self.db.alloc, self.name, "recid");
            self.db.incHandle();
            return Atomic.init(self.db.store, self.db.alloc, recid);
        }
        pub fn create(self: Self) DbError!Atomic {
            try validateName(self.name);
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            return self.createLocked();
        }
        pub fn open(self: Self) DbError!Atomic {
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            return self.openLocked();
        }
        pub fn createOrOpen(self: Self) DbError!Atomic {
            try validateName(self.name);
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            if (try existsType(&self.db.catalog, self.db.alloc, self.name)) return self.openLocked();
            return self.createLocked();
        }
    };
}

fn AtomicStringMaker(comptime S: type) type {
    const Atomic = atomicmod.AtomicString(S);
    return struct {
        const Self = @This();
        db: *Db(S),
        name: []const u8,
        initial: ?[]const u8,

        pub fn initialValue(self: Self, v: ?[]const u8) Self {
            var s = self;
            s.initial = v;
            return s;
        }
        fn createLocked(self: Self) DbError!Atomic {
            if (try existsType(&self.db.catalog, self.db.alloc, self.name)) return error.WrongConfiguration;
            // Always write a present record whose content encodes null-ness.
            const recid = try self.db.store.put(?[]const u8, self.db.alloc, self.initial, STRING_NULLABLE);
            errdefer self.db.store.delete(recid) catch {};
            var staged = try self.db.catalog.clone(self.db.alloc);
            errdefer staged.deinit(self.db.alloc);
            try putKV(&staged, self.db.alloc, self.name, "type", "AtomicString");
            try putKVDecimal(&staged, self.db.alloc, self.name, "recid", recid);
            try self.db.swapCatalog(&staged);
            self.db.incHandle();
            return Atomic.init(self.db.store, self.db.alloc, recid);
        }
        fn openLocked(self: Self) DbError!Atomic {
            try verifyType(&self.db.catalog, self.db.alloc, self.name, "AtomicString");
            const recid = try parseRecid(&self.db.catalog, self.db.alloc, self.name, "recid");
            self.db.incHandle();
            return Atomic.init(self.db.store, self.db.alloc, recid);
        }
        pub fn create(self: Self) DbError!Atomic {
            try validateName(self.name);
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            return self.createLocked();
        }
        pub fn open(self: Self) DbError!Atomic {
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            return self.openLocked();
        }
        pub fn createOrOpen(self: Self) DbError!Atomic {
            try validateName(self.name);
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            if (try existsType(&self.db.catalog, self.db.alloc, self.name)) return self.openLocked();
            return self.createLocked();
        }
    };
}

fn AtomicVarMaker(comptime S: type, comptime Se: type) type {
    const Atomic = atomicmod.AtomicVar(S, Se);
    const E = Se.Elem;
    return struct {
        const Self = @This();
        db: *Db(S),
        name: []const u8,
        se: Se,
        initial: ?E,

        fn createLocked(self: Self) DbError!Atomic {
            if (try existsType(&self.db.catalog, self.db.alloc, self.name)) return error.WrongConfiguration;
            // The ONLY atomic that preallocates for a null initial value.
            const recid = if (self.initial) |v|
                try self.db.store.put(E, self.db.alloc, v, self.se)
            else
                try self.db.store.preallocate();
            errdefer self.db.store.delete(recid) catch {};
            var staged = try self.db.catalog.clone(self.db.alloc);
            errdefer staged.deinit(self.db.alloc);
            try putKV(&staged, self.db.alloc, self.name, "type", "AtomicVar");
            try putKVDecimal(&staged, self.db.alloc, self.name, "recid", recid);
            const sd = try descriptor.serDescriptorOrCustom(self.db.alloc, self.se);
            defer self.db.alloc.free(sd);
            try putKV(&staged, self.db.alloc, self.name, "serializer", sd);
            try self.db.swapCatalog(&staged);
            self.db.incHandle();
            return Atomic.init(self.db.store, self.db.alloc, recid, self.se);
        }
        fn openLocked(self: Self) DbError!Atomic {
            try verifyType(&self.db.catalog, self.db.alloc, self.name, "AtomicVar");
            const sd = try getKV(&self.db.catalog, self.db.alloc, self.name, "serializer") orelse return error.DataCorruption;
            try descriptor.verifySer(self.db.alloc, sd, self.se);
            const recid = try parseRecid(&self.db.catalog, self.db.alloc, self.name, "recid");
            self.db.incHandle();
            return Atomic.init(self.db.store, self.db.alloc, recid, self.se);
        }
        pub fn create(self: Self) DbError!Atomic {
            try validateName(self.name);
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            return self.createLocked();
        }
        pub fn open(self: Self) DbError!Atomic {
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            return self.openLocked();
        }
        pub fn createOrOpen(self: Self) DbError!Atomic {
            try validateName(self.name);
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            if (try existsType(&self.db.catalog, self.db.alloc, self.name)) return self.openLocked();
            return self.createLocked();
        }
    };
}

// ============================================================ queue maker

fn QueueMaker(comptime S: type, comptime Se: type) type {
    const Queue = blocking.PersistentBlockingQueue(S, Se);
    return struct {
        const Self = @This();
        db: *Db(S),
        name: []const u8,
        se: Se,
        mode: blocking.Mode,
        catalog_type: []const u8,
        capacity: u64,

        fn createLocked(self: Self) DbError!*Queue {
            if (try existsType(&self.db.catalog, self.db.alloc, self.name)) return error.WrongConfiguration;
            const q = try self.db.alloc.create(Queue);
            errdefer self.db.alloc.destroy(q);
            q.* = try Queue.create(self.db.store, self.db.alloc, self.mode, self.capacity, self.se);
            // On a pre-publication failure, release the lease AND delete the fresh
            // (never-published) header record so it doesn't leak.
            errdefer {
                const hr = q.headerRecid();
                q.closeHandle();
                self.db.store.delete(hr) catch {};
            }
            var staged = try self.db.catalog.clone(self.db.alloc);
            errdefer staged.deinit(self.db.alloc);
            try putKV(&staged, self.db.alloc, self.name, "type", self.catalog_type);
            try putKVDecimal(&staged, self.db.alloc, self.name, "headerRecid", q.headerRecid());
            const sd = try descriptor.serDescriptorOrCustom(self.db.alloc, self.se);
            defer self.db.alloc.free(sd);
            try putKV(&staged, self.db.alloc, self.name, "serializer", sd);
            try self.db.swapCatalog(&staged);
            self.db.incHandle();
            return q;
        }
        fn openLocked(self: Self) DbError!*Queue {
            const t = try getKV(&self.db.catalog, self.db.alloc, self.name, "type") orelse return error.WrongConfiguration;
            if (!std.mem.eql(u8, t, self.catalog_type)) return error.WrongType;
            const sd = try getKV(&self.db.catalog, self.db.alloc, self.name, "serializer") orelse return error.DataCorruption;
            try descriptor.verifySer(self.db.alloc, sd, self.se);
            const header = try parseRecid(&self.db.catalog, self.db.alloc, self.name, "headerRecid");
            const q = try self.db.alloc.create(Queue);
            errdefer self.db.alloc.destroy(q);
            q.* = try Queue.open(self.db.store, self.db.alloc, header, self.se);
            errdefer q.closeHandle();
            // The header's stored mode must match the requested/catalog mode; a
            // mismatch is a corrupt catalog<->header pairing.
            const implied = try Self.modeForType(self.catalog_type);
            if ((try q.mode()) != implied) return error.DataCorruption;
            self.db.incHandle();
            return q;
        }
        fn modeForType(t: []const u8) DbError!blocking.Mode {
            if (std.mem.eql(u8, t, "Queue")) return .fifo;
            if (std.mem.eql(u8, t, "Stack")) return .lifo;
            if (std.mem.eql(u8, t, "CircularQueue")) return .circular;
            return error.DataCorruption;
        }
        pub fn create(self: Self) DbError!*Queue {
            try validateName(self.name);
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            return self.createLocked();
        }
        pub fn open(self: Self) DbError!*Queue {
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            return self.openLocked();
        }
        pub fn createOrOpen(self: Self) DbError!*Queue {
            try validateName(self.name);
            try self.db.lockAdmin();
            defer self.db.admin_mu.unlock();
            if (try existsType(&self.db.catalog, self.db.alloc, self.name)) return self.openLocked();
            return self.createLocked();
        }
    };
}

// ============================================================ catalog helpers

fn existsType(cat: *const NameCatalog, alloc: Allocator, name: []const u8) DbError!bool {
    const key = try keyName(alloc, name, "type");
    defer alloc.free(key);
    return cat.contains(key);
}

fn putKV(cat: *NameCatalog, alloc: Allocator, name: []const u8, suffix: []const u8, value: []const u8) DbError!void {
    const key = try keyName(alloc, name, suffix);
    defer alloc.free(key);
    try cat.put(alloc, key, value);
}

fn putKVDecimal(cat: *NameCatalog, alloc: Allocator, name: []const u8, suffix: []const u8, value: u64) DbError!void {
    var buf: [24]u8 = undefined;
    const v = std.fmt.bufPrint(&buf, "{d}", .{value}) catch return error.WrongConfiguration;
    try putKV(cat, alloc, name, suffix, v);
}

fn getKV(cat: *const NameCatalog, alloc: Allocator, name: []const u8, suffix: []const u8) DbError!?[]const u8 {
    const key = try keyName(alloc, name, suffix);
    defer alloc.free(key);
    return cat.get(key);
}

fn verifyType(cat: *const NameCatalog, alloc: Allocator, name: []const u8, want: []const u8) DbError!void {
    const t = try getKV(cat, alloc, name, "type") orelse return error.WrongConfiguration;
    if (!std.mem.eql(u8, t, want)) return error.WrongType;
}

// ============================================================ typed constructors (DBMaker)

const StoreOnHeap = storemod.StoreOnHeap;
const StoreByteArray = storemod.StoreByteArray;
const StoreDirect = storemod.StoreDirect;
const StoreWAL = storemod.StoreWAL;
const StoreReadOnlyWrapper = storemod.StoreReadOnlyWrapper;

/// A DB over a fresh heap store (Java `DBMaker.heapDB()`).
pub fn heapDb(alloc: Allocator) DbError!Db(StoreOnHeap) {
    const s = try alloc.create(StoreOnHeap);
    errdefer alloc.destroy(s);
    s.* = try StoreOnHeap.init(alloc, true);
    errdefer s.deinit();
    return Db(StoreOnHeap).init(alloc, s, true);
}

/// A DB over a fresh in-memory byte-array store (Java `DBMaker.memoryByteArrayDB()`).
pub fn memoryByteArrayDb(alloc: Allocator) DbError!Db(StoreByteArray) {
    const s = try alloc.create(StoreByteArray);
    errdefer alloc.destroy(s);
    s.* = try StoreByteArray.init(alloc, true);
    errdefer s.deinit();
    return Db(StoreByteArray).init(alloc, s, true);
}

/// A DB over an in-memory StoreDirect (Java `DBMaker.memoryDB()`/`memoryDirectDB()`).
pub fn memoryDirectDb(alloc: Allocator) DbError!Db(StoreDirect) {
    const s = try alloc.create(StoreDirect);
    errdefer alloc.destroy(s);
    s.* = try StoreDirect.init(alloc, true);
    errdefer s.deinit();
    return Db(StoreDirect).init(alloc, s, true);
}

/// A DB over a file-backed StoreDirect (Java `DBMaker.fileDB(f).make()`).
pub fn fileDb(alloc: Allocator, path: []const u8) DbError!Db(StoreDirect) {
    const s = try alloc.create(StoreDirect);
    errdefer alloc.destroy(s);
    s.* = try StoreDirect.openFile(alloc, path, true);
    errdefer s.deinit();
    return Db(StoreDirect).init(alloc, s, true);
}

/// A file-backed StoreDirect DB whose file(s) are deleted after close
/// (`fileDeleteAfterClose`). Both `<path>` and `<path>.ckpt` are removed.
pub fn fileDbDeleteAfterClose(alloc: Allocator, path: []const u8) DbError!Db(StoreDirect) {
    var db = try fileDb(alloc, path);
    // On a post-construction setup failure the DB is OPEN, so `deinit` alone would
    // trip its `state == closed` assert. Close first, then deinit.
    errdefer {
        db.close() catch {};
        db.deinit();
    }
    try db.registerCleanup(path);
    return db;
}

/// A file-backed StoreDirect DB whose file(s) are unlinked immediately AFTER the
/// DB is fully constructed and validated (Java `fileDeleteAfterOpen`; non-WAL).
/// A construction failure NEVER unlinks a pre-existing path. The
/// open file handles keep working after the directory entry is removed (POSIX).
pub fn fileDbDeleteAfterOpen(alloc: Allocator, path: []const u8) DbError!Db(StoreDirect) {
    try validateFileOptions(false, false, true); // wire the option guard
    var db = try fileDb(alloc, path); // validates the store/catalog BEFORE unlinking
    errdefer {
        db.close() catch {};
        db.deinit();
    }
    // Only now that construction succeeded do we unlink the path(s).
    try deleteIfPresent(path);
    const ck = try ckptPath(alloc, path);
    defer alloc.free(ck);
    try deleteIfPresent(ck);
    return db;
}

/// A DB over a unique fresh temp file that is deleted after close (Java
/// `tempFileDB`). A creation failure removes the temp file it created.
/// `dir` is the directory to create the temp file in (e.g. the system temp dir).
pub fn tempFileDb(alloc: Allocator, dir: []const u8) DbError!Db(StoreDirect) {
    const path = try uniqueTempPath(alloc, dir);
    errdefer alloc.free(path);
    // Creation cleanup guard: if constructing the DB fails, remove the file we
    // may have created so a failed temp DB never leaves an orphan behind.
    errdefer deleteIfPresent(path) catch {};
    const db = try fileDbDeleteAfterClose(alloc, path);
    alloc.free(path); // registerCleanup duped it; our copy is no longer needed
    return db;
}

fn uniqueTempPath(alloc: Allocator, dir: []const u8) DbError![]u8 {
    var seq: u64 = 0;
    while (true) : (seq += 1) {
        const stamp = std.time.nanoTimestamp();
        const path = try std.fmt.allocPrint(alloc, "{s}/mapdb5-{x}-{d}.tmp", .{ dir, @as(u128, @bitCast(stamp)), seq });
        // Pick a name that does not yet exist; the store creates the file. (A tiny
        // TOCTOU window is acceptable for a temp file — the store guards its own
        // format, and the DB init validates recid 1.)
        std.fs.cwd().access(path, .{}) catch |e| switch (e) {
            error.FileNotFound => return path,
            else => {
                alloc.free(path);
                return error.Io;
            },
        };
        alloc.free(path);
        if (seq > 1000) return error.Io;
    }
}

/// A file-backed WAL/transactional DB (Java `fileDB(f).transactionEnable()`).
/// `path` is the store's BASE: the log lives in `<path>.wal.<16 hex>` segment
/// files beside it (WAL format v3), with `<path>.lock` as the store lock. A
/// regular file at `<path>` or `<path>.wal`, or anything at `<path>.ckpt`,
/// refuses the open — those are pre-v3 artifacts and there is no migration.
pub fn fileWalDb(alloc: Allocator, path: []const u8) DbError!Db(StoreWAL) {
    const s = try alloc.create(StoreWAL);
    errdefer alloc.destroy(s);
    s.* = try StoreWAL.open(alloc, path, true);
    errdefer s.deinit();
    return Db(StoreWAL).init(alloc, s, true);
}

/// A file-backed WAL DB whose whole segment namespace is deleted inside the
/// store's close (Java `fileDB(f).transactionEnable().fileDeleteAfterClose()`).
/// D2, lock-owning: the store unlinks exactly its own `<base>.wal.<hex>`
/// segments plus `<base>.lock` while the store lock is still held, so no
/// second opener can acquire the namespace mid-delete. The DB layer registers
/// no cleanup paths of its own — the store owns the deletion.
pub fn fileWalDbDeleteAfterClose(alloc: Allocator, base: []const u8) DbError!Db(StoreWAL) {
    const s = try alloc.create(StoreWAL);
    errdefer alloc.destroy(s);
    s.* = try StoreWAL.open(alloc, base, true);
    errdefer s.deinit();
    s.setDeleteOnClose(true);
    return Db(StoreWAL).init(alloc, s, true);
}

/// A read-only DB over an existing file (Java `fileDB(f).readOnly().make()`).
/// Rejects an empty store (the catalog cannot be written) via `init`.
pub fn fileReadOnlyDb(alloc: Allocator, path: []const u8) DbError!Db(StoreReadOnlyWrapper(StoreDirect)) {
    const backing = try alloc.create(StoreDirect);
    errdefer alloc.destroy(backing);
    backing.* = try StoreDirect.openFile(alloc, path, true);
    errdefer backing.deinit();
    const wrapper = try alloc.create(StoreReadOnlyWrapper(StoreDirect));
    errdefer alloc.destroy(wrapper);
    wrapper.* = StoreReadOnlyWrapper(StoreDirect).init(backing);
    var db = try Db(StoreReadOnlyWrapper(StoreDirect)).init(alloc, wrapper, true);
    // The DB owns the wrapper (owns_store); it also frees the backing StoreDirect.
    db.ro_backing = @ptrCast(backing);
    db.ro_backing_deinit = struct {
        fn f(a: Allocator, p: *anyopaque) void {
            const st: *StoreDirect = @ptrCast(@alignCast(p));
            st.deinit();
            a.destroy(st);
        }
    }.f;
    return db;
}

/// Validate a file-DB option combination (Java `DBMaker.make` guards). The typed
/// constructors above make most illegal combinations unrepresentable; this is the
/// explicit check for the ones a runtime builder would need.
pub fn validateFileOptions(read_only: bool, transaction_enable: bool, delete_after_open: bool) DbError!void {
    if (read_only and transaction_enable) return error.WrongConfiguration;
    // WAL checkpointing recreates the path, so delete-after-open is unsafe.
    if (delete_after_open and transaction_enable) return error.WrongConfiguration;
}

// ------------------------------------------------------------------- tests

const testing = std.testing;
const LongFormat = @import("../ser/long.zig").LongFormat;
const StringGroupFormat = @import("../ser/string_group.zig").StringGroupFormat;
const StringSer = serializers.StringSer;

test "db init on fresh heap store commits empty catalog at recid 1" {
    const a = testing.allocator;
    var db = try heapDb(a);
    defer db.deinit();
    defer db.close() catch {};
    var cat = try db.getNameCatalog();
    defer cat.deinit(a);
    try testing.expectEqual(@as(usize, 0), cat.len());
}

test "treeMap create/open + catalog rows + double-open reject" {
    const a = testing.allocator;
    var db = try memoryByteArrayDb(a);
    defer db.deinit();
    defer db.close() catch {};

    var m = try db.treeMap("t", LongFormat.instance, StringGroupFormat.instance).counterEnable().create();
    try m.putOnly(1, "one");
    // second writable open of the same name → AlreadyOpen.
    try testing.expectError(error.AlreadyOpen, db.treeMap("t", LongFormat.instance, StringGroupFormat.instance).open());
    // catalog row assertions
    {
        db.admin_mu.lock();
        try testing.expectEqualStrings("TreeMap", db.catalog.get("t#type").?);
        try testing.expectEqualStrings("LONG", db.catalog.get("t#keySerializer").?);
        try testing.expectEqualStrings("STRING", db.catalog.get("t#valueSerializer").?);
        try testing.expectEqualStrings("true", db.catalog.get("t#valueInline").?);
        db.admin_mu.unlock();
    }
    try db.closeMap(m);
    // reopen works now that the handle is closed
    var m2 = try db.treeMap("t", LongFormat.instance, StringGroupFormat.instance).open();
    const v = try m2.get(&@as(i64, 1));
    defer if (v) |x| a.free(x);
    try testing.expectEqualStrings("one", v.?);
    try db.closeMap(m2);
}

test "close fails HandlesOpen while a handle is live" {
    const a = testing.allocator;
    var db = try memoryByteArrayDb(a);
    defer db.deinit();
    defer db.close() catch {};
    const al = try db.atomicLong("n").create();
    try testing.expectError(error.HandlesOpen, db.close());
    db.closeAtomic();
    _ = al;
    try db.close();
}

test "wrong type / mismatched descriptor rejected on open" {
    const a = testing.allocator;
    var db = try memoryByteArrayDb(a);
    defer db.deinit();
    defer db.close() catch {};
    const al = try db.atomicLong("x").create();
    db.closeAtomic();
    _ = al;
    // opening "x" as an integer → WrongType
    try testing.expectError(error.WrongType, db.atomicInteger("x").open());
    // treeMap with the wrong key descriptor → WrongType (name exists as AtomicLong)
    try testing.expectError(error.WrongType, db.treeMap("x", LongFormat.instance, StringGroupFormat.instance).open());
}

test "closeMap refuses while a derived clone is live (C6)" {
    const a = testing.allocator;
    var db = try memoryByteArrayDb(a);
    defer db.deinit();
    defer db.close() catch {};
    var m = try db.treeMap("t", LongFormat.instance, StringGroupFormat.instance).create();
    const c = m.clone(); // derived handle sharing Inner
    try testing.expectError(error.HandlesOpen, db.closeMap(m)); // clone still owns it
    c.deinit(); // drop the derived clone first
    try db.closeMap(m); // now the last ref → allowed
}

test "maker rejects out-of-range maxNodeSize; hostile catalog value → DataCorruption (C2)" {
    const a = testing.allocator;
    var db = try memoryByteArrayDb(a);
    defer db.deinit();
    defer db.close() catch {};
    try testing.expectError(error.WrongConfiguration, db.treeMap("t", LongFormat.instance, StringGroupFormat.instance).maxNodeSize(2).create());
    // Corrupt the persisted maxNodeSize and confirm reopen fails cleanly.
    var m = try db.treeMap("t", LongFormat.instance, StringGroupFormat.instance).create();
    try db.closeMap(m);
    db.admin_mu.lock();
    try db.catalog.put(a, "t#maxNodeSize", "1");
    db.admin_mu.unlock();
    try testing.expectError(error.DataCorruption, db.treeMap("t", LongFormat.instance, StringGroupFormat.instance).open());
    _ = &m;
}

test "atomicVar over a serializer value round-trips + getAndSet" {
    const a = testing.allocator;
    var db = try memoryByteArrayDb(a);
    defer db.deinit();
    defer db.close() catch {};
    var av = try db.atomicVar("v", serializers.LongSer.instance, @as(?i64, 7)).create();
    try testing.expectEqual(@as(?i64, 7), try av.get());
    try testing.expectEqual(@as(?i64, 7), try av.getAndSet(@as(?i64, 9)));
    try testing.expectEqual(@as(?i64, 9), try av.get());
    db.closeAtomic();
    _ = &av;
}

test "queue create/open + mode-mismatch rejected" {
    const a = testing.allocator;
    var db = try memoryByteArrayDb(a);
    defer db.deinit();
    defer db.close() catch {};
    const q = try db.queue("q", StringSer.instance).create();
    try q.add("a");
    db.closeQueue(q);
    // reopen as a Stack → WrongType (catalog #type is Queue)
    try testing.expectError(error.WrongType, db.stack("q", StringSer.instance).open());
    const q2 = try db.queue("q", StringSer.instance).open();
    {
        const v = (try q2.poll()).?;
        defer StringSer.instance.deinitElem(a, v);
        try testing.expectEqualStrings("a", v);
    }
    db.closeQueue(q2);
}

test "rename/delete reject live handles; delete unlinks (M10/N2)" {
    const a = testing.allocator;
    var db = try memoryByteArrayDb(a);
    defer db.deinit();
    defer db.close() catch {};
    var m = try db.treeMap("t", LongFormat.instance, StringGroupFormat.instance).create();
    try testing.expectError(error.HandlesOpen, db.rename("t", "u"));
    try testing.expectError(error.HandlesOpen, db.delete("t"));
    try db.closeMap(m);
    try db.rename("t", "u");
    try testing.expect(try db.exists("u"));
    try testing.expect(!(try db.exists("t")));
    try testing.expect(try db.delete("u"));
    try testing.expect(!(try db.exists("u")));
    _ = &m;
}

test "hostile catalog rejected at open" {
    const a = testing.allocator;
    var cat = NameCatalog.init();
    defer cat.deinit(a);
    try cat.put(a, "x#type", "AtomicLong");
    try cat.put(a, "x#recid", "0"); // recid must be ≥ 1
    try cat.put(a, "x#bogus", "yes"); // unknown field
    try testing.expectError(error.DataCorruption, validateCatalog(a, &cat));
}

test "validateFileOptions rejects RO+WAL and deleteAfterOpen+WAL" {
    try testing.expectError(error.WrongConfiguration, validateFileOptions(true, true, false));
    try testing.expectError(error.WrongConfiguration, validateFileOptions(false, true, true));
    try validateFileOptions(false, false, true);
    try validateFileOptions(true, false, false);
}

test "file DB round-trip: write, close, reopen read-only, writes rejected (C1)" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    const file = try std.fmt.allocPrint(a, "{s}/ro.db", .{path});
    defer a.free(file);

    // Create a writable file DB with data, then close.
    {
        var db = try fileDb(a, file);
        defer db.deinit();
        var m = try db.treeMap("t", LongFormat.instance, StringGroupFormat.instance).create();
        try m.putOnly(1, "one");
        try db.closeMap(m);
        try db.close();
    }
    // Reopen read-only: open a map + atomic, read, writes rejected, close cleanly.
    {
        var db = try fileReadOnlyDb(a, file);
        defer db.deinit();
        var m = try db.treeMap("t", LongFormat.instance, StringGroupFormat.instance).open();
        const v = try m.get(&@as(i64, 1));
        defer if (v) |x| a.free(x);
        try testing.expectEqualStrings("one", v.?);
        // a write THROUGH the read-only wrapper is rejected
        try testing.expectError(error.ReadOnly, m.putOnly(2, "two"));
        try db.closeMap(m);
        try db.close();
    }
}

test "Db non-generic method surface is analyzed (compile coverage)" {
    // Force semantic analysis of every non-generic method (rollback/compact/
    // commit/getType/storePtr/... and the read-only wrapper teardown) so lazy
    // analysis cannot hide a compile error in a path the functional tests don't hit.
    std.testing.refAllDecls(Db(StoreByteArray));
    std.testing.refAllDecls(Db(StoreWAL));
    std.testing.refAllDecls(Db(StoreReadOnlyWrapper(StoreDirect)));
}

test "treeSet create/navigate + getType + commit + createOrOpen (smoke)" {
    const a = testing.allocator;
    var db = try memoryByteArrayDb(a);
    defer db.deinit();
    defer db.close() catch {};
    var set = try db.treeSet("s", LongFormat.instance).counterEnable().create();
    try testing.expect(try set.add(5));
    try testing.expect(try set.add(3));
    try testing.expectEqual(@as(?i64, 3), try set.first());
    try db.commit();
    const ty = (try db.getType("s")).?;
    defer a.free(ty);
    try testing.expectEqualStrings("TreeSet", ty);
    try db.closeSet(set);
    var set2 = try db.treeSet("s", LongFormat.instance).createOrOpen();
    try testing.expect(try set2.contains(&@as(i64, 5)));
    try db.closeSet(set2);
    _ = .{ &set, &set2 };
}

test "atomicString / atomicBoolean / circularQueue (smoke)" {
    const a = testing.allocator;
    var db = try memoryByteArrayDb(a);
    defer db.deinit();
    defer db.close() catch {};
    var as_ = try db.atomicString("s").initialValue("hi").create();
    {
        const v = try as_.get();
        defer if (v) |x| a.free(x);
        try testing.expectEqualStrings("hi", v.?);
    }
    db.closeAtomic();
    _ = &as_;
    var ab = try db.atomicBoolean("b").create();
    try ab.set(true);
    try testing.expect(try ab.get());
    db.closeAtomic();
    _ = &ab;
    const cq = try db.circularQueue("c", StringSer.instance, 2).create();
    try cq.add("a");
    try cq.add("b");
    try cq.add("c"); // circular: "a" dropped
    try testing.expectEqual(@as(u64, 2), try cq.size());
    db.closeQueue(cq);
}

test "read-only DB: RO+RO queue opens coexist; mutation rejected" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(dir);
    const file = try std.fmt.allocPrint(a, "{s}/roq.db", .{dir});
    defer a.free(file);
    {
        var db = try fileDb(a, file);
        defer db.deinit();
        const q = try db.queue("q", StringSer.instance).create();
        try q.add("a");
        db.closeQueue(q);
        try db.close();
    }
    {
        var db = try fileReadOnlyDb(a, file);
        defer db.deinit();
        const q1 = try db.queue("q", StringSer.instance).open();
        const q2 = try db.queue("q", StringSer.instance).open(); // RO+RO coexist
        {
            const v = (try q1.peek()).?;
            defer StringSer.instance.deinitElem(a, v);
            try testing.expectEqualStrings("a", v);
        }
        try testing.expectError(error.ReadOnly, q1.add("b")); // mutation rejected
        db.closeQueue(q1);
        db.closeQueue(q2);
        try db.close();
    }
}

test "rollback rejects missing recid-1 catalog + poisons the facade" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(dir);
    const file = try std.fmt.allocPrint(a, "{s}/wal.db", .{dir});
    defer a.free(file);
    var db = try fileWalDb(a, file);
    defer db.deinit();
    // Delete the catalog record and COMMIT the deletion, so the rollback reverts
    // to a committed state with no recid 1.
    const store = try db.storePtr();
    try store.delete(1);
    try store.commit();
    try testing.expectError(error.DataCorruption, db.rollback());
    try testing.expect(db.isClosed()); // poisoned to a terminal state; deinit safe
}

test "tempFileDb creates + cleans up its file" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(dir);
    var db = try tempFileDb(a, dir);
    defer db.deinit();
    var m = try db.treeMap("t", LongFormat.instance, LongFormat.instance).create();
    try m.putOnly(1, 2);
    try db.closeMap(m);
    try db.close(); // deletes the temp file
}
