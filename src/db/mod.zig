//! `db` layer — the DB/DBMaker facade. Ported from Java
//! `org.mapdb.db.{DB,DBMaker,Atomic}` + `org.mapdb.Bind`, with Zig-specific
//! rulings: `Db(comptime S)`, comptime-typed makers, no instance cache,
//! lease double-open rejection, and enforced close/deinit teardown order.

const std = @import("std");

pub const catalog = @import("catalog.zig");
pub const descriptor = @import("descriptor.zig");
pub const atomic = @import("atomic.zig");
pub const set = @import("set.zig");
pub const db = @import("db.zig");
pub const bind = @import("bind.zig");

// -------- re-exports --------

/// The name catalog map + its MDBC-v1 codec, at recid 1.
pub const NameCatalog = catalog.NameCatalog;
pub const CatalogSer = catalog.CatalogSer;
pub const RECID_CATALOG = catalog.RECID_CATALOG;

/// The DB facade over a store `S`.
pub const Db = db.Db;
pub const validateName = db.validateName;

// DBMaker-style typed constructors.
pub const heapDb = db.heapDb;
pub const memoryByteArrayDb = db.memoryByteArrayDb;
pub const memoryDirectDb = db.memoryDirectDb;
pub const fileDb = db.fileDb;
pub const fileDbDeleteAfterClose = db.fileDbDeleteAfterClose;
pub const fileDbDeleteAfterOpen = db.fileDbDeleteAfterOpen;
pub const tempFileDb = db.tempFileDb;
pub const fileWalDb = db.fileWalDb;
pub const fileReadOnlyDb = db.fileReadOnlyDb;
pub const validateFileOptions = db.validateFileOptions;

/// Atomic families.
pub const AtomicLong = atomic.AtomicLong;
pub const AtomicInteger = atomic.AtomicInteger;
pub const AtomicBoolean = atomic.AtomicBoolean;
pub const AtomicString = atomic.AtomicString;
pub const AtomicVar = atomic.AtomicVar;
pub const STRING_NULLABLE = atomic.STRING_NULLABLE;

/// Map-backed set.
pub const NavigableSet = set.NavigableSet;
pub const NoValueFormat = set.NoValueFormat;

/// Bind secondary-index helpers.
pub const Bind = bind.Bind;

test {
    std.testing.refAllDecls(@This());
}
