//! `StoreWAL` — transactional store: an in-memory [`StoreDirect`] volume plus a
//! write-ahead log file (Java `StoreWAL`). Ported from
//! `mapdb-rust-store/src/store/wal.rs`.
//!
//! Uncommitted mutations are staged in memory; [`StoreWAL.commit`] serializes
//! them as one WAL section, fsyncs (the durability point), then applies them to
//! the inner (memory-backed) StoreDirect. Recovery replays all committed
//! sections from the start of the file.
//!
//! # On-disk format v1
//!
//! This is **this implementation's** format v1, as ported from the Rust port's
//! v1. It is not a shared contract: the Java engine has since moved to a
//! segmented format v3. See `README.md` — the on-disk format is not stabilised
//! and no cross-engine compatibility is claimed.
//! ```text
//! file       := fileHeader section*
//! fileHeader := magic "MDBS.WAL" (8) | version i32=1 | flags i32=0        (16 B)
//! section    := tag u8 ('S' commit, 'C' checkpoint)
//!             | lsn i64 (strictly increasing)
//!             | bodyLen i64
//!             | hdrCrc i32 = CRC32(tag ++ lsn ++ bodyLen)
//!             | bodyCrc i32 = CRC32(body)
//!             | body: entries T_PREALLOC/T_RECORD/T_APPEND/T_DELETE (packLong framing)
//! ```
//! CRCs are validated BEFORE any entry is decoded (garbage never allocates);
//! replay is entry-by-entry in O(1) memory; a damaged section FOLLOWED by a
//! valid one is distinguishable from a torn tail — mid-log corruption raises
//! `DataCorruption` while a bad section at EOF is truncated (decision D4).
//!
//! CRC32 is IEEE (`std.hash.crc.Crc32`, ISO-HDLC / crc32fast-compatible).
//!
//! Concurrency: ONE global writer. All state lives
//! behind a single `RwLock`; commit/rollback are transaction boundaries that
//! never race in-flight mutations. `closed` is published under the write lock
//! and every write path rechecks it after acquiring.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const mod = @import("mod.zig");
const iv = @import("index_val.zig");
const tainted = @import("../tainted.zig");
const direct = @import("direct.zig");
const StoreDirect = direct.StoreDirect;
const STATE_LIVE = direct.STATE_LIVE;
const STATE_VOID = direct.STATE_VOID;
const AppendResult = mod.AppendResult;
const LeaseTable = mod.LeaseTable;

const Crc32 = std.hash.crc.Crc32;

const T_PREALLOC: u8 = 1;
const T_RECORD: u8 = 2;
const T_APPEND: u8 = 3;
const T_DELETE: u8 = 4;
/// Legacy (headerless format) trailing seal tag; v1 sections are length-prefixed.
const T_COMMIT: u8 = 8;

const MAGIC: [8]u8 = "MDBS.WAL".*;
const FORMAT_VERSION: i32 = 1;
/// File header: magic(8) + version(4) + flags(4).
const FILE_HDR: u64 = 16;
/// Section header: tag(1) + lsn(8) + bodyLen(8) + hdrCrc(4) + bodyCrc(4).
const SEC_HDR: usize = 25;
/// Bytes of the section header covered by hdrCrc (tag + lsn + bodyLen).
const SEC_HDR_CRC_LEN: usize = 17;
const TAG_SECTION: u8 = 'S';
const TAG_CKPT: u8 = 'C';

/// Default streaming-replay window (bytes); ctor override forces refill edges in tests.
const DEFAULT_REPLAY_BUF: usize = 1 << 20;
/// Default log size past which `commit()` triggers an automatic checkpoint.
pub const DEFAULT_AUTO_CHECKPOINT_BYTES: i64 = 1 << 30;

/// Streaming replay control flow (mirrors Rust `WalStop`): `error.Torn` marks a
/// torn tail (truncate + recover — availability); any other member is fatal
/// (mid-log corruption / IO — integrity). `error.Torn` never escapes a public
/// method: every boundary catches it and either truncates or maps it to
/// `DataCorruption` (see [`fatalOnly`]).
const WalError = DbError || error{Torn};

inline fn crc32(bytes: []const u8) u32 {
    return Crc32.hash(bytes);
}

/// A torn tail in a context that requires completeness IS corruption; any other
/// wal error is already a `DbError`. Callers use this at boundaries where a torn
/// tail cannot be tolerated (the checkpoint-temp / snapshot path).
inline fn fatalOnly(e: WalError) DbError {
    return if (e == error.Torn) error.DataCorruption else @errorCast(e);
}

/// Fallible recid conversion for decode paths: a CRC-valid but semantically
/// invalid entry carrying recid 0 (reserved) must return `DataCorruption`.
inline fn nzRes(recid: u64) WalError!u64 {
    if (recid == 0) return error.DataCorruption;
    return recid;
}

// ---------------------------------------------------------------- big-endian

inline fn putI64Be(buf: []u8, off: usize, v: i64) void {
    std.mem.writeInt(i64, buf[off..][0..8], v, .big);
}
inline fn putI32Be(buf: []u8, off: usize, v: i32) void {
    std.mem.writeInt(i32, buf[off..][0..4], v, .big);
}
inline fn getI64Be(buf: []const u8, off: usize) i64 {
    return std.mem.readInt(i64, buf[off..][0..8], .big);
}
inline fn getI32Be(buf: []const u8, off: usize) i32 {
    return std.mem.readInt(i32, buf[off..][0..4], .big);
}

const SecHdr = struct { tag: u8, lsn: i64, body_len: i64, hdr_crc: i32, body_crc: i32 };

fn parseSecHdr(hdr: *const [SEC_HDR]u8) SecHdr {
    return .{
        .tag = hdr[0],
        .lsn = getI64Be(hdr, 1),
        .body_len = getI64Be(hdr, 9),
        .hdr_crc = getI32Be(hdr, 17),
        .body_crc = getI32Be(hdr, 21),
    };
}

// ------------------------------------------------------------------ file I/O

/// Positioned full read; a short read (file shorter than claimed) is a torn tail.
fn readAt(file: std.fs.File, buf: []u8, pos: u64) WalError!void {
    const n = file.preadAll(buf, pos) catch return error.Io;
    if (n < buf.len) return error.Torn;
}

fn writeFileHeader(file: std.fs.File) DbError!void {
    var h: [FILE_HDR]u8 = undefined;
    @memcpy(h[0..8], &MAGIC);
    putI32Be(&h, 8, FORMAT_VERSION);
    putI32Be(&h, 12, 0);
    file.pwriteAll(&h, 0) catch return error.Io;
}

/// True when the file carries the v1 magic; rejects unknown future versions.
fn isV1(file: std.fs.File, size: u64) DbError!bool {
    if (size < FILE_HDR) return false;
    var h: [FILE_HDR]u8 = undefined;
    _ = file.preadAll(&h, 0) catch return error.Io;
    if (!std.mem.eql(u8, h[0..8], &MAGIC)) return false;
    const version = getI32Be(&h, 8);
    if (version != FORMAT_VERSION) return error.DataCorruption; // unsupported WAL format version
    return true;
}

/// A framed MapDB-family header must never be reinterpreted as the legacy
/// headerless WAL. In particular, this makes a hard magic swap reject old v1
/// files instead of treating their first byte as a torn legacy instruction and
/// destructively migrating an empty prefix.
fn hasFramedMagicPrefix(file: std.fs.File, size: u64) DbError!bool {
    if (size < 3) return false;
    var prefix: [3]u8 = undefined;
    const n = file.preadAll(&prefix, 0) catch return error.Io;
    if (n < prefix.len) return error.Io;
    return std.mem.eql(u8, &prefix, "MDB");
}

/// fsync the directory so a create/rename of `path` is itself durable. On the
/// durability path (initial WAL creation, checkpoint promotion): failure MUST
/// propagate. Linux-scoped.
fn fsyncDir(path: []const u8) DbError!void {
    const parent = std.fs.path.dirname(path) orelse ".";
    const dir_path = if (parent.len == 0) "." else parent;
    // `.iterate` forces a real O_RDONLY dir fd (a default O_PATH fd cannot be
    // fsync'd on Linux → EBADF).
    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch return error.Io;
    defer dir.close();
    std.posix.fsync(dir.fd) catch return error.Io;
}

/// `<path>.ckpt` (owned; caller frees).
fn ckptTmp(alloc: Allocator, path: []const u8) DbError![]u8 {
    return std.mem.concat(alloc, u8, &.{ path, ".ckpt" }) catch return error.OutOfMemory;
}

fn pathExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

/// CRC32 over the body range `[start, end)`, streamed through a bounded buffer.
fn bodyCrc(file: std.fs.File, start: u64, end: u64, bufsize: usize, alloc: Allocator) WalError!u32 {
    var crc = Crc32.init();
    if (start < end) {
        const span = end - start;
        const cap: usize = @intCast(@min(span, @as(u64, @max(bufsize, 16))));
        const buf = alloc.alloc(u8, cap) catch return error.OutOfMemory;
        defer alloc.free(buf);
        var p = start;
        while (p < end) {
            const n: usize = @intCast(@min(end - p, @as(u64, buf.len)));
            try readAt(file, buf[0..n], p);
            crc.update(buf[0..n]);
            p += n;
        }
    }
    return crc.final();
}

// -------------------------------------------------------------- staged state

/// Per-recid staged mutation set (uncommitted). Content == (base or inner) ++ appends.
const Staged = struct {
    created: bool = false,
    base_set: bool = false,
    /// `null` with `base_set == true` means explicit null content.
    base: ?[]u8 = null,
    headroom: usize = 0,
    deleted: bool = false,
    appends: std.ArrayListUnmanaged([]u8) = .empty,
    appends_len: usize = 0,

    fn deinit(self: *Staged, alloc: Allocator) void {
        if (self.base) |b| alloc.free(b);
        for (self.appends.items) |a| alloc.free(a);
        self.appends.deinit(alloc);
    }

    /// Reset base + appends (delete/update/CAS clobber both), freeing them.
    fn clearContent(self: *Staged, alloc: Allocator) void {
        if (self.base) |b| alloc.free(b);
        self.base = null;
        for (self.appends.items) |a| alloc.free(a);
        self.appends.clearRetainingCapacity();
        self.appends_len = 0;
    }
};

/// Classified commit operation, computed before any apply (state must not shift
/// mid-apply). `op == 0` = created+deleted: apply-only cleanup, not logged.
const WalOp = struct {
    op: u8,
    recid: u64,
    cap: usize,
    data: ?[]u8,
};

/// Capacity as the writer encodes it: 0 for null content, else 16-aligned, big
/// enough for header+content, within the plain-record limit — EXCEPT oversize
/// (linked) records, which the writer encodes with capacity 0.
fn capValid(cap: u64, data: ?[]const u8) bool {
    if (data) |d| {
        const max = @as(u64, iv.MAX_CAPACITY);
        const need = @as(u64, d.len) + 4;
        if (cap == 0) return need > max;
        return cap >= need and cap <= max and (cap & 15) == 0;
    } else {
        return cap == 0;
    }
}

/// Rounded plain-record capacity for `content_len` + `headroom` bytes, or
/// `RecordTooLarge` on overflow / exceeding MAX_CAPACITY. Caller guarantees the
/// content is not itself oversize (`4 + content_len <= MAX_CAPACITY`).
fn plainCap(content_len: usize, headroom: usize) DbError!u64 {
    const base = std.math.add(u64, 4, @as(u64, content_len)) catch return error.RecordTooLarge;
    const need = std.math.add(u64, base, @as(u64, headroom)) catch return error.RecordTooLarge;
    const rounded = (std.math.add(u64, need, 15) catch return error.RecordTooLarge) & ~@as(u64, 15);
    if (rounded > @as(u64, iv.MAX_CAPACITY)) return error.RecordTooLarge;
    return rounded;
}

// -------------------------------------------------------- streaming decoder

/// Streaming WAL decoder: a fixed-size window over the file with u64 positions,
/// bounded by `[start, limit)`, plus an incremental CRC32 (used by the legacy
/// trailing-seal format only). Never materializes the log, so 2 GiB+ files replay.
const WalIn = struct {
    file: std.fs.File,
    alloc: Allocator,
    limit: u64 = 0,
    win: []u8,
    win_start: u64 = 0,
    win_pos: usize = 0,
    win_len: usize = 0,
    crc: Crc32,

    fn init(file: std.fs.File, alloc: Allocator, bufsize: usize) DbError!WalIn {
        const win = alloc.alloc(u8, @max(bufsize, 16)) catch return error.OutOfMemory;
        return .{ .file = file, .alloc = alloc, .win = win, .crc = Crc32.init() };
    }

    fn deinit(self: *WalIn) void {
        self.alloc.free(self.win);
    }

    fn reset(self: *WalIn, start: u64, end: u64) void {
        self.win_start = start;
        self.limit = end;
        self.win_pos = 0;
        self.win_len = 0;
        self.crc = Crc32.init();
    }

    inline fn pos(self: *const WalIn) u64 {
        return self.win_start + self.win_pos;
    }
    inline fn remaining(self: *const WalIn) u64 {
        return self.limit - self.pos();
    }

    fn refill(self: *WalIn) WalError!void {
        self.win_start = self.pos();
        self.win_pos = 0;
        if (self.win_start >= self.limit) return error.Torn;
        const n: usize = @intCast(@min(self.limit - self.win_start, @as(u64, self.win.len)));
        try readAt(self.file, self.win[0..n], self.win_start);
        self.win_len = n;
    }

    /// Unsigned byte, NOT folded into the CRC (callers fold via `crcTag`).
    fn readByteRaw(self: *WalIn) WalError!u8 {
        if (self.win_pos >= self.win_len) try self.refill();
        const b = self.win[self.win_pos];
        self.win_pos += 1;
        return b;
    }

    fn crcTag(self: *WalIn, tag: u8) void {
        self.crc.update(&.{tag});
    }

    /// Packed long, CRC'd, capped at 10 bytes (over-long run = corruption).
    fn unpackLong(self: *WalIn) WalError!u64 {
        var ret: u64 = 0;
        var i: usize = 0;
        while (i < io.max_packed_long_bytes) : (i += 1) {
            const v = try self.readByteRaw();
            self.crc.update(&.{v});
            ret = (ret << 7) | @as(u64, v & 0x7F);
            if (v & 0x80 != 0) return ret;
        }
        return error.DataCorruption; // WAL packed long too long
    }

    /// Payload bytes, CRC'd.
    fn readFully(self: *WalIn, dst: []u8) WalError!void {
        var off: usize = 0;
        while (off < dst.len) {
            if (self.win_pos >= self.win_len) try self.refill();
            const n = @min(self.win_len - self.win_pos, dst.len - off);
            @memcpy(dst[off .. off + n], self.win[self.win_pos .. self.win_pos + n]);
            self.win_pos += n;
            off += n;
        }
        self.crc.update(dst);
    }

    /// Big-endian i32, NOT CRC'd (the stored section CRC itself).
    fn readIntRaw(self: *WalIn) WalError!i32 {
        var r: i32 = 0;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            r = (r << 8) | @as(i32, try self.readByteRaw());
        }
        return r;
    }

    fn crcValue(self: *const WalIn) u32 {
        return self.crc.final();
    }
    fn crcReset(self: *WalIn) void {
        self.crc = Crc32.init();
    }
};

/// Decode+apply one CRC-verified section body into `inner` (O(1) memory).
fn applySection(inner: *StoreDirect, win: *WalIn, start: u64, end: u64) WalError!void {
    win.reset(start, end);
    while (win.pos() < end) {
        const ty = try win.readByteRaw();
        switch (ty) {
            T_PREALLOC => try inner.walPrealloc(try nzRes(try win.unpackLong())),
            T_DELETE => try inner.delete(try nzRes(try win.unpackLong())),
            T_RECORD => {
                const recid = try nzRes(try win.unpackLong());
                const cap = try win.unpackLong();
                const len_plus = try win.unpackLong();
                var data: ?[]u8 = null;
                if (len_plus != 0) {
                    const len = len_plus - 1;
                    if (len > std.math.maxInt(i32) or len > win.remaining())
                        return error.DataCorruption; // bad WAL record length
                    const b = win.alloc.alloc(u8, try tainted.u64ToUsize(len)) catch return error.OutOfMemory;
                    win.readFully(b) catch |e| {
                        win.alloc.free(b);
                        return e;
                    };
                    data = b;
                }
                defer if (data) |d| win.alloc.free(d);
                if (!capValid(cap, data)) return error.DataCorruption; // bad WAL record capacity
                try inner.walPut(recid, try tainted.u64ToUsize(cap), data);
            },
            T_APPEND => {
                const recid = try nzRes(try win.unpackLong());
                const len = try win.unpackLong();
                if (len > std.math.maxInt(i32) or len > win.remaining())
                    return error.DataCorruption; // bad WAL append length
                const b = win.alloc.alloc(u8, try tainted.u64ToUsize(len)) catch return error.OutOfMemory;
                defer win.alloc.free(b);
                try win.readFully(b);
                switch (try inner.append(recid, b)) {
                    .refused => return error.DataCorruption, // WAL append refused
                    .new_size => {},
                }
            },
            else => return error.DataCorruption, // bad WAL entry tag
        }
    }
}

/// One legacy-format pending op (headerless trailing-seal format only).
fn applyOps(inner: *StoreDirect, ops: []const WalOp) WalError!void {
    for (ops) |op| {
        const recid = try nzRes(op.recid);
        switch (op.op) {
            T_PREALLOC => try inner.walPrealloc(recid),
            T_RECORD => try inner.walPut(recid, op.cap, op.data),
            T_APPEND => {
                const d = op.data.?;
                switch (try inner.append(recid, d)) {
                    .refused => return error.DataCorruption, // WAL append refused
                    .new_size => {},
                }
            },
            T_DELETE => try inner.delete(recid),
            else => return error.DataCorruption, // bad WAL op
        }
    }
}

/// True when `[from, size)` holds >=1 fully valid section proving durable
/// committed sections follow a bad one. `exact_next`: untrusted anchor requires
/// exactly `last_lsn + 2`; else any strictly-future LSN (`> last_lsn + 1`).
fn anyValidSectionFrom(
    file: std.fs.File,
    from: u64,
    size: u64,
    last_lsn: i64,
    exact_next: bool,
    bufsize: usize,
    alloc: Allocator,
) WalError!bool {
    var pos = from;
    while (pos + @as(u64, SEC_HDR) <= size) {
        var hdr: [SEC_HDR]u8 = undefined;
        readAt(file, &hdr, pos) catch |e| {
            if (e == error.Torn) return false;
            return e;
        };
        const h = parseSecHdr(&hdr);
        const body_start = pos + @as(u64, SEC_HDR);
        if (@as(i32, @bitCast(crc32(hdr[0..SEC_HDR_CRC_LEN]))) != h.hdr_crc or
            (h.tag != TAG_SECTION and h.tag != TAG_CKPT) or
            h.body_len < 0 or
            @as(u64, @intCast(h.body_len)) > size - body_start)
        {
            return false;
        }
        // checked: overflow at the LSN ceiling means no such successor exists.
        const lsn_ok = if (exact_next)
            (std.math.add(i64, last_lsn, 2) catch null) != null and h.lsn == last_lsn + 2
        else
            (std.math.add(i64, last_lsn, 1) catch null) != null and h.lsn > last_lsn + 1;
        const body_end = body_start + @as(u64, @intCast(h.body_len));
        if (lsn_ok and (try bodyCrc(file, body_start, body_end, bufsize, alloc)) == @as(u32, @bitCast(h.body_crc)))
            return true;
        pos = body_end;
    }
    return false;
}

// ------------------------------------------------------------ snapshot writer

/// Streaming snapshot body writer: buffers ~1 MiB chunks, tracks total body
/// length (u64 — bodies may exceed 2 GiB) and a rolling CRC32. Serves as the
/// `sink` for `StoreDirect.walSnapshot`.
const SnapshotWriter = struct {
    const FLUSH_AT: usize = 1 << 20;

    file: std.fs.File,
    at: u64,
    out: DataOutput2,
    crc: Crc32,
    body_len: u64 = 0,

    fn init(file: std.fs.File, at: u64, alloc: Allocator) SnapshotWriter {
        return .{ .file = file, .at = at, .out = DataOutput2.init(alloc), .crc = Crc32.init() };
    }
    fn deinit(self: *SnapshotWriter) void {
        self.out.deinit();
    }

    /// `StoreDirect.walSnapshot` sink entry point.
    pub fn emit(self: *SnapshotWriter, recid: u64, is_prealloc: bool, cap_bytes: usize, content: ?[]const u8) DbError!void {
        if (is_prealloc) return self.prealloc(recid);
        return self.record(recid, cap_bytes, content);
    }

    fn prealloc(self: *SnapshotWriter, recid: u64) DbError!void {
        try self.out.writeByte(T_PREALLOC);
        try self.out.packLong(recid);
        return self.maybeFlush();
    }

    fn record(self: *SnapshotWriter, recid: u64, cap_bytes: usize, content: ?[]const u8) DbError!void {
        try self.out.writeByte(T_RECORD);
        try self.out.packLong(recid);
        try self.out.packLong(@as(u64, cap_bytes));
        if (content) |d| {
            try self.out.packLong(@as(u64, d.len) + 1);
            try self.out.writeAll(d);
        } else {
            try self.out.packLong(0);
        }
        return self.maybeFlush();
    }

    fn maybeFlush(self: *SnapshotWriter) DbError!void {
        if (self.out.pos() >= FLUSH_AT) try self.flush();
    }

    fn flush(self: *SnapshotWriter) DbError!void {
        const b = self.out.bytes();
        if (b.len == 0) return;
        self.crc.update(b);
        self.file.pwriteAll(b, self.at) catch return error.Io;
        self.at += b.len;
        self.body_len += b.len;
        self.out.buf.clearRetainingCapacity();
    }
};

// -------------------------------------------------------------- WalState

/// The lock-guarded mutable state (Java's single ReadWriteLock covers all of it).
const WalState = struct {
    inner: StoreDirect,
    file: std.fs.File,
    staged: std.AutoHashMapUnmanaged(u64, Staged) = .empty,
    next_lsn: i64,
    checkpoint_basis: u64,
    auto_checkpoint_bytes: i64,
    /// Append position in the log (Java tracks this as `ch.position()`).
    log_pos: u64,
    replay_buf: usize,
    /// Set when a durability-path step (e.g. the post-rename directory fsync)
    /// failed after its visible effect: the store must not report any later
    /// commit/checkpoint durable until reopened. Guarded by the state lock.
    poisoned: bool = false,
    alloc: Allocator,

    fn clearStaged(self: *WalState) void {
        var it = self.staged.valueIterator();
        while (it.next()) |s| s.deinit(self.alloc);
        self.staged.clearRetainingCapacity();
    }

    // ---------- open-time recovery ----------

    fn recoverOpenedChannel(self: *WalState, created: bool, path: []const u8) DbError!void {
        const size = (self.file.stat() catch return error.Io).size;
        var legacy = false;
        const valid_end: u64 = if (size == 0) blk: {
            try writeFileHeader(self.file);
            self.file.sync() catch return error.Io;
            if (created) try fsyncDir(path);
            break :blk FILE_HDR;
        } else if (try isV1(self.file, size)) blk: {
            break :blk try self.replayV1(size);
        } else if (try hasFramedMagicPrefix(self.file, size)) {
            return error.DataCorruption;
        } else blk: {
            legacy = true;
            break :blk try self.replayLegacy(size);
        };
        self.file.setEndPos(valid_end) catch return error.Io;
        self.log_pos = valid_end;
        // replay of delete-then-reuse histories leaves stale free-list entries:
        // rebuild the allocator's free list from the final index.
        try self.inner.rebuildFreeRecids();
        if (legacy) try self.checkpointLocked(path); // migrate to v1
    }

    /// Scans v1 sections; applies each CRC-valid one; returns the end offset of
    /// the last valid section. Torn tail truncates; a CRC-failing section
    /// FOLLOWED by a valid one is mid-log corruption and errors.
    fn replayV1(self: *WalState, size: u64) DbError!u64 {
        var win = try WalIn.init(self.file, self.alloc, self.replay_buf);
        defer win.deinit();
        var pos = FILE_HDR;
        var last_lsn: i64 = 0;
        while (pos + @as(u64, SEC_HDR) <= size) {
            const StepResult = struct { lsn: i64, body_end: u64 };
            // Returns the parsed section, `null` for a suspect (self-CRC-failing)
            // header, `error.Torn` for a torn tail, else a fatal DbError.
            const step: WalError!?StepResult = blk: {
                var hdr: [SEC_HDR]u8 = undefined;
                readAt(self.file, &hdr, pos) catch |e| break :blk e;
                const h = parseSecHdr(&hdr);
                const body_start = pos + @as(u64, SEC_HDR);
                const hdr_ok = @as(i32, @bitCast(crc32(hdr[0..SEC_HDR_CRC_LEN]))) == h.hdr_crc and
                    (h.tag == TAG_SECTION or h.tag == TAG_CKPT);
                if (!hdr_ok) break :blk @as(?StepResult, null); // suspect
                if (h.body_len < 0 or @as(u64, @intCast(h.body_len)) > size - body_start)
                    break :blk error.Torn; // verified header, body past EOF: torn by construction
                const body_end = body_start + @as(u64, @intCast(h.body_len));
                const bcrc = bodyCrc(self.file, body_start, body_end, self.replay_buf, self.alloc) catch |e| break :blk e;
                if (bcrc != @as(u32, @bitCast(h.body_crc))) {
                    // bodyEnd TRUSTED (hdrCrc valid): anything valid after it = bit rot.
                    const follows = anyValidSectionFrom(self.file, body_end, size, last_lsn, false, self.replay_buf, self.alloc) catch |e| break :blk e;
                    if (follows) break :blk error.DataCorruption; // mid-log corruption: body CRC mismatch but valid sections follow
                    break :blk error.Torn;
                }
                break :blk @as(?StepResult, .{ .lsn = h.lsn, .body_end = body_end });
            };

            const parsed: ?StepResult = step catch |e| {
                if (e == error.Torn) return pos; // torn tail: truncate here
                return fatalOnly(e);
            };
            const v = parsed orelse {
                // suspect header: torn tail unless a later valid section proves rot.
                return self.suspectSection(pos, size, last_lsn);
            };
            if (v.lsn <= last_lsn) return error.DataCorruption; // WAL LSN not increasing
            applySection(&self.inner, &win, pos + @as(u64, SEC_HDR), v.body_end) catch |e| return fatalOnly(e);
            last_lsn = v.lsn;
            self.next_lsn = std.math.add(i64, v.lsn, 1) catch return error.DataCorruption; // WAL LSN space exhausted
            pos = v.body_end;
        }
        return pos;
    }

    /// A section whose header fails its own CRC. The declared bodyLen is
    /// untrusted, so calling it corruption needs the section at the declared end
    /// to be fully valid AND carry EXACTLY the next expected LSN (`last_lsn + 2`).
    fn suspectSection(self: *WalState, pos: u64, size: u64, last_lsn: i64) DbError!u64 {
        var hdr: [SEC_HDR]u8 = undefined;
        readAt(self.file, &hdr, pos) catch |e| {
            if (e == error.Torn) return pos;
            return fatalOnly(e);
        };
        const h = parseSecHdr(&hdr);
        const body_start = pos + @as(u64, SEC_HDR);
        if (h.body_len >= 0 and @as(u64, @intCast(h.body_len)) <= size - body_start) {
            const follows = anyValidSectionFrom(self.file, body_start + @as(u64, @intCast(h.body_len)), size, last_lsn, true, self.replay_buf, self.alloc) catch |e| return fatalOnly(e);
            if (follows) return error.DataCorruption; // mid-log corruption: header damaged but valid sections follow
        }
        return pos;
    }

    /// Legacy (headerless) log: trailing-COMMIT-seal sections. Returns end offset
    /// of the last valid section.
    fn replayLegacy(self: *WalState, size: u64) DbError!u64 {
        if (size == 0) return 0;
        var win = try WalIn.init(self.file, self.alloc, self.replay_buf);
        defer win.deinit();
        win.reset(0, size);
        var valid_end: u64 = 0;
        var pending: std.ArrayListUnmanaged(WalOp) = .empty;
        defer {
            for (pending.items) |op| if (op.data) |d| self.alloc.free(d);
            pending.deinit(self.alloc);
        }
        const res: WalError!void = blk: {
            while (win.remaining() > 0) {
                const ty = win.readByteRaw() catch |e| break :blk e;
                if (ty == T_COMMIT) {
                    const computed = @as(i32, @bitCast(win.crcValue()));
                    const stored = win.readIntRaw() catch |e| break :blk e;
                    if (computed != stored) break :blk {}; // torn/corrupt tail
                    applyOps(&self.inner, pending.items) catch |e| break :blk e;
                    for (pending.items) |op| if (op.data) |d| self.alloc.free(d);
                    pending.clearRetainingCapacity();
                    valid_end = win.pos();
                    win.crcReset();
                    continue;
                }
                win.crcTag(ty);
                switch (ty) {
                    T_PREALLOC => {
                        const recid = win.unpackLong() catch |e| break :blk e;
                        pending.append(self.alloc, .{ .op = T_PREALLOC, .recid = recid, .cap = 0, .data = null }) catch break :blk error.OutOfMemory;
                    },
                    T_DELETE => {
                        const recid = win.unpackLong() catch |e| break :blk e;
                        pending.append(self.alloc, .{ .op = T_DELETE, .recid = recid, .cap = 0, .data = null }) catch break :blk error.OutOfMemory;
                    },
                    T_RECORD => {
                        const recid = win.unpackLong() catch |e| break :blk e;
                        const cap = win.unpackLong() catch |e| break :blk e;
                        const len_plus = win.unpackLong() catch |e| break :blk e;
                        var data: ?[]u8 = null;
                        if (len_plus != 0) {
                            const len = len_plus - 1;
                            if (len > std.math.maxInt(i32) or len > win.remaining()) break :blk {}; // torn
                            const b = self.alloc.alloc(u8, @intCast(len)) catch break :blk error.OutOfMemory;
                            win.readFully(b) catch |e| {
                                self.alloc.free(b);
                                break :blk e;
                            };
                            data = b;
                        }
                        if (!capValid(cap, data)) {
                            if (data) |d| self.alloc.free(d);
                            break :blk {}; // garbage capacity: torn tail
                        }
                        pending.append(self.alloc, .{ .op = T_RECORD, .recid = recid, .cap = @intCast(cap), .data = data }) catch {
                            if (data) |d| self.alloc.free(d);
                            break :blk error.OutOfMemory;
                        };
                    },
                    T_APPEND => {
                        const recid = win.unpackLong() catch |e| break :blk e;
                        const len = win.unpackLong() catch |e| break :blk e;
                        if (len > std.math.maxInt(i32) or len > win.remaining()) break :blk {}; // torn
                        const b = self.alloc.alloc(u8, @intCast(len)) catch break :blk error.OutOfMemory;
                        win.readFully(b) catch |e| {
                            self.alloc.free(b);
                            break :blk e;
                        };
                        pending.append(self.alloc, .{ .op = T_APPEND, .recid = recid, .cap = 0, .data = b }) catch {
                            self.alloc.free(b);
                            break :blk error.OutOfMemory;
                        };
                    },
                    else => break :blk {}, // unknown instruction: torn tail
                }
            }
            break :blk {};
        };
        res catch |e| {
            if (e == error.Torn) return valid_end;
            return fatalOnly(e);
        };
        return valid_end;
    }

    // ---------- merged content ----------

    /// Merged content = (staged base or inner content) ++ staged appends; `null`
    /// = null content. Returned slice owned by `self.alloc` (caller frees).
    fn merged(self: *WalState, recid: u64, s: *const Staged) DbError!?[]u8 {
        var base: ?[]u8 = null;
        errdefer if (base) |b| self.alloc.free(b);
        if (s.base_set) {
            if (s.base) |b| base = self.alloc.dupe(u8, b) catch return error.OutOfMemory;
        } else if ((try self.inner.recState(recid)) == STATE_LIVE) {
            base = try self.inner.rawGet(self.alloc, recid);
        }
        if (base == null and s.appends.items.len == 0) return null;
        const base_len = if (base) |b| b.len else 0;
        const total = std.math.add(usize, base_len, s.appends_len) catch return error.DataCorruption;
        const m = self.alloc.alloc(u8, total) catch return error.OutOfMemory;
        errdefer self.alloc.free(m);
        var p: usize = 0;
        if (base) |b| {
            @memcpy(m[0..b.len], b);
            p = b.len;
        }
        for (s.appends.items) |a| {
            @memcpy(m[p .. p + a.len], a);
            p += a.len;
        }
        if (base) |b| self.alloc.free(b);
        base = null;
        return m;
    }

    /// Staged entry for a write; establishes GetVoid on deleted/void recids.
    fn stagedForWrite(self: *WalState, recid: u64) DbError!*Staged {
        if (self.staged.getPtr(recid)) |s| {
            if (s.deleted) return error.GetVoid;
        } else {
            if ((try self.inner.recState(recid)) == STATE_VOID) return error.GetVoid;
            self.staged.put(self.alloc, recid, Staged{}) catch return error.OutOfMemory;
        }
        return self.staged.getPtr(recid).?;
    }

    // ---------- commit ----------

    fn commitLocked(self: *WalState, path: []const u8) DbError!void {
        if (self.poisoned) return error.DataCorruption; // WAL poisoned by an earlier durability failure
        // Refuse before writing rather than overflow next_lsn (2^63 sections is infeasible).
        if (self.next_lsn == std.math.maxInt(i64)) return error.DataCorruption; // WAL LSN space exhausted
        if (self.staged.count() == 0) return;

        // classify all ops BEFORE applying any (apply shifts inner state).
        var recids: std.ArrayListUnmanaged(u64) = .empty;
        defer recids.deinit(self.alloc);
        {
            var it = self.staged.keyIterator();
            while (it.next()) |k| recids.append(self.alloc, k.*) catch return error.OutOfMemory;
        }
        std.mem.sort(u64, recids.items, {}, std.sort.asc(u64));

        var ops: std.ArrayListUnmanaged(WalOp) = .empty;
        defer {
            for (ops.items) |op| if (op.data) |d| self.alloc.free(d);
            ops.deinit(self.alloc);
        }
        for (recids.items) |recid| {
            const s = self.staged.getPtr(recid).?;
            if (s.deleted) {
                const op: u8 = if (!s.created) T_DELETE else 0; // created+deleted: cleanup only
                ops.append(self.alloc, .{ .op = op, .recid = recid, .cap = 0, .data = null }) catch return error.OutOfMemory;
            } else if (!s.base_set and s.appends.items.len == 0) {
                ops.append(self.alloc, .{ .op = T_PREALLOC, .recid = recid, .cap = 0, .data = null }) catch return error.OutOfMemory;
            } else if (s.base_set or (try self.inner.recState(recid)) != STATE_LIVE) {
                const m = try self.merged(recid, s);
                errdefer if (m) |mm| self.alloc.free(mm);
                // cap == 0 in a T_RECORD is valid ONLY for null content or a
                // genuinely oversize (linked) record. A plain record whose
                // content+headroom rounds past MAX_CAPACITY must NOT collapse to
                // cap 0; reject it as RecordTooLarge instead.
                const cap_l: u64 = if (m) |b| blk: {
                    const base = @as(u64, b.len) + 4;
                    if (base > @as(u64, iv.MAX_CAPACITY)) break :blk 0 // genuinely oversize → linked
                    else break :blk try plainCap(b.len, s.headroom);
                } else 0;
                ops.append(self.alloc, .{ .op = T_RECORD, .recid = recid, .cap = @intCast(cap_l), .data = m }) catch return error.OutOfMemory;
            } else {
                // live base in inner: log only the appended tail.
                const m = self.alloc.alloc(u8, s.appends_len) catch return error.OutOfMemory;
                errdefer self.alloc.free(m);
                var p: usize = 0;
                for (s.appends.items) |a| {
                    @memcpy(m[p .. p + a.len], a);
                    p += a.len;
                }
                ops.append(self.alloc, .{ .op = T_APPEND, .recid = recid, .cap = 0, .data = m }) catch return error.OutOfMemory;
            }
        }

        // build the section body.
        var body = DataOutput2.init(self.alloc);
        defer body.deinit();
        for (ops.items) |op| {
            switch (op.op) {
                T_PREALLOC, T_DELETE => {
                    try body.writeByte(op.op);
                    try body.packLong(op.recid);
                },
                T_RECORD => {
                    try body.writeByte(T_RECORD);
                    try body.packLong(op.recid);
                    try body.packLong(@as(u64, op.cap));
                    if (op.data) |d| {
                        try body.packLong(@as(u64, d.len) + 1);
                        try body.writeAll(d);
                    } else {
                        try body.packLong(0);
                    }
                },
                T_APPEND => {
                    try body.writeByte(T_APPEND);
                    try body.packLong(op.recid);
                    const d = op.data.?;
                    try body.packLong(@as(u64, d.len));
                    try body.writeAll(d);
                },
                else => {}, // op 0: not logged
            }
        }

        // section header (tag, lsn, bodyLen) + CRCs; fsync = durability point (D1).
        const body_bytes = body.bytes();
        var hdr: [SEC_HDR]u8 = undefined;
        hdr[0] = TAG_SECTION;
        putI64Be(&hdr, 1, self.next_lsn);
        putI64Be(&hdr, 9, @as(i64, @intCast(body_bytes.len)));
        putI32Be(&hdr, 17, @as(i32, @bitCast(crc32(hdr[0..SEC_HDR_CRC_LEN]))));
        putI32Be(&hdr, 21, @as(i32, @bitCast(crc32(body_bytes))));
        self.file.pwriteAll(&hdr, self.log_pos) catch return error.Io;
        self.file.pwriteAll(body_bytes, self.log_pos + @as(u64, SEC_HDR)) catch return error.Io;
        self.file.sync() catch return error.Io;
        self.log_pos += @as(u64, SEC_HDR) + body_bytes.len;
        self.next_lsn += 1;

        // apply to the inner volume.
        for (ops.items) |op| {
            switch (op.op) {
                0 => try self.inner.delete(op.recid), // created+deleted: free the P recid
                T_PREALLOC => {}, // already P in inner since op time
                T_RECORD => try self.inner.walPut(op.recid, op.cap, op.data),
                T_APPEND => {
                    const d = op.data.?;
                    switch (try self.inner.append(op.recid, d)) {
                        .refused => return error.DataCorruption, // commit append refused
                        .new_size => {},
                    }
                },
                T_DELETE => try self.inner.delete(op.recid),
                else => {},
            }
        }
        self.clearStaged();
        try self.maybeAutoCheckpointLocked(path);
    }

    fn maybeAutoCheckpointLocked(self: *WalState, path: []const u8) DbError!void {
        const limit = self.auto_checkpoint_bytes;
        if (limit <= 0) return;
        const doubled = self.checkpoint_basis *| 2;
        if (self.log_pos >= @max(@as(u64, @intCast(limit)), doubled)) {
            try self.checkpointLocked(path);
        }
    }

    // ---------- checkpoint ----------

    /// Rewrite the log as one snapshot section of the inner store's committed
    /// state, atomically replacing the log. The rename is the commit point.
    fn checkpointLocked(self: *WalState, path: []const u8) DbError!void {
        if (self.poisoned) return error.DataCorruption; // WAL poisoned by an earlier durability failure
        if (self.next_lsn == std.math.maxInt(i64)) return error.DataCorruption; // WAL LSN space exhausted
        const tmp = try ckptTmp(self.alloc, path);
        defer self.alloc.free(tmp);
        std.fs.cwd().deleteFile(tmp) catch {};

        // 1) stream the snapshot section to the temp file, make it durable. Keep
        // `out` open PAST the rename so it installs directly as the new log
        // handle (reopening `path` after the rename and failing would strand the
        // store on the now-unlinked pre-checkpoint inode).
        const out = std.fs.cwd().createFile(tmp, .{ .read = true, .exclusive = true }) catch return error.Io;
        var keep_out = false;
        errdefer if (!keep_out) out.close();
        try writeFileHeader(out);
        // placeholder section header, patched below.
        out.pwriteAll(&[_]u8{0} ** SEC_HDR, FILE_HDR) catch return error.Io;

        var hdr: [SEC_HDR]u8 = undefined;
        var body_size: u64 = undefined;
        {
            var w = SnapshotWriter.init(out, FILE_HDR + @as(u64, SEC_HDR), self.alloc);
            defer w.deinit();
            try self.inner.walSnapshot(&w);
            try w.flush();
            const body_crc = @as(i32, @bitCast(w.crc.final()));
            hdr[0] = TAG_CKPT;
            putI64Be(&hdr, 1, self.next_lsn);
            putI64Be(&hdr, 9, @as(i64, @intCast(w.body_len)));
            putI32Be(&hdr, 17, @as(i32, @bitCast(crc32(hdr[0..SEC_HDR_CRC_LEN]))));
            putI32Be(&hdr, 21, body_crc);
            body_size = w.body_len;
        }
        out.pwriteAll(&hdr, FILE_HDR) catch return error.Io;
        out.sync() catch return error.Io; // snapshot fully durable before it may replace the log
        const size = FILE_HDR + @as(u64, SEC_HDR) + body_size;

        // 2) atomic swap: the rename is the checkpoint's commit point. Install
        // the retained handle and advance in-memory state BEFORE the (fallible)
        // directory fsync, so the store is always consistent with the promoted
        // file even if that final durability step returns an error.
        std.posix.rename(tmp, path) catch return error.Io;
        keep_out = true;
        self.file.close();
        self.file = out;
        self.log_pos = size;
        self.checkpoint_basis = size;
        self.next_lsn += 1; // the snapshot section consumed one LSN
        // The rename is visible but its directory-entry durability is unconfirmed
        // if this fsync fails; POSIX does not guarantee a later file sync makes
        // the rename durable. Poison so no subsequent commit/checkpoint can
        // report false durability until the store is reopened.
        fsyncDir(path) catch |e| {
            self.poisoned = true;
            return e;
        };
    }
};

/// Recover a store directly from a complete `<file>.ckpt` snapshot (crash after
/// the snapshot was fsynced but before the atomic rename). Returns `null` if the
/// temp is absent; `error` if present but not a complete v1 snapshot.
fn tryRecoverFromCkptTemp(alloc: Allocator, path: []const u8, tmp: []const u8, thread_safe: bool, replay_buf: usize) DbError!?WalState {
    if (!pathExists(tmp)) return null;
    var inner = try StoreDirect.init(alloc, thread_safe);
    var inner_ok = false;
    errdefer if (!inner_ok) inner.deinit();

    const tmp_file = std.fs.cwd().openFile(tmp, .{ .mode = .read_write }) catch return error.Io;
    var file_ok = false;
    errdefer if (!file_ok) tmp_file.close();

    const size = (tmp_file.stat() catch return error.Io).size;
    if (!try isV1(tmp_file, size)) return error.DataCorruption; // checkpoint temp is not a v1 WAL snapshot
    if (size < FILE_HDR + @as(u64, SEC_HDR)) return error.DataCorruption; // missing snapshot section
    var hdr: [SEC_HDR]u8 = undefined;
    _ = tmp_file.preadAll(&hdr, FILE_HDR) catch return error.Io;
    const h = parseSecHdr(&hdr);
    const body_start = FILE_HDR + @as(u64, SEC_HDR);
    const hdr_ok = @as(i32, @bitCast(crc32(hdr[0..SEC_HDR_CRC_LEN]))) == h.hdr_crc;
    // LSN must be positive with an available successor; body must exactly fill.
    if (h.tag != TAG_CKPT or
        !hdr_ok or
        h.lsn <= 0 or
        h.lsn == std.math.maxInt(i64) or
        h.body_len < 0 or
        body_start + @as(u64, @intCast(h.body_len)) != size)
        return error.DataCorruption; // checkpoint temp is not a complete snapshot
    if ((bodyCrc(tmp_file, body_start, size, replay_buf, alloc) catch |e| return fatalOnly(e)) != @as(u32, @bitCast(h.body_crc)))
        return error.DataCorruption; // checkpoint temp body CRC mismatch
    {
        var win = try WalIn.init(tmp_file, alloc, replay_buf);
        defer win.deinit();
        applySection(&inner, &win, body_start, size) catch |e| return fatalOnly(e);
    }
    try inner.rebuildFreeRecids();

    // promote temp → log (atomic), then reopen the log.
    tmp_file.close();
    file_ok = true; // tmp_file handle consumed; do not double-close on errdefer
    std.posix.rename(tmp, path) catch return error.Io;
    try fsyncDir(path);
    const file = std.fs.cwd().openFile(path, .{ .mode = .read_write }) catch return error.Io;
    var log_ok = false;
    errdefer if (!log_ok) file.close();
    const log_pos = (file.stat() catch return error.Io).size;
    const next_lsn = std.math.add(i64, h.lsn, 1) catch return error.DataCorruption; // WAL LSN space exhausted
    log_ok = true;
    inner_ok = true;
    return WalState{
        .inner = inner,
        .file = file,
        .next_lsn = next_lsn,
        .checkpoint_basis = size,
        .auto_checkpoint_bytes = DEFAULT_AUTO_CHECKPOINT_BYTES,
        .log_pos = log_pos,
        .replay_buf = replay_buf,
        .alloc = alloc,
    };
}

// ---------------------------------------------------------------- StoreWAL

/// Transactional store. One global writer behind `rw`.
pub const StoreWAL = struct {
    const Self = @This();

    rw: std.Thread.RwLock = .{},
    state: WalState,
    path: []u8,
    lease_table: LeaseTable,
    closed: std.atomic.Value(bool),
    /// Bumped on every `rollback` so open collections know their append-only
    /// structural caches (e.g. the btree left-edge spine) may have been reverted
    /// to a shorter tree and must be rebuilt before the next structural op.
    struct_gen: std.atomic.Value(u64),
    alloc: Allocator,
    /// TCK convenience: `init` created a temp file that `deinit` must remove.
    tmp_owned: bool,

    // ---------- construction ----------

    /// Open (creating if absent) the WAL-backed store at `path` (relative cwd).
    /// Replays any committed sections and recovers a crash-during-checkpoint
    /// temp; a torn tail truncates, mid-log corruption fails `DataCorruption`.
    /// `path` is copied (borrowed). The caller owns the returned store and must
    /// `deinit` it. `thread_safe` selects the segment-lock bank of the inner
    /// StoreDirect (the WAL itself is always single-writer under one RwLock).
    pub fn open(alloc: Allocator, path: []const u8, thread_safe: bool) DbError!Self {
        return openWith(alloc, path, thread_safe, DEFAULT_REPLAY_BUF, false);
    }

    /// `replay_buf` is a test hook: a tiny window forces refill edges in replay.
    pub fn openWith(alloc: Allocator, path: []const u8, thread_safe: bool, replay_buf: usize, tmp_owned: bool) DbError!Self {
        const path_owned = alloc.dupe(u8, path) catch return error.OutOfMemory;
        errdefer alloc.free(path_owned);
        const tmp = try ckptTmp(alloc, path);
        defer alloc.free(tmp);
        const created = !pathExists(path);

        // crash-during-checkpoint recovery: a complete temp snapshot wins.
        if (created and pathExists(tmp)) {
            if (try tryRecoverFromCkptTemp(alloc, path, tmp, thread_safe, replay_buf)) |state| {
                return wrap(alloc, path_owned, state, tmp_owned);
            }
        }

        var inner = try StoreDirect.init(alloc, thread_safe);
        // `inner`/`file` are moved into `state` below; thereafter ONLY `state`'s
        // copies are used or freed (a StoreDirect that has been operated on must
        // never be freed through a stale copy — its Shared/index_pages diverge).
        const file = std.fs.cwd().createFile(path, .{ .read = true, .truncate = false }) catch {
            inner.deinit();
            return error.Io;
        };
        var state = WalState{
            .inner = inner,
            .file = file,
            .next_lsn = 1,
            .checkpoint_basis = 0,
            .auto_checkpoint_bytes = DEFAULT_AUTO_CHECKPOINT_BYTES,
            .log_pos = FILE_HDR,
            .replay_buf = replay_buf,
            .alloc = alloc,
        };
        state.recoverOpenedChannel(created, path) catch |e| {
            state.clearStaged();
            state.staged.deinit(alloc);
            state.inner.deinit();
            state.file.close();
            return e;
        };
        return wrap(alloc, path_owned, state, tmp_owned);
    }

    /// TCK / heap-signature convenience constructor (deviation — see PORT
    /// PROGRESS). Opens a fresh WAL on a uniquely-named temp file in cwd; the
    /// file is removed by `deinit`. `open`/`openWith` are the real constructors.
    pub fn init(alloc: Allocator, thread_safe: bool) DbError!Self {
        const N = struct {
            var counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
        };
        const n = N.counter.fetchAdd(1, .monotonic);
        const pid = std.os.linux.getpid();
        var buf: [128]u8 = undefined;
        const name = std.fmt.bufPrint(&buf, "mapdb5_wal_tck_{d}_{d}.wal", .{ pid, n }) catch return error.OutOfMemory;
        std.fs.cwd().deleteFile(name) catch {};
        var ckbuf: [160]u8 = undefined;
        const ck = std.fmt.bufPrint(&ckbuf, "{s}.ckpt", .{name}) catch return error.OutOfMemory;
        std.fs.cwd().deleteFile(ck) catch {};
        return openWith(alloc, name, thread_safe, DEFAULT_REPLAY_BUF, true);
    }

    fn wrap(alloc: Allocator, path_owned: []u8, state: WalState, tmp_owned: bool) Self {
        return .{
            .state = state,
            .path = path_owned,
            .lease_table = LeaseTable.init(alloc),
            .closed = std.atomic.Value(bool).init(false),
            .struct_gen = std.atomic.Value(u64).init(0),
            .alloc = alloc,
            .tmp_owned = tmp_owned,
        };
    }

    pub fn deinit(self: *Self) void {
        if (!self.closed.load(.acquire)) self.close() catch {};
        self.state.clearStaged();
        self.state.staged.deinit(self.alloc);
        self.state.inner.deinit();
        self.state.file.close();
        self.lease_table.deinit();
        if (self.tmp_owned) {
            std.fs.cwd().deleteFile(self.path) catch {};
            const tmp = ckptTmp(self.alloc, self.path) catch null;
            if (tmp) |t| {
                std.fs.cwd().deleteFile(t) catch {};
                self.alloc.free(t);
            }
        }
        self.alloc.free(self.path);
    }

    // ---------- helpers ----------

    fn checkClosed(self: *Self) DbError!void {
        if (self.closed.load(.acquire)) return error.StoreClosed;
    }

    /// In-lock read gate: recheck `closed` AFTER acquiring the shared lock. A
    /// `close` that completes between the pre-lock fast check and lock
    /// acquisition otherwise lets a staged read return post-close content (the
    /// staged branch never delegates to `inner`, so its result would be
    /// race-dependent). Reads on a *poisoned* store are still permitted.
    fn readGate(self: *Self) DbError!void {
        if (self.closed.load(.acquire)) return error.StoreClosed;
    }

    /// In-lock mutation gate: under the write lock, reject a closed store
    /// (linearized close) OR a poisoned one. A poisoned
    /// WAL's namespace durability is indeterminate, so it must accept no further
    /// staged/inner mutation that could never commit; the error identity matches
    /// what commit/checkpoint already return for a poisoned store (Rust
    /// `DbError::corrupt`). Every mutation path calls this immediately after
    /// acquiring `rw`. `close` is the intentional exception (it must retry the
    /// directory fsync and release resources).
    fn writeGate(self: *Self) DbError!void {
        if (self.closed.load(.acquire)) return error.StoreClosed;
        if (self.state.poisoned) return error.DataCorruption; // WAL poisoned by an earlier durability failure
    }

    /// Test-only: force the poison flag. The durability-failure state is
    /// otherwise reachable only via a directory-fsync failure this environment
    /// cannot inject; the poison-gating test uses this to prove
    /// every mutation path is gated.
    pub fn poisonForTest(self: *Self) void {
        self.rw.lock();
        defer self.rw.unlock();
        self.state.poisoned = true;
    }

    /// Serialize a value with the store's allocator (outside any lock, Java/Rust).
    fn serializeVal(self: *Self, comptime R: type, value: R, ser: anytype) DbError![]u8 {
        var out = DataOutput2.init(self.alloc);
        errdefer out.deinit();
        try ser.serialize(&out, value);
        return out.toOwnedSlice();
    }

    // ---------- Store API ----------

    pub fn preallocate(self: *Self) DbError!u64 {
        mod.assertNotInAction("preallocate");
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        // Reserve the staged-map slot BEFORE allocating the inner recid, so the
        // post-allocation insert is infallible: an OOM here never leaves an
        // orphan P recid in `inner`.
        self.state.staged.ensureUnusedCapacity(self.alloc, 1) catch return error.OutOfMemory;
        const recid = try self.state.inner.preallocate();
        self.state.staged.putAssumeCapacity(recid, Staged{ .created = true });
        return recid;
    }

    pub fn put(self: *Self, comptime R: type, alloc: Allocator, value: R, ser: anytype) DbError!u64 {
        comptime mod.checkSer(R, @TypeOf(ser));
        _ = alloc;
        mod.assertNotInAction("put");
        const bytes = try self.serializeVal(R, value, ser);
        errdefer self.alloc.free(bytes);
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        // Reserve the staged-map slot before allocating the inner recid:
        // the insert below is then infallible and cannot orphan a P recid.
        self.state.staged.ensureUnusedCapacity(self.alloc, 1) catch return error.OutOfMemory;
        const recid = try self.state.inner.preallocate();
        self.state.staged.putAssumeCapacity(recid, Staged{ .created = true, .base_set = true, .base = bytes });
        return recid;
    }

    pub fn get(self: *Self, comptime R: type, alloc: Allocator, recid: u64, ser: anytype) DbError!?R {
        comptime mod.checkSer(R, @TypeOf(ser));
        mod.assertNotInAction("get");
        try self.checkClosed();
        self.rw.lockShared();
        defer self.rw.unlockShared();
        try self.readGate();
        const s = self.state.staged.getPtr(recid) orelse
            return self.state.inner.get(R, alloc, recid, ser);
        if (s.deleted) return error.GetVoid;
        const m = try self.state.merged(recid, s);
        defer if (m) |mm| self.alloc.free(mm);
        const mm = m orelse return null;
        var ag = mod.ActionGuard.enter();
        defer ag.exit();
        var inp = DataInput2.init(mm);
        return try ser.deserialize(alloc, &inp, mm.len);
    }

    pub fn read(self: *Self, recid: u64, action: mod.RecordRead) DbError!i64 {
        mod.assertNotInAction("read");
        try self.checkClosed();
        self.rw.lockShared();
        defer self.rw.unlockShared();
        try self.readGate();
        const s = self.state.staged.getPtr(recid) orelse
            return self.state.inner.read(recid, action);
        if (s.deleted) return error.GetVoid;
        const m = try self.state.merged(recid, s);
        defer if (m) |mm| self.alloc.free(mm);
        // ONE ActionGuard covers BOTH dispatch branches: the staged-null branch
        // dispatched `callOnNull` without a guard, so a reentrant `on_null`
        // action deadlocked on the shared lock instead of tripping the Debug
        // assert.
        var ag = mod.ActionGuard.enter();
        defer ag.exit();
        const mm = m orelse return action.callOnNull();
        var inp = DataInput2.init(mm);
        return action.callOnBytes(&inp, mm.len);
    }

    pub fn update(self: *Self, comptime R: type, alloc: Allocator, recid: u64, value: ?R, ser: anytype) DbError!void {
        _ = alloc;
        return self.updateHeadroomOpt(R, recid, value, ser, 0);
    }

    fn updateHeadroomOpt(self: *Self, comptime R: type, recid: u64, value: ?R, ser: anytype, headroom: usize) DbError!void {
        comptime mod.checkSer(R, @TypeOf(ser));
        mod.assertNotInAction("update");
        try self.checkClosed();
        const bytes: ?[]u8 = if (value) |v| try self.serializeVal(R, v, ser) else null;
        errdefer if (bytes) |b| self.alloc.free(b);
        // Fail fast when a plain-sized content plus its headroom would exceed
        // MAX_CAPACITY, rather than staging it and only failing at commit.
        if (bytes) |b| {
            if (@as(u64, b.len) + 4 <= @as(u64, iv.MAX_CAPACITY)) _ = try plainCap(b.len, headroom);
        }
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        const s = try self.state.stagedForWrite(recid);
        s.clearContent(self.alloc);
        s.base_set = true;
        s.base = bytes;
        s.headroom = headroom;
    }

    pub fn compareAndSwap(self: *Self, comptime R: type, alloc: Allocator, recid: u64, expect: ?R, new: ?R, ser: anytype) DbError!bool {
        comptime mod.checkSer(R, @TypeOf(ser));
        mod.assertNotInAction("compareAndSwap");
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();

        // resolve current logical value.
        var current: ?R = null;
        var have_current = false;
        if (self.state.staged.getPtr(recid)) |s| {
            if (s.deleted) return error.GetVoid;
            const m = try self.state.merged(recid, s);
            defer if (m) |mm| self.alloc.free(mm);
            if (m) |mm| {
                var ag = mod.ActionGuard.enter();
                defer ag.exit();
                var inp = DataInput2.init(mm);
                current = try ser.deserialize(alloc, &inp, mm.len);
                have_current = true;
            }
        } else {
            if ((try self.state.inner.recState(recid)) == STATE_VOID) return error.GetVoid;
            // `inner.get` enters/exits its own ActionGuard and asserts
            // not-in-action at entry, so it MUST run before the guard below.
            current = try self.state.inner.get(R, alloc, recid, ser);
            have_current = current != null;
        }

        // Every remaining serializer callback made while `rw` is held — `equals`,
        // the CAS-side `serialize(new)`, and the `deinitElem` cleanup — runs under
        // ONE ActionGuard, so a reentrant callback trips the Debug assert instead
        // of deadlocking on the global write lock (see
        // the direct.zig:1382 pattern). Serialization stays under the lock. The
        // `deinitElem` defer is registered AFTER entering, so LIFO frees it while
        // the guard is still active.
        var ag = mod.ActionGuard.enter();
        defer ag.exit();
        defer if (have_current) {
            if (current) |c| ser.deinitElem(alloc, c);
        };

        const eq = blk: {
            if (current == null and expect == null) break :blk true;
            if (current != null and expect != null) {
                break :blk ser.equals(current.?, expect.?);
            }
            break :blk false;
        };
        if (!eq) return false;

        const new_bytes: ?[]u8 = if (new) |v| try self.serializeVal(R, v, ser) else null;
        errdefer if (new_bytes) |b| self.alloc.free(b);
        const s = try self.state.stagedForWrite(recid);
        s.clearContent(self.alloc);
        s.base_set = true;
        s.base = new_bytes;
        s.headroom = 0;
        return true;
    }

    pub fn delete(self: *Self, recid: u64) DbError!void {
        mod.assertNotInAction("delete");
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        const s = try self.state.stagedForWrite(recid);
        s.clearContent(self.alloc);
        s.deleted = true;
        s.base_set = false;
    }

    pub fn commit(self: *Self) DbError!void {
        mod.assertNotInAction("commit");
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        return self.state.commitLocked(self.path);
    }

    pub fn checkpoint(self: *Self) DbError!void {
        mod.assertNotInAction("checkpoint");
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        return self.state.checkpointLocked(self.path);
    }

    pub fn compact(self: *Self) DbError!void {
        return self.checkpoint();
    }

    pub fn setAutoCheckpointBytes(self: *Self, bytes: i64) DbError!void {
        self.rw.lock();
        defer self.rw.unlock();
        // A mutating config path: gate on closed AND poisoned under the lock.
        // Previously it checked `closed` only before acquiring.
        try self.writeGate();
        self.state.auto_checkpoint_bytes = bytes;
    }

    pub fn close(self: *Self) DbError!void {
        // Acquire the write lock BEFORE publishing `closed`, so an in-flight
        // commit/checkpoint that rechecks `closed` under the lock observes the
        // close atomically (no append after close).
        self.rw.lock();
        defer self.rw.unlock();
        if (self.closed.swap(true, .acq_rel)) {
            // Already closed — but if the first close's directory-fsync retry
            // failed, the checkpoint rename's durability is STILL unconfirmed
            // (`poisoned` stays set). Re-enter and retry the fsync (mirrors
            // StoreDirect close re-entering while poisoned).
            if (!self.state.poisoned) return;
            fsyncDir(self.path) catch |e| return e;
            self.state.poisoned = false;
            return;
        }
        // If a prior checkpoint left the rename's directory durability
        // unconfirmed (poisoned), retry the directory fsync now.
        var poison_err: ?DbError = null;
        if (self.state.poisoned) {
            if (fsyncDir(self.path)) {
                self.state.poisoned = false;
            } else |e| {
                poison_err = e;
            }
        }
        // Always release resources, then surface the durability error (if any).
        const sync_res = self.state.file.sync();
        const inner_res = self.state.inner.close();
        if (poison_err) |e| return e;
        sync_res catch return error.Io;
        try inner_res;
    }

    pub fn isClosed(self: *Self) bool {
        return self.closed.load(.acquire);
    }

    pub fn verify(self: *Self) DbError!void {
        try self.checkClosed();
        self.rw.lockShared();
        defer self.rw.unlockShared();
        try self.readGate();
        return self.state.inner.verify();
    }

    pub fn getAllRecids(self: *Self, alloc: Allocator) DbError![]u64 {
        try self.checkClosed();
        self.rw.lockShared();
        defer self.rw.unlockShared();
        try self.readGate();

        var set: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer set.deinit(alloc);
        {
            const inner_ids = try self.state.inner.getAllRecids(alloc);
            defer alloc.free(inner_ids);
            for (inner_ids) |r| set.put(alloc, r, {}) catch return error.OutOfMemory;
        }
        {
            var it = self.state.staged.iterator();
            while (it.next()) |kv| {
                const recid = kv.key_ptr.*;
                const s = kv.value_ptr;
                if (s.deleted) {
                    _ = set.remove(recid);
                } else if (s.base_set or s.appends.items.len != 0) {
                    set.put(alloc, recid, {}) catch return error.OutOfMemory;
                } else {
                    _ = set.remove(recid); // pure prealloc
                }
            }
        }
        var out: std.ArrayListUnmanaged(u64) = .empty;
        errdefer out.deinit(alloc);
        out.ensureTotalCapacity(alloc, set.count()) catch return error.OutOfMemory;
        var kit = set.keyIterator();
        while (kit.next()) |k| out.appendAssumeCapacity(k.*);
        std.mem.sort(u64, out.items, {}, std.sort.asc(u64));
        return out.toOwnedSlice(alloc) catch return error.OutOfMemory;
    }

    pub fn getCurrentSize(self: *Self) u64 {
        self.rw.lockShared();
        defer self.rw.unlockShared();
        return self.state.inner.getCurrentSize();
    }

    pub fn isThreadSafe(self: *Self) bool {
        return self.state.inner.isThreadSafe();
    }

    pub fn isTx(_: *Self) bool {
        return true;
    }

    /// lease registry accessor (the StoreLease capability).
    pub fn leaseTable(self: *Self) *LeaseTable {
        return &self.lease_table;
    }

    pub fn structuralGeneration(self: *Self) u64 {
        return self.struct_gen.load(.acquire);
    }

    // ---------- StoreDelta ----------

    pub fn append(self: *Self, recid: u64, data: []const u8) DbError!AppendResult {
        mod.assertNotInAction("append");
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        // establishes GetVoid on deleted/void recids.
        _ = try self.state.stagedForWrite(recid);
        const base_live = blk: {
            const s = self.state.staged.getPtr(recid).?;
            break :blk !s.base_set and (try self.state.inner.recState(recid)) == STATE_LIVE;
        };
        if (base_live) {
            const cap_rem = try self.state.inner.capacityRemaining(recid);
            const appends_len = self.state.staged.getPtr(recid).?.appends_len;
            if (appends_len + data.len > cap_rem) return .refused;
        }
        const base_len: usize = blk: {
            if (base_live) {
                if (try self.state.inner.rawGet(self.alloc, recid)) |b| {
                    defer self.alloc.free(b);
                    break :blk b.len;
                }
                break :blk 0;
            }
            const s = self.state.staged.getPtr(recid).?;
            break :blk if (s.base) |b| b.len else 0;
        };
        const copy = self.alloc.dupe(u8, data) catch return error.OutOfMemory;
        errdefer self.alloc.free(copy);
        const s = self.state.staged.getPtr(recid).?;
        s.appends.append(self.alloc, copy) catch return error.OutOfMemory;
        s.appends_len += data.len;
        return .{ .new_size = base_len + s.appends_len };
    }

    pub fn capacityRemaining(self: *Self, recid: u64) DbError!usize {
        try self.checkClosed();
        self.rw.lockShared();
        defer self.rw.unlockShared();
        try self.readGate();
        const s = self.state.staged.getPtr(recid) orelse
            return self.state.inner.capacityRemaining(recid);
        if (s.deleted) return error.GetVoid;
        if (s.base_set) return std.math.maxInt(usize); // capacity established at commit
        if ((try self.state.inner.recState(recid)) == STATE_LIVE)
            return (try self.state.inner.capacityRemaining(recid)) -| s.appends_len;
        return std.math.maxInt(usize);
    }

    pub fn updateWithHeadroom(self: *Self, comptime R: type, alloc: Allocator, recid: u64, value: R, ser: anytype, headroom: usize) DbError!void {
        _ = alloc;
        return self.updateHeadroomOpt(R, recid, @as(?R, value), ser, headroom);
    }

    // ---------- StoreTx ----------

    pub fn rollback(self: *Self) DbError!void {
        mod.assertNotInAction("rollback");
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        var created: std.ArrayListUnmanaged(u64) = .empty;
        defer created.deinit(self.alloc);
        {
            var it = self.state.staged.iterator();
            while (it.next()) |kv| {
                if (kv.value_ptr.created) created.append(self.alloc, kv.key_ptr.*) catch return error.OutOfMemory;
            }
        }
        for (created.items) |recid| try self.state.inner.delete(recid); // free the P recid
        self.state.clearStaged();
        // Signal open collections their append-only structural caches may now
        // describe a taller-than-real tree (a reverted uncommitted grow).
        _ = self.struct_gen.fetchAdd(1, .release);
    }
};

test {
    std.testing.refAllDecls(@This());
}
