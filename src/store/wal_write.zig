//! The **section writer** — the only place a v3 section reaches the device.
//!
//! Port of `mapdb-rust-store/src/store/wal_write.rs` (slice A2), which is itself
//! Java `StoreWAL.appendSection` / `BodySink` / `rollover`. `wal_segments.zig`
//! owns which FILES exist, `wal_recover.zig` owns how bytes are read back, and
//! this module owns how they get written:
//!
//! - **W1/W4** — a section's force completes before [`appendSection`] returns, so
//!   no section is appended before its predecessor's force finished. Recovery's
//!   mid-log-rot inference ("a valid section follows an invalid one ⇒
//!   corruption") is sound ONLY under that.
//! - **W3** — rollover happens only at a section boundary, after the sealed
//!   segment's last section is forced with a SIZE-persisting force, so a
//!   non-final segment ends exactly at a section boundary with zero trailing
//!   bytes.
//! - **W9** — a failed or partial write/force fails the store CLOSED. Every error
//!   out of [`appendSection`] is that failure; the caller must not let a retry
//!   append into a segment that may hold partial bytes.
//!
//! The durability-event seam the W table is stated over lives in
//! [`wal_io`](wal_io.zig) — rust declares it here, but the zig port needed it a
//! slice earlier (B0), and that file-layout deviation is explained there.
//!
//! # Two passes, never one buffer
//!
//! The body is emitted TWICE — a measure pass (length + CRC, no I/O) and a write
//! pass — instead of being accumulated into a list. That is what lets one commit
//! exceed 2 GiB: `bodyLen` is an `i64` in the format, and nothing here buffers or
//! narrows the body — though the >2 GiB proof itself is a stress-tier test, as it
//! is in Java, not anything the unit suite runs.
//! The header is still written FIRST and final, so the crash shapes are
//! the ones recovery classifies (a tear mid-body leaves a valid header over a
//! short or CRC-bad body — S3/S4/S5), and the pass-divergence check runs BEFORE
//! the force, so a nondeterministic emitter fails the commit closed rather than
//! acknowledging a section that replay rejects as bit rot.
//!
//! # What zig does not need
//!
//! Rust carries an `IoGuard` whose `Drop` marks the store closed if the writer
//! leaves through a PANIC after I/O began — its stand-in for Java's `Error` arm,
//! which cannot be turned into a return value without `catch_unwind`. Zig has no
//! unwinding, so there is no such path: every failure here is an error return, and
//! the obligation those returns carry is that the caller fail the store closed on
//! all of them. Until B2 part 2 writes that caller (`commitLocked`), the
//! obligation is stated here, not yet discharged anywhere — part 2 must implement
//! and mutation-test it. Only the mechanism rust needed is absent.

const std = @import("std");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;

const segments = @import("wal_segments.zig");
const WalSegmentSet = segments.WalSegmentSet;
const Segment = segments.Segment;
const SEG_HDR = segments.SEG_HDR;
const crcDomainOf = segments.crcDomainOf;

const wal_io = @import("wal_io.zig");
const WalIo = wal_io.WalIo;
const WalOpKind = wal_io.WalOpKind;
const walIoEvent = wal_io.walIoEvent;
const walIoPwrite = wal_io.walIoPwrite;

const wr = @import("wal_recover.zig");
const sealSecHdr = wr.sealSecHdr;
const SEC_HDR = wr.SEC_HDR;

const Crc32 = std.hash.crc.Crc32;

/// Java's `BodySink` buffer, byte for byte: entry framing (tens of bytes per
/// entry) is coalesced through it so a large commit is not syscall-bound, while a
/// payload at or past this size bypasses it and is written where it lies.
const SINK_BUF: usize = 64 << 10;

// --------------------------------------------------------------- the body sink

/// One pass over a section body. The measure pass (`file == null`) accumulates
/// length and CRC only; the write pass also writes the bytes at increasing
/// offsets. Offsets and the running length are `u64`: a body may exceed 2 GiB and
/// no whole-body allocation exists in either pass.
pub const BodySink = struct {
    file: ?std.fs.File = null,
    crc: Crc32,
    pos: u64 = 0,
    count: u64 = 0,
    /// The write pass's coalescing buffer; empty in the measure pass, which never
    /// buffers because it never writes.
    buf: []u8 = &.{},
    used: usize = 0,
    /// The seam the write pass's raw writes route through (a test can inject
    /// a genuine PARTIAL write); null in the measure pass, which never writes.
    io: ?*const WalIo = null,

    fn measure(crc: Crc32) BodySink {
        return .{ .crc = crc };
    }

    fn writer(file: std.fs.File, body_start: u64, crc: Crc32, buf: []u8, io: ?*const WalIo) BodySink {
        return .{ .file = file, .crc = crc, .pos = body_start, .buf = buf, .io = io };
    }

    /// Emits `b` into this pass. The CRC and the length advance in BOTH passes;
    /// only the write pass touches the device.
    pub fn write(self: *BodySink, b: []const u8) DbError!void {
        self.crc.update(b);
        self.count += b.len;
        const file = self.file orelse return;
        if (b.len >= SINK_BUF) {
            try self.flush();
            try walIoPwrite(self.io, file, b, self.pos);
            self.pos += b.len;
            return;
        }
        if (self.used + b.len > SINK_BUF) try self.flush();
        @memcpy(self.buf[self.used .. self.used + b.len], b);
        self.used += b.len;
    }

    fn flush(self: *BodySink) DbError!void {
        if (self.used == 0) return;
        const file = self.file orelse unreachable; // the measure pass never buffers
        try walIoPwrite(self.io, file, self.buf[0..self.used], self.pos);
        self.pos += self.used;
        self.used = 0;
    }
};

// -------------------------------------------------------------- the two forces

/// The data-only force (W1/W4) as ONE operation: no caller can report the event
/// without performing the sync, or reorder one around the other. That the sync
/// really is `fdatasync` — not a no-op, not the wrong flavour — is pinned by the
/// gate's strace probe (`wal_sync_probe.zig`), which counts the actual syscalls;
/// the seam trace alone is declared intent, not evidence.
fn forceData(io: ?*const WalIo, file: std.fs.File, seq: i64, end: u64, tag: u8) DbError!void {
    try walIoEvent(io, WalOpKind.force_data, seq, end, 0, tag);
    std.posix.fdatasync(file.handle) catch return error.Io;
}

/// The sealing force (W3) — force(true), never a data-only sync: the sealed
/// segment's SIZE is the payload (D5). One operation, like [forceData], and
/// pinned by the same probe. Public because the cleaner's episode roll (B3,
/// `wal.zig`) seals the active segment through exactly this function — a second
/// spelling of "event + fsync" would reintroduce the drift the one-function
/// rule exists to prevent.
pub fn forceFull(io: ?*const WalIo, file: std.fs.File, seq: i64, len: u64) DbError!void {
    try walIoEvent(io, WalOpKind.force_full, seq, len, 0, 0);
    std.posix.fsync(file.handle) catch return error.Io;
}

// ------------------------------------------------------------ append a section

/// Appends one complete section to the active segment and forces it, rolling over
/// first when the segment is full.
///
/// `emit` runs TWICE and **must produce the same length and CRC both times** —
/// the check is length plus CRC, exactly Java's, so a CRC-colliding divergence is
/// accepted identically to the reference. A divergence either half can see
/// refuses to acknowledge the section (before the force) rather than leave a
/// stored `bodyCrc` that replay reads as bit rot.
///
/// Every error return is a W9 failure: the caller closes the store. On success the
/// active segment's `file_len` and `valid_end` have moved to the section's end,
/// and `set.logBytes()` accounts for it.
pub fn appendSection(
    set: *WalSegmentSet,
    segment_bytes: u64,
    io: ?*const WalIo,
    tag: u8,
    lsn: i64,
    alloc: Allocator,
    ctx: anytype,
    comptime emit: fn (@TypeOf(ctx), *BodySink) DbError!void,
) DbError!void {
    // W3: the rollover condition is checked ONLY here, at a section boundary, and
    // only when the active segment is nonempty — so one section may exceed
    // `segment_bytes` and an oversize section gets a segment to itself, rather
    // than a segment being sealed with nothing in it.
    const roll = roll: {
        const a = try activeOf(set);
        break :roll a.file_len >= segment_bytes and !a.empty();
    };
    if (roll) {
        {
            const a = set.active().?;
            try a.ensureOpen();
            // The seal takes the FULL force: W3's whole load collapses if a
            // port's data sync loses a sealed segment's tail extent, because
            // recovery would then see a torn NON-FINAL segment and refuse a
            // legitimate image.
            try forceFull(io, a.handle().?, a.seq, a.file_len);
            // The sealed segment will never be read or written again by this store
            // (nothing reads a segment after recovery). Releasing here is the same
            // recorded divergence as W7's: the reference keeps the stale handle,
            // and copying it would put an O(segments) descriptor leak in every
            // engine.
            a.release();
        }
        // `a` is DEAD from here: `createSegment` may reallocate the segment list.
        _ = try set.createSegment(lsn);
    }

    const seg_header, const off, const seq = h: {
        const a = try activeOf(set);
        break :h .{ a.header, a.file_len, a.seq };
    };

    // ---- pass 1: measure. No I/O, and no allocation proportional to the body.
    var bcrc = Crc32.init();
    crcDomainOf(&bcrc, &seg_header, off);
    var measure = BodySink.measure(bcrc);
    try emit(ctx, &measure);
    const body_len = measure.count;
    const body_crc = @as(i32, @bitCast(measure.crc.final()));
    const hdr = sealSecHdr(&seg_header, off, tag, lsn, body_len, body_crc);

    const active = set.active().?;
    try active.ensureOpen();
    const file = active.handle().?;

    try walIoEvent(io, WalOpKind.sec_header, seq, off, SEC_HDR, tag);
    try walIoPwrite(io, file, &hdr, off);
    const body_start = off + SEC_HDR;
    try walIoEvent(io, WalOpKind.sec_body, seq, body_start, body_len, tag);

    // ---- pass 2: write. Must reproduce pass 1's bytes exactly.
    const buf = alloc.alloc(u8, SINK_BUF) catch return error.OutOfMemory;
    defer alloc.free(buf);
    var wcrc = Crc32.init();
    crcDomainOf(&wcrc, &seg_header, off);
    var w = BodySink.writer(file, body_start, wcrc, buf, io);
    try emit(ctx, &w);
    try w.flush();
    if (w.count != body_len or @as(i32, @bitCast(w.crc.final())) != body_crc) {
        // Refused BEFORE the force, so nothing acknowledges a section whose stored
        // `bodyCrc` describes bytes other than the ones on the device.
        return error.DataCorruption; // section body diverged between the CRC pass and the write pass
    }

    // force(false) — a DATA sync. This relies on the POSIX guarantee that
    // fdatasync persists "the metadata required to retrieve the data", which for
    // an append means the new file size. Where the SIZE itself is the payload —
    // creating a segment (W2), sealing one at rollover (W3), the post-truncate
    // force (W7) — a full sync is used instead, and the distinction is spec.
    const end = body_start + body_len;
    try forceData(io, file, seq, end, tag);

    active.file_len = end;
    active.valid_end = end;
}

/// The active segment, or the one error this module cannot recover from: a
/// writable store always has one after recovery (R7 creates it), so its absence is
/// a sequencing bug in the caller rather than anything about the store.
fn activeOf(set: *WalSegmentSet) DbError!*Segment {
    return set.active() orelse error.WrongConfiguration;
}
