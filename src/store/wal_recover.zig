//! The WAL's **v3 codec and recovery state machine** — sections, entries, the
//! `'K'` clean mark, and the two-pass replay (R3-R7) that turns a segment set
//! into an in-memory store.
//!
//! Port of the recovery half of Java `StoreWAL` (format v3) by way of
//! `mapdb-rust-store/src/store/wal_recover.rs` (slice A1); the namespace half
//! (N/H/W2/W5/W6, the store lock) is [`wal_segments`](wal_segments.zig) and ran
//! already — R0-R2 happen inside `WalSegmentSet.open`. This module is everything
//! after that.
//!
//! ```text
//! section := tag u8 ('S' commit | 'C' image | 'K' clean mark)
//!          | lsn i64 | bodyLen i64 | hdrCrc i32 | bodyCrc i32      // 25 bytes
//!          | body
//! mark    := cleanedThroughSeq i64 | logStartLsn i64               // 16 bytes
//! entry   := T_PREALLOC recid
//!          | T_RECORD   recid cap len+1|0 payload?
//!          | T_APPEND   recid (lsn - baseLsn) len payload
//!          | T_DELETE   recid                       // packLong framing
//! ```
//!
//! Both CRCs are **domain-bound**: each is an ordinary CRC-32 fed the segment's
//! 36 header bytes and the section's own offset as a prefix
//! (`Segment.crcDomain`). A section byte-copied to another segment, or to another
//! offset in its own, therefore fails its checksums — the property that lets the
//! torn-tail lookahead below trust what it finds.
//!
//! # The shape of recovery, and why it is two passes
//!
//! Pass 1 ([`scanSegment`]) establishes **boundaries only**: how far each
//! segment's valid section prefix runs, its LSN span, and whether anything in it
//! is corrupt — with no per-recid state whatsoever. Pass 2 ([`applySection`])
//! replays entries in ascending LSN order and is the sole authority on content.
//! A verdict found in pass 1 is **held**, not thrown: the segment carrying it may
//! be below a clean mark and about to be deleted, and refusing to open a store
//! over rot in bytes nobody will ever read is how a recoverable store gets
//! bricked. R4 decides which held verdicts matter.
//!
//! The three questions recovery must answer — where does the retained log
//! legitimately begin, is each missing segment authorized, and does each delta
//! still have the image it extends — are all answered by comparing **numbers a
//! conforming writer recorded** (`firstLsn` in every segment header,
//! `logStartLsn` in every mark, the base LSN in every `T_APPEND`) rather than by
//! inferring intent from LSN density or section tags. That is the whole reason v3
//! exists.
//!
//! # Arithmetic, and why it is spelled out
//!
//! Every LSN here is a number read off a disk that may hold anything, and Java's
//! `long` arithmetic wraps where Zig's safe build panics. A panic is not a
//! verdict: it downs the process where the reference merely answers "no proof
//! follows" or "this image is corrupt". So the wrapping sites are written with
//! `+%` / `-%` explicitly — the lookahead's `+1`/`+2`, S9's `+1`, R4's chain `+1`,
//! and `T_APPEND`'s base delta — and every framing bound is proved by
//! SUBTRACTION from the known file length before a sum is formed. R7's `+1` is
//! the one deliberate exception: it is CHECKED, because LSN exhaustion is the
//! adopted per-engine divergence (design §4 D6 / §7 Q8), and `StoreFull` says
//! what is true — nothing on disk is damaged, the LSN space is used up.
//!
//! **Allocation failure is operational, never a verdict** (design §6 risk 14).
//! `error.OutOfMemory` propagates and the caller runs its ordinary failed-open
//! cleanup; it is never HELD, never classified as a torn tail, and never allowed
//! to continue recovery. Java has no ruling to copy here — its constructor
//! catches `IOException` and `RuntimeException`, not `OutOfMemoryError` — so this
//! is a port policy, made once and written down.
//!
//! # Diagnostics
//!
//! Rust formats offsets, segment names and recids into its corruption messages,
//! and its tests assert on substrings of them. `DbError` carries no payload, so
//! this port uses a typed side channel instead: a **static** reason string plus
//! the numbers it is about, in [`Diag`], written immediately before the refusal it
//! explains. No allocation on a failure path, nothing load-bearing for control
//! flow — and, unlike a substring match, an assertion on `diag.reason` compares
//! against the named constant itself, so a test cannot pass because two different
//! rules happen to share a word.
//!
//! Pass 1's verdicts land on `Segment.held` / `Segment.held_at` first, because
//! they are HELD rather than raised; R4 promotes the one that actually refuses.
//!
//! # What is NOT here
//!
//! The section WRITER and the cleaning cycle that emits `'K'` arrive with B2 and
//! B3; this module reads. Like B0 it is **unhooked** — no public open reaches it
//! until B2's cutover, so no hybrid can exist on disk.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const iv = @import("index_val.zig");
const tainted = @import("../tainted.zig");
const direct = @import("direct.zig");
const StoreDirect = direct.StoreDirect;
const STATE_LIVE = direct.STATE_LIVE;
const mod = @import("mod.zig");
const AppendResult = mod.AppendResult;
const wal_io = @import("wal_io.zig");
const WalOpKind = wal_io.WalOpKind;
const walIoEvent = wal_io.walIoEvent;
const segments = @import("wal_segments.zig");
const Segment = segments.Segment;
const WalSegmentSet = segments.WalSegmentSet;
const SEG_HDR = segments.SEG_HDR;
const crcDomainOf = segments.crcDomainOf;

const Crc32 = std.hash.crc.Crc32;

/// tag(1) + lsn(8) + bodyLen(8) + hdrCrc(4) + bodyCrc(4).
pub const SEC_HDR: u64 = 25;
/// Bytes of the section header covered by `hdrCrc` — everything before the two
/// checksums.
pub const SEC_HDR_CRC_LEN: usize = 17;

/// A committed transaction.
pub const TAG_SECTION: u8 = 'S';
/// A cleaner-written image: semantically identical to `'S'`, and deliberately so
/// — the retained `'C'` sections are collectively the checkpoint, so there is no
/// "newest image wins" rule to implement.
pub const TAG_IMAGE: u8 = 'C';
/// A clean mark. Carries no entries and is never handed to the entry decoder.
pub const TAG_MARK: u8 = 'K';
/// `cleanedThroughSeq i64 | logStartLsn i64`, fixed width — a mark is a fact, not
/// a record, so it is not packLong-framed.
pub const MARK_BODY_LEN: i64 = 16;

const T_PREALLOC: u8 = 1;
const T_RECORD: u8 = 2;
const T_APPEND: u8 = 3;
const T_DELETE: u8 = 4;

/// `'S'`, `'C'` and `'K'` — **all three**, in the main scan and in the lookahead
/// alike.
///
/// Transcribing v1's two-tag set here is the single easiest way to port this
/// format wrongly: a `'K'` sitting after a rotted section would not be recognised
/// as a valid section, the lookahead would report "nothing valid follows", and
/// deliberate mid-log rot would be silently truncated away as a torn tail.
fn validTag(tag: u8) bool {
    return tag == TAG_SECTION or tag == TAG_IMAGE or tag == TAG_MARK;
}

inline fn getI32Be(b: []const u8, off: usize) i32 {
    return std.mem.readInt(i32, b[off..][0..4], .big);
}

inline fn getI64Be(b: []const u8, off: usize) i64 {
    return std.mem.readInt(i64, b[off..][0..8], .big);
}

inline fn putI32Be(b: []u8, off: usize, v: i32) void {
    std.mem.writeInt(i32, b[off..][0..4], v, .big);
}

inline fn putI64Be(b: []u8, off: usize, v: i64) void {
    std.mem.writeInt(i64, b[off..][0..8], v, .big);
}

/// `Crc32.final()` is a `u32`; every stored checksum on disk is an `i32`, exactly
/// as Java writes it. Same bits, and the comparison must happen in one domain.
inline fn asI32(v: u32) i32 {
    return @bitCast(v);
}

/// Why the last refusal happened. Written immediately before the `error` return
/// it explains and never read for control flow.
///
/// The caller owns one and passes it in, and [`recover`] CLEARS it on entry — so
/// the reason always describes the recovery that just failed, never an earlier
/// one. Without that, a caller reusing a `Diag` reads a stale explanation for a
/// fresh refusal, which is worse than no explanation at all.
pub const Diag = struct {
    /// One of the `R_*` constants below, or `""` when nothing has refused yet.
    reason: []const u8 = "",
    /// Segment sequence number the refusal is about, or 0.
    seq: i64 = 0,
    /// Byte offset within that segment, or 0.
    at: u64 = 0,
    /// Record id, or 0.
    recid: u64 = 0,
    /// A number the reason needs and the other fields do not name — the count of
    /// stranded appends, the offending delta, the offending capacity.
    detail: i64 = 0,

    /// Last writer wins, deliberately: a note immediately precedes its own
    /// `return error`, so there is never a second one to lose.
    pub fn note(self: *Diag, reason: []const u8, seq: i64, at: u64, recid: u64, detail: i64) void {
        self.* = .{ .reason = reason, .seq = seq, .at = at, .recid = recid, .detail = detail };
    }

    fn plain(self: *Diag, reason: []const u8) void {
        self.note(reason, 0, 0, 0, 0);
    }
};

// R4's refusals.
pub const R_RETIRES_ALL = "clean mark retires the whole segment set";
pub const R_HELD = "held verdict in a retained segment";
pub const R_FLOOR = "the retained log does not begin where the mark attests: sections below it are gone";
pub const R_CHAIN = "segment does not begin where its predecessor ended: sections between them are gone";
pub const R_SELF = "segment's first section is not the LSN its header states: its leading sections are gone";
// R6's refusals.
pub const R_PASS_DRIFT = "segment changed between recovery passes";
pub const R_ENTRY_OVERRUN = "entry overran its section body";
pub const R_PACKLONG = "packed long too long";
pub const R_PREALLOC_LIVE = "PREALLOC over a content-live record";
pub const R_RECORD_LEN = "bad record length";
pub const R_RECORD_CAP = "bad record capacity";
pub const R_APPEND_LEN = "bad append length";
pub const R_APPEND_DELTA = "bad append base delta";
pub const R_APPEND_BASE_HIGH = "append cites a base above the applied one: sections are missing";
pub const R_APPEND_REFUSED = "the inner store refused a logged append";
pub const R_ENTRY_TAG = "bad entry tag";
pub const R_RECID_ZERO = "entry references the reserved recid 0";
pub const R_RECID_TWICE = "two entries for one recid in one section";
/// The inner store's own verdict, raised while replay applied an entry. See
/// [`innerFault`].
pub const R_INNER_STORE = "the inner store rejected an entry replay applied to it";
/// The skip audit.
pub const R_AUDIT = "replay skipped append(s) whose base image is absent and which no later entry superseded";

pub const SecHdr = struct {
    tag: u8,
    lsn: i64,
    body_len: i64,
    hdr_crc: i32,
    body_crc: i32,
};

pub fn parseSecHdr(hdr: *const [@as(usize, SEC_HDR)]u8) SecHdr {
    return .{
        .tag = hdr[0],
        .lsn = getI64Be(hdr, 1),
        .body_len = getI64Be(hdr, 9),
        .hdr_crc = getI32Be(hdr, 17),
        .body_crc = getI32Be(hdr, 21),
    };
}

/// The 25 header bytes for a section whose body has already been MEASURED — a
/// length and a body CRC, not the bytes themselves.
///
/// This is the shape B2's streaming writer needs: its pass 1 produces exactly
/// these two numbers and never materializes the body, so a signature taking a
/// `[]const u8` cannot serve it. Split out here rather than duplicated there, so
/// the port keeps ONE encoding of a section header — both A1 reviews found the
/// un-split version in Rust and named the same failure mode, a writer and a test
/// kit that drift into two.
pub fn sealSecHdr(
    seg_header: *const [@as(usize, SEG_HDR)]u8,
    offset: u64,
    tag: u8,
    lsn: i64,
    body_len: u64,
    body_crc: i32,
) [@as(usize, SEC_HDR)]u8 {
    var hdr: [@as(usize, SEC_HDR)]u8 = undefined;
    hdr[0] = tag;
    putI64Be(&hdr, 1, lsn);
    putI64Be(&hdr, 9, @bitCast(body_len));
    var h = Crc32.init();
    crcDomainOf(&h, seg_header, offset);
    h.update(hdr[0..SEC_HDR_CRC_LEN]);
    putI32Be(&hdr, 17, asI32(h.final()));
    putI32Be(&hdr, 21, body_crc);
    return hdr;
}

/// [`sealSecHdr`] for a caller that HOLDS the body: the byte-level test kit. The
/// production writer never materializes a body, so it always seals from a
/// measured length and CRC instead.
pub fn buildSecHdr(
    seg_header: *const [@as(usize, SEG_HDR)]u8,
    offset: u64,
    tag: u8,
    lsn: i64,
    body: []const u8,
) [@as(usize, SEC_HDR)]u8 {
    var b = Crc32.init();
    crcDomainOf(&b, seg_header, offset);
    b.update(body);
    return sealSecHdr(seg_header, offset, tag, lsn, body.len, asI32(b.final()));
}

/// The 16-byte `'K'` body. Written by the cleaner (B3) and by the test kit.
pub fn buildMarkBody(cleaned_through_seq: i64, log_start_lsn: i64) [16]u8 {
    var b: [16]u8 = undefined;
    putI64Be(&b, 0, cleaned_through_seq);
    putI64Be(&b, 8, log_start_lsn);
    return b;
}

/// CRC-32 of a section header in its domain — compare against `hdrCrc`.
fn hdrCrc(seg: *const Segment, offset: u64, hdr: *const [@as(usize, SEC_HDR)]u8) i32 {
    var h = Crc32.init();
    seg.crcDomain(&h, offset);
    h.update(hdr[0..SEC_HDR_CRC_LEN]);
    return asI32(h.final());
}

/// The segment's file handle. Every read helper here needs one, and every caller
/// opens it once per pass before entering them.
///
/// Panics rather than returning an error, deliberately: a released handle is a
/// sequencing bug in THIS module, and the shape it used to have in Rust —
/// `DataCorruption("segment handle released mid-pass")` — told the user their
/// store was damaged when the port had merely mis-ordered its own
/// `ensureOpen`/`release` calls. B2 grows considerably more of that choreography,
/// so the lie would get easier to trigger, not harder.
fn handle(seg: *const Segment) std.fs.File {
    return seg.handle() orelse
        @panic("WAL segment handle released mid-pass: caller must ensureOpen");
}

/// `false` when the file is shorter than the read demands — the segment shrank
/// under us, which recovery treats exactly as a torn tail.
fn readAtOpt(file: std.fs.File, buf: []u8, pos: u64) DbError!bool {
    const n = file.preadAll(buf, pos) catch return error.Io;
    return n == buf.len;
}

fn readSecHdr(seg: *const Segment, pos: u64) DbError!?[@as(usize, SEC_HDR)]u8 {
    var hdr: [@as(usize, SEC_HDR)]u8 = undefined;
    if (!try readAtOpt(handle(seg), &hdr, pos)) return null;
    return hdr;
}

/// CRC-32 over a section body in its domain, streamed through a bounded window so
/// a body larger than memory still verifies. `null` means the file was short.
fn bodyCrc(
    seg: *const Segment,
    section_offset: u64,
    start: u64,
    end: u64,
    replay_buf: usize,
    alloc: Allocator,
) DbError!?i32 {
    const file = handle(seg);
    var crc = Crc32.init();
    seg.crcDomain(&crc, section_offset);
    if (start < end) {
        // The minimum is taken in the WIDE type and only the bounded result is
        // narrowed. This port is 64-bit only (`tainted.zig` asserts it), so the
        // 32-bit defect Rust shipped and fixed here — a 4 GiB body casting to a
        // `usize` 0, sizing the buffer at zero and looping forever — cannot occur;
        // the ordering is kept anyway because it is the rule Appendix A states and
        // the one a reader checks for.
        const cap: usize = try tainted.u64ToUsize(@min(end - start, @as(u64, @max(replay_buf, 16))));
        const buf = alloc.alloc(u8, cap) catch return error.OutOfMemory;
        defer alloc.free(buf);
        var p = start;
        while (p < end) {
            const n: usize = try tainted.u64ToUsize(@min(end - p, @as(u64, buf.len)));
            if (!try readAtOpt(file, buf[0..n], p)) return null;
            crc.update(buf[0..n]);
            p += n;
        }
    }
    return asI32(crc.final());
}

// ---------- streaming entry decoder ----------

/// A fixed-size window over one section body, with `u64` file positions.
///
/// Never materializes a body, so a commit larger than memory replays: Java streams
/// both writing and reading for exactly this reason, and a port that reads whole
/// bodies regresses every large transaction into an allocation of its full size.
///
/// It folds no CRC into its reads, and does not need to: a v3 section's CRCs are
/// verified in pass 1, before a single entry is decoded ("garbage never
/// allocates"). The v1 reader this replaces computes one incrementally, because
/// its legacy trailing-seal format could only be checked at the end.
pub const SecIn = struct {
    file: std.fs.File,
    alloc: Allocator,
    /// SOFT end: the section being decoded. Reading past it is corruption.
    limit: u64 = 0,
    /// HARD end: how far the window may read AHEAD of the soft limit. Equal to the
    /// soft limit for replay, which decodes one section at a time; B3's cleaner
    /// scan sets it to the segment's validated end so one window can span a
    /// section boundary.
    ///
    /// That split is what makes the scan cost one syscall per WINDOW instead of
    /// per section. Java measured the difference: a log written by single-op
    /// commits is nearly all section headers, and reading each one with its own
    /// positional read (plus the window drop that followed) issued ~148k reads to
    /// walk 34 MB.
    hard_limit: u64 = 0,
    win: []u8,
    win_start: u64 = 0,
    win_pos: usize = 0,
    win_len: usize = 0,
    /// Reads issued. Never reset; a caller takes a difference. Kept
    /// unconditionally rather than behind a test-only switch, for the reason B0's
    /// durability counters are: a conditional field makes the struct layout differ
    /// between the tested and the shipped build.
    reads: u64 = 0,
    /// Where the two corruption verdicts this reader can raise on its own — an
    /// entry overrunning its body, and an over-long packed long — record
    /// themselves. Borrowed from the caller.
    diag: *Diag,

    pub fn init(file: std.fs.File, alloc: Allocator, bufsize: usize, diag: *Diag) DbError!SecIn {
        const win = alloc.alloc(u8, @max(bufsize, 16)) catch return error.OutOfMemory;
        return .{ .file = file, .alloc = alloc, .win = win, .diag = diag };
    }

    pub fn deinit(self: *SecIn) void {
        self.alloc.free(self.win);
        self.win = &.{};
    }

    /// Positions the reader over `[start, end)` and DROPS the window. Both bounds
    /// become `end`.
    pub fn reset(self: *SecIn, start: u64, end: u64) void {
        self.win_start = start;
        self.limit = end;
        self.hard_limit = end;
        self.win_pos = 0;
        self.win_len = 0;
    }

    /// Positions the reader over `[start, end)` and KEEPS the window when it
    /// already covers `start`. The hard limit is untouched, so this narrows the
    /// soft bound to one section without paying for a re-read.
    pub fn rebound(self: *SecIn, start: u64, end: u64) void {
        self.limit = end;
        if (start >= self.win_start and start < self.win_start + @as(u64, self.win_len)) {
            self.win_pos = @intCast(start - self.win_start);
        } else {
            self.win_start = start;
            self.win_pos = 0;
            self.win_len = 0;
        }
    }

    /// Sets the hard bound the window may read to, dropping it. Used once per
    /// segment by B3's cleaner scan.
    pub fn resetHard(self: *SecIn, start: u64, hard_end: u64) void {
        self.reset(start, hard_end);
    }

    /// Moves to `pos` within the current bounds, keeping the window when it covers
    /// the target — the payload seek that makes the scan's cost proportional to
    /// entries rather than to the bytes they carry.
    pub fn seek(self: *SecIn, pos_to: u64) void {
        const limit = self.limit;
        self.rebound(pos_to, limit);
    }

    pub fn pos(self: *const SecIn) u64 {
        return self.win_start + @as(u64, self.win_pos);
    }

    pub fn remaining(self: *const SecIn) u64 {
        return self.limit - self.pos();
    }

    /// A read past the section's end is **corruption**, not a torn tail: pass 1
    /// already proved this section whole and CRC-valid, so an entry that runs off
    /// its end means the body's framing disagrees with its own length.
    fn refill(self: *SecIn) DbError!void {
        self.win_start = self.pos();
        self.win_pos = 0;
        if (self.win_start >= self.limit) {
            self.diag.note(R_ENTRY_OVERRUN, 0, self.limit, 0, 0);
            return error.DataCorruption;
        }
        // Minimum in u64, THEN narrow — see `bodyCrc`. Filled to the HARD limit, so
        // one window can serve several sections; the soft limit above is what
        // bounds the caller.
        const n: usize = try tainted.u64ToUsize(
            @min(@max(self.hard_limit, self.limit) - self.win_start, @as(u64, self.win.len)),
        );
        if (!try readAtOpt(self.file, self.win[0..n], self.win_start)) return error.Io;
        self.win_len = n;
        self.reads += 1;
    }

    pub fn readByte(self: *SecIn) DbError!u8 {
        if (self.pos() >= self.limit or self.win_pos >= self.win_len) try self.refill();
        const b = self.win[self.win_pos];
        self.win_pos += 1;
        return b;
    }

    /// packLong: MSB-first 7-bit groups, high bit terminates.
    ///
    /// Capped at 10 bytes, where Java's decoder loops to the terminator. That
    /// difference is deliberate and pre-existing (v1 caps it too): the canonical
    /// encodings agree, so the cap only changes which *malformed* input is refused
    /// and how quickly. It is recorded as a per-engine expectation in the
    /// corruption fixtures rather than smoothed over.
    pub fn unpackLong(self: *SecIn) DbError!u64 {
        var ret: u64 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            const v = try self.readByte();
            ret = (ret << 7) | @as(u64, v & 0x7F);
            if (v & 0x80 != 0) return ret;
        }
        self.diag.plain(R_PACKLONG);
        return error.DataCorruption;
    }

    pub fn readFully(self: *SecIn, dst: []u8) DbError!void {
        var off: usize = 0;
        while (off < dst.len) {
            if (self.pos() >= self.limit or self.win_pos >= self.win_len) try self.refill();
            const n = @min(self.win_len - self.win_pos, dst.len - off);
            @memcpy(dst[off .. off + n], self.win[self.win_pos .. self.win_pos + n]);
            self.win_pos += n;
            off += n;
        }
    }
};

/// Capacity as the writer encodes it: 0 for null content, else 16-aligned, big
/// enough for header+content and within the plain-record limit — EXCEPT oversize
/// (linked) records, which the writer encodes with capacity 0. Anything else never
/// came from this writer.
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

// ---------- the two per-recid identities (§4.2) ----------

/// The two per-recid identities replay maintains, plus the deferred skip audit.
///
/// **Not a replay floor under another name.** The v2 floor was derived by looking
/// *ahead* for each recid's newest self-contained entry and then deciding what to
/// apply, so a wrong floor silently recovered different data. These are derived
/// purely from what has already been applied and decide nothing on their own: the
/// only thing they can do when they are wrong is refuse the open (the audit),
/// which is why they replaced it.
///
/// The maps survive recovery — B2's commit classifier stamps every `T_APPEND` with
/// `content_base_lsn[recid]`, and fabricating that stamp instead of reading it is
/// a silent-loss channel.
pub const Identities = struct {
    /// LSN of the content image currently applied for a recid. Set by a
    /// content-bearing `T_RECORD`; CLEARED by `T_DELETE`, by a null-content
    /// `T_RECORD` and by `T_PREALLOC`.
    content_base_lsn: std.AutoHashMapUnmanaged(u64, i64) = .empty,
    /// LSN at which a recid's state was last made self-contained. Set by EVERY
    /// self-contained non-void entry; cleared by `T_DELETE`. Consumed by B3's
    /// cleaner.
    state_lsn: std.AutoHashMapUnmanaged(u64, i64) = .empty,
    /// Recids whose stranded `T_APPEND` replay skipped, minus those a later
    /// self-contained entry has since superseded.
    skipped_appends: std.AutoHashMapUnmanaged(u64, void) = .empty,

    pub fn deinit(self: *Identities, alloc: Allocator) void {
        self.content_base_lsn.deinit(alloc);
        self.state_lsn.deinit(alloc);
        self.skipped_appends.deinit(alloc);
        self.* = .{};
    }

    /// A content-bearing image: both identities move to this section's LSN.
    pub fn content(self: *Identities, alloc: Allocator, recid: u64, lsn: i64) DbError!void {
        self.content_base_lsn.put(alloc, recid, lsn) catch return error.OutOfMemory;
        self.state_lsn.put(alloc, recid, lsn) catch return error.OutOfMemory;
        _ = self.skipped_appends.remove(recid);
    }

    /// A self-contained entry that leaves the record with NO content image — a null
    /// `T_RECORD` or a `T_PREALLOC`. Merely declining to set a new content base is
    /// not enough: a recid that was content-live and became null would keep a stale
    /// base, and a later writer could then stamp an append from a state in which
    /// append is not valid.
    pub fn stateOnly(self: *Identities, alloc: Allocator, recid: u64, lsn: i64) DbError!void {
        _ = self.content_base_lsn.remove(recid);
        self.state_lsn.put(alloc, recid, lsn) catch return error.OutOfMemory;
        _ = self.skipped_appends.remove(recid);
    }

    /// The record is gone: both identities cleared, any pending skip discharged.
    pub fn voided(self: *Identities, recid: u64) void {
        _ = self.content_base_lsn.remove(recid);
        _ = self.state_lsn.remove(recid);
        _ = self.skipped_appends.remove(recid);
    }

    /// End of replay: every skipped append must have been superseded. A recid still
    /// here means the retained log holds a delta whose base is gone and nothing
    /// later re-established it — the store cannot be reconstructed, so the open
    /// refuses rather than return a record missing acknowledged bytes.
    fn audit(self: *const Identities, diag: *Diag) DbError!void {
        if (self.skipped_appends.count() == 0) return;
        var it = self.skipped_appends.keyIterator();
        const one = it.next().?.*;
        diag.note(R_AUDIT, 0, 0, one, @intCast(self.skipped_appends.count()));
        return error.DataCorruption;
    }
};

/// Records a reason for a `DataCorruption` the INNER STORE raised while replay
/// was applying an entry, and passes every other error through untouched.
///
/// The inner store validates the slot it is about to overwrite (index parity, the
/// capacity domain) and answers `DataCorruption` when that fails. Replay has no
/// better description to offer than "it was not the WAL that objected" — but a
/// refusal that reaches the caller with NO reason, or with the previous one, is
/// the failure mode the whole `Diag` mechanism exists to prevent, and Rust does
/// not have it because its error carries its own message.
///
/// Whether any WAL IMAGE can reach this today is a property of OTHER rules —
/// `capValid` mirrors `walPut`'s capacity domain exactly, and the §4.2 identity
/// table only applies an append to a record it has just seen established — not of
/// this call site. That is precisely the kind of reasoning this workstream
/// declines to leave implicit, so the reasons are recorded rather than assumed
/// unreachable.
///
/// `OutOfMemory` and `Io` pass through UNCHANGED: they are operational, not
/// verdicts (design §6 risk 14), and giving them a corruption reason would be the
/// same lie in the other direction.
fn innerFault(e: DbError, diag: *Diag, recid: u64, lsn: i64) DbError {
    if (e == error.DataCorruption) diag.note(R_INNER_STORE, 0, 0, recid, lsn);
    return e;
}

// ---------- R3: pass 1 ----------

/// Records a verdict against a segment; the caller stops scanning it and R4
/// decides whether it matters. First message wins.
fn hold(seg: *Segment, reason: []const u8, at: u64) void {
    if (seg.held == null) {
        seg.held = reason;
        seg.held_at = at;
    }
}

// The held reasons, as static strings. Rust interpolates the offset into each
// message; here the offset travels beside the reason in `Segment.held_at`. `pub`
// so a test can assert WHICH rule held, by identity rather than by substring.
pub const H_SHORT = "segment is shorter than its own sections claim";
pub const H_HDR_DAMAGED = "section header damaged in a non-final segment";
pub const H_MIDLOG_HDR = "mid-log corruption: section header damaged but valid sections follow";
pub const H_BODY_PAST_END = "section body extends past the end of a non-final segment";
pub const H_BODY_CRC = "section body CRC mismatch in a non-final segment";
pub const H_MIDLOG_BODY = "mid-log corruption: section body CRC mismatch but valid sections follow";
pub const H_LSN_BACK = "section LSN does not follow the previous one";
pub const H_LSN_GAP = "section LSNs must be consecutive";
pub const H_TRAILING = "non-final segment has trailing bytes past its last section";
pub const H_MARK_LEN = "clean mark body is not 16 bytes";
pub const H_MARK_SHORT = "clean mark body is truncated";
pub const H_MARK_THROUGH = "clean mark attests a non-positive cleanedThroughSeq";
pub const H_MARK_START = "clean mark attests a logStartLsn that is not at or below its own LSN";
pub const H_MARK_SELF = "clean mark authorizes removing its own segment";

/// R3, one segment (table S). Leaves `valid_end`, `first_lsn`, `last_lsn` and at
/// most one held verdict on `seg`; returns the highest `cleanedThroughSeq`
/// attested by a valid `'K'` **inside this segment**.
///
/// `look_last_in` enters as the scan-local anchor seeded from the cross-segment
/// carry, and is used ONLY as the suspect-header lookahead's anchor. The density
/// checks (S2/S9) deliberately restart at every segment boundary — the
/// cross-boundary link is R4's job, over the retained set alone. Checking it here
/// would refuse a perfectly legitimate crash image (segment 1 present, segment 2
/// already unlinked, segment 3 carrying the mark that authorized it), and the
/// verdict would originate in a retained segment while being caused by a
/// superseded one — the one shape R4's "discard verdicts from below the mark"
/// cannot rescue.
///
/// `is_active` marks the highest segment, the only one a torn tail can reach: W3
/// seals every other segment at a section boundary with `force(true)`, so a tear
/// anywhere below the highest name is corruption by construction.
fn scanSegment(
    seg: *Segment,
    look_last_in: i64,
    is_active: bool,
    replay_buf: usize,
    alloc: Allocator,
    mark_log_start: *i64,
) DbError!i64 {
    var look_last = look_last_in;
    var seg_through: i64 = 0;
    const len = seg.file_len;
    var pos = SEG_HDR;
    // END OF THE ACCEPTED PREFIX. W7 truncates the active segment to exactly
    // this, so forgetting to advance it below does not produce a different
    // verdict — it DELETES every valid section preceding a later tear.
    seg.valid_end = pos;
    // Every bound is proved by subtraction from the known file length before any
    // sum is formed: `bodyLen` is a disk field that may be `i64` maxint, and
    // `pos + 25 + bodyLen` overflows a u64 long before it exceeds the file.
    while (pos <= len and len - pos >= SEC_HDR) {
        const hdr = (try readSecHdr(seg, pos)) orelse {
            if (!is_active) hold(seg, H_SHORT, pos);
            return seg_through;
        };
        const h = parseSecHdr(&hdr);
        const body_start = pos + SEC_HDR;

        if (hdrCrc(seg, pos, &hdr) != h.hdr_crc or !validTag(h.tag)) {
            // S3. The declared bodyLen is UNTRUSTED — it lives in the bytes that
            // just failed their own checksum — so proving corruption needs a
            // section at exactly the declared end carrying exactly the LSN the
            // damaged one would have been followed by.
            if (!is_active) {
                hold(seg, H_HDR_DAMAGED, pos);
                return seg_through;
            }
            if (h.body_len >= 0 and @as(u64, @intCast(h.body_len)) <= len - body_start) {
                // The untrusted anchor: the walk STARTS at the damaged header's
                // declared end and may advance through several framed candidates
                // before finding `lookLastLsn + 2`.
                if (try anyValidSectionFrom(seg, body_start + @as(u64, @intCast(h.body_len)), len, look_last, true, replay_buf, alloc)) {
                    hold(seg, H_MIDLOG_HDR, pos);
                }
            }
            // TORN TAIL: stop immediately; `valid_end` is already the end of the
            // last accepted section (SEG_HDR when none was accepted).
            return seg_through;
        }
        if (h.body_len < 0 or @as(u64, @intCast(h.body_len)) > len - body_start) {
            // S5: a verified header whose body runs past the end of the file is a
            // torn tail by construction — there is nothing to look ahead at.
            if (!is_active) hold(seg, H_BODY_PAST_END, pos);
            return seg_through;
        }
        const body_end = body_start + @as(u64, @intCast(h.body_len));
        const computed = (try bodyCrc(seg, pos, body_start, body_end, replay_buf, alloc)) orelse {
            if (!is_active) hold(seg, H_SHORT, pos);
            return seg_through;
        };
        if (computed != h.body_crc) {
            // S4. Here `body_end` IS trusted — the header sealed it — so the
            // lookahead starts at a real section boundary and any strictly future
            // LSN proves durable sections follow.
            if (!is_active) {
                hold(seg, H_BODY_CRC, pos);
                return seg_through;
            }
            if (try anyValidSectionFrom(seg, body_end, len, look_last, false, replay_buf, alloc)) {
                hold(seg, H_MIDLOG_BODY, pos);
            }
            return seg_through;
        }

        // The section is whole. Everything from here is a WRITER-defect class:
        // CRC-valid means these bytes were produced deliberately, so the verdict is
        // corruption rather than a torn tail — but it is still HELD, because this
        // segment may be superseded.
        if (seg.last_lsn != 0) {
            // Both density checks live under this guard, and that is frozen
            // reference behaviour, not an oversight: 0 doubles as the "no section
            // seen" sentinel, so an unguarded S2 would refuse the first section of
            // every segment on `0 <= 0`. The visible consequence is that a whole
            // LEADING RUN of crafted lsn==0 sections is accepted and replayed while
            // staying invisible to first_lsn/last_lsn.
            if (h.lsn <= seg.last_lsn) {
                hold(seg, H_LSN_BACK, pos);
                return seg_through;
            }
            // S9. LSNs are DENSE by construction — one per section, the reservation
            // never burns one, rollback never mints one — so recovery demands them
            // consecutive rather than merely increasing. A gap is what detects a
            // clean whose 'C' sections vanished WHOLLY, leaving the predecessor
            // ending at a clean section boundary so nothing else looks wrong;
            // without it the mark silently authorizes deleting the only surviving
            // copy.
            //
            // The `+%` never actually wraps on an image that gets this far, and
            // that is precisely because S2 returned above: `last_lsn == i64::MAX`
            // makes every `lsn` fail `lsn <= last_lsn` or stop here first. The
            // wrapping form is what keeps the unreachable case an answer instead of
            // a panic — the ORDER of the two checks is load-bearing, not stylistic.
            if (h.lsn != seg.last_lsn +% 1) {
                hold(seg, H_LSN_GAP, pos);
                return seg_through;
            }
        }
        if (h.tag == TAG_MARK) {
            switch (try readMark(seg, body_start, h.body_len, h.lsn, seg.seq)) {
                .fault => |reason| {
                    hold(seg, reason, pos);
                    return seg_through;
                },
                .ok => |m| {
                    // The reduction is per-SEGMENT-scan and strict: an equal
                    // `through` later in the same segment does not displace the
                    // first one's logStartLsn. `mark_log_start` is whatever the last
                    // segment-local maximum set it to and is never re-derived from
                    // the global maximum below — frozen behaviour, pinned by the
                    // Java edge tests.
                    if (m.through > seg_through) {
                        seg_through = m.through;
                        mark_log_start.* = m.log_start;
                    }
                },
            }
        }
        if (seg.first_lsn == 0) seg.first_lsn = h.lsn;
        seg.last_lsn = h.lsn;
        look_last = h.lsn;
        pos = body_end;
        seg.valid_end = pos; // ONLY a whole accepted section advances it.
    }
    if (pos < len and !is_active) {
        // S6: W3 leaves no trailing bytes below the highest name.
        hold(seg, H_TRAILING, pos);
    }
    return seg_through;
}

const MarkVerdict = union(enum) {
    ok: struct { through: i64, log_start: i64 },
    fault: []const u8,
};

/// Reads and validates one `'K'` body. A `.fault` is a held verdict; the error
/// union carries I/O only.
fn readMark(
    seg: *const Segment,
    body_start: u64,
    body_len: i64,
    lsn: i64,
    seg_seq: i64,
) DbError!MarkVerdict {
    if (body_len != MARK_BODY_LEN) return .{ .fault = H_MARK_LEN };
    var body: [16]u8 = undefined;
    if (!try readAtOpt(handle(seg), &body, body_start)) return .{ .fault = H_MARK_SHORT };
    const through = getI64Be(&body, 0);
    const log_start = getI64Be(&body, 8);
    if (through <= 0) return .{ .fault = H_MARK_THROUGH };
    if (log_start <= 0 or log_start > lsn) return .{ .fault = H_MARK_START };
    if (through >= seg_seq) {
        // K4: a mark may never authorize removing its own segment, which is what
        // makes the retained set non-empty by construction.
        return .{ .fault = H_MARK_SELF };
    }
    return .{ .ok = .{ .through = through, .log_start = log_start } };
}

/// True when `[from, limit)` holds at least one fully valid section, proving that
/// durable committed sections follow a bad one — corruption, not a torn tail.
///
/// A **framed candidate walk**, not a bytewise search and not a full validation: a
/// candidate is framing-valid on its header CRC, tag and body length alone. `'K'`
/// body constraints, entry decoding and the one-entry-per-recid rule are
/// deliberately NOT checked here — a port that calls its complete section
/// validator classifies torn tails differently from the reference.
///
/// With `exact_next` (untrusted anchor: the damaged section's own bodyLen) the
/// candidate must carry EXACTLY `last_lsn + 2`, the damaged section having been
/// `last_lsn + 1`; otherwise (trusted anchor) any strictly future LSN counts. Both
/// reject "embedded fake" patterns from user data holding copies of earlier
/// sections: stale copies carry old LSNs, and under the CRC domain a copied
/// section fails its checksums at any other offset anyway.
///
/// Never crosses a segment boundary — `limit` is this segment's length.
fn anyValidSectionFrom(
    seg: *const Segment,
    from: u64,
    limit: u64,
    last_lsn: i64,
    exact_next: bool,
    replay_buf: usize,
    alloc: Allocator,
) DbError!bool {
    var pos = from;
    while (pos <= limit and limit - pos >= SEC_HDR) {
        const hdr = (try readSecHdr(seg, pos)) orelse return false;
        const h = parseSecHdr(&hdr);
        const body_start = pos + SEC_HDR;
        if (hdrCrc(seg, pos, &hdr) != h.hdr_crc or
            !validTag(h.tag) or
            h.body_len < 0 or
            @as(u64, @intCast(h.body_len)) > limit - body_start)
        {
            return false;
        }
        const body_end = body_start + @as(u64, @intCast(h.body_len));
        // WRAPPING, not checked and not saturating: `last_lsn` is a number read off
        // a disk that may hold anything, Java's long arithmetic wraps, and a
        // safe-build panic here downs the process where the reference merely
        // answers "no proof follows". A candidate LSN that matches the wrapped
        // value is a legitimate (if unreachable) answer; a panic is not.
        const lsn_ok = if (exact_next)
            h.lsn == last_lsn +% 2
        else
            h.lsn > last_lsn +% 1;
        if (lsn_ok) {
            const c = (try bodyCrc(seg, pos, body_start, body_end, replay_buf, alloc)) orelse
                return false;
            if (c == h.body_crc) return true;
        }
        // Wrong lsn, or right lsn with a bad body CRC: advance the frame.
        pos = body_end;
    }
    return false;
}

// ---------- R4: adjudicate ----------

/// R4. Returns the index at which the **retained** suffix begins — the segments
/// above `cleaned_through`. Verdicts and LSN discontinuities originating below it
/// are DISCARDED: those segments are superseded and about to be deleted, so rot
/// inside them is irrelevant and throwing on it would brick a store over bytes
/// nobody will read.
///
/// Every check here is an **equality between two recorded numbers**. The lowest
/// retained segment's stated start must equal the newest mark's `logStartLsn`, or
/// 1 when there is no mark. Each subsequent segment's stated start must equal
/// where its present predecessor ended — or, when that predecessor holds no
/// section, where IT said it would start, which is exactly what separates W7's
/// legitimately empty rotate target from a segment whose sections vanished. And a
/// segment must hold what its own header promised.
///
/// A missing sequence number needs **no rule at all**: if it held sections its
/// successor's stated start will not match its predecessor's end; if it held none,
/// nothing is missing. That is why the sequence numbers W6 burns on create-crash
/// residue are simply invisible here.
fn adjudicate(
    segs: []const Segment,
    cleaned_through: i64,
    mark_log_start: i64,
    diag: *Diag,
) DbError!usize {
    var start: usize = 0;
    while (start < segs.len and segs[start].seq <= cleaned_through) start += 1;
    if (start == segs.len) {
        // Unreachable: K4 makes a mark's own segment outrank everything it
        // authorizes removing, so the segment holding the newest mark is always
        // retained. Checked rather than assumed, because everything below depends
        // on it.
        diag.note(R_RETIRES_ALL, cleaned_through, 0, 0, 0);
        return error.DataCorruption;
    }
    const retained = segs[start..];
    for (retained) |*s| {
        if (s.held) |held| {
            // The HELD reason is promoted verbatim, so the refusal names the
            // pass-1 rule rather than the fact that R4 was the one to raise it.
            diag.note(held, s.seq, s.held_at, 0, 0);
            return error.DataCorruption;
        }
    }
    // The floor runs ALWAYS, not only when there is no anchor. The two witness
    // different things — the chain witnesses LSN continuity, the floor witnesses
    // the mark-image contract — and making them alternatives leaves a hole: a mark
    // with no image behind it, whose superseded segments are still present,
    // satisfies the chain (their data is below the mark, so no LSN is missing) and
    // violates the floor. The open would then succeed, pass 2 would replay only the
    // retained set, and R5 would unlink the segments holding the only copy of the
    // data.
    const expected_start: i64 = if (mark_log_start > 0) mark_log_start else 1;
    // ONE loop, and the self check runs on EVERY retained segment including the
    // first: a port that skips it on `retained[0]` accepts a segment whose stated
    // start matches the floor while its acknowledged leading sections are gone, and
    // replay then returns state with that prefix silently missing.
    var prev: ?*const Segment = null;
    for (retained) |*s| {
        const stated = s.headerFirstLsn();
        if (prev) |p| {
            // Wrapping: `last_lsn` is a disk field, and a crafted section carrying
            // i64 maxint reaches here through the sentinel guard (the first section
            // of a segment is accepted whatever its LSN). The reference wraps; a
            // safe-build `+` would panic.
            const after = if (p.last_lsn != 0) p.last_lsn +% 1 else p.headerFirstLsn();
            if (stated != after) {
                diag.note(R_CHAIN, s.seq, 0, 0, stated);
                return error.DataCorruption;
            }
        } else {
            if (stated != expected_start) {
                diag.note(R_FLOOR, s.seq, 0, 0, expected_start);
                return error.DataCorruption;
            }
        }
        // A segment must also hold what its own header promised, or its prefix was
        // lost. The gate is `first_lsn != 0`, NOT "the segment is nonempty": the two
        // differ exactly on a segment holding only crafted lsn==0 sections, which is
        // nonempty with first_lsn 0 and whose self-check the reference therefore
        // SKIPS.
        if (s.first_lsn != 0 and s.first_lsn != stated) {
            diag.note(R_SELF, s.seq, 0, 0, stated);
            return error.DataCorruption;
        }
        prev = s;
    }
    return start;
}

// ---------- R6: pass 2 ----------

/// R6, one segment. Pass 1 is the sole authority on section boundaries: this walk
/// re-reads headers it already validated and never re-derives them, so a
/// disagreement between the two passes is impossible by construction.
fn pass2(
    seg: *const Segment,
    inner: *StoreDirect,
    ids: *Identities,
    replay_buf: usize,
    alloc: Allocator,
    diag: *Diag,
) DbError!void {
    const file = handle(seg);
    var input = try SecIn.init(file, alloc, replay_buf, diag);
    defer input.deinit();
    // Reused across sections rather than allocated per section: the rule is
    // per-section and `clearRetainingCapacity` enforces exactly that, without a
    // fresh allocation for every commit in the log.
    var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer seen.deinit(alloc);
    var pos = SEG_HDR;
    while (pos < seg.valid_end) {
        var hdr: [@as(usize, SEC_HDR)]u8 = undefined;
        if (!try readAtOpt(file, &hdr, pos)) return error.Io;
        const h = parseSecHdr(&hdr);
        const body_start = pos + SEC_HDR;
        // Unreachable by construction — pass 1 validated exactly these bytes and
        // `valid_end` is where it stopped — and checked anyway, because "cannot
        // happen" plus an unchecked cast is a panic rather than a wrong answer if
        // the file changes underneath us. `body_start > valid_end` is tested FIRST:
        // a guard whose own subtraction underflows in the scenario it exists for
        // would be worse than no guard at all.
        if (body_start > seg.valid_end or
            h.body_len < 0 or
            @as(u64, @intCast(h.body_len)) > seg.valid_end - body_start)
        {
            diag.note(R_PASS_DRIFT, seg.seq, pos, 0, 0);
            return error.DataCorruption;
        }
        const body_end = body_start + @as(u64, @intCast(h.body_len));
        // A 'K' body carries no entries and is NEVER passed to the entry decoder;
        // 'C' is semantically identical to 'S' and gets no special handling.
        if (h.tag != TAG_MARK) {
            try applySection(inner, &input, &seen, body_start, body_end, h.lsn, ids, alloc, diag);
        }
        pos = body_end;
    }
}

/// Decodes and applies one CRC-verified section body as the §4.2 **state
/// transition table**; a malformed entry is a writer bug or corruption, never a
/// torn tail. `lsn` is the enclosing section's.
///
/// Every row states what happens to BOTH identities, because getting that wrong is
/// how the in-memory tables desynchronize from the store:
///
/// ```text
/// entry             precondition                      action        contentBase  state    skip
/// T_RECORD content  —                                 walPut        = lsn        = lsn    clear
/// T_RECORD null     —                                 walPut(null)  cleared      = lsn    clear
/// T_PREALLOC        R is not content-live             walPrealloc   cleared      = lsn    clear
/// T_PREALLOC        R IS content-live                 DataCorruption
/// T_DELETE          —                                 walDelete     cleared      cleared  clear
/// T_APPEND          baseLsn == contentBase[R]         append        unchanged    unch.    unch.
/// T_APPEND          contentBase[R] absent or > base   SKIP          unchanged    unch.    add R
/// T_APPEND          contentBase[R] < baseLsn          DataCorruption
/// ```
///
/// A superseded `T_RECORD` is RE-APPLIED rather than skipped, which is correct
/// because it is idempotent and costs only recovery-time work.
fn applySection(
    inner: *StoreDirect,
    input: *SecIn,
    seen: *std.AutoHashMapUnmanaged(u64, void),
    start: u64,
    end: u64,
    lsn: i64,
    ids: *Identities,
    alloc: Allocator,
    diag: *Diag,
) DbError!void {
    input.reset(start, end);
    // At most one entry per recid per section, for 'C' sections as well as 'S'.
    // The classifier coalesces every append() call for a recid into one entry, so a
    // second entry would mean the ordered-replay reasoning no longer applies to
    // this section.
    seen.clearRetainingCapacity();
    while (input.pos() < end) {
        const ty = try input.readByte();
        switch (ty) {
            T_PREALLOC => {
                const recid = try entryRecid(seen, try input.unpackLong(), alloc, diag);
                // walPrealloc no-ops on ANY set slot, so applying it to a
                // content-live record would silently leave a record that is still
                // there while the identities describe a preallocated one. The
                // precondition is "not content-live" rather than "void or already
                // preallocated" to be TOTAL over doctored images: a null-content
                // target matches neither of those and must not fall through
                // undefined.
                const state = inner.recState(recid) catch |e|
                    return innerFault(e, diag, recid, lsn);
                if (state == STATE_LIVE) {
                    diag.note(R_PREALLOC_LIVE, 0, 0, recid, lsn);
                    return error.DataCorruption;
                }
                inner.walPrealloc(recid) catch |e| return innerFault(e, diag, recid, lsn);
                try ids.stateOnly(alloc, recid, lsn);
            },
            T_DELETE => {
                const recid = try entryRecid(seen, try input.unpackLong(), alloc, diag);
                // Tolerant of a void target on purpose: that is the shape a
                // skipped-append history leaves behind.
                inner.walDelete(recid) catch |e| return innerFault(e, diag, recid, lsn);
                ids.voided(recid);
            },
            T_RECORD => {
                const recid = try entryRecid(seen, try input.unpackLong(), alloc, diag);
                const cap = try input.unpackLong();
                const len_plus = try input.unpackLong();
                var data: ?[]u8 = null;
                defer if (data) |d| alloc.free(d);
                if (len_plus != 0) {
                    const len = len_plus - 1;
                    // Capped at both `i32` maxint and the section remainder BEFORE
                    // it is narrowed or allocated.
                    if (len > std.math.maxInt(i32) or len > input.remaining()) {
                        diag.note(R_RECORD_LEN, 0, 0, recid, @bitCast(len));
                        return error.DataCorruption;
                    }
                    const b = alloc.alloc(u8, try tainted.u64ToUsize(len)) catch
                        return error.OutOfMemory;
                    data = b;
                    try input.readFully(b);
                }
                if (!capValid(cap, data)) {
                    diag.note(R_RECORD_CAP, 0, 0, recid, @bitCast(cap));
                    return error.DataCorruption;
                }
                inner.walPut(recid, try tainted.u64ToUsize(cap), data) catch |e|
                    return innerFault(e, diag, recid, lsn);
                if (data == null) {
                    try ids.stateOnly(alloc, recid, lsn);
                } else {
                    try ids.content(alloc, recid, lsn);
                }
            },
            T_APPEND => {
                const recid = try entryRecid(seen, try input.unpackLong(), alloc, diag);
                const base_lsn = try decodeBaseLsn(try input.unpackLong(), lsn, recid, diag);
                const len = try input.unpackLong();
                if (len > std.math.maxInt(i32) or len > input.remaining()) {
                    diag.note(R_APPEND_LEN, 0, 0, recid, @bitCast(len));
                    return error.DataCorruption;
                }
                const base: ?i64 = ids.content_base_lsn.get(recid);
                if (base) |b| {
                    if (b < base_lsn) {
                        // Unreachable in a conforming set (retirement is a prefix in
                        // LSN order, so a base below the current one cannot be the
                        // missing part); defence in depth over S9.
                        diag.note(R_APPEND_BASE_HIGH, 0, 0, recid, base_lsn);
                        return error.DataCorruption;
                    }
                }
                const b = alloc.alloc(u8, try tainted.u64ToUsize(len)) catch
                    return error.OutOfMemory;
                defer alloc.free(b);
                // Consumed either way: the frame is still framed.
                try input.readFully(b);
                if (base != null and base.? == base_lsn) {
                    const applied = inner.append(recid, b) catch |e|
                        return innerFault(e, diag, recid, lsn);
                    switch (applied) {
                        .refused => {
                            diag.note(R_APPEND_REFUSED, 0, 0, recid, lsn);
                            return error.DataCorruption;
                        },
                        .new_size => {},
                    }
                } else {
                    // The base this delta extends is gone (cleaned, or superseded by
                    // a newer image that already contains these bytes): skip and
                    // remember.
                    ids.skipped_appends.put(alloc, recid, {}) catch return error.OutOfMemory;
                }
            },
            else => {
                diag.note(R_ENTRY_TAG, 0, 0, 0, ty);
                return error.DataCorruption;
            },
        }
    }
}

/// The recid an entry names, checked once for both rules that apply to it before
/// any of the entry's other fields are read.
///
/// - **one entry per recid per section**, `'C'` sections included. The classifier
///   coalesces every `append()` call for a recid into one entry, so a second entry
///   would mean the ordered-replay reasoning no longer applies.
/// - **recid 0 is reserved** and never allocated, so no conforming writer emits
///   it. Refusing it here is a deliberate port strictness — the reference decoder
///   does not check, and hands 0 to the inner store — of the same class as the
///   port's 10-byte packLong cap: it changes which MALFORMED images are refused,
///   never which conforming ones are accepted, and the corruption fixtures record
///   it per engine rather than assuming uniform strictness.
fn entryRecid(
    seen: *std.AutoHashMapUnmanaged(u64, void),
    recid: u64,
    alloc: Allocator,
    diag: *Diag,
) DbError!u64 {
    if (recid == 0) {
        diag.plain(R_RECID_ZERO);
        return error.DataCorruption;
    }
    const gop = seen.getOrPut(alloc, recid) catch return error.OutOfMemory;
    if (gop.found_existing) {
        diag.note(R_RECID_TWICE, 0, 0, recid, 0);
        return error.DataCorruption;
    }
    return recid;
}

/// Turns the encoded `packLong(lsn - baseLsn)` back into an absolute base LSN,
/// BEFORE any mutation. The delta must be >= 1 — so an append can never cite a
/// base in its own section, and `baseLsn < lsn` always — and must leave a base LSN
/// >= 1, since LSNs start at 1. Both bounds are what make the table's comparison
/// meaningful instead of an accidental "skip" on a garbage value.
pub fn decodeBaseLsn(delta_bits: u64, lsn: i64, recid: u64, diag: *Diag) DbError!i64 {
    // Compared as i64 with the same bits the reference sees, and wrapping where it
    // wraps. `lsn` is a number read off a disk that may hold anything — a crafted
    // section is accepted with ANY lsn while the segment is still empty (the
    // sentinel guard) — so `lsn - 1` at i64 minint is a reachable input, and a safe
    // build panics where Java wraps. The bounds stay total at `lsn == 0`, which IS
    // reachable: a leading run of lsn==0 sections replays and may carry an append.
    const delta: i64 = @bitCast(delta_bits);
    if (delta < 1 or delta > lsn -% 1) {
        diag.note(R_APPEND_DELTA, 0, 0, recid, delta);
        return error.DataCorruption;
    }
    return lsn -% delta;
}

// ---------- the ordered algorithm ----------

/// What recovery hands back to the store: where the log continues, and the
/// identities replay rebuilt. The caller owns the identities and must
/// [`deinit`](Recovered.deinit) them.
pub const Recovered = struct {
    next_lsn: i64,
    identities: Identities,

    pub fn deinit(self: *Recovered, alloc: Allocator) void {
        self.identities.deinit(alloc);
    }
};

/// The ordered recovery algorithm, R3-R7. R0-R2 (enumerate, classify, remove
/// create-crash residue) already ran inside `WalSegmentSet.open`.
///
/// 1. **R3** pass 1 — namespace only, no per-recid state: per segment the valid
///    section prefix, any HELD verdict, LSN continuity; globally the newest `'K'`.
/// 2. **R4** adjudicate — discard every verdict from a superseded segment, throw
///    the rest, and check the floor/chain/self equalities over the retained set.
/// 3. **R5** unlink the superseded segments, then fsync the directory.
/// 4. **R6** pass 2 — apply the §4.2 table in ascending (segment, offset) order,
///    then the skip audit.
/// 5. **R7** finish — `nextLsn`, and IFF the active segment's valid prefix is
///    shorter than its length: truncate, force, rotate (W7), fsync.
///
/// **R5 runs before R6**, so an open that refuses can do so with the namespace
/// already pruned. That is deliberate and fixed, not incidental: "a failed open
/// leaves the files untouched" is not a v3 invariant, and the fixture oracles
/// assert an exact post-open file set per row instead. Allocation failure is no
/// different (risk 14): mutations that completed before it stay completed, because
/// a failed open is not transactional.
///
/// A read-only recovery takes every decision identically and performs none of the
/// mutations: no create, no residue delete, no unlink, no truncate, no rotate, no
/// directory fsync. It still computes `next_lsn` and the identities.
pub fn recover(
    set: *WalSegmentSet,
    inner: *StoreDirect,
    replay_buf: usize,
    alloc: Allocator,
    diag: *Diag,
) DbError!Recovered {
    // The reason must describe THIS recovery: a caller that reuses a `Diag` would
    // otherwise read an earlier open's explanation for this one's refusal.
    diag.* = .{};
    const read_only = set.isReadOnly();
    if (set.segmentsSlice().len == 0) {
        // N1: a fresh store. The writable open creates a segment with
        // `firstLsn = 1` using the CURRENT `nextSeq` — classification has already
        // set that to 1 when no name was observed and to the burned successor
        // otherwise, so no residue conditional belongs here. The read-only open
        // creates nothing and simply reports where the log would begin.
        if (!read_only) _ = try set.createSegment(1);
        try inner.rebuildFreeRecids();
        return .{ .next_lsn = 1, .identities = .{} };
    }

    // ---- R3 ----
    const n0 = set.segmentsSlice().len;
    const active_idx = n0 - 1;
    var cleaned_through: i64 = 0;
    var mark_log_start: i64 = 0;
    // TWO anchors, deliberately. `carry` is cross-segment and is seeded into each
    // scan; the scan-local one inside `scanSegment` is what the lookahead consults.
    // Anchoring the lookahead at 0 for the first damaged section of each segment
    // would diverge from Java.
    var carry: i64 = 0;
    var i: usize = 0;
    while (i < n0) : (i += 1) {
        const seg = &set.segmentsSlice()[i];
        try seg.ensureOpen();
        const scanned = scanSegment(seg, carry, i == active_idx, replay_buf, alloc, &mark_log_start);
        // Released the moment this segment's scan is done, WHATEVER the verdict —
        // including an error, which is why the release precedes the propagation
        // below. Pass 2 reopens the ones it needs. This is what bounds the
        // descriptor count to O(1) rather than O(segments): a store is allowed to
        // reach roughly twice the live data size in log, so a large one means
        // thousands of segments against a default `ulimit -n` of 1024.
        seg.release();
        cleaned_through = @max(cleaned_through, try scanned);
        // Both halves live in this caller loop, not inside the scan, and BOTH run
        // even when a HOLD stopped the scan early. Skipping the carry half on a held
        // segment diverges in the direction that LOSES data: a superseded segment
        // that holds mid-scan stops propagating its anchor, so a damaged header in
        // the active segment is measured against a stale carry, the exact-next
        // candidate is not found, and "mid-log corruption" (refuse) silently becomes
        // "torn tail" (truncate and open).
        //
        // A segment ending in an accepted lsn==0 section must NOT erase the
        // preceding segment's anchor: `last_lsn` is still 0 there, and the carry
        // stands. Frozen sentinel behaviour again.
        if (seg.last_lsn != 0) carry = seg.last_lsn;
    }

    // ---- R4 ----
    const retained_from = try adjudicate(set.segmentsSlice(), cleaned_through, mark_log_start, diag);

    // R7's answer is computed over the RETAINED set, deliberately, rather than over
    // every valid section. The two agree on every conforming image — K4 puts a
    // mark's own segment above everything it authorizes removing, and LSNs ascend
    // with (segment, offset) — and differ only on a doctored image where a
    // superseded segment carries a spuriously high LSN, where the global reading
    // would leave a gap that fails S9 on the NEXT open.
    var max_valid_lsn: i64 = 0;
    for (set.segmentsSlice()[retained_from..]) |s| {
        max_valid_lsn = @max(max_valid_lsn, s.last_lsn);
    }
    // An all-empty retained set holds no LSN to count from, and "0 + 1" would
    // restart the log at 1 — reissuing LSNs a mark already accounted for. The lowest
    // segment's header says where the log begins; that is the answer, and it is why
    // the field is in the header. The condition is "no NONZERO section LSN in the
    // retained set", not "all retained segments are empty".
    if (max_valid_lsn == 0) {
        // The plain subtraction is safe because H9 refuses a header stating
        // `firstLsn <= 0` before a segment ever joins the set (`wal_segments.zig`,
        // table H). Named here because the dependency is invisible at this call
        // site: relaxing H9 would arm an underflow.
        max_valid_lsn = set.segmentsSlice()[retained_from].headerFirstLsn() - 1;
    }

    // ---- R5 ---- (no-op under read-only)
    try set.unlinkThrough(cleaned_through);

    // ---- R6 ----
    var ids: Identities = .{};
    errdefer ids.deinit(alloc);
    const n = set.segmentsSlice().len;
    i = 0;
    while (i < n) : (i += 1) {
        // Filtered by sequence number rather than by index: R5 has already shifted
        // the indices, and under a read-only open it removed nothing at all, so the
        // superseded segments are still both on disk and in the live list. Replaying
        // one because its file is still there would give a read-only open a
        // different record map than a writable open of the same namespace — the one
        // property this mode exists to preserve.
        if (set.segmentsSlice()[i].seq <= cleaned_through) continue;
        const is_active = i == n - 1;
        try set.segmentsSlice()[i].ensureOpen();
        const applied = pass2(&set.segmentsSlice()[i], inner, &ids, replay_buf, alloc, diag);
        // The active segment keeps its handle: R7 may still truncate it.
        if (!is_active) set.segmentsSlice()[i].release();
        try applied;
    }
    // The audit runs BEFORE R7's truncate: an open that refuses here has mutated
    // nothing further. The bytes a torn tail would lose were never a valid section,
    // so the ordering is conformance and forensics rather than data — but a port
    // that reordered it would fail the fixtures.
    try ids.audit(diag);

    // ---- R7 ----
    // A RECORDED divergence, not an oversight. The reference adds without checking
    // and opens the store with `nextLsn == i64::MIN` (`StoreWAL.java:547`), which is
    // reachable on a CRC-valid doctored image: a lone segment stating
    // `firstLsn = i64::MAX` whose single 'K' sits at that LSN satisfies K4, the
    // floor and the self check. The port refuses instead, because the reference's
    // answer opens a store that accepts exactly one more commit — written at a
    // negative LSN — and is then permanently unopenable, since the next scan reads
    // that section as S2. Refusing loses nothing a conforming writer could produce
    // (2^63 transactions), and `StoreFull` says what is true: nothing on disk is
    // damaged, the LSN space is used up. If the owner wants byte-for-byte parity
    // with the reference here (Q8), `+%` is the whole change — it is a one-line
    // reversal, deliberately isolated. A safe-build PANIC is neither ruling.
    const next_lsn = std.math.add(i64, max_valid_lsn, 1) catch return error.StoreFull;
    if (!read_only) {
        const active = set.active().?;
        const torn = active.valid_end < active.file_len;
        const valid_end = active.valid_end;
        const seq = active.seq;
        if (torn) {
            // W7. The truncate is not itself forced, so a crash after
            // truncate-then-shorter-reappend can resurface pre-truncation bytes.
            // Force, then rotate, so later appends never reuse this segment's
            // checksum domain at all. Conditional on an ACTUAL truncation: rotating
            // on every open would burn a sequence number per open and demote a
            // legitimate valid-empty highest segment to non-highest (H8).
            try active.ensureOpen();
            try walIoEvent(set.io, WalOpKind.truncate, seq, valid_end, 0, 0);
            handle(active).setEndPos(valid_end) catch return error.Io;
            active.file_len = valid_end;
            // The file's SIZE is the payload here: never fdatasync.
            try walIoEvent(set.io, WalOpKind.force_full, seq, valid_end, 0, 0);
            std.posix.fsync(handle(active).handle) catch return error.Io;
            // A RECORDED divergence, and the port's is the better behaviour. The
            // reference never releases the truncated predecessor
            // (`StoreWAL.java:548-560` releases nothing, and pass 2's `finally`
            // exempts the active segment), so a Java store holds that stale channel
            // after every torn-tail open and TWO once the first commit opens the
            // successor's. Nothing reads a segment after recovery, and the
            // O(1)-descriptor rule is a tested invariant here, so the port releases
            // it. Copying the reference would reintroduce the leak in every engine.
            active.release();
            // `active` is DEAD from here: `createSegment` may reallocate the list.
            _ = try set.createSegment(next_lsn);
        }
    }
    // Replay of delete-then-reuse histories leaves stale free-list entries for
    // revived recids: rebuild the allocator's free list from the final index.
    try inner.rebuildFreeRecids();
    return .{ .next_lsn = next_lsn, .identities = ids };
}

comptime {
    // The whole port is Linux-scoped (`wal_segments.zig` asserts the same).
    if (builtin.os.tag != .linux) @compileError("mapdb-zig-store WAL v3 is Linux-only");
}
