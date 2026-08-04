//! Transactional store over the v3 segmented write-ahead log — the PUBLIC
//! layer, and the only file that knows all four v3 modules at once.
//!
//! Port of `mapdb-rust-store/src/store/wal.rs` (slice A2's public surface),
//! which is itself Java `StoreWAL`. The division of labour:
//!
//! - `wal_segments.zig` (B0) owns which FILES exist: the `<base>.wal.<16 hex>`
//!   namespace, the store lock, W2 create, W5/W6 unlink discipline, D1's
//!   legacy-refusal rows, D2's namespace delete.
//! - `wal_recover.zig` (B1) owns how bytes are READ back: the section/entry
//!   codec and the two-pass recovery state machine R0-R7.
//! - `wal_write.zig` (B2 part 1) owns how a section reaches the DEVICE: the
//!   two-pass streaming writer, W1/W4 force ordering, W3 rollover.
//! - This file owns the STORE: staging, the commit classifier, the §4.2
//!   identity maps, W9 fail-closed, D2's lock-owning delete-on-close, D4's
//!   platform gate, D8's config surface.
//!
//! One global writer behind `rw`; every write path rechecks `closed` after
//! acquiring the lock (close publishes `closed` under the same lock, so no
//! staged mutation or durable append can slip in after `close()` completed).
//!
//! # W9, the caller's half
//!
//! Every error out of `appendSection` means the active segment may hold partial
//! bytes; the ONLY safe answer is to fail the store closed so no retry can
//! append a complete section after them (v1 returned the error with the store
//! open; the next open then read the retry's acknowledged section as mid-log
//! garbage and discarded it — a latent v1 defect this obligation exists to
//! prevent). The same applies PAST the durability point: if applying a forced
//! section to the inner volume fails, memory and log have diverged and no
//! retry can reconcile them — close, and let reopen replay the durable state.
//! Zig has no unwinding, so unlike rust there is no panic path around these
//! returns; the error returns here are the entire surface, and the mutation
//! suite pins that every one of them closes the store.
//!
//! # The cleaner (B3)
//!
//! The incremental cleaner — Java's re-home / W10 audit / forced-`'K'` +
//! unlink cycle, ported from rust's A3 (`wal.rs`, the cleaner block). An
//! EPISODE (seal the active segment, take its successor as the floor) is
//! driven in budgeted CYCLES (retire the oldest `cycle_width` segments), each
//! a publish walk ('C' images of every record whose state still lives in the
//! retiring range), a verify walk (W10: refuse the mark while anything is
//! un-re-homed), then the forced `'K'` and the unlink. `checkpoint()` is the
//! same machinery with an unbounded budget; commit's automatic hook pays
//! `FOREGROUND_BUDGET` per commit, or loops at the hard ceiling. The
//! futility latch stops a healthy-but-uncompactable log from being re-cleaned
//! on every commit.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const mod = @import("mod.zig");
const iv = @import("index_val.zig");
const direct = @import("direct.zig");
const StoreDirect = direct.StoreDirect;
const STATE_LIVE = direct.STATE_LIVE;
const STATE_VOID = direct.STATE_VOID;
const AppendResult = mod.AppendResult;
const LeaseTable = mod.LeaseTable;

const segments = @import("wal_segments.zig");
const WalSegmentSet = segments.WalSegmentSet;
const SEG_HDR = segments.SEG_HDR;
const FIRST_SEQ = segments.FIRST_SEQ;

const wal_io = @import("wal_io.zig");
const WalIo = wal_io.WalIo;

const wr = @import("wal_recover.zig");
const Diag = wr.Diag;
const Identities = wr.Identities;
const SecIn = wr.SecIn;
const parseSecHdr = wr.parseSecHdr;
const buildMarkBody = wr.buildMarkBody;
const SEC_HDR = wr.SEC_HDR;
const MARK_BODY_LEN = wr.MARK_BODY_LEN;
const TAG_SECTION = wr.TAG_SECTION;
const TAG_IMAGE = wr.TAG_IMAGE;
const TAG_MARK = wr.TAG_MARK;

const wal_write = @import("wal_write.zig");
const appendSection = wal_write.appendSection;
const forceFull = wal_write.forceFull;
const BodySink = wal_write.BodySink;

// ------------------------------------------------------------------ constants

/// Entry types inside a section body (v3 §4.2, same values as v1 and Java).
const T_PREALLOC: u8 = 1;
const T_RECORD: u8 = 2;
const T_APPEND: u8 = 3;
const T_DELETE: u8 = 4;
/// Not an entry type: "created and deleted inside one transaction", which is
/// applied (the preallocated recid is freed) and never logged.
const T_TRANSIENT: u8 = 0;

/// Default streaming-replay window (bytes); the ctor override forces refill
/// edges in tests.
const DEFAULT_REPLAY_BUF: usize = 1 << 20;

/// Default segment size. The writer seals and rolls PAST this, at a section
/// boundary, so one section may exceed it and an oversize section gets a
/// segment to itself.
pub const DEFAULT_SEGMENT_BYTES: u64 = 64 << 20;

/// Smallest legal segment size: a segment header plus one section header.
/// Anything below it cannot hold a single section.
pub const MIN_SEGMENT_BYTES: u64 = SEG_HDR + SEC_HDR;

/// Floor under the cleaning trigger (D8): a log smaller than this is never
/// cleaned, however small the live data is. Without a floor a store holding a
/// few hundred bytes would clean on every commit.
pub const DEFAULT_MIN_LOG_BYTES: u64 = 1 << 30;

/// Default space-amplification target (D8): clean once the log exceeds this
/// multiple of the live data. It bounds SPACE, not write amplification.
pub const DEFAULT_SPACE_AMPLIFICATION: u32 = 2;

// Static diagnostic reasons for the store `Diag` (same discipline as
// `wal_recover`'s R_* set: cleared on entry, written immediately before the
// error return it explains, asserted by IDENTITY in tests). Rust formats the
// failure into the error's message; `DbError` has no payload, so the reason
// travels here instead.

/// The commit section's write or force failed (W9): the store is closed, the
/// durable state on disk is intact, reopen replays it.
pub const W_COMMIT_WRITE: []const u8 =
    "wal commit: section write/force failed; store closed (W9), reopen to recover";
/// Applying a FORCED section to the inner volume failed: memory and log have
/// diverged, the store is closed, reopen replays the committed section.
pub const W_COMMIT_APPLY: []const u8 =
    "wal commit: apply failed after the durability point; store closed, reopen to recover the committed section";
/// The inner store refused a committed append during apply — a writer bug
/// surfacing after the durability point, never an operational condition.
pub const W_COMMIT_APPEND_REFUSED: []const u8 =
    "wal commit: inner store refused a committed append after the durability point";
/// A cleaner section ('C' image, 'K' mark, or the episode's sealing roll)
/// failed to reach the device (W9): the store is closed, the durable log is
/// intact, reopen replays it.
pub const W_CLEAN_WRITE: []const u8 =
    "wal cleaner: section write/force failed; store closed (W9), reopen to recover";
/// Moving the identities after a DURABLE 'C' image failed: memory and log have
/// diverged (a half-moved identity map could stamp a wrong append base), the
/// store is closed, reopen rebuilds the identities from the log.
pub const W_CLEAN_APPLY: []const u8 =
    "wal cleaner: identity update failed after a durable image; store closed, reopen to recover";
/// Retiring-range I/O failed (a scan read, or the post-mark unlink): the
/// store's I/O is broken and it says so once — closed, reopen to recover.
pub const W_CLEAN_IO: []const u8 =
    "wal cleaner: I/O failed while cleaning; store closed, reopen to recover";
/// A recid is BOTH committed-live and allocated by an in-flight transaction —
/// impossible through the allocator, so re-emitting either way would be a
/// guess. Refused; nothing deleted. `recid` names it, `detail` its state LSN.
pub const W_CLEAN_INFLIGHT: []const u8 =
    "wal cleaner: recid has committed state and is also allocated by an in-flight transaction";
/// The identity map attests committed state for a recid the inner store holds
/// nothing for. Refused rather than retiring a segment whose contents were
/// not re-homed. `recid` names it, `detail` its state LSN.
pub const W_CLEAN_MISSING: []const u8 =
    "wal cleaner: recid has committed state but the inner store holds nothing for it";
/// W10: the cycle would retire a segment while a recid still has its only
/// self-contained entry inside the retiring range — an under-re-emission that
/// must fail loudly BEFORE the data is destroyed. Nothing has been deleted;
/// the durable log is intact. `seq` is the target segment, `recid` the record
/// being protected, `detail` its stranded state LSN.
pub const W_CLEAN_UNREHOMED: []const u8 =
    "wal cleaner: a record was not re-homed above the retiring range; refusing to write the clean mark (W10)";
/// The cleaner scan met a section header that does not fit before the
/// segment's validated end — the walk verifies no CRC (the section was
/// verified whole at open), so it says what it trusts.
pub const W_CLEAN_SCAN_HDR: []const u8 =
    "wal cleaner scan: section header does not fit before the segment's validated end";
/// The cleaner scan met a section whose claimed body runs past the segment's
/// validated end.
pub const W_CLEAN_SCAN_BODY: []const u8 =
    "wal cleaner scan: section body runs past the segment's validated end";
/// The cleaner scan met an entry tag outside the §4.2 set.
pub const W_CLEAN_SCAN_TAG: []const u8 =
    "wal cleaner scan: bad entry tag";

// --------------------------------------------------------------- staged state

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
/// mid-apply).
const WalOp = struct {
    /// One of `T_*`, or [`T_TRANSIENT`].
    op: u8,
    recid: u64,
    /// `T_RECORD` only.
    cap: usize,
    /// Owned by the ops list; freed after commit.
    data: ?[]u8,
    /// `T_APPEND` only: the LSN of the content image this delta extends, read
    /// from the live identities at classify time and written to the log as
    /// `packLong(sectionLsn - base_lsn)`. 0 for every other op, all of which
    /// are self-contained.
    base_lsn: i64 = 0,
};

/// Capacity as the writer encodes it, for merged content `m` plus a `headroom`
/// hint: 0 for null content and for genuinely oversize content (stored linked),
/// else 16-aligned and big enough for header+content.
///
/// Headroom is a HINT; the record is the promise. A staged base reports
/// unlimited capacity, so an append can push the merged content to the plain
/// maximum and the requested headroom then overflows it. Clamping keeps the
/// record plain with an exact capacity, which is what a later `T_APPEND`
/// needs. Falling to capacity 0 there would make the writer acknowledge a
/// commit the decoder rejects as a garbage capacity (`capValid` allows 0 only
/// when the CONTENT itself is oversize), i.e. an unopenable log.
fn recordCap(m: ?[]const u8, headroom: usize) u64 {
    const b = m orelse return 0;
    const max = @as(u64, iv.MAX_CAPACITY);
    // u64 throughout, saturating: the sum of a plain-sized record and a large
    // headroom is checked against the ceiling, never wrapped into it.
    const cap = ((4 +| @as(u64, b.len)) +| @as(u64, headroom) +| 15) & ~@as(u64, 15);
    if (cap > max) {
        return if (4 + @as(u64, b.len) <= max) max else 0;
    }
    return cap;
}

// ------------------------------------------------------------------- options

/// Options for [`StoreWAL.openCfg`]. The seam and diag fields are test
/// surfaces rather than API: production opens pass null for both.
pub const WalOptions = struct {
    thread_safe: bool = true,
    /// D7: INTERNAL read-only mode only — same scanner, no mutation. There is
    /// no public read-only DB surface in this workstream.
    read_only: bool = false,
    segment_bytes: u64 = DEFAULT_SEGMENT_BYTES,
    /// Streaming window for replay; a tiny value forces refill edges in tests.
    replay_buf: usize = DEFAULT_REPLAY_BUF,
    /// The durability-event seam, installed into the segment set — the ONE
    /// store-owned pointer (`segs.io`); nothing else holds a copy. Borrowed
    /// for the life of the store; the installer owns the lifetime.
    io: ?*const WalIo = null,
    /// Receives the recovery diagnostic on a refused open; the store's own
    /// `Diag` starts empty either way.
    diag: ?*Diag = null,
};

// -------------------------------------------------------------- WalState

/// The lock-guarded mutable state (Java's single ReadWriteLock covers all of it).
const WalState = struct {
    inner: StoreDirect,
    segs: WalSegmentSet,
    staged: std.AutoHashMapUnmanaged(u64, Staged) = .empty,
    /// The two per-recid identities, maintained atomically with the committed
    /// apply of the entry that sets them — never before, never from staged
    /// state. Replay rebuilds them; the commit classifier reads them.
    ids: Identities = .{},
    /// Next section LSN — exactly consecutive within a segment.
    next_lsn: i64,
    segment_bytes: u64,
    min_log_bytes: u64 = DEFAULT_MIN_LOG_BYTES,
    space_amplification: u32 = DEFAULT_SPACE_AMPLIFICATION,
    read_only: bool,
    /// Committed self-contained entries over this store's lifetime — every one
    /// of which can obsolete an earlier image, which is what makes it the
    /// cleaner's futility-latch staleness clock.
    committed_state_changes: i64 = 0,
    /// The store-level diagnostic: cleared on entry to `commitLocked` and
    /// `checkpoint`, written immediately before every error return that maps a
    /// writer, apply or cleaner failure, so it always describes the failure
    /// just returned or nothing.
    diag: Diag = .{},
    alloc: Allocator,

    // ---- the cleaner (B3). Every field is touched under the write lock.
    /// The cycle in progress, or `null` when idle.
    cleaner: ?Cleaner = null,
    /// The active segment when the log first became due; no cycle may select
    /// at or above it, so reaching it means the whole log has been rewritten
    /// once. 0 = no episode in progress.
    clean_floor_seq: i64 = 0,
    /// The lifetime retired/written counters as the current episode began. Its
    /// achievement is `retired - written` over the episode — NET PROGRESS, not
    /// the change in log size, because concurrent commits move the log for
    /// reasons that have nothing to do with whether cleaning is working.
    episode_retired: i64 = 0,
    episode_written: i64 = 0,
    /// Images this episode has re-emitted, and the segments below the floor
    /// when its FIRST cycle opened — the range it set out to rewrite. The
    /// terminal is qualified against that range, not against what is left: a
    /// completed episode retires prefixes until nothing remains, so its final
    /// cycle is always as wide as the remainder.
    episode_records: i64 = 0,
    episode_segments: usize = 0,
    /// Segments the NEXT cycle may retire in one go. A cycle that retires one
    /// segment pays for one mark, and a mark can cost more than a small
    /// segment holds: at the minimum segment size a cycle retires ~61 bytes
    /// and appends ~107, so one-at-a-time cleaning grows the log forever on a
    /// log a single wide pass would collapse.
    cycle_width: usize = 1,
    cycle_retired_at: i64 = 0,
    cycle_written_at: i64 = 0,
    /// The cycle now open runs at the WIDEST width available to it. Only an
    /// episode whose last cycle was saturated may arm the latch: a futile
    /// narrow cycle is evidence about the width, not about the log.
    cycle_saturated: bool = false,
    last_cycle_saturated: bool = false,
    /// Log size when an episode completed its whole range WITHOUT shrinking
    /// the log — the configured ratio is unachievable. Latched so it is not
    /// retried on every commit. 0 = not latched.
    futile_at_bytes: u64 = 0,
    /// The target when the latch armed; a materially LOWER one re-arms
    /// cleaning.
    futile_at_target: u64 = 0,
    /// `committed_state_changes` when the latch armed, and the images the
    /// futile episode re-emitted. A latch is a proof about the log as it
    /// stood, and commits invalidate proofs: a mass delete of null-content or
    /// preallocated records obsoletes every image in the log while moving
    /// neither the log's size nor the target.
    futile_at_changes: i64 = 0,
    futile_records: i64 = 0,
    /// Lifetime cleaner accounting, both halves — bytes re-emitted, bytes
    /// retired.
    cleaner_bytes_written: i64 = 0,
    cleaner_bytes_retired: i64 = 0,
    /// Fault injection, and the only reason it exists: W10 is a check on phase
    /// 1's loop, so a suite that cannot make that loop DROP a record cannot
    /// tell a working W10 from one that passes because nothing ever fails it.
    /// Dropping a recid here is precisely the under-re-emission W10 is for.
    /// Test-only by convention (rust gates it `cfg(test)`; zig cannot
    /// conditionally declare a field without forking the struct layout, which
    /// is the same reason `SecIn.reads` is unconditional). 0 = disabled, and
    /// recid 0 is refused by every decoder, so no production entry matches.
    drop_recid_from_publish: u64 = 0,

    fn clearStaged(self: *WalState) void {
        var it = self.staged.valueIterator();
        while (it.next()) |s| s.deinit(self.alloc);
        self.staged.clearRetainingCapacity();
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

    /// Classifies the staged set into the ops one commit section will carry.
    /// Runs BEFORE any apply, because applying shifts the inner store's state.
    /// The returned ops (and their payloads) are owned by the caller.
    fn classify(self: *WalState) DbError!std.ArrayListUnmanaged(WalOp) {
        var recids: std.ArrayListUnmanaged(u64) = .empty;
        defer recids.deinit(self.alloc);
        {
            var it = self.staged.keyIterator();
            while (it.next()) |k| recids.append(self.alloc, k.*) catch return error.OutOfMemory;
        }
        // Ascending recid order IS the on-disk entry order.
        std.mem.sort(u64, recids.items, {}, std.sort.asc(u64));

        var ops: std.ArrayListUnmanaged(WalOp) = .empty;
        errdefer freeOps(self.alloc, &ops);
        for (recids.items) |recid| {
            const s = self.staged.getPtr(recid).?;
            if (s.deleted) {
                // created+deleted in one transaction: apply-only cleanup, not logged.
                const op: u8 = if (s.created) T_TRANSIENT else T_DELETE;
                ops.append(self.alloc, .{ .op = op, .recid = recid, .cap = 0, .data = null }) catch return error.OutOfMemory;
            } else if (!s.base_set and s.appends.items.len == 0) {
                // T_PREALLOC exists to make a NEWLY ALLOCATED recid durable. On
                // a record that was already committed, an empty staged entry
                // means nothing was changed, so nothing is logged — structural
                // defence in depth: no path that leaves an empty entry behind
                // can turn it into a prealloc over a live record, which §4.2
                // rejects on replay.
                if (s.created) {
                    ops.append(self.alloc, .{ .op = T_PREALLOC, .recid = recid, .cap = 0, .data = null }) catch return error.OutOfMemory;
                }
            } else if (s.base_set or (try self.inner.recState(recid)) != STATE_LIVE) {
                const m = try self.merged(recid, s);
                errdefer if (m) |mm| self.alloc.free(mm);
                const cap = recordCap(m, s.headroom);
                ops.append(self.alloc, .{ .op = T_RECORD, .recid = recid, .cap = @intCast(cap), .data = m }) catch return error.OutOfMemory;
            } else {
                // Live plain base in inner: log only the appended tail.
                const m = self.alloc.alloc(u8, s.appends_len) catch return error.OutOfMemory;
                errdefer self.alloc.free(m);
                var p: usize = 0;
                for (s.appends.items) |a| {
                    @memcpy(m[p .. p + a.len], a);
                    p += a.len;
                }
                // This branch is reached only when the record is committed,
                // content-bearing and plain, which is exactly the shape that
                // has a content base — so the identity must be there. Its
                // absence is a writer bug, and the design's weakest point is a
                // WRONG stamp, so refuse to invent one: a delta with a
                // fabricated base is a silent-loss channel. (Java raises an
                // `AssertionError` here; zig aborts, which is the same "this
                // store has a bug" verdict without the store-open caveat.)
                const base_lsn = self.ids.content_base_lsn.get(recid) orelse
                    std.debug.panic("no content base LSN for appended recid {d}", .{recid});
                ops.append(self.alloc, .{ .op = T_APPEND, .recid = recid, .cap = 0, .data = m, .base_lsn = base_lsn }) catch return error.OutOfMemory;
            }
        }
        return ops;
    }

    /// The LSN the next section may use, refusing BEFORE anything is written
    /// when the space is exhausted.
    ///
    /// The reference advances `nextLsn` with an unchecked `long` add
    /// (`StoreWAL.java:1838-1883`). The ports refuse instead — the adopted
    /// divergence of §4 D6 / §7 Q8, already implemented on the recovery side —
    /// and the check must happen HERE, before the write: advancing after the
    /// force would durably land a section at `i64::MAX` with a wrapped
    /// successor, which is neither the reference's ruling nor the port's.
    fn reserveLsn(self: *const WalState) DbError!struct { lsn: i64, after: i64 } {
        const lsn = self.next_lsn;
        const after = std.math.add(i64, lsn, 1) catch return error.StoreFull;
        return .{ .lsn = lsn, .after = after };
    }

    fn commitLocked(self: *WalState, closed: *std.atomic.Value(bool)) DbError!void {
        if (self.staged.count() == 0) return;
        // The Diag protocol: cleared on entry so it always describes THIS
        // commit's failure or nothing.
        self.diag = .{};
        var ops = try self.classify();
        defer freeOps(self.alloc, &ops);
        const r = try self.reserveLsn();
        // Validated BEFORE `appendSection` can roll over or write, so a
        // mis-stamped delta fails with nothing on the device.
        for (ops.items) |op| {
            if (op.op == T_APPEND and r.lsn <= op.base_lsn) {
                std.debug.panic("append base LSN {d} is not below its section LSN {d}, recid={d}", .{ op.base_lsn, r.lsn, op.recid });
            }
        }

        // The emitter runs TWICE (measure + write passes) over this immutable
        // ops snapshot, so a commit staging more than 2 GiB emits one genuinely
        // huge section instead of dying in a doubling buffer. Deterministic by
        // construction: `ops`, their payloads and the section LSN are all
        // fixed before the first pass.
        var ectx = EmitCtx{ .ops = ops.items, .section_lsn = r.lsn, .alloc = self.alloc };
        appendSection(&self.segs, self.segment_bytes, self.segs.io, TAG_SECTION, r.lsn, self.alloc, &ectx, emitEntries) catch |e| {
            // W9: a failed or partial write/force fails the store CLOSED, so no
            // retry can append a complete section after the partial bytes. The
            // error keeps its identity (`OutOfMemory` stays operational — risk
            // 14); the reason says which phase failed.
            self.diag.note(W_COMMIT_WRITE, self.activeSeq(), 0, 0, 0);
            self.failClosed(closed);
            return e;
        };
        self.next_lsn = r.after;
        // The cleaner's staleness clock: SELF-CONTAINED entries only. An append
        // extends a record whose image is already the log's youngest, so it
        // obsoletes nothing, while a record, a delete and a prealloc each
        // supersede whatever stood before.
        for (ops.items) |op| {
            switch (op.op) {
                T_RECORD, T_DELETE, T_PREALLOC => self.committed_state_changes += 1,
                else => {},
            }
        }

        // Apply to the inner volume. PAST THE DURABILITY POINT: the section is
        // on disk and owns an LSN, so if any apply fails, memory and log have
        // diverged and this handle can never be made consistent again — a
        // retried commit would re-emit the same frames under a NEW section LSN
        // and the forced one would be applied twice on reopen. Fail closed; the
        // durable state on disk is intact and reopen replays it. The error
        // keeps its identity (rust wraps it into a corruption MESSAGE, which
        // `DbError` cannot carry — and reclassifying an operational failure as
        // corruption is the lie the B1 review named); the phase travels in the
        // Diag unless the apply already recorded a more specific reason.
        self.applyCommitted(ops.items, r.lsn) catch |e| {
            if (self.diag.reason.len == 0)
                self.diag.note(W_COMMIT_APPLY, 0, 0, 0, 0);
            self.failClosed(closed);
            return e;
        };
        self.clearStaged();
        try self.autoCleanLocked(closed);
    }

    /// Applies one committed section's ops and moves the identities by the SAME
    /// §4.2 transition row replay would take for the entry just written — that
    /// shared table is what keeps the live maps and a rebuilt-from-log copy
    /// identical.
    fn applyCommitted(self: *WalState, ops: []const WalOp, section_lsn: i64) DbError!void {
        for (ops) |op| {
            switch (op.op) {
                T_TRANSIENT => {
                    try self.inner.delete(op.recid); // created+deleted: free the P recid
                    // Nothing was logged, so nothing established an identity
                    // for this incarnation; clearing is defensive, not
                    // load-bearing.
                    self.ids.voided(op.recid);
                },
                T_PREALLOC => {
                    // Already P in inner since op time.
                    try self.ids.stateOnly(self.alloc, op.recid, section_lsn);
                },
                T_RECORD => {
                    try self.inner.walPut(op.recid, op.cap, op.data);
                    if (op.data == null) {
                        try self.ids.stateOnly(self.alloc, op.recid, section_lsn);
                    } else {
                        try self.ids.content(self.alloc, op.recid, section_lsn);
                    }
                },
                T_APPEND => {
                    const d = op.data.?; // T_APPEND carries its payload
                    switch (try self.inner.append(op.recid, d)) {
                        .refused => {
                            self.diag.note(W_COMMIT_APPEND_REFUSED, 0, 0, op.recid, 0);
                            return error.DataCorruption;
                        },
                        .new_size => {},
                    }
                    // An append leaves both identities where they are: the base
                    // image it extends is still the one a later append cites.
                },
                T_DELETE => {
                    try self.inner.delete(op.recid);
                    self.ids.voided(op.recid);
                },
                else => unreachable, // unknown classified op
            }
        }
    }

    /// The store cannot be made consistent again: close it rather than let a
    /// caller retry into a segment holding partial bytes. Durable state on
    /// disk is intact and reopen replays it.
    fn failClosed(self: *WalState, closed: *std.atomic.Value(bool)) void {
        closed.store(true, .release);
        self.segs.close();
        self.inner.close() catch {};
    }

    /// Seals the active segment and starts a successor, if the active one
    /// holds any section. W3's force flavour applies: the seal persists SIZE.
    fn rollActiveIfNonempty(self: *WalState, closed: *std.atomic.Value(bool)) DbError!void {
        const roll = if (self.segs.active()) |a| !a.empty() else false;
        if (!roll) return;
        self.rollActiveInner() catch |e| {
            // A half-created segment is not recoverable in place.
            if (self.diag.reason.len == 0)
                self.diag.note(W_CLEAN_WRITE, self.activeSeq(), 0, 0, 0);
            self.failClosed(closed);
            return e;
        };
    }

    fn rollActiveInner(self: *WalState) DbError!void {
        const a = self.segs.active().?; // checked by the caller
        try a.ensureOpen();
        try forceFull(self.segs.io, a, a.file_len);
        a.release();
        // `a` is DEAD from here: `createSegment` may reallocate the list.
        _ = try self.segs.createSegment(self.next_lsn);
    }

    // ---------------------------------------------------------- the trigger

    /// The size the log is allowed to reach.
    ///
    /// `live` is the inner store's `getCurrentSize()` — allocated bytes minus
    /// reclaimed — which is PAGE-GRANULAR: it includes the header and rounds
    /// to slices, so it reports about 2 MiB for a store holding 200 bytes. The
    /// ratio is therefore a log-versus-footprint ratio, exact at scale and
    /// conservative below a few MiB, where it DELAYS cleaning rather than
    /// hastening it. That direction is the safe one, but it means
    /// `setMinLogBytes` is not an absolute cap on a tiny store: below ~2 MiB
    /// of footprint the amplification term, not the floor, decides.
    fn cleaningTarget(self: *WalState) u64 {
        const live = self.inner.getCurrentSize();
        const scaled = live *| @as(u64, self.space_amplification);
        return @max(self.min_log_bytes, scaled);
    }

    /// It bounds SPACE, not WRITE amplification, and the difference is not
    /// academic: cleaning strictly the oldest segment is FIFO, not
    /// cost-benefit, so for a cold-head workload that segment is ~100% live
    /// and re-emitting it buys nothing this cycle. Oldest-first is kept as an
    /// explicit trade-off with the pathological case named rather than hidden.
    fn cleaningDue(self: *WalState) bool {
        return self.min_log_bytes > 0 and self.segs.logBytes() > self.cleaningTarget();
    }

    /// The hard ceiling: the log is past TWICE what the trigger allows, so
    /// bounding the pause has stopped being the priority and the committing
    /// writer participates until it is back under.
    fn cleaningUrgent(self: *WalState) bool {
        return self.min_log_bytes > 0 and self.segs.logBytes() > self.cleaningTarget() *| 2;
    }

    /// Whether the futility latch is armed — a healthy, fully compacted log
    /// that cannot meet the configured ratio.
    fn cleaningExhausted(self: *const WalState) bool {
        return self.futile_at_bytes > 0;
    }

    /// Releases the futility latch, whatever armed it.
    fn clearLatch(self: *WalState) void {
        self.futile_at_bytes = 0;
        self.futile_at_target = 0;
        self.futile_at_changes = 0;
        self.futile_records = 0;
    }

    /// Abandons the episode WITHOUT judging it — for a configuration change or
    /// an explicit `checkpoint()`, after which nothing it observed is still
    /// about the same store.
    fn abandonEpisode(self: *WalState) void {
        self.clearLatch();
        self.clean_floor_seq = 0;
        self.episode_retired = 0;
        self.episode_written = 0;
        self.episode_records = 0;
        self.episode_segments = 0;
        self.cycle_width = 1;
        self.last_cycle_saturated = false;
    }

    /// Ends the episode, having walked its whole range. Called ONLY on
    /// completion, because only a completed episode says anything: it is the
    /// bounded window the no-net-progress terminal is measured over.
    fn endEpisode(self: *WalState) void {
        const futile = self.clean_floor_seq != 0 and
            !paidForItself(
                self.cleaner_bytes_retired - self.episode_retired,
                self.cleaner_bytes_written - self.episode_written,
            );
        if (futile and self.last_cycle_saturated) {
            self.futile_at_bytes = @max(self.segs.logBytes(), 1);
            self.futile_at_target = self.cleaningTarget();
            self.futile_at_changes = self.committed_state_changes;
            self.futile_records = @max(self.episode_records, 1);
        }
        self.clean_floor_seq = 0;
        self.episode_retired = 0;
        self.episode_written = 0;
        self.episode_records = 0;
        self.episode_segments = 0;
        // Reset WITH the episode, not across it: a guard that outlives what it
        // describes would let an episode that did NO work (nothing below its
        // floor, so `futile` is trivially true) arm the terminal on the
        // strength of a PREVIOUS episode's wide last cycle. `cycle_width`
        // does persist deliberately — the width a log needs is a property of
        // the log.
        self.last_cycle_saturated = false;
    }

    /// Opens a cycle over the oldest retirable segments IF the trigger is
    /// live. Returns whether a cycle is now open.
    ///
    /// An EPISODE begins by SEALING the active segment and taking its fresh
    /// successor as the floor. No cycle may select at or above that floor, so
    /// everything that existed when the episode began is retirable and nothing
    /// the episode itself writes is: once the lowest present segment reaches
    /// the floor, the episode has rewritten the whole log exactly once.
    /// Sealing is what makes that true — using the PRE-EXISTING active segment
    /// as the floor leaves it untouched, and it also subsumes the
    /// single-segment case, where a `segment_bytes` above the trigger would
    /// otherwise leave a log growing forever with no candidate at all.
    ///
    /// The terminal is FUTILITY, not reaching the floor. An episode that
    /// reclaimed bytes and ended is a success, and the right response is
    /// another episode; latching on "reached the floor" suppresses cleaning
    /// after every SUCCESSFUL one — including above the hard ceiling, where
    /// the writer is supposed to be made to participate, so the ceiling would
    /// not be one.
    fn beginCycleIfDue(self: *WalState, closed: *std.atomic.Value(bool)) DbError!bool {
        if (!self.cleaningDue()) {
            // The trigger went quiet. The EPISODE is not over: keeping its
            // floor across a dip is what stops a workload hovering around the
            // target paying a fresh seal, create and directory fsync every few
            // commits. Only the latch is released, because a quiet trigger
            // means the situation changed.
            self.clearLatch();
            return false;
        }
        if (self.futile_at_bytes > 0) {
            const room = self.cleaningTarget();
            const retry = self.futile_at_bytes +| room;
            // A MATERIAL drop, not any drop: the target is the inner store's
            // footprint, and an ordinary update moves it by a couple of
            // hundred bytes in either direction as the allocator reuses
            // extents.
            const dropped = self.futile_at_target - (self.futile_at_target >> 3);
            const grew = self.segs.logBytes() >= retry;
            const shrank = room <= dropped;
            // ...and neither of those can see a state-only mass delete, which
            // obsoletes every image in the log while moving neither number.
            const churned =
                self.committed_state_changes - self.futile_at_changes >= self.futile_records;
            if (!grew and !shrank and !churned) return false;
            self.clearLatch();
        }
        if (self.clean_floor_seq == 0) {
            // The seal is CLEANING's cost, not the writer's: this rollover
            // exists only to give the episode a floor, and its 36-byte
            // successor header would otherwise be invisible to every tick.
            const log_before = self.segs.logBytes();
            const retired_before = self.cleaner_bytes_retired;
            try self.rollActiveIfNonempty(closed);
            _ = self.chargeCleaner(log_before, retired_before);
            self.clean_floor_seq = self.segs.active().?.seq; // writable store
            self.episode_retired = self.cleaner_bytes_retired;
            self.episode_written = self.cleaner_bytes_written;
        }
        // BINARY search for the floor, not a walk: the walk is O(segments
        // below the floor) and runs at every cycle start, which is every
        // commit or two.
        const all = self.segs.segmentsSlice();
        const below = std.sort.partitionPoint(segments.Segment, all, self.clean_floor_seq, struct {
            fn belowFloor(floor: i64, s: segments.Segment) bool {
                return s.seq < floor;
            }
        }.belowFloor);
        if (below == 0 or below >= all.len) {
            self.endEpisode(); // the episode has rewritten everything it could
            return false;
        }
        if (self.episode_segments == 0) self.episode_segments = below;
        // One segment per cycle, or as many as the width search has reached.
        // A wide cycle is not a wider PAUSE — it is still driven in budgeted
        // ticks — and it is the only way to amortise one mark over many
        // segments.
        const width = @min(@min(@max(self.cycle_width, 1), CYCLE_WIDTH_CAP), below);
        // SATURATED = as wide as this episode is ever allowed to go, measured
        // against the range it STARTED with. Against the remainder it would be
        // vacuous: a completed episode's final cycle always covers what is
        // left.
        self.cycle_saturated = width >= @min(CYCLE_WIDTH_CAP, self.episode_segments);
        const target = all[width - 1].seq;
        self.startCycle(target);
        return true;
    }

    /// Opens a cycle retiring everything at or below `target_seq`. The caller
    /// must have established that a segment above it exists.
    ///
    /// **O(1).** Candidates are discovered by WALKING THE RETIRING RANGE
    /// itself, one bounded unit at a time — computing them from the
    /// `state_lsn` map would be O(live recids) under the write lock, and for a
    /// large store far more work than the segment being retired even contains.
    ///
    /// The walk finds every candidate and no others: a recid needs re-emission
    /// exactly when `state_lsn[R] <= boundary_lsn`, that value IS the LSN of
    /// its newest self-contained entry, and the retained log begins at
    /// `boundary_lsn + 1` — so that entry is inside the range and the recid
    /// appears in the walk. The FILTER stays over `state_lsn`, which is what
    /// keeps a recid merely allocated by an in-flight transaction out of the
    /// set: it has no committed entry and so no `state_lsn` at all.
    ///
    /// No surviving `T_APPEND` can be orphaned by this. The worry is a delta
    /// ABOVE the range whose base lies INSIDE it; it is unreachable, because
    /// `content_base_lsn[R] <= boundary < state_lsn[R]` cannot happen — every
    /// entry that raises `state_lsn` either moves `content_base_lsn` to the
    /// SAME LSN or clears it. So a delta whose base is in the range belongs to
    /// a candidate, which is re-emitted with that delta already folded into
    /// its content; replay then skips the stranded delta and the image
    /// supersedes it, which is what the skip audit is built to tolerate.
    fn startCycle(self: *WalState, target_seq: i64) void {
        self.cycle_retired_at = self.cleaner_bytes_retired;
        self.cycle_written_at = self.cleaner_bytes_written;
        const successor = for (self.segs.segmentsSlice()) |*s| {
            if (s.seq > target_seq) break s;
            // K4: a mark may not authorize removing its own segment, so a
            // cycle retiring everything has nowhere to record itself.
        } else unreachable; // a cycle always leaves a segment above its target
        self.cleaner = Cleaner.init(target_seq, successor.headerFirstLsn());
    }

    /// Charges one unit of cleaning and returns what it charged: what the log
    /// grew by, plus what the unit retired (which shrank it).
    ///
    /// Both halves of the accounting must be in the SAME unit, and the unit is
    /// FILE bytes. The sections a tick appends are not what it costs the log:
    /// an append that rolls over creates a segment header, and the mark that
    /// closes a cycle usually lands in a segment of its own. Charging section
    /// bytes against `retired`, which sums whole file lengths, reports
    /// progress on an episode that is growing the log — a treadmill that never
    /// reaches its terminal because it never stops "progressing".
    fn chargeCleaner(self: *WalState, log_before: u64, retired_before: i64) i64 {
        // Charges NOTHING once the store is closed: a section append can fail
        // the store from inside a unit, after which the segment set is empty
        // and the delta would be a large negative charge.
        if (self.segs.segmentsSlice().len == 0 and self.cleaner == null) return 0;
        const charge = @as(i64, @intCast(self.segs.logBytes())) - @as(i64, @intCast(log_before)) +
            (self.cleaner_bytes_retired - retired_before);
        self.cleaner_bytes_written += charge;
        return charge;
    }

    // ------------------------------------------------------------ the phases

    /// Phase 1, one bounded unit: walk the retiring range and publish, as a
    /// single `'C'` section, an image of every record met whose state still
    /// lives inside it. Returns the steps walked.
    ///
    /// **Check, copy and publish are one serialized unit** — the whole method
    /// runs under the WAL write lock — and that is correctness, not style.
    /// Split them and the cleaner sees R live, copies image I, a committer
    /// writes update U, and the cleaner then appends a stale `C(R, I)` AFTER
    /// U: replay resurrects the old value.
    ///
    /// One section per unit, and every section is forced before the next is
    /// appended: recovery infers mid-log rot from "a valid section follows an
    /// invalid one", which is sound only while that holds.
    fn publishUnit(
        self: *WalState,
        closed: *std.atomic.Value(bool),
        budget: *const Budget,
        written_so_far: i64,
        records_so_far: usize,
    ) DbError!usize {
        const byte_room: u64 = if (budget.max_bytes > 0)
            @intCast(@max(@as(i64, @intCast(budget.max_bytes)) - written_so_far, 1))
        else
            1 << 20;
        const rec_room: usize = if (budget.max_records > 0)
            @max(budget.max_records -| records_so_far, 1)
        else
            SCAN_UNIT_ENTRIES;
        const cap = @min(byte_room, 1 << 20);
        var out = DataOutput2.init(self.alloc);
        defer out.deinit();
        const r = try self.reserveLsn();

        // (recid, carries content) per emitted image, applied to the
        // identities only after the section is durable.
        const Emitted = struct { recid: u64, content: bool };
        var emitted: std.ArrayListUnmanaged(Emitted) = .empty;
        defer emitted.deinit(self.alloc);
        // Recids already encoded into THIS section. A recid met again in a
        // later section of the range is normally filtered by its own raised
        // `state_lsn` — but the identities move only once the section is
        // durable, so within one unfinished batch that filter has not fired
        // yet, and the decoder's one-entry-per-recid-per-section rule would be
        // violated. Replay refuses such a section outright.
        var in_batch: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer in_batch.deinit(self.alloc);

        const boundary = self.cleaner.?.boundary_lsn;
        const Visit = struct {
            st: *WalState,
            out: *DataOutput2,
            emitted: *std.ArrayListUnmanaged(Emitted),
            in_batch: *std.AutoHashMapUnmanaged(u64, void),
            boundary: i64,
            cap: u64,

            const Sink = struct {
                out: *DataOutput2,
                recid: u64,
                content_seen: *bool,
                pub fn emit(sk: @This(), prealloc: bool, cap_bytes: usize, content: ?[]u8) DbError!void {
                    if (prealloc) {
                        try sk.out.writeU8(T_PREALLOC);
                        try sk.out.packLong(sk.recid);
                    } else {
                        try sk.out.writeU8(T_RECORD);
                        try sk.out.packLong(sk.recid);
                        try sk.out.packLong(@as(u64, cap_bytes));
                        if (content) |d| {
                            try sk.out.packLong(@as(u64, d.len) + 1);
                            try sk.out.writeAll(d);
                            sk.content_seen.* = true;
                        } else {
                            try sk.out.packLong(0);
                        }
                    }
                }
            };

            fn visit(v: @This(), recid: u64) DbError!bool {
                // Fault injection (test-only): dropping a recid from phase 1
                // is precisely the under-re-emission W10 exists to catch.
                if (recid == v.st.drop_recid_from_publish and recid != 0) return true;
                if (v.in_batch.contains(recid)) return true;
                // Across units no dedup is needed: a recid re-emitted by an
                // earlier unit has a `state_lsn` above the boundary, exactly
                // like one a concurrent commit re-homed. Both are simply not
                // candidates.
                const sl = v.st.ids.state_lsn.get(recid) orelse return true;
                if (sl > v.boundary) return true;
                if (v.st.staged.getPtr(recid)) |s| {
                    if (s.created) {
                        // A recid an in-flight transaction allocated has no
                        // committed entry and therefore no `state_lsn`; the
                        // allocator cannot hand out a recid that is
                        // committed-live. Both at once would mean inner's slot
                        // has been overwritten with a preallocation while
                        // committed content is still attested — re-emitting
                        // either way would be a guess.
                        v.st.diag.note(W_CLEAN_INFLIGHT, 0, 0, recid, sl);
                        return error.DataCorruption;
                    }
                }
                var content_seen = false;
                const live = try v.st.inner.walSnapshotOne(recid, Sink{
                    .out = v.out,
                    .recid = recid,
                    .content_seen = &content_seen,
                });
                if (!live) {
                    // `state_lsn` present means "committed non-void", and
                    // inner IS the committed state, so this cannot happen
                    // without the identity map having diverged from the store.
                    // Refuse rather than retire a segment whose contents were
                    // not re-homed.
                    v.st.diag.note(W_CLEAN_MISSING, 0, 0, recid, sl);
                    return error.DataCorruption;
                }
                v.emitted.append(v.st.alloc, .{ .recid = recid, .content = content_seen }) catch
                    return error.OutOfMemory;
                v.in_batch.put(v.st.alloc, recid, {}) catch return error.OutOfMemory;
                // An image larger than one unit's allowance still goes whole:
                // a record cannot be split across sections.
                return @as(u64, v.out.bytes().len) < v.cap;
            }
        };
        const steps = try scanUnit(
            &self.cleaner.?,
            &self.segs,
            &self.diag,
            self.alloc,
            rec_room,
            Visit{
                .st = self,
                .out = &out,
                .emitted = &emitted,
                .in_batch = &in_batch,
                .boundary = boundary,
                .cap = cap,
            },
            Visit.visit,
        );

        if (emitted.items.len != 0) {
            var bctx = RawBodyCtx{ .body = out.bytes() };
            appendSection(&self.segs, self.segment_bytes, self.segs.io, TAG_IMAGE, r.lsn, self.alloc, &bctx, emitRawBody) catch |e| {
                // W9, the cleaner's half: partial bytes may be on the device.
                if (self.diag.reason.len == 0)
                    self.diag.note(W_CLEAN_WRITE, self.activeSeq(), 0, 0, 0);
                self.failClosed(closed);
                return e;
            };
            self.next_lsn = r.after;
            // IMAGES, not entries walked: the staleness clock compares the
            // store's committed self-contained entries against the live set
            // the futile episode had to preserve, and entries walked is
            // neither — it counts the garbage too.
            self.episode_records += @intCast(emitted.items.len);
            // Identities move by the §4.2 row of each entry the section
            // contains, AFTER it is durable and atomically with it. An
            // allocator failure here is a crash shape rust cannot produce
            // (its map inserts are infallible): the image is durable but the
            // maps may now be half-moved, and a half-moved identity could
            // stamp a wrong append base — the design's weakest point — so it
            // fails CLOSED with its error identity kept (risk 14), exactly
            // like a post-durability apply failure in commit. Reopen rebuilds
            // the identities from the log.
            //
            // Whether this arm is REACHABLE is a property of other rules, and
            // the workstream declines to leave that implicit: every emitted
            // recid passed the candidate filter, so it already occupies
            // `state_lsn` (and, when content-bearing in inner, `content_base_
            // lsn` — content is set by exactly the applies that populate it),
            // and a put over a present key never grows the map. The guard is
            // defence in depth for the day an invariant above it moves.
            for (emitted.items) |em| {
                const move = if (em.content)
                    self.ids.content(self.alloc, em.recid, r.lsn)
                else
                    self.ids.stateOnly(self.alloc, em.recid, r.lsn);
                move catch |e| {
                    if (self.diag.reason.len == 0)
                        self.diag.note(W_CLEAN_APPLY, 0, 0, em.recid, 0);
                    self.failClosed(closed);
                    return e;
                };
            }
        }
        const c = &self.cleaner.?;
        if (c.range_done) {
            c.published = true;
            c.rewind(); // also clears range_done, for the verify walk
        }
        return steps;
    }

    /// Phase 2 — W10, one bounded unit: re-walk the retiring range and assert
    /// that every recid it mentions has been re-homed above it.
    ///
    /// **A mark cannot be made self-verifying after the unlink**, because the
    /// evidence is exactly what is being deleted: a manifest of what was
    /// re-homed cannot prove completeness, since an omitted recid is omitted
    /// from the manifest too. The verifiable moment is here, while the
    /// segments still exist. What it buys is that an under-re-emission — a
    /// dropped `T_PREALLOC`, a dropped null-content record — fails loudly
    /// BEFORE the data is destroyed, instead of silently until the free-recid
    /// rebuild re-issues the recid and a later allocation collides with it.
    /// The skip audit cannot see this class at all: a record wholly contained
    /// in the range with no surviving append leaves no entry to skip.
    ///
    /// Chunking it across ticks is sound because the predicate is MONOTONE:
    /// once `state_lsn[R]` is absent-or-above, only a new self-contained entry
    /// at a still higher LSN can change it.
    ///
    /// Its boundary, stated so it is not over-trusted: W10 is sufficient for
    /// OMISSION, not for image FIDELITY. It asks "was this recid re-homed?",
    /// and a cleaner that emitted a CRC-valid but semantically wrong image
    /// raises `state_lsn` just the same and passes.
    fn verifyUnit(self: *WalState, budget: *const Budget, records_so_far: usize) DbError!usize {
        const rec_room: usize = if (budget.max_records > 0)
            @max(budget.max_records -| records_so_far, 1)
        else
            SCAN_UNIT_ENTRIES;
        const c = &self.cleaner.?;
        const Verify = struct {
            st: *WalState,
            boundary: i64,
            target: i64,
            fn visit(v: @This(), recid: u64) DbError!bool {
                if (v.st.ids.state_lsn.get(recid)) |sl| {
                    if (sl <= v.boundary) {
                        v.st.diag.note(W_CLEAN_UNREHOMED, v.target, 0, recid, sl);
                        return error.DataCorruption;
                    }
                }
                return true;
            }
        };
        const steps = try scanUnit(
            c,
            &self.segs,
            &self.diag,
            self.alloc,
            rec_room,
            Verify{ .st = self, .boundary = c.boundary_lsn, .target = c.target_seq },
            Verify.visit,
        );
        if (c.range_done) c.verified = true;
        return steps;
    }

    /// Closes a cycle: append the forced `'K'`, then unlink.
    ///
    /// **Ordering is the whole content of this method.** Every re-emitted
    /// image was forced as it was written and every rollover sealed its
    /// predecessor with a size-persisting force, so no mark ever attests
    /// bytes that were not forced (W1). The `'K'` is forced before the unlink
    /// (W5): a failed unlink is a leak the next open retries, never
    /// permission to advance an unproven mark. Every crash point in between
    /// is state-preserving — before the mark the retiring segments replay and
    /// cleaning simply re-runs, after it they are already superseded.
    fn finishCycle(self: *WalState, closed: *std.atomic.Value(bool)) DbError!void {
        const target = self.cleaner.?.target_seq;
        const log_start = self.cleaner.?.log_start_lsn;
        try self.appendMark(closed, target, log_start);
        var retired: u64 = 0;
        for (self.segs.segmentsSlice()) |*s| {
            if (s.seq > target) break;
            retired += s.file_len;
        }
        self.segs.unlinkThrough(target) catch |e| {
            if (self.diag.reason.len == 0)
                self.diag.note(W_CLEAN_IO, target, 0, 0, 0);
            self.failClosed(closed);
            return e;
        };
        self.cleaner_bytes_retired += @intCast(retired);
        self.cleaner = null;
    }

    /// One cleaning tick: re-emit, then verify (W10), then close the cycle —
    /// as far as `budget` allows, stopping at the first limit reached. Returns
    /// the bytes written. At most ONE cycle is closed per tick, so a caller
    /// driving this in a loop always sees the cycle boundary and can
    /// re-decide.
    fn cleanTick(self: *WalState, closed: *std.atomic.Value(bool), budget: *const Budget) DbError!i64 {
        var timer: ?std.time.Timer = if (budget.max_nanos > 0)
            std.time.Timer.start() catch null
        else
            null;
        var written: i64 = 0;
        var records: usize = 0;
        var closed_cycle = false;
        var pending: ?DbError = null;
        while (self.cleaner != null) {
            const log_before = self.segs.logBytes();
            const retired_before = self.cleaner_bytes_retired;
            const published = self.cleaner.?.published;
            const verified = self.cleaner.?.verified;
            var step_err: ?DbError = null;
            if (!published) {
                if (self.publishUnit(closed, budget, written, records)) |n| records += n else |e| step_err = e;
            } else if (!verified) {
                if (self.verifyUnit(budget, records)) |n| records += n else |e| step_err = e;
            } else {
                if (self.finishCycle(closed)) |_| {
                    closed_cycle = true;
                    written += self.chargeCleaner(log_before, retired_before);
                    break;
                } else |e| step_err = e;
            }
            if (step_err) |e| {
                // The two error classes part company HERE, and the reference
                // separates them explicitly: `IOException` goes through
                // `failClosed`, and only a `DBException` — a W10 refusal or an
                // identity disagreement — rewinds and keeps the handle
                // (StoreWAL.java:2628-2660).
                //
                // Collapsing them is not cosmetic. Automatic cleaning runs
                // INSIDE commit, after the section is forced and applied and
                // the staged transaction cleared, so a read error while
                // reopening a retiring segment would return an error from
                // `commit()` with the store still open and later writes still
                // admitted — the store's I/O is broken and it says so once,
                // then carries on.
                //
                // Zig's third class — an allocator refusal (risk 14,
                // operational) — takes the rewind arm: nothing durable
                // happened (the post-durability halves fail the store closed
                // inside their own units before returning), the LSN is
                // unmoved, and a retry under less pressure is legitimate.
                if (e == error.Io) {
                    if (self.diag.reason.len == 0)
                        self.diag.note(W_CLEAN_IO, 0, 0, 0, 0);
                    self.failClosed(closed);
                    pending = e;
                    break;
                }
                // A unit refused — W10 caught an under-re-emission, or an
                // identity map disagreed with the inner store. The cursor has
                // ALREADY stepped past the entry that refused (it advances
                // before the visitor runs), so a later tick would resume
                // beyond it, find nothing wrong in what remains, and write the
                // mark: the loud refusal would become exactly the silent loss
                // it exists to prevent. Rewind, so any retry re-walks the
                // range from the bottom and reaches the same verdict — or a
                // genuinely different one, if a commit has since re-homed the
                // recid, which makes the retirement safe for real.
                if (self.cleaner) |*cc| cc.rewind();
                pending = e;
                break;
            }
            written += self.chargeCleaner(log_before, retired_before);
            if (budget.max_records > 0 and records >= budget.max_records) break;
            if (budget.max_bytes > 0 and written >= @as(i64, @intCast(budget.max_bytes))) break;
            if (timer) |*t| {
                if (t.read() >= budget.max_nanos) break;
            }
        }
        if (pending) |e| return e;
        if (closed_cycle) {
            // The cycle is closed and its whole cost is now charged, so this
            // is the first moment its net is knowable. THREE bands, not two:
            // halving on any gain oscillates around the break-even width,
            // because a cycle that barely pays is not evidence the width is
            // too big. Widen when it does not pay, hold when it pays modestly,
            // and give width back only when it pays HANDSOMELY.
            const cost = self.cleaner_bytes_written - self.cycle_written_at;
            const gain = self.cleaner_bytes_retired - self.cycle_retired_at - cost;
            if (gain <= cost >> 3) {
                self.cycle_width = @min(CYCLE_WIDTH_CAP, @max(self.cycle_width, 1) * 2);
            } else if (gain > cost >> 1) {
                self.cycle_width = @max(self.cycle_width / 2, 1);
            }
            self.last_cycle_saturated = self.cycle_saturated;
        }
        return written;
    }

    /// Commit's inline clean. Gated on the TRIGGER alone, never on "a cycle is
    /// open": continuing an open cycle here regardless would mean the first
    /// commit after a background tick started one dragged it to completion
    /// synchronously, moving the work back onto the commit path. An abandoned
    /// cycle costs nothing durable — its images are forced and its retired
    /// segments simply stay, so the log carries duplicates until someone
    /// finishes it.
    fn autoCleanLocked(self: *WalState, closed: *std.atomic.Value(bool)) DbError!void {
        if (!self.cleaningDue()) {
            self.clearLatch(); // the floor outlives a dip; see beginCycleIfDue
            return;
        }
        // ONE bounded slice per commit. This runs inside commit's write-lock
        // hold and cannot release it, so a loop here would be one
        // uninterrupted hold for the whole pass: the per-tick budget would
        // bound an internal iteration while the commit that triggered it
        // still paid for all of them, consecutively, with every reader and
        // writer waiting.
        if (self.cleaner != null or try self.beginCycleIfDue(closed)) {
            _ = try self.cleanTick(closed, &FOREGROUND_BUDGET);
        }
        // The exception is the hard ceiling. Once the log has run away — past
        // twice its target — the writer participates until it is back under,
        // and the pause is accepted deliberately: an unbounded pause is the
        // lesser evil against an unbounded log.
        while (self.cleaningUrgent() and
            (self.cleaner != null or try self.beginCycleIfDue(closed)))
        {
            _ = try self.cleanTick(closed, &FOREGROUND_BUDGET);
        }
    }

    /// `checkpoint()`'s body: clean the log all the way down.
    ///
    /// Rolling first is what makes this a WHOLE-log clean — every
    /// section-bearing segment is then strictly below the active one, so a
    /// single cycle whose target is `active.seq - 1` retires all of them and
    /// its re-emission set is the whole committed store. One cycle, one mark,
    /// one unlink, through exactly the machinery a budgeted tick uses.
    fn cleanWholeLog(self: *WalState, closed: *std.atomic.Value(bool)) DbError!void {
        while (self.cleaner != null) {
            _ = try self.cleanTick(closed, &UNBOUNDED_BUDGET); // finish a partial cycle
        }
        const log_before = self.segs.logBytes();
        const retired_before = self.cleaner_bytes_retired;
        try self.rollActiveIfNonempty(closed);
        _ = self.chargeCleaner(log_before, retired_before);
        const target = self.segs.active().?.seq - 1;
        // Below the first sequence number there is nothing to retire: the
        // active segment is the store's first and it is empty, so the log is
        // already as small as it can be.
        if (target < FIRST_SEQ or self.segs.segmentsSlice().len < 2) return;
        self.startCycle(target);
        while (self.cleaner != null) {
            _ = try self.cleanTick(closed, &UNBOUNDED_BUDGET);
        }
        self.abandonEpisode(); // an explicit full clean re-arms the automatic one
    }

    /// Writes a `'K'` mark: the fact that everything at or below
    /// `cleaned_through_seq` may be removed, and where the retained log
    /// begins. Forced before any unlink (W5).
    fn appendMark(
        self: *WalState,
        closed: *std.atomic.Value(bool),
        cleaned_through_seq: i64,
        log_start_lsn: i64,
    ) DbError!void {
        var body = buildMarkBody(cleaned_through_seq, log_start_lsn);
        const r = try self.reserveLsn();
        var bctx = RawBodyCtx{ .body = &body };
        appendSection(&self.segs, self.segment_bytes, self.segs.io, TAG_MARK, r.lsn, self.alloc, &bctx, emitRawBody) catch |e| {
            if (self.diag.reason.len == 0)
                self.diag.note(W_CLEAN_WRITE, self.activeSeq(), 0, 0, 0);
            self.failClosed(closed);
            return e;
        };
        self.next_lsn = r.after;
    }

    fn activeSeq(self: *WalState) i64 {
        return if (self.segs.active()) |a| a.seq else 0;
    }
};

/// A pre-built section body ('C' image batch or 'K' mark), emitted verbatim.
/// Both passes see the same immutable slice, so the output is identical by
/// construction.
const RawBodyCtx = struct { body: []const u8 };

fn emitRawBody(ctx: *const RawBodyCtx, sink: *BodySink) DbError!void {
    try sink.write(ctx.body);
}

fn freeOps(alloc: Allocator, ops: *std.ArrayListUnmanaged(WalOp)) void {
    for (ops.items) |op| if (op.data) |d| alloc.free(d);
    ops.deinit(alloc);
}

// ============================== the cleaner (B3) =============================
// Port of rust's A3 (`wal.rs`, the cleaner block), which is itself Java
// `StoreWAL`'s incremental cleaner. Every constant is the reference's exact
// number — the budget values are a measured deliverable, not a detail.

/// One cleaning tick's allowance. `0` means "no limit" in every field, which is
/// what an explicit `checkpoint()` runs under.
const Budget = struct {
    max_records: usize,
    max_bytes: u64,
    max_nanos: u64,
};

/// The budget a COMMIT pays (D8, adopted from the reference verbatim).
///
/// These numbers are the deliverable, not a detail. Java measured the
/// store-size sweep that produced them: against the previous `(4096 records,
/// 8 MiB, no time bound)`, commits over 1 ms went 326 -> 1 and p99.9
/// 744 µs -> 176 µs, for ~1% of log high-water and ZERO extra device bytes.
/// `max_nanos` is a SOFT ceiling — checked between work units, so a single
/// oversize image still runs whole — which makes it a bound on how much work
/// is STARTED, not a deadline.
const FOREGROUND_BUDGET = Budget{
    .max_records = 256,
    .max_bytes = 512 << 10,
    .max_nanos = 500_000,
};

/// What `checkpoint()` runs under: no limit, because the caller asked for all
/// of it.
const UNBOUNDED_BUDGET = Budget{ .max_records = 0, .max_bytes = 0, .max_nanos = 0 };

/// Entries one scan unit walks when the budget names no record limit.
const SCAN_UNIT_ENTRIES: usize = 256;

/// Window for the two scans. Small on purpose: they read entry HEADERS and
/// seek over payloads, so a replay-sized window would read a megabyte to
/// decode ten bytes whenever entries are far apart, and the "bounded unit"
/// would not be bounded in device reads at all.
const SCAN_BUF: usize = 4096;

/// Ceiling on `WalState.cycle_width`. A cycle's CLOSE is not budgeted —
/// summing the retiring prefix, then closing, deleting and fsyncing every file
/// in it, all under the write lock — so an uncapped width buys mark
/// amortisation with an unbounded pause, which is the trade the incremental
/// cleaner exists to refuse.
const CYCLE_WIDTH_CAP: usize = 64;

/// A cleaning cycle in progress: retire every segment with `seq <= target_seq`
/// by re-emitting, above them, a self-contained image of every record whose
/// state still lives inside them. Resumable across ticks with any budget.
const Cleaner = struct {
    /// `cleanedThroughSeq` the closing `'K'` will attest.
    target_seq: i64,
    /// `logStartLsn` the closing `'K'` will attest — the successor's STATED
    /// start, read from its header rather than computed, so the number
    /// recovery compares against is the number the writer recorded.
    log_start_lsn: i64,
    /// The last LSN the retiring range accounts for, `log_start_lsn - 1`.
    ///
    /// Deriving the re-emission boundary from the number the mark will record
    /// — rather than from the retiring segment's own `last_lsn` — makes the
    /// writer's obligation and recovery's check two readings of ONE value, and
    /// it is total over the empty-segment case, where a `last_lsn` of 0 says
    /// nothing.
    boundary_lsn: i64,
    /// Phase 1 (re-emit) has walked the whole range.
    published: bool = false,
    /// Phase 2 (W10) has walked it again.
    verified: bool = false,

    // ---- the scan cursor: phase 1 uses it, then rewinds and phase 2 reuses it
    /// Index into the segment list; the retiring range is a prefix of it.
    seg: usize = 0,
    /// Offset of the next SECTION to enter within `seg`.
    offset: u64 = 0,
    /// Offset of the next ENTRY inside the section being walked, or `null`
    /// between sections.
    entry_pos: ?u64 = null,
    /// End of the section body being walked.
    body_end: u64 = 0,
    /// The current walk has reached the top of the retiring range.
    range_done: bool = false,

    fn init(target_seq: i64, log_start_lsn: i64) Cleaner {
        return .{
            .target_seq = target_seq,
            .log_start_lsn = log_start_lsn,
            .boundary_lsn = log_start_lsn - 1,
        };
    }

    /// Rewinds the cursor to the bottom of the range, for the second walk.
    /// Deliberately does NOT reset `published`/`verified` — the reference's
    /// `rewind` leaves them alone (`StoreWAL.java:2546-2552`), so a retry of a
    /// refused cycle resumes past phase 1 and re-reaches the same verdict in
    /// VERIFY rather than re-publishing. Do not "fix" this.
    fn rewind(self: *Cleaner) void {
        self.seg = 0;
        self.offset = 0;
        self.entry_pos = null;
        self.range_done = false;
    }
};

/// Did re-emitting `written` bytes to retire `retired` pay for itself? A GAIN
/// OF AN EIGHTH of what was written, not merely a positive one.
///
/// Epsilon progress is not progress. At the minimum segment size, one-at-a-time
/// cleaning was measured re-emitting 174 KB to reclaim 179 KB — a 33x write
/// amplification for a 3% gain — and a strictly-positive test calls that
/// success, so the cleaner runs forever, the log grows at traffic rate, and
/// the terminal is never reached.
fn paidForItself(retired: i64, written: i64) bool {
    return retired - written > (written >> 3);
}

/// Walks up to `max_steps` entries of the retiring range, handing each entry's
/// recid to `visit`, and stops early when `visit` returns `false`. Returns the
/// steps taken; sets `c.range_done` once the range is exhausted.
///
/// The unit is **an entry**, not a section. A section may be arbitrarily large
/// — a rollover happens only at a section boundary, so one commit can exceed
/// `segment_bytes` on its own — so "one section per tick" would hold the write
/// lock for an unbounded time, which is exactly the pause this cleaner
/// removes. Payloads are SEEKED over, not read, so the cost is proportional to
/// the number of entries rather than to the bytes they carry.
///
/// The reader is rebuilt per unit rather than carried in [`Cleaner`], which is
/// a deliberate difference from the reference: a `SecIn` borrows its segment's
/// file handle, and a cursor that owned one would make the WAL state
/// self-referential. It costs one window refill per unit — 256 entries — not
/// per section.
fn scanUnit(
    c: *Cleaner,
    segs: *WalSegmentSet,
    diag: *Diag,
    alloc: Allocator,
    max_steps: usize,
    ctx: anytype,
    comptime visit: fn (@TypeOf(ctx), u64) DbError!bool,
) DbError!usize {
    var steps: usize = 0;
    outer: while (steps < max_steps) {
        {
            const list = segs.segmentsSlice();
            if (c.seg >= list.len or list[c.seg].seq > c.target_seq) {
                c.range_done = true;
                return steps;
            }
            try list[c.seg].ensureOpen();
        }
        var leave_segment = false;
        var stop = false;
        {
            const seg = &segs.segmentsSlice()[c.seg];
            const valid_end = seg.valid_end;
            const seq = seg.seq;
            // The reader BORROWS the segment's handle, so it lives in this
            // inner scope, which ends BEFORE the leave path releases the
            // segment: the borrower dies before the owner closes the
            // descriptor. That is the handle rule `wal_segments.zig` states,
            // and rust enforces it by drop order; today `SecIn.deinit` only
            // frees its window, but scoping it keeps a future deinit change
            // from becoming a latent read of a closed fd (B3 review,
            // non-blocking finding 1).
            var r = try SecIn.init(seg.handle().?, alloc, SCAN_BUF, diag);
            defer r.deinit();
            // The HARD bound is the segment, set once; `rebound` then narrows
            // the soft bound per section without dropping the window.
            r.resetHard(SEG_HDR, valid_end);
            if (c.offset < SEG_HDR) c.offset = SEG_HDR;
            while (true) {
                if (steps >= max_steps) break;
                if (c.entry_pos == null) {
                    if (c.offset >= valid_end) {
                        leave_segment = true;
                        steps += 1;
                        break;
                    }
                    // The header is read THROUGH the window, and both bounds are
                    // checked BEFORE the bytes are: this walk verifies no CRC —
                    // the section was verified whole at open — so it says what it
                    // trusts, and a header or body running past the validated end
                    // would otherwise surface as a bare overrun out of a scan that
                    // catches none.
                    if (valid_end - c.offset < SEC_HDR) {
                        diag.note(W_CLEAN_SCAN_HDR, seq, c.offset, 0, 0);
                        return error.DataCorruption;
                    }
                    r.rebound(c.offset, valid_end);
                    var hdr: [@as(usize, SEC_HDR)]u8 = undefined;
                    try r.readFully(&hdr);
                    const h = parseSecHdr(&hdr);
                    const body_start = c.offset + SEC_HDR;
                    if (h.body_len < 0 or @as(u64, @intCast(h.body_len)) > valid_end - body_start) {
                        diag.note(W_CLEAN_SCAN_BODY, seq, c.offset, 0, h.body_len);
                        return error.DataCorruption;
                    }
                    c.body_end = body_start + @as(u64, @intCast(h.body_len));
                    c.offset = c.body_end; // where the NEXT section begins
                    // Entering a section costs a header read and is charged like
                    // an entry. Without that, a range of mark-only or empty
                    // sections is walked ENTIRELY within one unit at no budgeted
                    // cost — the same unbounded-work-under-the-lock defect as a
                    // per-section unit, with metadata instead of payload.
                    steps += 1;
                    if (h.tag == TAG_MARK) continue; // a 'K' body carries no entries
                    c.entry_pos = body_start;
                }
                r.rebound(c.entry_pos.?, c.body_end); // the section bound, window kept
                while (r.pos() < c.body_end and steps < max_steps) {
                    const recid = try nextEntryRecid(&r, seq, diag);
                    c.entry_pos = r.pos();
                    steps += 1;
                    if (!try visit(ctx, recid)) {
                        stop = true;
                        break;
                    }
                }
                if (c.entry_pos) |p| {
                    if (p >= c.body_end) c.entry_pos = null; // section done
                }
                if (stop) break;
            }
        }
        if (leave_segment) {
            // Released the moment the walk leaves it: what keeps the
            // descriptor count O(1) rather than O(segments in the range).
            segs.segmentsSlice()[c.seg].release();
            c.seg += 1;
            c.offset = 0;
            c.entry_pos = null;
            continue;
        }
        if (stop) break :outer;
    }
    return steps;
}

/// Decodes one entry for its recid alone, seeking over the payload.
fn nextEntryRecid(r: *SecIn, seq: i64, diag: *Diag) DbError!u64 {
    const ty = try r.readByte();
    const recid = try r.unpackLong();
    switch (ty) {
        T_PREALLOC, T_DELETE => {},
        T_RECORD => {
            _ = try r.unpackLong(); // capacity
            const len_plus = try r.unpackLong();
            if (len_plus != 0) {
                // Checked, unlike rust's bare add: `len_plus` is a disk value,
                // and a wrapped seek target would walk BACKWARDS through a
                // section instead of refusing (the overrun itself is caught
                // by the reader's soft limit either way — this pins the
                // refusing path).
                const to = std.math.add(u64, r.pos(), len_plus - 1) catch {
                    diag.note(wr.R_ENTRY_OVERRUN, seq, r.pos(), recid, 0);
                    return error.DataCorruption;
                };
                r.seek(to);
            }
        },
        T_APPEND => {
            _ = try r.unpackLong(); // base delta
            const len = try r.unpackLong();
            const to = std.math.add(u64, r.pos(), len) catch {
                diag.note(wr.R_ENTRY_OVERRUN, seq, r.pos(), recid, 0);
                return error.DataCorruption;
            };
            r.seek(to);
        },
        else => {
            diag.note(W_CLEAN_SCAN_TAG, seq, r.pos(), recid, ty);
            return error.DataCorruption;
        },
    }
    return recid;
}

// ------------------------------------------------------------ entry framing

const EmitCtx = struct {
    ops: []const WalOp,
    section_lsn: i64,
    alloc: Allocator,
};

/// Emits the §4.2 entry frames for one section body. Runs once per pass; both
/// passes see the same immutable ops, so the output is identical by
/// construction. Large payloads are written as their own sink calls, which the
/// sink routes past its coalescing buffer.
fn emitEntries(ctx: *const EmitCtx, sink: *BodySink) DbError!void {
    for (ctx.ops) |op| {
        var frame = DataOutput2.init(ctx.alloc);
        defer frame.deinit();
        switch (op.op) {
            T_PREALLOC, T_DELETE => {
                try frame.writeU8(op.op);
                try frame.packLong(op.recid);
            },
            T_RECORD => {
                try frame.writeU8(T_RECORD);
                try frame.packLong(op.recid);
                try frame.packLong(@as(u64, op.cap));
                try frame.packLong(if (op.data) |d| @as(u64, d.len) + 1 else 0);
            },
            T_APPEND => {
                try frame.writeU8(T_APPEND);
                try frame.packLong(op.recid);
                // Base identity, as a delta against this section's own LSN
                // (§4.2): >= 1 by construction, because the base was
                // established by a strictly earlier section, and typically one
                // byte because a hot record's base is recent.
                try frame.packLong(@as(u64, @intCast(ctx.section_lsn - op.base_lsn)));
                try frame.packLong(@as(u64, op.data.?.len));
            },
            T_TRANSIENT => continue, // not logged
            else => unreachable, // unknown classified op
        }
        try sink.write(frame.bytes());
        if (op.op == T_RECORD or op.op == T_APPEND) {
            if (op.data) |d| try sink.write(d);
        }
    }
}

// ---------------------------------------------------------------- StoreWAL

/// Transactional store (spec 02 §7). One global writer behind `rw`.
pub const StoreWAL = struct {
    const Self = @This();

    rw: std.Thread.RwLock = .{},
    state: WalState,
    /// The store's BASE path — `<base>.wal.<16 hex>` are its segments.
    /// Absolutized by the namespace layer; this is the caller's spelling.
    base: []u8,
    lease_table: LeaseTable,
    closed: std.atomic.Value(bool),
    /// Bumped on every `rollback` so open collections know their append-only
    /// structural caches (e.g. the btree left-edge spine) may have been
    /// reverted to a shorter tree and must be rebuilt before the next
    /// structural op.
    struct_gen: std.atomic.Value(u64),
    /// D2: delete the whole namespace inside `close`, while the lock is still
    /// held. Set by the DB layer's delete-after-close mode.
    delete_on_close: std.atomic.Value(bool),
    alloc: Allocator,
    /// TCK convenience: `init` created a temp dir that `deinit` must remove.
    tmp_dir: ?[]u8 = null,

    // ---------- construction ----------

    /// Opens the store at `base` (creating a fresh namespace if absent); its
    /// segments are `<base>.wal.<16 hex>`. Refuses (D1, deleting nothing) a
    /// regular file at `<base>` or `<base>.wal` and anything at `<base>.ckpt`.
    /// The caller owns the returned store and must `deinit` it. `thread_safe`
    /// selects the segment-lock bank of the inner StoreDirect (the WAL itself
    /// is always single-writer under one RwLock).
    pub fn open(alloc: Allocator, base: []const u8, thread_safe: bool) DbError!Self {
        return openCfg(alloc, base, .{ .thread_safe = thread_safe });
    }

    /// `replay_buf` is a test hook: a tiny window forces refill edges in
    /// streaming replay.
    pub fn openWith(alloc: Allocator, base: []const u8, thread_safe: bool, replay_buf: usize) DbError!Self {
        return openCfg(alloc, base, .{ .thread_safe = thread_safe, .replay_buf = replay_buf });
    }

    /// Opens with a non-default segment size. Rollover happens at a section
    /// boundary PAST this many bytes, so one section may exceed it.
    pub fn openSegmentBytes(alloc: Allocator, base: []const u8, segment_bytes: u64) DbError!Self {
        return openCfg(alloc, base, .{ .segment_bytes = segment_bytes });
    }

    pub fn openCfg(alloc: Allocator, base: []const u8, opts: WalOptions) DbError!Self {
        if (opts.segment_bytes < MIN_SEGMENT_BYTES) {
            return error.WrongConfiguration; // WAL segment size below the 61-byte minimum (a segment header plus one section header)
        }
        // D4, the platform gate: a durable writable open REQUIRES a working
        // directory fsync — the acknowledgement rule is "the section is forced
        // AND the directory entry of the segment holding it is durable" — and
        // Windows cannot express one. Refused BY NAME at open, with no
        // override: an escape hatch that skipped the fsync would make
        // acknowledged commits undurable across a crash while appearing to
        // work. The predicate is Java's exact one (an OS test, not a probe).
        // Read-only opens are exempt — they unlink, truncate and rotate
        // nothing, so they make no durability claim a missing directory fsync
        // could break.
        if (!opts.read_only and builtin.os.tag == .windows) {
            return error.WrongConfiguration; // StoreWAL durable mode is unsupported on Windows
        }
        const base_owned = alloc.dupe(u8, base) catch return error.OutOfMemory;
        errdefer alloc.free(base_owned);
        var inner = try StoreDirect.init(alloc, opts.thread_safe);
        var segs = WalSegmentSet.openWithIo(alloc, base, opts.read_only, opts.io) catch |e| {
            inner.deinit();
            return e;
        };
        // A failed recovery closes and frees the set, which releases the store
        // lock — Java's `finally { closeQuietly() }`.
        var local_diag: Diag = .{};
        const diag = opts.diag orelse &local_diag;
        const rec = wr.recover(&segs, &inner, opts.replay_buf, alloc, diag) catch |e| {
            segs.deinit();
            inner.deinit();
            return e;
        };
        return .{
            .state = .{
                .inner = inner,
                .segs = segs,
                .ids = rec.identities,
                .next_lsn = rec.next_lsn,
                .segment_bytes = opts.segment_bytes,
                .read_only = opts.read_only,
                .alloc = alloc,
            },
            .base = base_owned,
            .lease_table = LeaseTable.init(alloc),
            .closed = std.atomic.Value(bool).init(false),
            .struct_gen = std.atomic.Value(u64).init(0),
            .delete_on_close = std.atomic.Value(bool).init(false),
            .alloc = alloc,
        };
    }

    /// TCK / heap-signature convenience constructor (deviation — see PORT
    /// PROGRESS). Opens a fresh WAL namespace in a uniquely-named temp dir
    /// under cwd; `deinit` removes the whole dir. `open`/`openCfg` are the
    /// real constructors.
    pub fn init(alloc: Allocator, thread_safe: bool) DbError!Self {
        const N = struct {
            var counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
        };
        const n = N.counter.fetchAdd(1, .monotonic);
        const pid = std.os.linux.getpid();
        var buf: [128]u8 = undefined;
        const dir_name = std.fmt.bufPrint(&buf, "mapdb5_wal_tck_{d}_{d}.d", .{ pid, n }) catch unreachable;
        std.fs.cwd().deleteTree(dir_name) catch {};
        std.fs.cwd().makeDir(dir_name) catch return error.Io;
        // The directory is OURS to remove on every failure window until its
        // ownership has actually moved into `tmp_dir` — `deinit` deletes only
        // through that field, so an error before the handoff would otherwise
        // strand the directory.
        var dir_owned = false;
        errdefer if (!dir_owned) std.fs.cwd().deleteTree(dir_name) catch {};
        var base_buf: [160]u8 = undefined;
        const base = std.fmt.bufPrint(&base_buf, "{s}/store", .{dir_name}) catch unreachable;
        var s = try openCfg(alloc, base, .{ .thread_safe = thread_safe });
        errdefer s.deinit();
        s.tmp_dir = alloc.dupe(u8, dir_name) catch return error.OutOfMemory;
        dir_owned = true;
        return s;
    }

    pub fn deinit(self: *Self) void {
        if (!self.closed.load(.acquire)) self.close() catch {};
        self.state.clearStaged();
        self.state.staged.deinit(self.alloc);
        self.state.ids.deinit(self.alloc);
        self.state.segs.deinit();
        self.state.inner.deinit();
        self.lease_table.deinit();
        if (self.tmp_dir) |d| {
            std.fs.cwd().deleteTree(d) catch {};
            self.alloc.free(d);
        }
        self.alloc.free(self.base);
    }

    // ---------- helpers ----------

    fn checkClosed(self: *Self) DbError!void {
        if (self.closed.load(.acquire)) return error.StoreClosed;
    }

    /// In-lock read gate: recheck `closed` AFTER acquiring the shared lock.
    /// `close` publishes `closed` under the WRITE lock and tears the state
    /// down there, so a check taken before acquiring can be overtaken — and
    /// the result is observably wrong rather than untidy: a `get` of a record
    /// staged with `base_set` answers from the staged base without touching
    /// the (now closed) inner store, and `capacityRemaining` on it would
    /// answer `maxInt(usize)`. Java takes the read lock first and checks under
    /// it (`StoreWAL.java:1359-1386`).
    fn readGate(self: *Self) DbError!void {
        if (self.closed.load(.acquire)) return error.StoreClosed;
    }

    /// In-lock mutation gate: under the write lock, reject a closed store
    /// (linearized close) or a read-only one. Every mutation path calls this
    /// immediately after acquiring `rw`. `close` is the intentional exception.
    fn writeGate(self: *Self) DbError!void {
        if (self.closed.load(.acquire)) return error.StoreClosed;
        if (self.state.read_only) return error.ReadOnly;
    }

    /// Serialize a value with the store's allocator (outside any lock, Java/Rust).
    fn serializeVal(self: *Self, comptime R: type, value: R, ser: anytype) DbError![]u8 {
        var out = DataOutput2.init(self.alloc);
        errdefer out.deinit();
        try ser.serialize(&out, value);
        return out.toOwnedSlice();
    }

    // ---------- config (D8) ----------

    /// Floor under the cleaning trigger (D8): a log smaller than this is never
    /// cleaned automatically, however small the live data is. 0 disables
    /// automatic cleaning.
    pub fn setMinLogBytes(self: *Self, bytes: u64) DbError!void {
        // Lock FIRST, then re-check under it: `close` publishes `closed` while
        // holding this same lock, so a check taken before acquiring it can be
        // overtaken and the setter would then mutate a torn-down state and
        // report success (Java holds the write lock across its check,
        // StoreWAL.java:2107-2135).
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        self.state.min_log_bytes = bytes;
        // A configuration change invalidates every observation the current
        // episode made, latch included.
        self.state.abandonEpisode();
    }

    /// Size past which the writer seals the active segment and rolls to the
    /// next one (D8). Tuning knob and test hook, exactly as in the reference
    /// (`StoreWAL.java:2171-2181`): the rollover itself always happens at a
    /// section boundary (W3), so a single section larger than this simply gets
    /// a segment of its own.
    ///
    /// The same floor as the open-time option — a segment below it cannot hold
    /// one section — and, like Java, the floor is checked BEFORE the lock, so
    /// a bad argument is refused identically on an open and on a closed store.
    pub fn setSegmentBytes(self: *Self, bytes: u64) DbError!void {
        if (bytes < MIN_SEGMENT_BYTES) return error.WrongConfiguration;
        // See `setMinLogBytes`: lock first, re-check under it. (Java does not
        // abandon the cleaning episode here, and neither do the ports — the
        // omission is faithful.)
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        self.state.segment_bytes = bytes;
    }

    /// Space-amplification target (D8): clean once the log exceeds this
    /// multiple of the live data.
    pub fn setSpaceAmplification(self: *Self, factor: u32) DbError!void {
        if (factor == 0) return error.WrongConfiguration; // must be at least 1
        // See `setMinLogBytes`: lock first, re-check under it.
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        self.state.space_amplification = factor;
        // See `setMinLogBytes`: the episode's observations are stale now.
        self.state.abandonEpisode();
    }

    /// D2: delete this base's whole segment namespace inside [`close`], while
    /// the store lock is still held. Used by the DB layer's delete-after-close
    /// and temporary-store modes.
    pub fn setDeleteOnClose(self: *Self, on: bool) void {
        self.delete_on_close.store(on, .release);
    }

    // ---------- observers ----------

    /// Bytes the log currently costs on the device.
    pub fn logBytes(self: *Self) DbError!u64 {
        self.rw.lockShared();
        defer self.rw.unlockShared();
        try self.readGate();
        return self.state.segs.logBytes();
    }

    /// Sequence numbers of the live segments, ascending. Caller frees.
    pub fn segmentSeqs(self: *Self, alloc: Allocator) DbError![]i64 {
        self.rw.lockShared();
        defer self.rw.unlockShared();
        // Lock-then-check like every fallible read: `segs.close` clears the
        // segment list, so an ungated call queued behind `close` would answer
        // an allocated EMPTY namespace rather than `StoreClosed`.
        try self.readGate();
        const segs = self.state.segs.segmentsSlice();
        const out = alloc.alloc(i64, segs.len) catch return error.OutOfMemory;
        for (segs, 0..) |s, i| out[i] = s.seq;
        return out;
    }

    /// The LSN the next section will carry.
    pub fn nextLsn(self: *Self) i64 {
        self.rw.lockShared();
        defer self.rw.unlockShared();
        return self.state.next_lsn;
    }

    /// How many segment files this store currently holds open. The steady
    /// state is at most ONE — the active segment — and that bound is the
    /// point, so it is observable rather than merely intended.
    pub fn openSegmentFiles(self: *Self) usize {
        self.rw.lockShared();
        defer self.rw.unlockShared();
        return self.state.segs.openFileCount();
    }

    /// The store's base path: its segments are `<base>.wal.<16 hex>`.
    pub fn basePath(self: *const Self) []const u8 {
        return self.base;
    }

    /// Whether the futility latch is armed: the log is fully compacted and
    /// still cannot meet the configured space-amplification ratio, so
    /// automatic cleaning has stopped retrying it. Released by a quiet
    /// trigger, a configuration change, a further target's worth of growth, a
    /// materially lower target, or enough committed churn. Ungated like
    /// `nextLsn`: the post-close answer is a truthful snapshot.
    pub fn cleaningExhausted(self: *Self) bool {
        self.rw.lockShared();
        defer self.rw.unlockShared();
        return self.state.cleaningExhausted();
    }

    /// Lifetime cleaner accounting: bytes re-emitted, bytes retired. Ungated
    /// like `nextLsn`: the post-close answer is a truthful snapshot.
    pub fn cleanerBytes(self: *Self) struct { written: i64, retired: i64 } {
        self.rw.lockShared();
        defer self.rw.unlockShared();
        return .{
            .written = self.state.cleaner_bytes_written,
            .retired = self.state.cleaner_bytes_retired,
        };
    }

    /// The store-level diagnostic (a copy): describes the most recent commit
    /// failure this handle mapped, or nothing. Post-close reads are permitted
    /// — the diag is exactly what a caller wants to inspect after W9 closed
    /// the store.
    pub fn lastDiag(self: *Self) Diag {
        self.rw.lockShared();
        defer self.rw.unlockShared();
        return self.state.diag;
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
        self.rw.lockShared();
        defer self.rw.unlockShared();
        try self.readGate();
        const s = self.state.staged.getPtr(recid) orelse
            return self.state.inner.read(recid, action);
        if (s.deleted) return error.GetVoid;
        const m = try self.state.merged(recid, s);
        defer if (m) |mm| self.alloc.free(mm);
        // ONE ActionGuard covers BOTH dispatch branches: a reentrant `on_null`
        // action must trip the Debug assert, not deadlock on the shared lock.
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
        // Fail at update time, not commit time. Oversize CONTENT is fine
        // (stored linked at commit) — but content that fits a plain record
        // must also fit with its headroom, because linked records take no
        // appends and silently going linked would break the guarantee the
        // headroom was asked for.
        if (bytes) |b| {
            const plain = 4 +| @as(u64, b.len);
            const max = @as(u64, iv.MAX_CAPACITY);
            if (plain <= max and ((plain +| @as(u64, headroom) +| 15) & ~@as(u64, 15)) > max) {
                return error.RecordTooLarge;
            }
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

        // Every remaining serializer callback made while `rw` is held —
        // `equals`, the CAS-side `serialize(new)`, and the `deinitElem`
        // cleanup — runs under ONE ActionGuard, so a reentrant callback trips
        // the Debug assert instead of deadlocking on the global write lock.
        // The `deinitElem` defer is registered AFTER entering, so LIFO frees
        // it while the guard is still active.
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
        // writeGate re-checks `closed` under the lock: otherwise a commit of a
        // pure staged preallocation could append+force a section after `close`
        // completed, since applying it does not touch the inner store.
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        return self.state.commitLocked(&self.closed);
    }

    /// Cleans the log all the way down: retire every segment below a freshly
    /// rolled one by re-emitting, above them, a self-contained image of every
    /// record they still own, then a forced `'K'` mark authorizing their
    /// removal, then the unlink.
    ///
    /// Rolling first is what makes it a whole-log clean; the cycle then runs
    /// unbudgeted, because the caller asked for all of it. This is the
    /// incremental cleaner with its budget set to "everything" — the only
    /// sense in which a whole-store checkpoint still exists. The v1 whole-file
    /// rewrite, its `.ckpt` temp and its rename commit point are gone.
    ///
    /// Staged (uncommitted) mutations are untouched: they exist only in
    /// memory and are not part of any log.
    pub fn checkpoint(self: *Self) DbError!void {
        mod.assertNotInAction("checkpoint");
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        // The Diag protocol: cleared on entry so it always describes THIS
        // checkpoint's failure or nothing.
        self.state.diag = .{};
        return self.state.cleanWholeLog(&self.closed);
    }

    pub fn compact(self: *Self) DbError!void {
        return self.checkpoint();
    }

    pub fn close(self: *Self) DbError!void {
        // Acquire the write lock BEFORE publishing `closed`, so an in-flight
        // commit that rechecks `closed` under the lock observes the close
        // atomically (no append after close). Any op still runs to completion
        // first (it holds the lock); we then win it and shut down.
        self.rw.lock();
        defer self.rw.unlock();
        if (self.closed.swap(true, .acq_rel)) return; // double close is a no-op
        // D2: the namespace deletion runs while the store lock is STILL HELD —
        // close-then-delete would let a second opener acquire the namespace
        // and have its live segments deleted underneath it. The deletion error
        // is captured, both teardowns always run, and it takes precedence.
        var deleted: DbError!void = {};
        if (self.delete_on_close.load(.acquire) and !self.state.read_only) {
            deleted = self.state.segs.deleteNamespace();
        }
        self.state.segs.close();
        const inner_res = self.state.inner.close();
        try deleted;
        try inner_res;
    }

    pub fn isClosed(self: *Self) bool {
        return self.closed.load(.acquire);
    }

    pub fn verify(self: *Self) DbError!void {
        self.rw.lockShared();
        defer self.rw.unlockShared();
        try self.readGate();
        return self.state.inner.verify();
    }

    pub fn getAllRecids(self: *Self, alloc: Allocator) DbError![]u64 {
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
        const was_staged = self.state.staged.contains(recid);
        // Runs for its GetVoid validation even when nothing will be staged.
        _ = try self.state.stagedForWrite(recid);
        if (data.len == 0) {
            // A zero-length append stages NOTHING — not even the empty
            // `Staged` entry `stagedForWrite` just left behind, which would
            // turn a contract-defined no-op into a section at commit:
            // T_PREALLOC on an untouched record (burning an LSN, and naming a
            // content-live recid in a prealloc, which §4.2 rejects on replay),
            // or a zero-length T_APPEND that `inner.append` REFUSES on a
            // linked record — after the section is durable, so the refusal
            // arrives on the post-durability path and fails the store closed.
            if (!was_staged) self.removeStaged(recid);
            const base_len: usize = blk: {
                if (self.state.staged.getPtr(recid)) |s| {
                    if (s.base_set) break :blk if (s.base) |b| b.len else 0;
                }
                if ((try self.state.inner.recState(recid)) == STATE_LIVE) {
                    if (try self.state.inner.rawGet(self.alloc, recid)) |b| {
                        defer self.alloc.free(b);
                        break :blk b.len;
                    }
                }
                break :blk 0;
            };
            const appends_len: usize = if (self.state.staged.getPtr(recid)) |s| s.appends_len else 0;
            return .{ .new_size = base_len + appends_len };
        }
        const base_live = blk: {
            const s = self.state.staged.getPtr(recid).?;
            break :blk !s.base_set and (try self.state.inner.recState(recid)) == STATE_LIVE;
        };
        if (base_live) {
            const cap_rem = try self.state.inner.capacityRemaining(recid);
            const appends_len = self.state.staged.getPtr(recid).?.appends_len;
            if (appends_len + data.len > cap_rem) {
                // REFUSED is a no-op, so it must stage NOTHING. An empty
                // `Staged` left behind here would be classified as T_PREALLOC
                // at commit: it burns an LSN, and a prealloc naming a
                // content-live record is exactly what §4.2 rejects on replay.
                if (!was_staged) self.removeStaged(recid);
                return .refused;
            }
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

    fn removeStaged(self: *Self, recid: u64) void {
        if (self.state.staged.fetchRemove(recid)) |kv| {
            var s = kv.value;
            s.deinit(self.alloc);
        }
    }

    pub fn capacityRemaining(self: *Self, recid: u64) DbError!usize {
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
        // NEITHER IDENTITY MOVES ON ROLLBACK, and that is the whole rule: both
        // are set only by a committed apply, so a transaction that never
        // committed established nothing to undo. The `created` recids deleted
        // just above were preallocated in inner at op time but never logged,
        // so they hold no identity either.
        //
        // Signal open collections their append-only structural caches may now
        // describe a taller-than-real tree (a reverted uncommitted grow).
        _ = self.struct_gen.fetchAdd(1, .release);
    }
};

test {
    std.testing.refAllDecls(@This());
}

// ------------------------------------------------- in-module cleaner tests
// Port of rust's seven A3-only in-module tests (`wal.rs`, "the cleaner"
// section). In-module for the same reason rust's are: they poke `WalState`
// internals no public surface reaches. The black-box cleaner tests live in
// `store_wal_test.zig` with the rest of the public suite.

const testing = std.testing;
const sers = @import("../ser/serializers.zig");
const TestL = sers.LongSer.instance;
const TestB = sers.ByteArraySer.instance;

var wal_test_scratch_n: std.atomic.Value(u64) = .init(0);

/// A unique scratch dir with a base path inside it (test-section local; the
/// black-box suite has its own richer twin).
const TestScratch = struct {
    alloc: Allocator,
    dir: []u8,
    base: []u8,

    fn init(alloc: Allocator, tag: []const u8) !TestScratch {
        const n = wal_test_scratch_n.fetchAdd(1, .monotonic);
        const dir = try std.fmt.allocPrint(
            alloc,
            "/tmp/mapdb5_wal_cleaner_{d}_{s}_{d}",
            .{ std.os.linux.getpid(), tag, n },
        );
        errdefer alloc.free(dir);
        std.fs.cwd().deleteTree(dir) catch {};
        try std.fs.cwd().makePath(dir);
        const base = try std.fmt.allocPrint(alloc, "{s}/store.db", .{dir});
        return .{ .alloc = alloc, .dir = dir, .base = base };
    }

    fn deinit(self: *TestScratch) void {
        std.fs.cwd().deleteTree(self.dir) catch {};
        self.alloc.free(self.base);
        self.alloc.free(self.dir);
    }
};

fn testPut(s: *StoreWAL, v: i64) !u64 {
    return s.put(i64, testing.allocator, v, TestL);
}

fn testGet(s: *StoreWAL, recid: u64) !?i64 {
    return s.get(i64, testing.allocator, recid, TestL);
}

test "wal3 B3: a gain of an eighth is what counts as paying for itself" {
    // Epsilon progress is not progress: re-emitting 174 KB to reclaim 179 KB
    // is a 33x write amplification for a 3% gain, and a strictly-positive
    // test calls that success — so the cleaner runs forever and the terminal
    // is never reached.
    try testing.expect(!paidForItself(179_000, 174_000));
    try testing.expect(!paidForItself(100, 100));
    try testing.expect(!paidForItself(112, 100)); // exactly an eighth is not enough
    try testing.expect(paidForItself(113, 100));
    try testing.expect(paidForItself(1000, 100));
}

test "wal3 B3 W10: the mark is refused when a record was not re-homed" {
    // The check that cannot be deferred past the unlink: the evidence is
    // exactly what would be deleted. Fault injection drops one recid from
    // phase 1, which is the under-re-emission W10 exists for.
    var sc = try TestScratch.init(testing.allocator, "w10");
    defer sc.deinit();
    var s = try StoreWAL.openSegmentBytes(testing.allocator, sc.base, MIN_SEGMENT_BYTES);
    defer s.deinit();
    const victim = try testPut(&s, 1);
    try s.commit();
    var i: i64 = 0;
    while (i < 6) : (i += 1) {
        _ = try testPut(&s, i);
        try s.commit();
    }
    const segs_before = try s.segmentSeqs(testing.allocator);
    defer testing.allocator.free(segs_before);
    try testing.expect(segs_before.len > 2);
    s.state.drop_recid_from_publish = victim;

    try testing.expectError(error.DataCorruption, s.checkpoint());
    // The refusal names the record it is protecting, by identity.
    const d = s.lastDiag();
    try testing.expectEqual(W_CLEAN_UNREHOMED.ptr, d.reason.ptr);
    try testing.expectEqual(victim, d.recid);
    // Nothing was deleted and the durable log is intact.
    {
        const segs_after = try s.segmentSeqs(testing.allocator);
        defer testing.allocator.free(segs_after);
        try testing.expect(segs_after.len >= segs_before.len); // a refused cycle must not retire anything
    }
    try testing.expect(!s.isClosed()); // a refusal is not a store failure
    try testing.expectEqual(@as(?i64, 1), try testGet(&s, victim));

    // Removing the fault is NOT enough, and that is the reference's behaviour
    // rather than a port defect. `rewind` resets the cursor and deliberately
    // does not reset `published` (StoreWAL.java:2546-2552), so the partial
    // cycle a retry resumes is still past phase 1: it re-walks the range in
    // VERIFY, finds the same record un-re-homed, and refuses again. Java
    // reaches the identical state — its `checkpoint` also finishes the
    // partial cycle first (StoreWAL.java:2476) — so a port that "fixed" this
    // by re-publishing would diverge.
    s.state.drop_recid_from_publish = 0;
    try testing.expectError(error.DataCorruption, s.checkpoint());

    // The documented escape is the one the rewind comment names: a COMMIT
    // that re-homes the recid, which makes the retirement safe for real
    // rather than merely re-attempted. Then the same cycle completes.
    try s.update(i64, testing.allocator, victim, 1, TestL);
    try s.commit();
    try s.checkpoint();
    {
        const segs_after = try s.segmentSeqs(testing.allocator);
        defer testing.allocator.free(segs_after);
        try testing.expect(segs_after.len < segs_before.len);
    }
    try testing.expectEqual(@as(?i64, 1), try testGet(&s, victim));
    try s.close();
    var s2 = try StoreWAL.open(testing.allocator, sc.base, true);
    defer s2.deinit();
    try testing.expectEqual(@as(?i64, 1), try testGet(&s2, victim));
    try s2.verify();
}

test "wal3 B3 W5: the mark is forced before any unlink" {
    // A failed unlink is a leak the next open retries; an unlink before the
    // mark is durable is permission the log never gave.
    var sc = try TestScratch.init(testing.allocator, "w5");
    defer sc.deinit();
    var rec = wal_io.RecordingIo.init(testing.allocator);
    defer rec.deinit();
    const seam = rec.io();
    var s = try StoreWAL.openCfg(testing.allocator, sc.base, .{
        .segment_bytes = MIN_SEGMENT_BYTES,
        .io = &seam,
    });
    defer s.deinit();
    var i: i64 = 0;
    while (i < 4) : (i += 1) {
        _ = try testPut(&s, i);
        try s.commit();
    }
    const from = rec.events.items.len;
    try s.checkpoint();
    const evs = rec.events.items[from..];
    // The force the assertion finds must be the 'K' ITSELF — matched by the
    // event's TAG, not by position. A forced 'C' image is also a force_data
    // event, so "the last force precedes the first unlink" was satisfiable
    // with the mark's own force deleted (B3 review, blocking finding 1).
    // And it must be forced ON THE SEGMENT THE MARK WAS WRITTEN TO: the force's
    // `seq` is required to equal the seq of the mark's own section header. A
    // tag-matched force says only that SOME descriptor was synced — a force
    // that named the active segment while syncing a stale one passed this test
    // and the syscall gate both (B3 r2 review, blocking finding 1). Production
    // now derives the event and the fd from one `*Segment`, and this is the
    // assertion that a caller cannot reintroduce the split.
    var mark_force: ?usize = null;
    var mark_force_seq: i64 = 0;
    var mark_hdr_seq: ?i64 = null;
    var first_unlink: ?usize = null;
    for (evs, 0..) |e, idx| {
        if (e.kind == .sec_header and e.tag == TAG_MARK) mark_hdr_seq = e.seq;
        if (e.kind == .force_data and e.tag == TAG_MARK) {
            mark_force = idx;
            mark_force_seq = e.seq;
        }
        if (e.kind == .unlink and first_unlink == null) first_unlink = idx;
    }
    try testing.expect(mark_force != null); // the mark is forced, as the mark
    try testing.expect(mark_hdr_seq != null); // and it really was written
    try testing.expectEqual(mark_hdr_seq.?, mark_force_seq); // on the segment that holds it
    try testing.expect(first_unlink != null); // segments are retired
    try testing.expect(mark_force.? < first_unlink.?); // the 'K' before the first unlink
    try testing.expectEqual(wal_io.WalOpKind.dir_sync, evs[evs.len - 1].kind); // and the unlinks are made durable
}

test "wal3 B3: the closing mark states the successor's own first LSN" {
    // logStartLsn is READ from the successor's header, never computed, so the
    // number recovery compares against is the number the writer recorded.
    var sc = try TestScratch.init(testing.allocator, "mark");
    defer sc.deinit();
    var s = try StoreWAL.openSegmentBytes(testing.allocator, sc.base, MIN_SEGMENT_BYTES);
    defer s.deinit();
    var i: i64 = 0;
    while (i < 4) : (i += 1) {
        _ = try testPut(&s, i);
        try s.commit();
    }
    var local_closed = std.atomic.Value(bool).init(false);
    try s.state.rollActiveIfNonempty(&local_closed);
    const target = s.state.segs.active().?.seq - 1;
    s.state.startCycle(target);
    const c = s.state.cleaner.?;
    const want = for (s.state.segs.segmentsSlice()) |*seg| {
        if (seg.seq > target) break seg.headerFirstLsn();
    } else unreachable;
    try testing.expectEqual(want, c.log_start_lsn);
    try testing.expectEqual(want - 1, c.boundary_lsn);
    s.state.cleaner = null;
    try s.close();
}

test "wal3 B3: the futility latch arms only on a saturated completed episode" {
    var sc = try TestScratch.init(testing.allocator, "latch");
    defer sc.deinit();
    var s = try StoreWAL.open(testing.allocator, sc.base, true);
    defer s.deinit();
    const st = &s.state;
    // An episode that gained nothing, from a cycle that was NOT as wide as
    // the episode allows, says something about the width — not about the log.
    st.clean_floor_seq = 1;
    st.episode_retired = 0;
    st.episode_written = 0;
    st.cleaner_bytes_retired = 100;
    st.cleaner_bytes_written = 100;
    st.last_cycle_saturated = false;
    st.endEpisode();
    try testing.expect(!st.cleaningExhausted());
    // The same episode, concluded from a saturated cycle, is evidence.
    st.clean_floor_seq = 1;
    st.episode_retired = 0;
    st.episode_written = 0;
    st.last_cycle_saturated = true;
    st.endEpisode();
    try testing.expect(st.cleaningExhausted());
    // The guard is reset WITH the episode: an episode that did no work must
    // not arm the terminal on a previous one's wide cycle.
    try testing.expect(!st.last_cycle_saturated);
    // A quiet trigger releases it — the situation changed.
    st.min_log_bytes = std.math.maxInt(u64);
    var local_closed = std.atomic.Value(bool).init(false);
    try testing.expect(!(try st.beginCycleIfDue(&local_closed)));
    try testing.expect(!st.cleaningExhausted());
}

test "wal3 B3: an in-flight allocation over committed state refuses rather than guesses" {
    var sc = try TestScratch.init(testing.allocator, "inflight");
    defer sc.deinit();
    var s = try StoreWAL.openSegmentBytes(testing.allocator, sc.base, MIN_SEGMENT_BYTES);
    defer s.deinit();
    const r = try testPut(&s, 1);
    try s.commit();
    var i: i64 = 0;
    while (i < 4) : (i += 1) {
        _ = try testPut(&s, i);
        try s.commit();
    }
    // A recid that is BOTH committed-live and allocated by an in-flight
    // transaction cannot happen through the allocator; forge it, because the
    // cleaner's response to it is the point.
    s.state.staged.put(testing.allocator, r, Staged{ .created = true }) catch unreachable;
    try testing.expectError(error.DataCorruption, s.checkpoint());
    const d = s.lastDiag();
    try testing.expectEqual(W_CLEAN_INFLIGHT.ptr, d.reason.ptr);
    try testing.expectEqual(r, d.recid);
    s.state.clearStaged();
}

test "wal3 B3: the scan seeks over payloads instead of reading them" {
    // The cost of a cleaning pass is proportional to the number of ENTRIES,
    // not to the bytes they carry: a scan that read payloads would make the
    // "bounded unit" unbounded in device reads.
    var sc = try TestScratch.init(testing.allocator, "scancost");
    defer sc.deinit();
    // The segment must hold all twenty: at 1 MiB the log rolls over after ~10
    // and the walk below, which only ever enters the first segment, sees half
    // of them — the test then measures the read cost of a walk it did not
    // perform.
    var s = try StoreWAL.openSegmentBytes(testing.allocator, sc.base, 8 << 20);
    defer s.deinit();
    // Twenty big records in one segment: 20 entries, ~2 MB of payload.
    var i: u64 = 0;
    while (i < 20) : (i += 1) {
        const payload = try testing.allocator.alloc(u8, 100_000);
        defer testing.allocator.free(payload);
        @memset(payload, @truncate(i));
        _ = try s.put([]const u8, testing.allocator, payload, TestB);
        try s.commit();
    }
    const list = s.state.segs.segmentsSlice();
    try list[0].ensureOpen();
    const seg = &list[0];
    var diag: Diag = .{};
    var r = try SecIn.init(seg.handle().?, testing.allocator, SCAN_BUF, &diag);
    defer r.deinit();
    r.resetHard(SEG_HDR, seg.valid_end);
    var off: u64 = SEG_HDR;
    var entries: usize = 0;
    while (off < seg.valid_end) {
        r.rebound(off, seg.valid_end);
        var hdr: [@as(usize, SEC_HDR)]u8 = undefined;
        try r.readFully(&hdr);
        const h = parseSecHdr(&hdr);
        const body_start = off + SEC_HDR;
        const body_end = body_start + @as(u64, @intCast(h.body_len));
        r.rebound(body_start, body_end);
        while (r.pos() < body_end) {
            _ = try nextEntryRecid(&r, 1, &diag);
            entries += 1;
        }
        off = body_end;
    }
    seg.release();
    try testing.expectEqual(@as(usize, 20), entries);
    // Walking 20 entries over ~2 MB must not read the payloads.
    try testing.expect(r.reads <= 3 * @as(u64, entries));
}
