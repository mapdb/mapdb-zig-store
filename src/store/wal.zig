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
//! # The cleaner is B3
//!
//! `checkpoint()`/`compact()` and the automatic cleaning hook inside commit are
//! STUBS on this branch: the incremental cleaner (Java's re-home / W10 audit /
//! forced-`'K'` + unlink cycle) is slice B3, which joins this branch before it
//! reaches `main` — a cutover without the cleaner would be an unbounded-log
//! regression, which is why the branch does not merge without it. D8's three
//! config knobs land HERE (they are part of the public surface and the crash
//! harness needs them); the fields the cleaner consumes are maintained from
//! this slice on.

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

const wal_io = @import("wal_io.zig");
const WalIo = wal_io.WalIo;

const wr = @import("wal_recover.zig");
const Diag = wr.Diag;
const Identities = wr.Identities;
const SEC_HDR = wr.SEC_HDR;
const TAG_SECTION = wr.TAG_SECTION;

const wal_write = @import("wal_write.zig");
const appendSection = wal_write.appendSection;
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
    /// cleaner's (B3) futility-latch staleness clock.
    committed_state_changes: i64 = 0,
    /// The store-level diagnostic: cleared on entry to `commitLocked`, written
    /// immediately before every error return that maps a writer or apply
    /// failure, so it always describes the failure just returned or nothing.
    diag: Diag = .{},
    alloc: Allocator,

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

    /// B3 STUB — the automatic cleaning hook inside commit (Java's
    /// `cleanTickLocked` wrapper). The trigger (`logBytes > max(min_log_bytes,
    /// space_amplification × liveDataBytes)`), the bounded foreground slice and
    /// the futility latch all land with the cleaner. Until then commits never
    /// clean, which is exactly why this branch does not merge before B3.
    fn autoCleanLocked(self: *WalState, closed: *std.atomic.Value(bool)) DbError!void {
        _ = self;
        _ = closed;
    }

    fn activeSeq(self: *WalState) i64 {
        return if (self.segs.active()) |a| a.seq else 0;
    }
};

fn freeOps(alloc: Allocator, ops: *std.ArrayListUnmanaged(WalOp)) void {
    for (ops.items) |op| if (op.data) |d| alloc.free(d);
    ops.deinit(alloc);
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
        // B3: a configuration change also abandons the cleaning episode in
        // progress, latch included (`abandon_episode`).
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
        // B3: also `abandon_episode`.
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

    /// B3 STUB — the whole-log clean (Java's `checkpoint()`: roll first, then
    /// retire every segment below the fresh one by re-emitting a
    /// self-contained image of every record they still own, a forced `'K'`
    /// mark, and the unlink). Until the cleaner lands this is a no-op: the
    /// log is unbounded on this branch, which is why the branch does not
    /// reach `main` before B3. The v1 whole-file rewrite, its `.ckpt` temp
    /// and its rename commit point are gone.
    pub fn checkpoint(self: *Self) DbError!void {
        mod.assertNotInAction("checkpoint");
        self.rw.lock();
        defer self.rw.unlock();
        try self.writeGate();
        // B3: `cleanWholeLog(&self.closed)`.
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
