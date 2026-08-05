//! Stage C slice **C2z**: the zig deterministic generator for the two WAL v3
//! accept bundles, `wal3-zig-tail` and `wal3-zig-cleaned`
//! (`todo/store-cross/impl-contract-stage3.md` §5.1-§5.4 and §5.3.1).
//!
//! Run it:
//!
//! ```
//! zig build fixtures -- --wal3 <dir> [--force]
//! ```
//!
//! Writes `<dir>/wal3-zig-tail/` and `<dir>/wal3-zig-cleaned/` (segments only,
//! base `x`), plus `fragment.tsv` and `layout.tsv`. Assembly, compression and
//! the `expect`/`post` rows are the sync script's job (C4).
//!
//! ## Its own mode, and why it is not the parked `mainStageC`
//!
//! The Stage C plan's slice table says C2z "unparks `mainStageC` and deletes
//! the `main()` fail-fast". Taken literally that restores a generator that
//! cannot run: `mainStageC`'s body still drives `makeWalFixture`, which writes
//! the single-file `wal-v1-zig-*` fixtures a v3 store cannot produce — the
//! exact reason the fail-fast was added at B2 part 2. So this is a separate
//! mode beside `--golden`, the v1 half stays parked behind its refusal, and
//! its RETIREMENT stays where the plan actually put it (§9, C7z). The upshot
//! is also the useful one: all three engines' v3 generators now publish a
//! directory holding exactly the two bundles and the two sidecars, so C4
//! consumes them uniformly.
//!
//! ## The bar is NOT java's bytes
//!
//! D6 permits writers to diverge in how they group entries into sections, so
//! this generator is not required to reproduce `Wal3FixtureWriter`'s output
//! byte for byte. What it must reach is the STRUCTURE: every §5.3.1 witness
//! row, and all 24 adopted recipes deriving against the published bytes
//! (`python3 todo/store-cross/xcheck_bundles.py <dir>`). A green generator is
//! not sufficient evidence — row 5 is invisible to any generator, and
//! `rowFiveIsInvisibleToThisGenerator` asserts that blindness rather than
//! leaving it as a caveat.
//!
//! ## Why the `cleaned` workload is not §5.3's literal one
//!
//! Rollover is `active.file_len >= segment_bytes and !active.isEmpty()` tested
//! BEFORE a section is appended, so sections pile into a segment until it
//! crosses the limit and only the NEXT one rotates. Checkpointing after T3
//! makes the cleaner's image cover F's 1.2 MB of live data, which overflows
//! the segment holding it, so the forced `'K'` mark lands as the FIRST section
//! of the next segment — where §5.3.1 row 2 forbids it. Measured against THIS
//! engine by `rejectedCandidateWorkloadsMeasured`, because "java behaves this
//! way" is the hypothesis a port tests, not evidence about it.
//!
//! ## Self-checks, and one deliberate deviation from java and rust
//!
//! The published bytes are re-parsed by `Seg`, a local minimal v3 decoder
//! written from the format description rather than from `src/store/`. A
//! generator that self-checks with the code that wrote the bytes checks
//! nothing.
//!
//! Where java and rust raise an `AssertionError`/panic carrying a message and
//! their gates match SUBSTRINGS of it, this file returns
//! `error.ShapeViolation` and records a typed `Row` in a `Grade` — so the gate
//! asserts the refused row by IDENTITY. That is the same reasoning B1 used for
//! `Diag.reason`, and it is stronger: a test that matches "row 1 requires
//! exactly three retained segments" still passes when the refusal moves to a
//! different check whose message happens to contain that sentence.
//!
//! §5.3.1 row 6 (`file_len < segment_bytes`) is decided HERE and nowhere else:
//! `segment_bytes` is a generator setting and leaves no trace in the bytes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const root = @import("../root.zig");
const DbError = root.DbError;
const StoreWAL = root.StoreWAL;
const DataInput2 = root.DataInput2;
const DataOutput2 = root.DataOutput2;

// ------------------------------------------------------- §5.1 configuration

/// §5.1, pinned: rotates deterministically without 64 MiB fixtures. The
/// setter's floor is `SEG_HDR + SEC_HDR` = 61.
const SEGMENT_BYTES: u64 = 65_536;
/// §5.1: above the whole workload's byte total, so the budgeted auto-cleaner —
/// whose foreground slice has a WALL-CLOCK arm and would therefore stop at a
/// machine-speed-dependent point — never starts. Asserted after the fact.
const MIN_LOG_BYTES: u64 = 64 * 1024 * 1024;

pub const TAIL_ID = "wal3-zig-tail";
pub const CLEANED_ID = "wal3-zig-cleaned";
/// §5: distinct per bundle so content differs even where recids coincide.
const TAIL_BASE: u64 = 141;
const CLEANED_BASE: u64 = 151;
const BASE_NAME = "x";

// ----------------------------------------------------------------- serializer

/// Raw-bytes serializer: content == value, so the on-disk bytes are exactly
/// the contract's payload function.
const RawSer = struct {
    pub const Elem = []const u8;
    pub const instance: RawSer = .{};

    pub fn serialize(_: RawSer, out: *DataOutput2, v: []const u8) DbError!void {
        try out.writeAll(v);
    }
    pub fn deserialize(_: RawSer, alloc: Allocator, in: *DataInput2, size: ?usize) DbError![]const u8 {
        const n = size orelse return error.DataCorruption;
        const b = try alloc.alloc(u8, n);
        errdefer alloc.free(b);
        try in.readFully(b);
        return b;
    }
    pub fn cloneElem(_: RawSer, alloc: Allocator, v: []const u8) DbError![]const u8 {
        return alloc.dupe(u8, v);
    }
    pub fn deinitElem(_: RawSer, alloc: Allocator, v: []const u8) void {
        alloc.free(v);
    }
    pub fn compare(_: RawSer, a: []const u8, b: []const u8) std.math.Order {
        return std.mem.order(u8, a, b);
    }
    pub fn equals(_: RawSer, a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
    pub fn fixedSize(_: @This()) ?usize {
        return null;
    }
    pub fn equalsBySerializedBytes(_: @This()) bool {
        return true;
    }
};
const R = RawSer.instance;

/// Contract payload function: `payload(id, len)[i] = (i*131 + id) & 0xff`.
fn payloadAlloc(alloc: Allocator, payload_id: u64, len: usize) ![]u8 {
    const b = try alloc.alloc(u8, len);
    for (b, 0..) |*x, i| x.* = @truncate((@as(u64, i) *% 131 +% payload_id) & 0xff);
    return b;
}

// ------------------------------------------------------------- the workloads

/// Recids the workload allocated. Both shapes allocate the same six, in the
/// same order.
pub const Recids = struct {
    a: u64 = 0,
    b: u64 = 0,
    c: u64 = 0,
    d: u64 = 0,
    e: u64 = 0,
    f: u64 = 0,
};

fn openStore(alloc: Allocator, base: []const u8) !StoreWAL {
    var s = try StoreWAL.open(alloc, base, false);
    errdefer {
        s.close() catch {};
        s.deinit();
    }
    try s.setSegmentBytes(SEGMENT_BYTES);
    try s.setMinLogBytes(MIN_LOG_BYTES);
    return s;
}

fn put(alloc: Allocator, s: *StoreWAL, id: u64, len: usize) !u64 {
    const p = try payloadAlloc(alloc, id, len);
    defer alloc.free(p);
    return s.put([]const u8, alloc, p, R);
}

fn setTo(alloc: Allocator, s: *StoreWAL, recid: u64, id: u64, len: usize) !void {
    const p = try payloadAlloc(alloc, id, len);
    defer alloc.free(p);
    try s.update([]const u8, alloc, recid, p, R);
}

fn t1(alloc: Allocator, s: *StoreWAL, r: *Recids, base: u64) !void {
    r.a = try put(alloc, s, base, 100);
    r.b = try put(alloc, s, base + 1, 0);
    r.c = try put(alloc, s, base + 2, 40);
    try s.commit();
}

fn t2(alloc: Allocator, s: *StoreWAL, r: *Recids) !void {
    try s.update([]const u8, alloc, r.c, null, R);
    r.d = try s.preallocate();
    try s.commit();
}

fn t3(alloc: Allocator, s: *StoreWAL, r: *Recids, base: u64) !void {
    r.e = try put(alloc, s, base + 3, 256);
    r.f = try put(alloc, s, base + 4, 1_200_000);
    try s.commit();
}

fn t4(alloc: Allocator, s: *StoreWAL, r: *const Recids, base: u64) !void {
    try s.delete(r.e);
    try setTo(alloc, s, r.a, base + 5, 120);
    try s.commit();
}

/// Gives C content, then takes it away again: two sections, no new recid, and C
/// is null before and after. The SECOND one is §5.3.1 row 5's size-preserving
/// `T_APPEND` candidate — a null `T_RECORD` and a payload-free `T_APPEND` are
/// the same four bytes — and row 5 reads section index 1, so this pair must be
/// the first two sections of the middle segment and in this order.
fn shapeC(alloc: Allocator, s: *StoreWAL, r: *const Recids, base: u64) !void {
    try setTo(alloc, s, r.c, base + 6, 48);
    try s.commit();
    try s.update([]const u8, alloc, r.c, null, R);
    try s.commit();
}

/// Pushes the active segment past `segment_bytes` and then commits once more,
/// so the LAST commit lands alone in a fresh segment. Rollover is tested BEFORE
/// a section is appended, so an oversized section joins the segment it
/// overflows and only its successor rotates: one commit cannot do this, and the
/// Stage C plan predicted otherwise. Both halves rewrite A and the second
/// restores A's §5.2 content, so the final logical state is untouched.
///
/// "Only its successor rotates" is about ORDINARY appends. Cleaning rotates too,
/// at two unconditional episode seals; neither is reachable here, because the
/// sole checkpoint is already behind us and `minLogBytes` keeps auto-clean from
/// ever firing (§5.1). Rotating with one of those instead would change the
/// cleaning history the whole shape is built around.
fn shapeRotate(alloc: Allocator, s: *StoreWAL, r: *const Recids, base: u64) !void {
    try setTo(alloc, s, r.a, base + 7, @intCast(SEGMENT_BYTES));
    try s.commit();
    try setTo(alloc, s, r.a, base + 5, 120);
    try s.commit();
}

/// §5.2's T1-T5: no cleaning ever runs, and T5 rolls back.
fn tailWorkload(alloc: Allocator, base_path: []const u8, r: *Recids) !void {
    var s = try openStore(alloc, base_path);
    defer s.deinit();
    try t1(alloc, &s, r, TAIL_BASE);
    try t2(alloc, &s, r);
    try t3(alloc, &s, r, TAIL_BASE);
    try t4(alloc, &s, r, TAIL_BASE);
    _ = try put(alloc, &s, TAIL_BASE + 6, 64); // T5: staged, then rolled back
    try s.rollback();
    if (s.cleanerBytes().written != 0) return error.CleanerRanInTailShape;
    try assertFinalState(alloc, &s, r, TAIL_BASE);
    try s.close();
}

/// §5.3's amended workload: the checkpoint after T2, then the two
/// state-preserving shaping pairs. See the module docs for the measurement.
fn cleanedWorkload(alloc: Allocator, base_path: []const u8, r: *Recids) !void {
    var s = try openStore(alloc, base_path);
    defer s.deinit();
    try t1(alloc, &s, r, CLEANED_BASE);
    try t2(alloc, &s, r);
    // §5.1, §5.4 obligation 3: auto-clean must not have begun before the
    // explicit checkpoint, or the bundle stops at a machine-speed-dependent
    // point and the two-run byte comparison fails on a loaded host.
    if (s.cleanerBytes().written != 0) return error.AutoCleanBeganBeforeCheckpoint;
    try s.checkpoint(); // the ONLY cleaning, and it runs unbudgeted
    const after_checkpoint = s.cleanerBytes().written;
    if (after_checkpoint <= 0) return error.CheckpointWroteNoImage;

    try t3(alloc, &s, r, CLEANED_BASE); // 1.2 MB: oversizes the LOWEST retained segment
    try shapeC(alloc, &s, r, CLEANED_BASE); // the middle segment's first two sections
    try t4(alloc, &s, r, CLEANED_BASE);
    try shapeRotate(alloc, &s, r, CLEANED_BASE); // one commit to cross, one to land alone

    // §5.4 obligation 4: exactly one episode, at one prescribed boundary.
    if (s.cleanerBytes().written != after_checkpoint) return error.CleanedTwice;
    try assertFinalState(alloc, &s, r, CLEANED_BASE);
    try s.close();
}

/// The final logical state §5.2 pins, which §5.3 shares verbatim.
fn assertFinalState(alloc: Allocator, s: *StoreWAL, r: *const Recids, base: u64) !void {
    try assertStateWithA(alloc, s, r, base, base + 5, 120);
}

/// §5.2's final logical state with A's content named by the caller.
///
/// Every adopted workload ends with A holding `p(base+5, 120)`; the one probe
/// variant that deliberately stops mid-pair ends with A holding the oversized
/// payload instead. Naming A's expectation rather than skipping the check keeps
/// that variant's exception scoped to the ONE record it is about — otherwise an
/// unrelated state defect in it would be exempt too.
fn assertStateWithA(
    alloc: Allocator,
    s: *StoreWAL,
    r: *const Recids,
    base: u64,
    a_id: u64,
    a_len: usize,
) !void {
    try s.verify();
    try expectPayload(alloc, s, r.a, a_id, a_len);
    try expectPayload(alloc, s, r.b, base + 1, 0);
    try expectNull(alloc, s, r.c);
    try expectNull(alloc, s, r.d);
    if (s.get([]const u8, alloc, r.e, R)) |_| {
        return error.DeletedRecordIsReadable;
    } else |e| if (e != error.GetVoid) return e;
    try expectPayload(alloc, s, r.f, base + 4, 1_200_000);

    // The leak detector: §5.2's rolled-back put has no recid row and must not
    // be reachable, so the recid SET is compared exactly.
    const all = try s.getAllRecids(alloc);
    defer alloc.free(all);
    std.mem.sort(u64, all, {}, std.sort.asc(u64));
    var want = [_]u64{ r.a, r.b, r.c, r.f };
    std.mem.sort(u64, &want, {}, std.sort.asc(u64));
    if (!std.mem.eql(u64, all, &want)) return error.RecidSetMismatch;
}

fn expectPayload(alloc: Allocator, s: *StoreWAL, recid: u64, id: u64, len: usize) !void {
    const got = (try s.get([]const u8, alloc, recid, R)) orelse return error.UnexpectedNull;
    defer alloc.free(@constCast(got));
    const want = try payloadAlloc(alloc, id, len);
    defer alloc.free(want);
    if (!std.mem.eql(u8, got, want)) return error.PayloadMismatch;
}

fn expectNull(alloc: Allocator, s: *StoreWAL, recid: u64) !void {
    const got = try s.get([]const u8, alloc, recid, R);
    if (got) |g| {
        alloc.free(@constCast(g));
        return error.ExpectedNull;
    }
}

// ------------------------------------------------------------ the v3 decoder
//
// Layout, from the format description in `todo/store-wal3/wal-v3-adoption.md`:
// a 36-byte segment header magic[8] | version(4) | flags(4) | seq(8) |
// firstLsn(8) | crc32(4) with the CRC over the first 32 bytes; then 25-byte
// section headers tag(1) | lsn(8) | bodyLen(8) | hdrCrc(4) | bodyCrc(4), each
// CRC primed with the 36 header bytes and be64(sectionOffset) BEFORE the
// section's own bytes — the offset is in the domain, which is what makes a
// section un-relocatable.
//
// Deliberately not `src/store/wal_segments.zig`'s parser, and not `walfmt.py`.

const SEG_HDR: usize = 36;
const SEG_HDR_CRC_LEN: usize = 32;
const SEC_HDR: usize = 25;
const SEC_HDR_CRC_LEN: usize = 17;
const MAGIC = "MDBS.WAL";
const FORMAT_VERSION: u32 = 3;
const MARK_BODY_LEN: i64 = 16;

const Sec = struct { off: usize, tag: u8, lsn: i64 };
const Mark = struct { index: usize, through: i64, log_start: i64 };

const Seg = struct {
    rel_name: []const u8,
    raw: []const u8,
    seq: i64,
    first_lsn: i64,
    sections: []const Sec,
    mark: ?Mark,

    fn first(self: Seg) Sec {
        return self.sections[0];
    }
    fn last(self: Seg) Sec {
        return self.sections[self.sections.len - 1];
    }
};

fn crc32(bytes: []const u8) u32 {
    return std.hash.Crc32.hash(bytes);
}

/// A hasher primed with a section's domain: all 36 header bytes then
/// `be64(sectionOffset)`, fed BEFORE the section's own bytes. Getting this
/// order wrong is why the decoder is written out rather than shared.
fn domain(raw: []const u8, section_off: usize) std.hash.Crc32 {
    var h: std.hash.Crc32 = .init();
    h.update(raw[0..SEG_HDR]);
    var off: [8]u8 = undefined;
    std.mem.writeInt(u64, &off, @intCast(section_off), .big);
    h.update(&off);
    return h;
}

fn be32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .big);
}

fn be64(b: []const u8, off: usize) i64 {
    return std.mem.readInt(i64, b[off..][0..8], .big);
}

/// `{d:0>16x}` — hex, NOT decimal (§3).
fn segmentName(alloc: Allocator, seq: i64) ![]u8 {
    return std.fmt.allocPrint(alloc, "{s}.wal.{x:0>16}", .{ BASE_NAME, @as(u64, @bitCast(seq)) });
}

fn parseSegment(arena: Allocator, rel_name: []const u8, raw: []const u8) !Seg {
    if (raw.len < SEG_HDR) return error.ShorterThanASegmentHeader;
    if (!std.mem.eql(u8, raw[0..8], MAGIC)) return error.BadMagic;
    if (be32(raw, 8) != FORMAT_VERSION) return error.WrongFormatVersion;
    if (be32(raw, 12) != 0) return error.NonzeroHeaderFlags;
    if (crc32(raw[0..SEG_HDR_CRC_LEN]) != be32(raw, SEG_HDR_CRC_LEN))
        return error.SegmentHeaderCrcMismatch;

    var sections: std.ArrayListUnmanaged(Sec) = .empty;
    var mark: ?Mark = null;
    var off: usize = SEG_HDR;
    while (off < raw.len) {
        if (off + SEC_HDR > raw.len) return error.TruncatedSectionHeader;
        const tag = raw[off];
        if (tag != 'S' and tag != 'C' and tag != 'K') return error.UnknownSectionTag;
        const lsn = be64(raw, off + 1);
        const body_len = be64(raw, off + 9);
        var h = domain(raw, off);
        h.update(raw[off .. off + SEC_HDR_CRC_LEN]);
        if (h.final() != be32(raw, off + 17)) return error.SectionHeaderCrcMismatch;
        // Subtract rather than add: `off + SEC_HDR + body_len <= raw.len` reads
        // more naturally and OVERFLOWS for a body_len near i64 max, wrapping
        // negative and passing the very check it is. Both operands of the
        // remaining-bytes form are already bounded by the file length.
        if (body_len < 0 or body_len > @as(i64, @intCast(raw.len - off - SEC_HDR)))
            return error.SectionBodyPastEndOfFile;
        const body_len_usize: usize = @intCast(body_len);
        var hb = domain(raw, off);
        hb.update(raw[off + SEC_HDR ..][0..body_len_usize]);
        if (hb.final() != be32(raw, off + 21)) return error.SectionBodyCrcMismatch;
        if (tag == 'K') {
            if (body_len != MARK_BODY_LEN) return error.MarkBodyWrongLength;
            if (mark != null) return error.TwoMarksInOneSegment;
            mark = .{
                .index = sections.items.len,
                .through = be64(raw, off + SEC_HDR),
                .log_start = be64(raw, off + SEC_HDR + 8),
            };
        }
        try sections.append(arena, .{ .off = off, .tag = tag, .lsn = lsn });
        off += SEC_HDR + body_len_usize;
    }
    if (off != raw.len) return error.TrailingBytesAfterLastSection;
    if (sections.items.len == 0) return error.PublishedSegmentWithNoSections;
    return .{
        .rel_name = rel_name,
        .raw = raw,
        .seq = be64(raw, 16),
        .first_lsn = be64(raw, 24),
        .sections = sections.items,
        .mark = mark,
    };
}

// ------------------------------------------------- enumeration and self-check

/// The §5.3.1 / §5.3 row a grading refusal names. Asserted by IDENTITY, which
/// is the deviation this file makes from java's and rust's substring matching:
/// a message can be reworded, and a substring can appear in the wrong check.
pub const Row = enum {
    segment_count,
    name_mismatch,
    first_lsn_mismatch,
    noncontiguous_sequences,
    lsn_not_ascending,
    tail_starts_above_one,
    tail_carries_non_s,
    two_marks,
    no_mark,
    k4,
    log_start_range,
    floor_not_above_one,
    /// §5.3.1 row 1
    retained_cardinality,
    active_not_highest,
    /// §5.3.1 row 2, mark placement half
    mark_in_wrong_segment,
    no_c_image_before_mark,
    no_s_after_mark,
    /// §5.3.1 row 4
    lowest_first_lsn_is_not_the_floor,
    retained_lsns_not_dense,
    /// §5.3.1 row 2, section half
    middle_too_few_sections,
    middle_section_is_the_mark,
    /// §5.3.1 row 3
    active_not_single_section,
    /// §5.3.1 row 6
    active_not_under_segment_bytes,
};

/// A grading verdict: the row that failed, plus a human-readable detail. The
/// gate matches `row`; the detail is for the operator.
pub const Grade = struct {
    row: ?Row = null,
    detail: [256]u8 = undefined,
    detail_len: usize = 0,

    fn fail(self: *Grade, row: Row, comptime fmt: []const u8, args: anytype) error{ShapeViolation} {
        self.row = row;
        const w = std.fmt.bufPrint(&self.detail, fmt, args) catch self.detail[0..0];
        self.detail_len = w.len;
        return error.ShapeViolation;
    }

    pub fn message(self: *const Grade) []const u8 {
        return self.detail[0..self.detail_len];
    }
};

fn isSegmentName(name: []const u8) bool {
    const prefix = BASE_NAME ++ ".wal.";
    if (!std.mem.startsWith(u8, name, prefix)) return false;
    const hex = name[prefix.len..];
    if (hex.len != 16) return false;
    for (hex) |c| if (!std.ascii.isDigit(c) and !(c >= 'a' and c <= 'f')) return false;
    return true;
}

fn dropLock(dir_path: []const u8, alloc: Allocator) void {
    const p = std.fs.path.join(alloc, &.{ dir_path, BASE_NAME ++ ".lock" }) catch return;
    defer alloc.free(p);
    std.fs.cwd().deleteFile(p) catch {};
}

/// The published namespace, decoded, ordered by sequence. Everything returned
/// is owned by `arena`.
fn readNamespace(arena: Allocator, dir_path: []const u8, g: *Grade) ![]Seg {
    var dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer dir.close();
    var segs: std.ArrayListUnmanaged(Seg) = .empty;
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) return error.UnexpectedNonFileInNamespace;
        if (std.mem.eql(u8, entry.name, BASE_NAME ++ ".lock"))
            return error.LockSidecarPresentAtEnumeration;
        // §5.4 obligation 7: no scratch, no foreign files.
        if (!isSegmentName(entry.name)) return error.ForeignFileInNamespace;
        const name = try arena.dupe(u8, entry.name);
        const raw = try dir.readFileAlloc(arena, entry.name, 1 << 30);
        try segs.append(arena, try parseSegment(arena, name, raw));
    }
    const out = segs.items;
    std.mem.sort(Seg, out, {}, struct {
        fn lt(_: void, x: Seg, y: Seg) bool {
            return x.seq < y.seq;
        }
    }.lt);
    for (out) |s| {
        const want = try segmentName(arena, s.seq);
        if (!std.mem.eql(u8, s.rel_name, want))
            return g.fail(.name_mismatch, "{s} does not match {{x:0>16}} of its own sequence {d}", .{ s.rel_name, s.seq });
    }
    return out;
}

/// §5.4 obligation 7, shared by both shapes.
fn checkCommon(segs: []const Seg, g: *Grade) !void {
    if (segs.len < 2)
        return g.fail(.segment_count, "{d} segment(s); both shapes need >= 2", .{segs.len});
    var prev_lsn: i64 = std.math.minInt(i64);
    for (segs, 0..) |s, i| {
        if (s.first_lsn != s.first().lsn)
            return g.fail(.first_lsn_mismatch, "{s} states firstLsn {d}, its first section holds {d}", .{ s.rel_name, s.first_lsn, s.first().lsn });
        if (i > 0 and s.seq != segs[i - 1].seq + 1)
            return g.fail(.noncontiguous_sequences, "sequences are not contiguous: {d} then {d}", .{ segs[i - 1].seq, s.seq });
        for (s.sections) |sec| {
            if (sec.lsn <= prev_lsn)
                return g.fail(.lsn_not_ascending, "LSN {d} at {s}:{d} does not follow {d}", .{ sec.lsn, s.rel_name, sec.off, prev_lsn });
            prev_lsn = sec.lsn;
        }
    }
}

/// §5.2's generator self-check.
fn checkTail(segs: []const Seg, g: *Grade) !void {
    try checkCommon(segs, g);
    if (segs[0].seq != 1)
        return g.fail(.tail_starts_above_one, "sequences must start at 1, not {d}", .{segs[0].seq});
    for (segs) |s| for (s.sections) |sec| {
        if (sec.tag != 'S')
            return g.fail(.tail_carries_non_s, "{s}:{d} is tag '{c}'; an uncleaned log carries only 'S'", .{ s.rel_name, sec.off, sec.tag });
    };
}

/// One resolved layout symbol.
pub const Symbol = struct { name: []const u8, seq: i64 };

/// §5.3's self-check and FIVE of §5.3.1's six witness rows, returning the
/// layout index §5.3.1 asks the generator to publish.
///
/// Which five, stated precisely because "checks §5.3.1" would be a false
/// claim. Rows 1, 2, 3, 4 and 6 are checked here. **Row 5 is not** — it asks
/// whether the middle segment's second section holds an entry admitting a
/// size-preserving `T_APPEND` rewrite, which means decoding the entry stream
/// and searching for a replacement encoding of exactly the same length. That
/// is `derive._stranded_append`'s job, and reimplementing it here would be a
/// second entry codec to keep in step with the first.
///
/// Rows 1-5 are re-derived independently by `derive.check_witnesses` from the
/// same bytes, so the four checked in both places are checked by two codecs.
/// Row 6 exists ONLY here: `segment_bytes` is a generator setting.
fn checkCleaned(arena: Allocator, segs: []const Seg, g: *Grade) ![]Symbol {
    try checkCommon(segs, g);

    var mark_seg: ?Seg = null;
    for (segs) |s| {
        if (s.mark == null) continue;
        if (mark_seg != null) return g.fail(.two_marks, "two segments carry a 'K' mark", .{});
        mark_seg = s;
    }
    const ms = mark_seg orelse
        return g.fail(.no_mark, "no 'K' mark; checkpoint() must force one", .{});
    const m = ms.mark.?;
    const mark_lsn = ms.sections[m.index].lsn;
    if (!(m.through > 0 and m.through < ms.seq))
        return g.fail(.k4, "K4 violated: cleanedThroughSeq {d} is not in (0, {d})", .{ m.through, ms.seq });
    if (!(m.log_start > 0 and m.log_start <= mark_lsn))
        return g.fail(.log_start_range, "logStartLsn {d} is not in (0, {d}]", .{ m.log_start, mark_lsn });

    var retained: std.ArrayListUnmanaged(Seg) = .empty;
    for (segs) |s| if (s.seq > m.through) try retained.append(arena, s);
    const ret = retained.items;
    if (ret.len == 0 or ret[0].seq <= 1)
        return g.fail(.floor_not_above_one, "the retained floor must be above segment 1 (§5.3)", .{});
    if (ret.len != 3)
        return g.fail(.retained_cardinality, "§5.3.1 row 1 requires exactly three retained segments; this bundle retains {d}", .{ret.len});
    const lowest = ret[0];
    const middle = ret[1];
    const active = ret[2];
    if (active.seq != segs[segs.len - 1].seq)
        return g.fail(.active_not_highest, "the highest retained segment is not the highest segment", .{});

    if (ms.seq != lowest.seq)
        return g.fail(.mark_in_wrong_segment, "the mark sits in segment {d}; §5.3.1 row 2 forbids it in the middle retained segment, so it must be in the lowest one ({d}) beside the 'C' image", .{ ms.seq, lowest.seq });
    var image_before = false;
    for (ms.sections[0..m.index]) |sec| {
        if (sec.tag == 'C') image_before = true;
    }
    if (!image_before) return g.fail(.no_c_image_before_mark, "no 'C' image precedes the mark", .{});
    if (active.last().tag != 'S')
        return g.fail(.no_s_after_mark, "no 'S' section follows the mark", .{});

    // row 4: the lowest retained segment's stated firstLsn IS the mark's floor,
    // and the retained set is dense — checkCommon proved ascent, this proves
    // there are no gaps.
    if (lowest.first_lsn != m.log_start)
        return g.fail(.lowest_first_lsn_is_not_the_floor, "§5.3.1 row 4: the lowest retained segment states firstLsn {d}, the mark attests {d}", .{ lowest.first_lsn, m.log_start });
    var expect_lsn = m.log_start;
    for (ret) |s| for (s.sections) |sec| {
        if (sec.lsn != expect_lsn)
            return g.fail(.retained_lsns_not_dense, "§5.3.1 row 4: LSNs are not dense across the retained set: expected {d} at {s}:{d}, found {d}", .{ expect_lsn, s.rel_name, sec.off, sec.lsn });
        expect_lsn += 1;
    };

    // row 2
    if (middle.sections.len < 2)
        return g.fail(.middle_too_few_sections, "§5.3.1 row 2: the middle retained segment carries {d} section(s), fewer than two", .{middle.sections.len});
    for (middle.sections[0..2], 0..) |sec, i| {
        if (sec.tag == 'K')
            return g.fail(.middle_section_is_the_mark, "§5.3.1 row 2: section {d} of the middle retained segment is the mark; both must be entry-bearing", .{i});
    }

    // row 3
    if (active.sections.len != 1)
        return g.fail(.active_not_single_section, "§5.3.1 row 3: the active segment carries {d} sections, not one", .{active.sections.len});

    // row 6 — checkable HERE ONLY.
    if (active.raw.len >= SEGMENT_BYTES)
        return g.fail(.active_not_under_segment_bytes, "§5.3.1 row 6: the active segment is {d} bytes, not under segmentBytes {d}; Q8's appended record would force a rollover and there would be no section to assert", .{ active.raw.len, SEGMENT_BYTES });

    return selectorIndex(arena, segs, m.through);
}

/// §5.3.1's layout index: every segment selector in
/// `catalogue.SEGMENT_SELECTORS` that resolves to EXACTLY ONE segment.
///
/// Exactly one is the whole point. A recipe addresses its target by selector
/// and the deriver refuses to pick between candidates, so a selector resolving
/// to zero or to two makes the cell unbuildable — and one resolving to the
/// WRONG single segment produces a cell labelled `reject` that is really an
/// accept. The index records resolution as a SET: a selector missing here is a
/// selector this bundle cannot host, which is as much a fact as the ones
/// present, and `xcheck_bundles.py` compares both directions.
///
/// Mirrors `derive._segment_candidates` deliberately and independently.
fn selectorIndex(arena: Allocator, segs: []const Seg, through: i64) ![]Symbol {
    var retained: std.ArrayListUnmanaged(Seg) = .empty;
    for (segs) |s| if (s.seq > through) try retained.append(arena, s);
    const ret = retained.items;
    const highest = segs[segs.len - 1].seq;

    var out: std.ArrayListUnmanaged(Symbol) = .empty;
    // Candidates are collected into a growable list rather than a fixed buffer:
    // the count is a property of the bundle being graded, and this function is
    // pointed at arbitrary probe output, not only at the generator's own.
    var cand: std.ArrayListUnmanaged(i64) = .empty;

    cand.clearRetainingCapacity();
    if (ret.len > 0) try cand.append(arena, ret[0].seq);
    try emitUnique(arena, &out, "lowest_retained", cand.items);

    cand.clearRetainingCapacity();
    if (ret.len > 1) for (ret[1..]) |s| {
        if (s.seq != highest) try cand.append(arena, s.seq);
    };
    try emitUnique(arena, &out, "middle_retained", cand.items);

    cand.clearRetainingCapacity();
    if (ret.len > 1) for (ret[1..]) |s| {
        if (s.sections.len == 1) try cand.append(arena, s.seq);
    };
    try emitUnique(arena, &out, "single_section_retained", cand.items);

    cand.clearRetainingCapacity();
    try cand.append(arena, highest);
    try emitUnique(arena, &out, "highest", cand.items);

    cand.clearRetainingCapacity();
    for (segs) |s| if (s.mark != null) try cand.append(arena, s.seq);
    try emitUnique(arena, &out, "mark", cand.items);

    return out.items;
}

fn emitUnique(arena: Allocator, out: *std.ArrayListUnmanaged(Symbol), name: []const u8, cands: []const i64) !void {
    if (cands.len == 1) try out.append(arena, .{ .name = name, .seq = cands[0] });
}

/// Grades an arbitrary namespace directory against §5.3's self-check and the
/// FIVE §5.3.1 rows `checkCleaned` can decide — 1, 2, 3, 4 and 6, never 5 —
/// exactly as the generator grades its own output.
///
/// Exists so a candidate workload can be FALSIFIED rather than only confirmed:
/// the gate runs the rejected probe variants through this and requires each to
/// be refused with the `Row` claimed. Without it, a generator whose shaping is
/// unnecessary and one whose shaping is essential look identical.
pub fn gradeCleaned(arena: Allocator, dir_path: []const u8, g: *Grade) ![]Symbol {
    dropLock(dir_path, arena);
    return checkCleaned(arena, try readNamespace(arena, dir_path, g), g);
}

/// A one-line structural summary of any namespace: where the mark sits, and
/// how the retained set is shaped around it.
///
/// The companion to `gradeCleaned`. Grading reports the FIRST row a candidate
/// violates, which is not always the row that candidate is interesting for —
/// §5.3's literal workload loses on row 1 long before anything looks at row 2,
/// even though row 2 is the reason it can never be repaired by adding a
/// segment.
pub fn describeShape(arena: Allocator, dir_path: []const u8) ![]u8 {
    dropLock(dir_path, arena);
    var g: Grade = .{};
    const segs = try readNamespace(arena, dir_path, &g);
    var through: i64 = 0;
    var mark: []const u8 = "none";
    for (segs) |s| if (s.mark) |m| {
        through = m.through;
        mark = try std.fmt.allocPrint(arena, "{d}:{d}", .{ s.seq, m.index });
    };
    var retained: std.ArrayListUnmanaged(u8) = .empty;
    try retained.append(arena, '[');
    var first = true;
    for (segs) |s| if (s.seq > through) {
        if (!first) try retained.appendSlice(arena, ", ");
        first = false;
        try retained.print(arena, "{d}", .{s.seq});
    };
    try retained.append(arena, ']');
    return std.fmt.allocPrint(arena, "mark={s} retained={s} activeSections={d}", .{
        mark,
        retained.items,
        segs[segs.len - 1].sections.len,
    });
}

// ------------------------------------------------------------------ emission

fn sha256Hex(data: []const u8) [64]u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &d, .{});
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&d}) catch unreachable;
    return hex;
}

/// One shape's finished product: its published bytes (in sequence order), its
/// recids and its layout index. Everything is arena-owned.
const Bundle = struct {
    id: []const u8,
    image: []const Seg,
    recids: Recids,
    layout: []const Symbol,
};

/// relName, length and sha of every segment — the comparison §5.4 obligation 8
/// makes across runs, over the complete map rather than file by file.
fn describeImage(arena: Allocator, image: []const Seg) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    for (image) |s|
        try out.print(arena, "{s}\t{d}\t{s}\n", .{ s.rel_name, s.raw.len, sha256Hex(s.raw) });
    return out.items;
}

fn rmTree(path: []const u8) void {
    std.fs.cwd().deleteTree(path) catch {};
}

const Workload = enum { tail, cleaned };

/// Runs one shape into a scratch directory, self-checks it, and returns it.
///
/// §5.4 obligation 1: the base is EMPTY, because the directory is wiped and
/// recreated here. Obligation 5: the store is CLOSED before anything reads the
/// files — a snapshot of an open store is not the published image.
fn produce(arena: Allocator, scratch: []const u8, which: Workload, g: *Grade) !Bundle {
    rmTree(scratch);
    try std.fs.cwd().makePath(scratch);
    const base_path = try std.fs.path.join(arena, &.{ scratch, BASE_NAME });
    var r: Recids = .{};
    switch (which) {
        .tail => try tailWorkload(arena, base_path, &r),
        .cleaned => try cleanedWorkload(arena, base_path, &r),
    }
    dropLock(scratch, arena);
    const segs = try readNamespace(arena, scratch, g);
    const layout = switch (which) {
        .tail => blk: {
            try checkTail(segs, g);
            break :blk try selectorIndex(arena, segs, 0); // no mark, nothing superseded
        },
        .cleaned => try checkCleaned(arena, segs, g),
    };
    const before = try describeImage(arena, segs);

    // Reopen: the same reader contract every accept cell will run, then prove
    // the reopen published nothing new — §5.5 says no accept-bundle cell
    // mutates, and all 12 of this bundle's accept cells rest on that.
    {
        var s = try openStore(arena, base_path);
        defer s.deinit();
        try assertFinalState(arena, &s, &r, switch (which) {
            .tail => TAIL_BASE,
            .cleaned => CLEANED_BASE,
        });
        try s.close();
    }
    dropLock(scratch, arena);
    const after = try describeImage(arena, try readNamespace(arena, scratch, g));
    if (!std.mem.eql(u8, before, after)) return error.CleanReopenChangedThePublishedBytes;

    return .{
        .id = switch (which) {
            .tail => TAIL_ID,
            .cleaned => CLEANED_ID,
        },
        .image = segs,
        .recids = r,
        .layout = layout,
    };
}

/// Produces one shape TWICE into separate scratch directories and refuses to
/// publish unless the complete relName->bytes maps agree (§5.4 obligation 8).
///
/// Necessary and not sufficient, and the difference matters: two runs in ONE
/// process share every process-wide seed. The gate's separate obligation to
/// run the generator in a second OS PROCESS is what covers the rest; this is
/// the cheap half that fails at the generator rather than three slices later.
fn produceTwice(arena: Allocator, root_dir: []const u8, which: Workload, g: *Grade) !Bundle {
    const d1 = try std.fs.path.join(arena, &.{ root_dir, ".run1" });
    const d2 = try std.fs.path.join(arena, &.{ root_dir, ".run2" });
    const b1 = try produce(arena, d1, which, g);
    const b2 = try produce(arena, d2, which, g);
    if (!std.mem.eql(u8, try describeImage(arena, b1.image), try describeImage(arena, b2.image)))
        return error.NotDeterministicAcrossTwoRuns;
    if (!std.meta.eql(b1.recids, b2.recids)) return error.RecidsDifferAcrossTwoRuns;
    if (b1.layout.len != b2.layout.len) return error.LayoutDiffersAcrossTwoRuns;
    for (b1.layout, b2.layout) |x, y| {
        if (!std.mem.eql(u8, x.name, y.name) or x.seq != y.seq)
            return error.LayoutDiffersAcrossTwoRuns;
    }
    rmTree(d2);
    return b1;
}

fn publish(arena: Allocator, out_dir: []const u8, b: Bundle) !void {
    const dest = try std.fs.path.join(arena, &.{ out_dir, b.id });
    rmTree(dest);
    try std.fs.cwd().makePath(dest);
    var dir = try std.fs.cwd().openDir(dest, .{});
    defer dir.close();
    for (b.image) |s| try dir.writeFile(.{ .sub_path = s.rel_name, .data = s.raw });
}

fn fragment(arena: Allocator, tail: Bundle, cleaned: Bundle, commit: []const u8) ![]u8 {
    var t: std.ArrayListUnmanaged(u8) = .empty;
    try t.appendSlice(arena, "# xfixtures fragment written by src/xfixtures/wal3_fixtures.zig (C2z).\n");
    try t.appendSlice(arena, "# The sync script merges fragments, appends the gzSha256 column to file rows\n");
    try t.appendSlice(arena, "# and adds the expect/post rows from catalogue.py.\n");
    for ([_]Bundle{ tail, cleaned }, [_]u64{ TAIL_BASE, CLEANED_BASE }) |b, base| {
        try t.print(arena, "fixture\t{s}\twal3-namespace\tzig\t{s}\n", .{ b.id, commit });
        // §2: file rows sorted numerically by segment sequence — `image` is.
        for (b.image) |s|
            try t.print(arena, "file\t{s}\t{s}\t{d}\t{s}\n", .{ b.id, s.rel_name, s.raw.len, sha256Hex(s.raw) });
        const r = b.recids;
        const rows = [_]struct { l: []const u8, id: u64, st: []const u8, pid: u64, len: usize }{
            .{ .l = "A", .id = r.a, .st = "live", .pid = base + 5, .len = 120 },
            .{ .l = "B", .id = r.b, .st = "live", .pid = base + 1, .len = 0 },
            .{ .l = "C", .id = r.c, .st = "null", .pid = base + 2, .len = 40 },
            .{ .l = "D", .id = r.d, .st = "prealloc", .pid = 0, .len = 0 },
            .{ .l = "E", .id = r.e, .st = "deleted", .pid = base + 3, .len = 256 },
            .{ .l = "F", .id = r.f, .st = "live", .pid = base + 4, .len = 1_200_000 },
        };
        for (rows) |x|
            try t.print(arena, "recid\t{s}\t{s}\t{d}\t{s}\t{d}\t{d}\n", .{ b.id, x.l, x.id, x.st, x.pid, x.len });
    }
    return t.items;
}

/// §5.3.1's layout index, as `symbol` rows in §10.1's shape.
///
/// What makes it more than decoration: these values come from THIS generator's
/// own decoder and its own knowledge of the workload, and
/// `derive.resolve_symbols` resolves the same names independently from the
/// published bytes. The gate compares them. A row nothing reads is a claim
/// nothing checked (§10.1), so this file is written to be read.
fn layoutSidecar(arena: Allocator, tail: Bundle, cleaned: Bundle) ![]u8 {
    var t: std.ArrayListUnmanaged(u8) = .empty;
    try t.appendSlice(arena, "# §5.3.1 layout index written by src/xfixtures/wal3_fixtures.zig (C2z).\n");
    try t.appendSlice(arena, "# symbol <fixtureId> <@segmentSelector> <relName>, one row per selector that\n");
    try t.appendSlice(arena, "# resolves to exactly one segment. An ABSENT selector is a claim too: this\n");
    try t.appendSlice(arena, "# bundle cannot host a recipe that addresses it. Cross-checked against\n");
    try t.appendSlice(arena, "# derive._segment_candidates, both directions, by xcheck_bundles.py.\n");
    for ([_]Bundle{ tail, cleaned }) |b|
        for (b.layout) |sym|
            try t.print(arena, "symbol\t{s}\t@{s}\t{s}\n", .{ b.id, sym.name, try segmentName(arena, sym.seq) });
    return t.items;
}

/// The whole generator: both shapes, twice each, published with their sidecars.
pub fn generate(arena: Allocator, out_dir: []const u8, force: bool, commit: []const u8, g: *Grade) !void {
    try std.fs.cwd().makePath(out_dir);
    {
        var dir = try std.fs.cwd().openDir(out_dir, .{ .iterate = true });
        defer dir.close();
        var it = dir.iterate();
        if (try it.next() != null and !force) return error.OutputDirectoryNotEmpty;
    }

    // A bundle's `image` holds arena COPIES of the published bytes (the scratch
    // files were read with `readFileAlloc`), so the scratch namespaces can go
    // as soon as they have been read and the two shapes can reuse the names.
    const tail = try produceTwice(arena, out_dir, .tail, g);
    const cleaned = try produceTwice(arena, out_dir, .cleaned, g);

    try publish(arena, out_dir, tail);
    try publish(arena, out_dir, cleaned);
    rmTree(try std.fs.path.join(arena, &.{ out_dir, ".run1" }));
    rmTree(try std.fs.path.join(arena, &.{ out_dir, ".run2" }));

    try writeSidecar(arena, out_dir, "fragment.tsv", try fragment(arena, tail, cleaned, commit));
    try writeSidecar(arena, out_dir, "layout.tsv", try layoutSidecar(arena, tail, cleaned));

    // §5.4 obligation 7 applied to the OUTPUT directory, not just to the
    // scratch namespaces. A forced rerun over a directory holding anything else
    // republishes the two bundles and leaves the rest in place, and the sync
    // script would then consume whatever was there. Checked rather than
    // deleted: the output path is one the caller chose, and silently emptying
    // it is a bigger risk than refusing to publish into it.
    {
        var dir = try std.fs.cwd().openDir(out_dir, .{ .iterate = true });
        defer dir.close();
        var it = dir.iterate();
        while (try it.next()) |e| {
            const known = std.mem.eql(u8, e.name, TAIL_ID) or
                std.mem.eql(u8, e.name, CLEANED_ID) or
                std.mem.eql(u8, e.name, "fragment.tsv") or
                std.mem.eql(u8, e.name, "layout.tsv");
            if (!known) return error.StrayFileInOutputDirectory;
        }
    }
}

fn writeSidecar(arena: Allocator, out_dir: []const u8, name: []const u8, data: []const u8) !void {
    const p = try std.fs.path.join(arena, &.{ out_dir, name });
    const f = try std.fs.cwd().createFile(p, .{ .truncate = true });
    defer f.close();
    try f.writeAll(data);
    try f.sync();
}

// --------------------------------------------------------------- shape probe

/// Runs one named candidate `cleaned` workload and leaves its segments on disk.
///
/// The Stage C plan predicted, from the rollover rule alone, that §5.3's
/// literal workload cannot produce §5.3.1's shape — and its proposed repair was
/// wrong in its second half. C2j measured both against java, C2r against rust.
/// This probe measures them against ZIG, because "the reference behaves this
/// way" is the hypothesis a port is supposed to test, not evidence about it.
///
/// Every variant that could become the generator's workload ends in the final
/// logical state §5.3 pins and asserts it before closing, so a variant that
/// reaches the shape by changing what the fixture MEANS fails here rather than
/// in review. The one exception is `shaped-half-rotate`, which exists precisely
/// to show that half of a state-preserving PAIR is not state-preserving; it
/// asserts the state it DOES reach — A holding the oversized payload, the rest
/// of §5.2 unchanged — rather than skipping the check.
pub const Variant = enum {
    /// §5.3 exactly as revision 1 wrote it
    spec,
    /// the plan's proposed move, on its own
    ckpt_after_t2,
    /// the plan's proposal in full: one oversized commit was expected to force
    /// the rotation into a single-section active segment. It does not.
    ckpt_after_t2_shaped,
    /// the adopted workload MINUS shapeC
    shaped_no_c,
    /// the adopted workload MINUS shapeRotate
    shaped_no_rotate,
    /// the adopted workload with only the half of shapeRotate that CROSSES
    /// segmentBytes. Ends with A holding the oversized payload, so it does NOT
    /// reach §5.3's final state and is measured for SHAPE only.
    shaped_half_rotate,
};

pub fn probeVariant(arena: Allocator, variant: Variant, dir_path: []const u8) !void {
    rmTree(dir_path);
    try std.fs.cwd().makePath(dir_path);
    const base_path = try std.fs.path.join(arena, &.{ dir_path, BASE_NAME });
    var r: Recids = .{};
    var s = try openStore(arena, base_path);
    defer s.deinit();
    const b = CLEANED_BASE;
    switch (variant) {
        .spec => {
            try t1(arena, &s, &r, b);
            try t2(arena, &s, &r);
            try t3(arena, &s, &r, b);
            try s.checkpoint();
            try t4(arena, &s, &r, b);
        },
        .ckpt_after_t2 => {
            try t1(arena, &s, &r, b);
            try t2(arena, &s, &r);
            try s.checkpoint();
            try t3(arena, &s, &r, b);
            try t4(arena, &s, &r, b);
        },
        .ckpt_after_t2_shaped => {
            try t1(arena, &s, &r, b);
            try t2(arena, &s, &r);
            try s.checkpoint();
            try t3(arena, &s, &r, b);
            try t4(arena, &s, &r, b);
            try shapeC(arena, &s, &r, b);
            try setTo(arena, &s, r.f, b + 4, 1_200_000);
            try s.commit();
        },
        .shaped_no_c => {
            try t1(arena, &s, &r, b);
            try t2(arena, &s, &r);
            try s.checkpoint();
            try t3(arena, &s, &r, b);
            try t4(arena, &s, &r, b);
            try shapeRotate(arena, &s, &r, b);
        },
        .shaped_no_rotate => {
            try t1(arena, &s, &r, b);
            try t2(arena, &s, &r);
            try s.checkpoint();
            try t3(arena, &s, &r, b);
            try shapeC(arena, &s, &r, b);
            try t4(arena, &s, &r, b);
        },
        .shaped_half_rotate => {
            try t1(arena, &s, &r, b);
            try t2(arena, &s, &r);
            try s.checkpoint();
            try t3(arena, &s, &r, b);
            try shapeC(arena, &s, &r, b);
            try t4(arena, &s, &r, b);
            try setTo(arena, &s, r.a, b + 7, @intCast(SEGMENT_BYTES));
            try s.commit();
        },
    }
    if (s.cleanerBytes().written <= 0) return error.CheckpointWroteNoImage;
    // Every variant says what state it reaches before it is allowed to be
    // measured. `shaped_half_rotate` is the one that does NOT reach §5.3's —
    // that is the point of it — so it names the state it does reach instead:
    // A holding the oversized payload, every other record where §5.2 leaves it.
    // The exception it is granted is exactly one record wide.
    if (variant == .shaped_half_rotate) {
        try assertStateWithA(arena, &s, &r, b, b + 7, @intCast(SEGMENT_BYTES));
    } else {
        try assertFinalState(arena, &s, &r, b);
    }
    try s.close();
    dropLock(dir_path, arena);
}

// ----------------------------------------------------------------- the gate
//
// The generator asserts §5.2/§5.3/§5.3.1/§5.4 about its own output while it
// runs, so the gate's first job is simply to RUN it: an assertion in a program
// nobody invokes is not a check, and a generator invoked only by the sync
// script, in the planning repo, on the day of the cutover, is that defect one
// slice later.
//
// Its second job is the part the generator cannot do for itself, because a
// program cannot catch its own blind spot by re-reading its own output: that
// the two shapes really are DIFFERENT shapes, and that each shaping decision
// is load-bearing.

const testing = std.testing;

/// A scratch directory unique to one test, removed and recreated on entry.
fn testDir(arena: Allocator, tag: []const u8) ![]u8 {
    // TMPDIR, never the working tree: a test that fails before its `defer`
    // would otherwise leave a multi-megabyte namespace inside the repo, where
    // the next `zig fmt`/`git status`/`--force` run has to deal with it.
    const tmp = std.posix.getenv("TMPDIR") orelse "/tmp";
    const p = try std.fmt.allocPrint(arena, "{s}/mapdb5_wal3_c2z_{d}_{s}", .{
        tmp,
        std.os.linux.getpid(),
        tag,
    });
    rmTree(p);
    try std.fs.cwd().makePath(p);
    return p;
}

fn readDirNames(arena: Allocator, path: []const u8) ![][]const u8 {
    var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
    defer dir.close();
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next()) |e| try out.append(arena, try arena.dupe(u8, e.name));
    std.mem.sort([]const u8, out.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    return out.items;
}

/// relPath, length and sha for every file under `root`, recursively.
fn describeTree(arena: Allocator, root_path: []const u8) ![]u8 {
    var rows: std.ArrayListUnmanaged([]const u8) = .empty;
    var dir = try std.fs.cwd().openDir(root_path, .{ .iterate = true });
    defer dir.close();
    var walker = try dir.walk(arena);
    defer walker.deinit();
    while (try walker.next()) |e| {
        if (e.kind != .file) continue;
        const raw = try dir.readFileAlloc(arena, e.path, 1 << 30);
        try rows.append(arena, try std.fmt.allocPrint(arena, "{s}\t{d}\t{s}\n", .{
            e.path, raw.len, sha256Hex(raw),
        }));
    }
    std.mem.sort([]const u8, rows.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.order(u8, x, y) == .lt;
        }
    }.lt);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    for (rows.items) |r| try out.appendSlice(arena, r);
    return out.items;
}

fn readSidecar(arena: Allocator, dir_path: []const u8, name: []const u8) ![]u8 {
    const p = try std.fs.path.join(arena, &.{ dir_path, name });
    return std.fs.cwd().readFileAlloc(arena, p, 1 << 20);
}

/// The variant must be REFUSED by the generator's own grading, with the `Row`
/// claimed — by IDENTITY, not by a substring of a message.
fn expectRefusal(arena: Allocator, dir_path: []const u8, want: Row) !void {
    var g: Grade = .{};
    if (gradeCleaned(arena, dir_path, &g)) |_| {
        std.debug.print("variant at {s} was expected to violate §5.3.1 ({s}) and satisfied " ++
            "every row instead — either the shaping is unnecessary or this expectation is stale\n", .{ dir_path, @tagName(want) });
        return error.TestUnexpectedResult;
    } else |e| {
        try testing.expectEqual(error.ShapeViolation, e);
        if (g.row != want) {
            std.debug.print("refused, but for the wrong row: want {s}, got {?s} ({s})\n", .{
                @tagName(want), if (g.row) |r| @tagName(r) else null, g.message(),
            });
            return error.TestUnexpectedResult;
        }
    }
}

// The whole generator, end to end. Every §5.2/§5.3/§5.3.1/§5.4 self-check
// inside it is exercised by this one call; the assertions here are about the
// PRODUCT.
test "C2z: the generator produces both bundles" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const dir = try testDir(arena, "both");
    defer rmTree(dir);
    var g: Grade = .{};
    try generate(arena, dir, true, "test", &g);

    for ([_][]const u8{ TAIL_ID, CLEANED_ID }) |id| {
        const b = try std.fs.path.join(arena, &.{ dir, id });
        const names = try readDirNames(arena, b);
        try testing.expect(names.len >= 2);
        for (names) |n| try testing.expect(isSegmentName(n));
    }
    // §5.3: the cleaned bundle's retained floor is above segment 1, which is
    // the shape v1 could not express — and why this bundle exists at all.
    const seg1 = try std.fs.path.join(arena, &.{ dir, CLEANED_ID, try segmentName(arena, 1) });
    try testing.expectError(error.FileNotFound, std.fs.cwd().access(seg1, .{}));

    // §5.4 obligation 7: no scratch survives, and nothing but the two bundles
    // and the two sidecars is published.
    const published = try readDirNames(arena, dir);
    try testing.expectEqual(@as(usize, 4), published.len);
    try testing.expectEqualStrings("fragment.tsv", published[0]);
    try testing.expectEqualStrings("layout.tsv", published[1]);
    try testing.expectEqualStrings(CLEANED_ID, published[2]);
    try testing.expectEqualStrings(TAIL_ID, published[3]);
}

// §5.4 obligation 7 for the output directory: a forced rerun over a directory
// holding anything else must be REFUSED, not quietly republished around.
test "C2z: the generator refuses to publish beside stray files" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const dir = try testDir(arena, "stray");
    defer rmTree(dir);
    var g: Grade = .{};
    try generate(arena, dir, true, "test", &g);
    const stray = try std.fs.path.join(arena, &.{ dir, "leftover.tsv" });
    try std.fs.cwd().writeFile(.{ .sub_path = stray, .data = "x" });
    try testing.expectError(error.StrayFileInOutputDirectory, generate(arena, dir, true, "test", &g));
}

// §5.4 obligation 1: a non-empty output directory is refused without `force`.
test "C2z: the generator refuses a nonempty output directory without force" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const dir = try testDir(arena, "noforce");
    defer rmTree(dir);
    const f = try std.fs.path.join(arena, &.{ dir, "something" });
    try std.fs.cwd().writeFile(.{ .sub_path = f, .data = "x" });
    var g: Grade = .{};
    try testing.expectError(error.OutputDirectoryNotEmpty, generate(arena, dir, false, "test", &g));
}

// §5.4 obligation 8's in-process half, over the complete published tree
// including both sidecars.
//
// The generator compares two runs of each SHAPE internally and refuses to
// publish otherwise, but `fragment.tsv` does not exist yet when that
// comparison runs, so the sidecars are the part it structurally cannot assert
// about itself. The ACROSS-PROCESS half is
// `ci/check.sh`'s `zig build fixtures -- --wal3`, run twice — see contract
// §5.4 obligation 8, which names both halves and says why one is not enough.
test "C2z: two generator runs agree over the whole tree" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const a = try testDir(arena, "det-a");
    defer rmTree(a);
    const b = try testDir(arena, "det-b");
    defer rmTree(b);
    var g: Grade = .{};
    try generate(arena, a, true, "test", &g);
    try generate(arena, b, true, "test", &g);
    try testing.expectEqualStrings(try describeTree(arena, a), try describeTree(arena, b));
}

// The two shapes must be genuinely different, or one of them is testing
// nothing — restated as the layout index each produces.
test "C2z: the two shapes differ, and the layout index says how" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const dir = try testDir(arena, "differ");
    defer rmTree(dir);
    var g: Grade = .{};
    try generate(arena, dir, true, "test", &g);

    const tail = try describeTree(arena, try std.fs.path.join(arena, &.{ dir, TAIL_ID }));
    const cleaned = try describeTree(arena, try std.fs.path.join(arena, &.{ dir, CLEANED_ID }));
    try testing.expect(!std.mem.eql(u8, tail, cleaned));

    // §5.3.1 rows 1-3 as the index they produce. The tail shape has no middle
    // retained segment because it has no mark and therefore only two segments;
    // the cleaned shape must have all three positions.
    const layout = try readSidecar(arena, dir, "layout.tsv");
    for ([_][]const u8{
        "symbol\t" ++ CLEANED_ID ++ "\t@middle_retained\tx.wal.0000000000000003",
        "symbol\t" ++ CLEANED_ID ++ "\t@single_section_retained\tx.wal.0000000000000004",
        "symbol\t" ++ CLEANED_ID ++ "\t@mark\tx.wal.0000000000000002",
    }) |want| {
        if (std.mem.indexOf(u8, layout, want) == null) {
            std.debug.print("layout.tsv is missing:\n  {s}\ngot:\n{s}\n", .{ want, layout });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expect(std.mem.indexOf(u8, layout, TAIL_ID ++ "\t@mark") == null);
}

// The published bundles open cleanly in a fresh directory and mutate nothing.
//
// This is §5.5's claim, and all 36 accept cells rest on it: "no ACCEPT bundle
// cell mutates", so no cell carries a `created:`/`truncated:` override. The
// generator checks it for its scratch copy; this checks the copy that was
// actually published, and opens it the way a cell does — a plain open, no
// generator settings.
test "C2z: the published bundles open without mutating" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const dir = try testDir(arena, "nomutate");
    defer rmTree(dir);
    var g: Grade = .{};
    try generate(arena, dir, true, "test", &g);

    for ([_][]const u8{ TAIL_ID, CLEANED_ID }) |id| {
        const cell = try testDir(arena, id);
        defer rmTree(cell);
        const src = try std.fs.path.join(arena, &.{ dir, id });
        for (try readDirNames(arena, src)) |n| {
            const from = try std.fs.path.join(arena, &.{ src, n });
            const to = try std.fs.path.join(arena, &.{ cell, n });
            try std.fs.cwd().copyFile(from, std.fs.cwd(), to, .{});
        }
        const before = try describeTree(arena, cell);
        {
            const base_path = try std.fs.path.join(arena, &.{ cell, BASE_NAME });
            var s = try StoreWAL.open(arena, base_path, false);
            defer s.deinit();
            try s.verify();
            try s.close();
        }
        dropLock(cell, arena);
        try testing.expectEqualStrings(before, try describeTree(arena, cell));
    }
}

// The three REJECTED candidate workloads, measured against THIS engine.
//
// What this pins, stated narrowly: all three lose §5.3.1 **row 1**. They are
// the history of how §5.3's table was arrived at, not a per-witness
// falsification — two change the checkpoint's position and the third tests a
// rewrite that was proposed and rejected, and none removes an adopted shaping
// step. The per-step falsifiers are the next test and
// `rowFiveIsInvisibleToThisGenerator`; the per-WITNESS-ROW falsifiers are
// `derive.py --self-test`'s.
//
// The three shape strings are the evidence that §5.3's amended table binds
// zig and not only java: C2j measured them against the reference, C2r against
// rust, and this reproduces them from a third writer and a third decoder.
test "C2z: the rejected candidate workloads, measured" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cases = [_]struct { v: Variant, shape: []const u8 }{
        // §5.3 as revision 1 literally wrote it: the cleaner's image covers F's
        // 1.2 MB, which overflows the segment holding it, so the forced mark
        // lands as section 0 of the NEXT segment. Adding segments cannot repair
        // it — whichever becomes the middle one opens with the 'K' row 2 forbids.
        .{ .v = .spec, .shape = "mark=3:0 retained=[2, 3] activeSections=2" },
        // The checkpoint moved: the mark is section 1 of the LOWEST retained
        // segment, beside the 'C' image, which is what row 2 needs.
        .{ .v = .ckpt_after_t2, .shape = "mark=2:1 retained=[2, 3] activeSections=1" },
        // The plan's own first proposal: one oversized commit was expected to
        // "force the rotation into a single-section active segment". It does
        // not — the 1.2 MB section joins the segment it overflows.
        .{ .v = .ckpt_after_t2_shaped, .shape = "mark=2:1 retained=[2, 3] activeSections=4" },
    };
    for (cases) |c| {
        const d = try testDir(arena, @tagName(c.v));
        defer rmTree(d);
        try probeVariant(arena, c.v, d);
        try testing.expectEqualStrings(c.shape, try describeShape(arena, d));
        try expectRefusal(arena, d, .retained_cardinality);
    }
}

// Each ADOPTED shaping step, removed on its own, and what it costs.
//
// The rotation pair is two commits because rollover is tested BEFORE a section
// is appended, and each half is removed separately rather than the pair as a
// unit — removing the pair together would show only that "some rotation is
// needed", which is not the claim §5.3 makes.
test "C2z: each shaping step is load-bearing" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cases = [_]struct { v: Variant, shape: []const u8 }{
        // No rotation at all: the log never opens a third segment, so `middle`
        // and `active` are the same file and row 1 is lost.
        .{ .v = .shaped_no_rotate, .shape = "mark=2:1 retained=[2, 3] activeSections=3" },
        // Only the half that CROSSES segmentBytes: the oversized section joins
        // the segment it overflows, so nothing has rotated yet.
        .{ .v = .shaped_half_rotate, .shape = "mark=2:1 retained=[2, 3] activeSections=4" },
    };
    for (cases) |c| {
        const d = try testDir(arena, @tagName(c.v));
        defer rmTree(d);
        try probeVariant(arena, c.v, d);
        try testing.expectEqualStrings(c.shape, try describeShape(arena, d));
        try expectRefusal(arena, d, .retained_cardinality);
    }
}

// The one shaping step this file CANNOT justify, made executable rather than
// argued.
//
// `shapeC` exists for §5.3.1 row 5, and row 5 is the row `checkCleaned` does
// not check — deciding it means decoding the entry stream and searching for a
// size-preserving replacement encoding. So dropping `shapeC` produces a bundle
// this generator's own grading ACCEPTS, and only `derive.check_witnesses`
// refuses it. This test asserts the zig side's BLINDNESS, which is the only
// part of it this file can own. If it ever starts failing, the generator has
// grown a row-5 check and this should become an `expectRefusal` instead —
// which is a better outcome, not a regression.
test "C2z: row 5 is invisible to this generator" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const d = try testDir(arena, "no-c");
    defer rmTree(d);
    try probeVariant(arena, .shaped_no_c, d);
    try testing.expectEqualStrings(
        "mark=2:1 retained=[2, 3, 4] activeSections=1",
        try describeShape(arena, d),
    );
    var g: Grade = .{};
    _ = try gradeCleaned(arena, d, &g); // accepted: rows 1,2,3,4,6 hold without shapeC
}
