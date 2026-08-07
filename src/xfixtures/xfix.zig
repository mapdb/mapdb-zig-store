//! Cross-port fixture reader: the **v1/v2 manifest dispatch**, the WAL v3
//! segment decoder, and the assertion helpers the conformance suite shares
//! (Stage C slice **C3z**, `todo/store-wal3/wal3-c3-plan.md`).
//!
//! # What this port does NOT have to do
//!
//! Java put its decoder in `org.mapdb.store` so it could borrow the engine's
//! constants instead of transcribing them; rust could not, because decision
//! C-D3 makes its reader compile into two different crates, so it transcribes
//! and keeps an in-crate equality test honest. Zig is in java's position and
//! better: this file is inside the package, so it imports `wal_segments.zig`
//! and `wal_recover.zig` directly and there is **nothing transcribed here to
//! drift**. It borrows three things on purpose:
//!
//! - the format constants (`SEG_HDR`, `SEC_HDR`, the tags, `MAX_CAPACITY`);
//! - `segments.crcDomainOf`, the engine's own definition of a section's CRC
//!   domain — all 36 header bytes then `be64(sectionOffset)`;
//! - `recover.parseSecHdr` and `io.DataInput2.unpackLong`, the engine's own
//!   section-header and packed-long readers.
//!
//! Borrowing those makes the §11.2 comparisons stronger **for behaviour the
//! pinned corpus exercises**, and that qualification is load-bearing. The two
//! golden tables are written by python (framing) and by the frozen java reader
//! (bodies), so they are external authorities: if the engine's own CRC domain,
//! its section-header parse or its packed-long reader disagreed with java's on a
//! sample byte, this suite would report it as a golden mismatch, where a second
//! in-repo transcription could only ever grade this file against itself.
//!
//! It is WEAKER for anything the corpus does not exercise, because then the
//! reader and the thing under test move together and nothing external notices.
//! `T_APPEND` is the concrete case: no golden row contains one, [`entries`]
//! refuses it before decoding its remaining fields, and the synthetic battery
//! encodes it with the same imported constant it then decodes with — so a drift
//! in the engine's opcode would be followed, not caught. The battery therefore
//! pins the four entry opcodes as literals, which is the one place this file
//! deliberately does not borrow. The C3z review drew the line.
//!
//! # What the decoder validates, and what it does not
//!
//! [`decode`] checks the magic, the format version, the header CRC, both
//! section CRCs, the section tag vocabulary and every entry-stream bound. It
//! does **not** re-implement the engine's rules: `flags == 0`, seq/filename
//! agreement, dense increasing LSNs, cross-segment linkage, mark ranges,
//! `capValid`, one-entry-per-recid. The engine does all of that, and this suite
//! opens the same bundles through the engine in the same run.
//!
//! # Refusals carry messages
//!
//! Every rule here reports through [`Ctx.err`], which formats a sentence into
//! the context before returning `error.XFixtures`. That is what makes
//! [`expectRefused`] able to demand more than "it failed": a refusal is only
//! useful if it says which rule fired.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const store_mod = @import("../store/mod.zig");
const wal_mod = @import("../store/wal.zig");
const StoreWAL = store_mod.StoreWAL;
const StoreDirect = store_mod.StoreDirect;
const segments = @import("../store/wal_segments.zig");
const recover = @import("../store/wal_recover.zig");
const iv = @import("../store/index_val.zig");

const Crc32 = std.hash.crc.Crc32;

// ---------------------------------------------------------------------------
// the engine's format constants, imported (never transcribed)
// ---------------------------------------------------------------------------

pub const SEG_HDR: usize = @intCast(segments.SEG_HDR);
pub const SEG_HDR_CRC_LEN: usize = segments.SEG_HDR_CRC_LEN;
pub const MAGIC: [8]u8 = segments.MAGIC;
pub const FORMAT_VERSION: i32 = segments.FORMAT_VERSION;

pub const SEC_HDR: usize = @intCast(recover.SEC_HDR);
pub const SEC_HDR_CRC_LEN: usize = recover.SEC_HDR_CRC_LEN;
pub const TAG_SECTION: u8 = recover.TAG_SECTION;
pub const TAG_IMAGE: u8 = recover.TAG_IMAGE;
pub const TAG_MARK: u8 = recover.TAG_MARK;
pub const MARK_BODY_LEN: i64 = recover.MARK_BODY_LEN;

pub const T_PREALLOC: u8 = recover.T_PREALLOC;
pub const T_RECORD: u8 = recover.T_RECORD;
pub const T_APPEND: u8 = recover.T_APPEND;
pub const T_DELETE: u8 = recover.T_DELETE;

/// `StoreDirect`'s plain-record capacity ceiling — half of `capValid`'s rule.
/// The C3r review found rust's witness missing it, and without the ceiling
/// [`checkCap`] accepts capacities recovery rejects and, worse, accepts
/// `cap == 0` for content that is not oversize at all.
pub const MAX_CAPACITY: u64 = @intCast(iv.MAX_CAPACITY);

// ---------------------------------------------------------------------------
// vocabularies (shared with org.mapdb.xfixtures.XFixtureManifest and xfix.rs)
// ---------------------------------------------------------------------------

pub const ENGINE = "zig";
pub const ENGINES = [_][]const u8{ "java", "rust", "zig" };
pub const MODES = [_][]const u8{ "ro", "rw" };
pub const VERDICTS = [_][]const u8{ "accept", "reject" };

/// Contract §2's `kind` vocabulary. D6 fixed the v2 set as "all v1 kinds +
/// `wal3-namespace`", and `port-wal`/`java-wal-namespace` are **retained as
/// valid tokens** though no v2 fixture uses them — retiring a fixture family is
/// not a reason to make a version-dispatch parser reject the token.
pub const V1_KINDS = [_][]const u8{ "direct", "reject", "port-wal", "java-wal-namespace" };
pub const V2_KINDS = [_][]const u8{ "direct", "reject", "wal3-namespace", "port-wal", "java-wal-namespace" };

/// A v2 fixture no engine wrote records `derived` here, and then owes exactly
/// one `derived` row (contract §2, amendment 3).
pub const V2_GENERATORS = [_][]const u8{ "java", "rust", "zig", "derived" };

pub const V1_OPENERS = [_][]const u8{ "direct", "wal" };
pub const V2_OPENERS = [_][]const u8{ "direct", "wal3" };

/// sha256 of the empty byte string — the zero-length-content marker that has to
/// stay distinguishable from NULL content.
pub const EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// ---------------------------------------------------------------------------
// the refusal context
// ---------------------------------------------------------------------------

pub const Error = error{XFixtures} || DbError;

/// Carries the allocator and the last refusal message.
///
/// `quiet` is set only by [`expectRefused`], for the same reason rust silences
/// the panic hook around its `catch_unwind`: a suite whose PASSING output is
/// full of refusal lines trains the reader to ignore exactly the lines that
/// matter.
pub const Ctx = struct {
    alloc: Allocator,
    buf: [2048]u8 = undefined,
    len: usize = 0,
    quiet: bool = false,

    pub fn err(self: *Ctx, comptime fmt: []const u8, args: anytype) error{XFixtures} {
        const s = std.fmt.bufPrint(&self.buf, fmt, args) catch self.buf[0..];
        self.len = s.len;
        if (!self.quiet) std.debug.print("[xfixtures] {s}\n", .{s});
        return error.XFixtures;
    }

    pub fn message(self: *const Ctx) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Asserts that `f(args...)` REFUSES, and that the refusal carried a message.
///
/// Two things are load-bearing. The call is made through `@call` rather than
/// taking an already-evaluated result, so `quiet` is in force while the rule
/// runs. And an empty message fails: `error.XFixtures` with nothing said would
/// satisfy a bare "it errored" check while telling a future reader nothing.
pub fn expectRefused(ctx: *Ctx, what: []const u8, comptime f: anytype, args: anytype) !void {
    ctx.quiet = true;
    ctx.len = 0;
    defer ctx.quiet = false;
    if (@call(.auto, f, args)) |_| {
        std.debug.print("[xfixtures] accepted {s}\n", .{what});
        return error.TestUnexpectedResult;
    } else |e| {
        if (e != error.XFixtures) {
            std.debug.print("[xfixtures] {s}: refused with {s}, not a stated rule\n", .{ what, @errorName(e) });
            return error.TestUnexpectedResult;
        }
        if (ctx.len == 0) {
            std.debug.print("[xfixtures] the refusal of {s} carried no message\n", .{what});
            return error.TestUnexpectedResult;
        }
    }
}

/// [`expectRefused`], plus the demand that the message NAMES the rule that fired.
///
/// Needed wherever an input can trip more than one rule — lesson (h) inside the
/// test harness itself. The write-gate probe is the case that forced it: pointing
/// the `rw` branch at a read-only handle refuses either because `preallocate` was
/// rejected (the rule) or because the `rollback` after it was (a different rule),
/// and a bare "it refused" cannot tell those apart. It could not, and a mutant
/// that swallowed the preallocate error survived.
pub fn expectRefusedSaying(
    ctx: *Ctx,
    what: []const u8,
    saying: []const u8,
    comptime f: anytype,
    args: anytype,
) !void {
    try expectRefused(ctx, what, f, args);
    if (std.mem.indexOf(u8, ctx.message(), saying) == null) {
        std.debug.print(
            "[xfixtures] {s}: refused, but the message does not mention `{s}`:\n  {s}\n",
            .{ what, saying, ctx.message() },
        );
        return error.TestUnexpectedResult;
    }
}

// ---------------------------------------------------------------------------
// small utilities
// ---------------------------------------------------------------------------

pub fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// Decompress a `.gz` blob (zig 0.15: `std.compress.flate.Decompress` over a
/// fixed `std.Io.Reader`, container `.gzip`). Owned result.
pub fn gunzip(ctx: *Ctx, gz: []const u8, raw_len: u64, what: []const u8) Error![]u8 {
    var in: std.Io.Reader = .fixed(gz);
    const window = try ctx.alloc.alloc(u8, std.compress.flate.max_window_len);
    defer ctx.alloc.free(window);
    var dec = std.compress.flate.Decompress.init(&in, .gzip, window);
    return dec.reader.allocRemaining(ctx.alloc, .limited64(raw_len + 1)) catch |e|
        ctx.err("gunzip {s} failed: {s}", .{ what, @errorName(e) });
}

/// The corpus payload function: `payload(id, len)[i] == (i*131 + id) & 0xff`.
/// Invertible from its first byte, which is what makes it usable as a witness
/// that an entry stream was framed the way the writer wrote it.
pub fn payload(alloc: Allocator, payload_id: u64, len: usize) ![]u8 {
    const buf = try alloc.alloc(u8, len);
    for (buf, 0..) |*b, i| b.* = @truncate(i * 131 + payload_id);
    return buf;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn lessThanStr(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn contains(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |h| if (eql(h, needle)) return true;
    return false;
}

/// A growable list of owned strings, with one `deinit` that frees all of them.
pub const Strings = struct {
    items: std.ArrayListUnmanaged([]const u8) = .empty,

    pub fn deinit(self: *Strings, alloc: Allocator) void {
        for (self.items.items) |s| alloc.free(s);
        self.items.deinit(alloc);
    }

    pub fn add(self: *Strings, alloc: Allocator, comptime fmt: []const u8, args: anytype) ![]const u8 {
        const s = try std.fmt.allocPrint(alloc, fmt, args);
        self.items.append(alloc, s) catch |e| {
            alloc.free(s);
            return e;
        };
        return s;
    }

    pub fn slice(self: *const Strings) []const []const u8 {
        return self.items.items;
    }
};

// ---------------------------------------------------------------------------
// the golden tables
// ---------------------------------------------------------------------------

/// The comment block `GOLDEN-BODY.tsv` carries, pinned verbatim.
///
/// The row comparison drops comments — but for this file that loses something.
/// The block is the file's PROVENANCE: it states that the frozen java reader
/// authored it, that `lenPlus` is raw, and how to regenerate it. Without a pin
/// that header could be deleted, or rewritten to claim python authorship, while
/// every test stayed green — and the authority claim is the reason this port is
/// graded against this file at all. (`GOLDEN-DECODE.tsv` needs no equivalent:
/// java compares it by row too.)
pub const GOLDEN_BODY_HEADER = [_][]const u8{
    "# The DECODED BODIES of every pinned schema-v2 sample section, as the FROZEN JAVA",
    "# READER reads them — contract §11.2's engine-against-engine half.",
    "#",
    "#   sec  <bundle> <relName> <index> <tag> <entryCount>",
    "#   ent  <bundle> <relName> <index> <ord> <kind> <recid> <cap> <lenPlus> <contentSha256>",
    "#   mark <bundle> <relName> <index> <cleanedThroughSeq> <logStartLsn>",
    "#",
    "# GOLDEN-DECODE.tsv pins FRAMING and deliberately stops there: walfmt.py is a",
    "# structural codec, and store record semantics written in python would be a fifth",
    "# implementation no one reviews. This file is the other half, and Java authors it",
    "# because Java is the reference for what a body MEANS.",
    "#",
    "# lenPlus IS RAW, NOT A LENGTH. `lenPlus == 0` is NULL content; `lenPlus == 1` is",
    "# ZERO-LENGTH content (StoreWAL.applySection). A reader that decodes lenPlus into a",
    "# length collapses the two, and two readers that both collapse it agree forever.",
    "# contentSha256 is `-` for NULL and the empty-string sha for zero-length, so the two",
    "# differ in both columns. The sample contains one of each: recid 12 and recid 11.",
    "#",
    "# `-` means the column does not apply to that entry kind. cap is emitted because a",
    "# reader must decode it to find the next entry at all; leaving it out would be a",
    "# field the comparison never reaches.",
    "#",
    "# Regenerate with mapdb-java-store's org.mapdb.xfixtures.Wal3BodyDump; the java suite",
    "# re-derives it and fails on drift.",
};

/// Data lines of a golden `.tsv`: comments and blank lines dropped. The comment
/// block is prose the authoring engine wrote; only the rows are a decode, and
/// only the rows are compared.
pub fn goldenRows(alloc: Allocator, text: []const u8) !std.ArrayListUnmanaged([]const u8) {
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer out.deinit(alloc);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimRight(u8, raw, "\r");
        if (line.len == 0 or line[0] == '#') continue;
        try out.append(alloc, line);
    }
    return out;
}

/// The leading comment block of a golden `.tsv`.
pub fn goldenHeader(alloc: Allocator, text: []const u8) !std.ArrayListUnmanaged([]const u8) {
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer out.deinit(alloc);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimRight(u8, raw, "\r");
        if (line.len == 0 or line[0] != '#') break;
        try out.append(alloc, line);
    }
    return out;
}

/// A golden `.tsv` is a leading comment block and then data rows, with nothing
/// else anywhere.
///
/// Zig compares rows and pins the leading block separately, where java compares
/// whole text. Without this the two are not equivalent: a comment inserted,
/// rewritten or deleted AFTER the first data row is dropped by `goldenRows` and
/// missed by `goldenHeader`, so it would be invisible here and visible to java.
/// The C3z review named the gap; this closes it without a second whole-text
/// comparison whose failures are unreadable.
pub fn assertGoldenShape(ctx: *Ctx, what: []const u8, text: []const u8) Error!void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var seen_data = false;
    var n: usize = 0;
    while (lines.next()) |raw| {
        n += 1;
        const line = std.mem.trimRight(u8, raw, "\r");
        if (line.len == 0) {
            // Only the empty piece a trailing newline leaves is allowed, and only
            // as the very last one.
            if (lines.peek() != null)
                return ctx.err("{s} line {d}: a blank line", .{ what, n });
            continue;
        }
        if (line[0] == '#') {
            if (seen_data) return ctx.err("{s} line {d}: a comment after the first data row", .{ what, n });
            continue;
        }
        seen_data = true;
    }
    if (!seen_data) return ctx.err("{s}: no data rows", .{what});
}

/// Compares two row lists line by line, reporting the FIRST disagreement with
/// its row number before falling back to the length check — a diff that only
/// says "1042 rows != 1041" makes a one-row drift expensive to find.
pub fn assertRowsEqual(ctx: *Ctx, what: []const u8, want: []const []const u8, got: []const []const u8) Error!void {
    const n = @min(want.len, got.len);
    for (0..n) |i| {
        if (!eql(want[i], got[i]))
            return ctx.err("{s} row {d}:\n  want {s}\n  got  {s}", .{ what, i + 1, want[i], got[i] });
    }
    if (want.len != got.len)
        return ctx.err("{s}: row count, want {d}, got {d}", .{ what, want.len, got.len });
}

// ---------------------------------------------------------------------------
// decoded shapes
// ---------------------------------------------------------------------------

pub const Header = struct {
    version: i32,
    flags: i32,
    seq: i64,
    first_lsn: i64,
    header_crc: u32,
};

pub const Section = struct {
    index: usize,
    offset: usize,
    tag: u8,
    lsn: i64,
    body_len: i64,
    hdr_crc: u32,
    body_crc: u32,
    /// Borrowed from the segment bytes the caller passed to [`decode`].
    body: []const u8,
};

/// One entry of an `'S'`/`'C'` body.
///
/// `cap` and `len_plus` are null for the kinds that do not carry them, and
/// **`len_plus` is RAW**: `0` is NULL content and `1` is zero-length content.
/// Decoding it into a length collapses the two, and two readers that both
/// collapse it agree forever.
pub const Entry = struct {
    tag: u8,
    recid: u64,
    cap: ?u64 = null,
    len_plus: ?u64 = null,
    /// Borrowed from the section body.
    content: ?[]const u8 = null,

    pub fn kind(self: Entry) []const u8 {
        return switch (self.tag) {
            T_PREALLOC => "PREALLOC",
            T_RECORD => "RECORD",
            T_DELETE => "DELETE",
            T_APPEND => "APPEND",
            else => "?",
        };
    }

    pub fn isRecord(self: Entry) bool {
        return self.tag == T_RECORD;
    }
};

pub const Segment = struct {
    header: Header = undefined,
    sections: std.ArrayListUnmanaged(Section) = .empty,
    /// Bytes after the last complete section — a torn tail, REPORTED rather than
    /// silently accepted so a caller can decide whether it is legal here.
    trailing: usize = 0,

    pub fn deinit(self: *Segment, alloc: Allocator) void {
        self.sections.deinit(alloc);
    }
};

fn be32(b: []const u8, off: usize) i32 {
    return std.mem.readInt(i32, b[off..][0..4], .big);
}

fn be64(b: []const u8, off: usize) i64 {
    return std.mem.readInt(i64, b[off..][0..8], .big);
}

/// A hasher primed with a section's CRC domain, using the ENGINE's definition of
/// it: all 36 header bytes then `be64(sectionOffset)`, fed before the section's
/// own bytes. The offset being in the domain is what makes a section
/// un-relocatable.
fn domain(raw: []const u8, section_off: usize) Crc32 {
    var c = Crc32.init();
    segments.crcDomainOf(&c, raw[0..SEG_HDR], @intCast(section_off));
    return c;
}

/// Decodes one segment file, validating both CRCs of every section.
pub fn decode(ctx: *Ctx, raw: []const u8, where: []const u8, out: *Segment) Error!void {
    if (raw.len < SEG_HDR)
        return ctx.err("{s}: {d} bytes is shorter than a {d}-byte segment header", .{ where, raw.len, SEG_HDR });
    if (!eql(raw[0..8], &MAGIC))
        return ctx.err("{s}: bad segment magic", .{where});
    const version = be32(raw, 8);
    if (version != FORMAT_VERSION)
        return ctx.err("{s}: format version {d}, want {d}", .{ where, version, FORMAT_VERSION });
    const header_crc: u32 = @bitCast(be32(raw, SEG_HDR_CRC_LEN));
    const want_hdr_crc = Crc32.hash(raw[0..SEG_HDR_CRC_LEN]);
    if (want_hdr_crc != header_crc)
        return ctx.err("{s}: segment header CRC {x:0>8}, computed {x:0>8}", .{ where, header_crc, want_hdr_crc });
    out.header = .{
        .version = version,
        .flags = be32(raw, 12),
        .seq = be64(raw, 16),
        .first_lsn = be64(raw, 24),
        .header_crc = header_crc,
    };

    var off: usize = SEG_HDR;
    while (off < raw.len) {
        if (off + SEC_HDR > raw.len) break; // torn: not even a whole section header
        const h = recover.parseSecHdr(raw[off..][0..SEC_HDR]);
        if (h.tag != TAG_SECTION and h.tag != TAG_IMAGE and h.tag != TAG_MARK)
            return ctx.err("{s}: unknown section tag {d} at offset {d}", .{ where, h.tag, off });
        var hc = domain(raw, off);
        hc.update(raw[off..][0..SEC_HDR_CRC_LEN]);
        const got_hc = hc.final();
        if (got_hc != @as(u32, @bitCast(h.hdr_crc)))
            return ctx.err("{s}: section header CRC at offset {d}", .{ where, off });
        if (h.body_len < 0)
            return ctx.err("{s}: negative bodyLen {d} at offset {d}", .{ where, h.body_len, off });
        // Compare by SUBTRACTION: `off + SEC_HDR + body_len <= raw.len` overflows
        // for a body_len near maxInt and wraps, passing the very check it is.
        // Both operands here are bounded by the file.
        if (@as(u64, @intCast(h.body_len)) > @as(u64, raw.len - off - SEC_HDR)) break; // torn: body not all here
        const body_len: usize = @intCast(h.body_len);
        const body = raw[off + SEC_HDR ..][0..body_len];
        var bc = domain(raw, off);
        bc.update(body);
        const got_bc = bc.final();
        if (got_bc != @as(u32, @bitCast(h.body_crc)))
            return ctx.err("{s}: section body CRC at offset {d}", .{ where, off });
        if (h.tag == TAG_MARK and h.body_len != MARK_BODY_LEN)
            return ctx.err("{s}: a 'K' body at {d} is {d} bytes, not {d}", .{ where, off, h.body_len, MARK_BODY_LEN });
        try out.sections.append(ctx.alloc, .{
            .index = out.sections.items.len,
            .offset = off,
            .tag = h.tag,
            .lsn = h.lsn,
            .body_len = h.body_len,
            .hdr_crc = @bitCast(h.hdr_crc),
            .body_crc = @bitCast(h.body_crc),
            .body = body,
        });
        off += SEC_HDR + body_len;
    }
    out.trailing = raw.len - off;
}

/// [`decode`] plus the requirement every PINNED file must satisfy: the segment
/// is framed all the way to its last byte.
///
/// The rule cannot live in [`decode`], which reports a torn tail on purpose so a
/// caller can decide whether one is legal. It cannot be measured by the sample
/// either — no pinned file has a torn tail, so deleting the rule left the whole
/// suite green, which the C3z campaign measured. That is lesson (g) in its pure
/// form: a rule whose subject never varies in the corpus is reachable only by a
/// synthetic input. Every production call site goes through here, so the rule is
/// written once and the battery can address it directly.
pub fn decodeComplete(ctx: *Ctx, raw: []const u8, where: []const u8, out: *Segment) Error!void {
    try decode(ctx, raw, where, out);
    if (out.trailing != 0)
        return ctx.err("{s}: {d} bytes follow the last section", .{ where, out.trailing });
}

/// Decodes the ordered entry stream of an `'S'` or `'C'` section.
///
/// `'C'` is decoded exactly like `'S'`: the two tags differ in what recovery
/// does with the section, not in how a body is framed (`StoreWAL.java:850`).
/// Only `'K'` is withheld — its body is a mark, see [`mark`].
pub fn entries(ctx: *Ctx, s: *const Section, where: []const u8, out: *std.ArrayListUnmanaged(Entry)) Error!void {
    if (s.tag != TAG_SECTION and s.tag != TAG_IMAGE)
        return ctx.err("{s} section {d}: tag '{c}' carries no entry stream", .{ where, s.index, s.tag });
    var in = DataInput2.init(s.body);
    while (in.pos < s.body.len) {
        const at = in.pos;
        const tag = in.readU8() catch return ctx.err("{s} section {d}: entry stream ends at {d}", .{ where, s.index, at });
        var e = Entry{ .tag = tag, .recid = 0 };
        e.recid = in.unpackLong() catch
            return ctx.err("{s} section {d}: entry at {d} ends mid-recid", .{ where, s.index, at });
        switch (tag) {
            T_PREALLOC, T_DELETE => {},
            T_RECORD => {
                e.cap = in.unpackLong() catch
                    return ctx.err("{s} section {d}: entry at {d} ends mid-capacity", .{ where, s.index, at });
                const len_plus = in.unpackLong() catch
                    return ctx.err("{s} section {d}: entry at {d} ends mid-length", .{ where, s.index, at });
                e.len_plus = len_plus;
                if (len_plus > 0) {
                    const n = std.math.cast(usize, len_plus - 1) orelse
                        return ctx.err("{s} section {d}: lenPlus {d} at {d} is not a length", .{ where, s.index, len_plus, at });
                    e.content = in.takeBytes(n) catch
                        return ctx.err("{s} section {d}: {d} content bytes at {d} run past the {d}-byte body", .{ where, s.index, n, at, s.body.len });
                }
            },
            T_APPEND => return ctx.err(
                "{s} section {d}: T_APPEND at {d} is not decoded here — the C3 body dump has no " ++
                    "columns for it and no fixture exercises it; extend both together",
                .{ where, s.index, at },
            ),
            else => return ctx.err("{s} section {d}: unknown entry tag {d} at {d}", .{ where, s.index, tag, at }),
        }
        try out.append(ctx.alloc, e);
    }
}

pub const Mark = struct { through: i64, log_start: i64 };

/// The two fields of a `'K'` mark body, in wire order.
pub fn mark(ctx: *Ctx, s: *const Section, where: []const u8) Error!Mark {
    if (s.tag != TAG_MARK)
        return ctx.err("{s} section {d}: not a mark section", .{ where, s.index });
    if (s.body.len != MARK_BODY_LEN)
        return ctx.err("{s} section {d}: mark body is {d} bytes", .{ where, s.index, s.body.len });
    return .{ .through = be64(s.body, 0), .log_start = be64(s.body, 8) };
}

// ---------------------------------------------------------------------------
// the independent witnesses
// ---------------------------------------------------------------------------

/// The independent witness for the emitted `cap` column.
///
/// Nothing else in the slice observes `cap`: replay consumes it and exposes only
/// the resulting record, and the golden comparison grades the column against a
/// file another engine wrote. An emitter that consumed the varint correctly and
/// printed a fabricated number would pass both. This is `wal_recover.capValid`'s
/// rule restated over what the dump can see — a plain capacity is 16-aligned and
/// leaves room for the 4-byte header; 0 means oversize content stored linked.
///
/// The negative-capacity case rust's witness carries has no counterpart here:
/// `cap` arrives from `unpackLong`, whose domain is `u64`, so the encoding
/// cannot express it.
pub fn checkCap(ctx: *Ctx, cap: u64, len: usize, where: []const u8) Error!void {
    const need = 4 + @as(u64, len);
    if (cap == 0) {
        // `cap == 0` is how the writer encodes OVERSIZE content, stored linked.
        // Accepting it unconditionally blesses a zero capacity on content that
        // fits a plain record, which is exactly the value recovery refuses.
        if (need <= MAX_CAPACITY)
            return ctx.err(
                "{s}: cap 0 means content stored linked because it is oversize, but {d} content " ++
                    "bytes need only {d} and the plain-record ceiling is {d}",
                .{ where, len, need, MAX_CAPACITY },
            );
        return;
    }
    if (!(cap >= need and cap <= MAX_CAPACITY and (cap & 15) == 0))
        return ctx.err(
            "{s}: cap {d} is not a valid capacity for {d} content bytes (must be 16-aligned, at " ++
                "least {d}, and at most {d})",
            .{ where, cap, len, need, MAX_CAPACITY },
        );
}

/// The witness that these content bytes lie in the payload LANGUAGE.
///
/// `payload(id, len)[i] == (i*131 + id) & 0xff` is invertible from its first
/// byte, so rebuilding it from the recovered id and comparing catches a run that
/// is not a payload at all — which is what a decoder that read the packed-long
/// continuation bit the wrong way round produces. It is **not** a check that
/// this bundle issued this payload: it consults no fixture history, and since
/// `payload` is an arithmetic progression, every suffix of a payload is another
/// payload. `lenPlus` and the golden sha column cover that gap. Zero-length
/// content carries no id and is vacuously fine.
pub fn checkPayload(ctx: *Ctx, c: []const u8, where: []const u8) Error!void {
    if (c.len == 0) return;
    const id: u64 = c[0];
    for (c, 0..) |b, i| {
        const want: u8 = @truncate(i * 131 + id);
        if (b != want)
            return ctx.err(
                "{s}: the {d} content bytes are not payload({d}, {d}) — they differ at index {d} " ++
                    "({d} vs {d}), so this entry stream was not framed the way the writer wrote it",
                .{ where, c.len, id, c.len, i, b, want },
            );
    }
}

/// The independent witness for the two `'K'` mark longs, which are otherwise
/// indistinguishable once decoded — both are longs in one 16-byte body, so a
/// decoder returning them in the other order emits a self-consistent file. These
/// are the engine's own S8/K4 rules; the sample's mark is `(through=2,
/// logStart=9)` in segment 4, so a swap makes `through` 9 and trips K4 at once.
pub fn checkMark(ctx: *Ctx, m: Mark, seg_seq: i64, lsn: i64, where: []const u8) Error!void {
    if (m.through <= 0)
        return ctx.err("{s}: cleanedThroughSeq is {d}", .{ where, m.through });
    if (m.through >= seg_seq)
        return ctx.err(
            "{s}: a mark in segment {d} authorizes removing segment {d}, including itself (K4)",
            .{ where, seg_seq, m.through },
        );
    if (!(m.log_start > 0 and m.log_start <= lsn))
        return ctx.err(
            "{s}: logStartLsn {d} is not an LSN at or below the mark's own {d} (S8)",
            .{ where, m.log_start, lsn },
        );
}

// ---------------------------------------------------------------------------
// MANIFEST.tsv — the v1/v2 dispatch
// ---------------------------------------------------------------------------

/// Up to nine tab-separated fields of one manifest line, plus the true count.
const Fields = struct {
    f: [9][]const u8 = undefined,
    n: usize = 0,
};

fn split(line: []const u8) Fields {
    var out = Fields{};
    var it = std.mem.splitScalar(u8, line, '\t');
    while (it.next()) |field| {
        if (out.n < out.f.len) out.f[out.n] = field;
        out.n += 1;
    }
    return out;
}

/// Field-count plus emptiness. A TSV row with a blank column parses "fine" and
/// then every consumer of that column sees `""`, so the emptiness half is not
/// decoration.
fn arity(ctx: *Ctx, t: Fields, want: usize, line: []const u8) Error!void {
    if (t.n != want)
        return ctx.err("bad {s} row: expected {d} fields, got {d}: {s}", .{ t.f[0], want, t.n, line });
    for (t.f[0..t.n], 0..) |field, i| {
        if (field.len == 0)
            return ctx.err("bad {s} row: field {d} is empty: {s}", .{ t.f[0], i, line });
    }
}

/// A canonical decimal non-negative integer: no sign, no leading zero, no
/// whitespace, in range. A permissive parse accepts `+7` and `007`, both of
/// which would make two manifests that differ textually mean the same thing.
fn nat(ctx: *Ctx, s: []const u8, line: []const u8) Error!u64 {
    if (s.len == 0) return ctx.err("empty integer in: {s}", .{line});
    for (s) |c| {
        if (c < '0' or c > '9')
            return ctx.err("not a canonical decimal non-negative integer: {s} in: {s}", .{ s, line });
    }
    if (s.len > 1 and s[0] == '0')
        return ctx.err("not a canonical decimal non-negative integer: {s} in: {s}", .{ s, line });
    return std.fmt.parseInt(u64, s, 10) catch
        ctx.err("integer out of range: {s} in: {s}", .{ s, line });
}

/// A single path component that is safe to join onto a cell directory. The
/// manifest is data, and a `relName` of `../../x` would be executed as written.
fn relName(ctx: *Ctx, s: []const u8, line: []const u8) Error![]const u8 {
    const ok = s.len > 0 and
        std.mem.indexOfAny(u8, s, "/\\\x00") == null and
        !eql(s, ".") and !eql(s, "..") and s[0] != '-';
    if (!ok) return ctx.err("unsafe relName {s} in: {s}", .{ s, line });
    return s;
}

/// 64 lowercase hex digits. The frozen java reader validates both hash columns
/// of a `file` row (`XFixtureManifest.sha256`); this reader stored them raw until
/// the C3z review, which meant a manifest could carry `aa`/`bb` and parse — and
/// several of this suite's own scaffolds did exactly that, so a case named for a
/// later rule was resting on a manifest the reference implementation refuses.
fn sha256Field(ctx: *Ctx, s: []const u8, line: []const u8) Error![]const u8 {
    if (s.len != 64) return ctx.err("not 64 lowercase hex digits: {s} in: {s}", .{ s, line });
    for (s) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return ctx.err("not 64 lowercase hex digits: {s} in: {s}", .{ s, line });
    }
    return s;
}

/// A nonempty, even-length, lowercase-hex byte string — an `edit` row's `before`
/// and `after` columns.
fn hexBytes(ctx: *Ctx, s: []const u8, line: []const u8) Error![]const u8 {
    if (s.len == 0 or s.len % 2 != 0)
        return ctx.err("not a whole number of lowercase hex bytes: {s} in: {s}", .{ s, line });
    for (s) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return ctx.err("not a whole number of lowercase hex bytes: {s} in: {s}", .{ s, line });
    }
    return s;
}

/// `catalogue.ARG_VALUE_CHARS`, transcribed. TAB, `,` and `=` are absent by
/// construction: they are the three separators the row is re-split on.
const ARG_VALUE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._@:/+-";

/// An `action` row's argument spec, matching `catalogue.render_action_args`:
/// `k=v` pairs joined by `,`, **keys in sorted order**, each key
/// `[a-z][a-z0-9_]*`, each value nonempty and drawn from [`ARG_VALUE_CHARS`].
///
/// The sort order is CHECKED rather than normalised. The spec travels to
/// [`runAction`] as a string and is compared, in todo's gate, against ONE
/// rendering authority; a reader that accepted any order would accept a manifest
/// python refuses, and the two roots would then disagree about what the same
/// cell says.
fn actionArgs(ctx: *Ctx, s: []const u8, line: []const u8) Error![]const u8 {
    var prev: ?[]const u8 = null;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse
            return ctx.err("action argument `{s}` is not one k=v pair in: {s}", .{ pair, line });
        // TWO statements, not one: an empty key and a second `=` are different
        // malformations and a conjunction gives neither its own red. Measured —
        // the collapsed form's deletion made `k[0]` index an empty slice and the
        // mutant died by a PANIC rather than by a rule.
        if (eq == 0)
            return ctx.err("action argument `{s}` has an empty key in: {s}", .{ pair, line });
        if (std.mem.count(u8, pair, "=") != 1)
            return ctx.err("action argument `{s}` is not one k=v pair in: {s}", .{ pair, line });
        const k = pair[0..eq];
        const v = pair[eq + 1 ..];
        // `k.len == 0` FIRST, so deleting the empty-key refusal above lands here
        // with a named message instead of an out-of-bounds index. A guard whose
        // removal is a panic is a guard whose red belongs to the language.
        if (k.len == 0 or k[0] < 'a' or k[0] > 'z')
            return ctx.err("action argument key `{s}` is not [a-z][a-z0-9_]* in: {s}", .{ k, line });
        for (k) |c| {
            const ok = (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '_';
            if (!ok) return ctx.err("action argument key `{s}` is not [a-z][a-z0-9_]* in: {s}", .{ k, line });
        }
        if (prev) |p| {
            if (!std.mem.lessThan(u8, p, k))
                return ctx.err("action argument keys must be sorted and distinct: `{s}` follows `{s}` in: {s}", .{ k, p, line });
        }
        prev = k;
        if (v.len == 0)
            return ctx.err("action argument {s}={s}: the value must be nonempty and drawn from the pinned character class in: {s}", .{ k, v, line });
        for (v) |c| {
            if (std.mem.indexOfScalar(u8, ARG_VALUE_CHARS, c) == null)
                return ctx.err("action argument {s}={s}: the value must be nonempty and drawn from the pinned character class in: {s}", .{ k, v, line });
        }
    }
    return s;
}

/// The `(fixture, engine, mode)` triple two rows share when they address the
/// same cell.
fn cellEq(a: [3][]const u8, b: [3][]const u8) bool {
    return eql(a[0], b[0]) and eql(a[1], b[1]) and eql(a[2], b[2]);
}

fn oneOf(ctx: *Ctx, s: []const u8, allowed: []const []const u8, what: []const u8, line: []const u8) Error![]const u8 {
    if (!contains(allowed, s))
        return ctx.err("unknown {s} `{s}` in: {s}", .{ what, s, line });
    return s;
}

pub const RecState = enum { live, null_rec, prealloc, deleted };

fn parseState(ctx: *Ctx, s: []const u8, line: []const u8) Error!RecState {
    if (eql(s, "live")) return .live;
    if (eql(s, "null")) return .null_rec;
    if (eql(s, "prealloc")) return .prealloc;
    if (eql(s, "deleted")) return .deleted;
    return ctx.err("unknown recid state `{s}` in: {s}", .{ s, line });
}

pub const RecidRow = struct {
    fixture: []const u8,
    label: []const u8,
    recid: u64,
    state: RecState,
    payload_id: u64,
    len: usize,
};

/// A `recidrange` may not be unbounded: the reader materialises one row per
/// recid, so `0 4294967295` is a manifest that hangs the suite.
const MAX_RANGE_SPAN: u64 = 1 << 20;

pub const FixtureRow = struct { id: []const u8, kind: []const u8 };

pub const FileRow = struct {
    fixture: []const u8,
    rel: []const u8,
    raw_len: u64,
    raw_sha: []const u8,
    gz_sha: []const u8,
};

/// `expect <fid> <engine> <verdict> <opener> <placeAs> <openArg>` — seven
/// fields, and the SAME arity as a v2 `expect` row with different columns in
/// them. That collision is why the version line is a hard dispatch and not a
/// hint; see [`parse`].
pub const V1Expect = struct {
    fixture: []const u8,
    engine: []const u8,
    verdict: []const u8,
    opener: []const u8,
    place_as: []const u8,
    open_arg: []const u8,
};

/// `expect <fid> <engine> <mode> <verdict> <opener> <openArg>`.
pub const V2Expect = struct {
    fixture: []const u8,
    engine: []const u8,
    mode: []const u8,
    verdict: []const u8,
    opener: []const u8,
    open_arg: []const u8,
};

/// `post <fid> <engine> <mode> <relName> <disposition>`.
pub const V2Post = struct {
    fixture: []const u8,
    engine: []const u8,
    mode: []const u8,
    rel: []const u8,
    verb: []const u8,
    len: ?u64 = null,
    sha: ?[]const u8 = null,
};

/// `applies <fid> <engine> <mode>` — a cell this corpus actually CONTAINS
/// (contract §2.3, slice C5).
///
/// The preflight corpus's cell set is legitimately partial — 3 fixtures and 7
/// cells for this engine, not `fixtures × modes` — so "every declared fixture
/// owes one cell per mode" is the wrong cardinality rule for it. `applies` says
/// which cells exist, and the corpus executor's rule becomes "the cells I ran
/// are exactly the `applies` rows addressed to me".
pub const V2Applies = struct {
    fixture: []const u8,
    engine: []const u8,
    mode: []const u8,
};

/// `action <fid> <engine> <mode> <verb> <args>` — a post-open executor step.
pub const V2Action = struct {
    fixture: []const u8,
    engine: []const u8,
    mode: []const u8,
    verb: []const u8,
    /// The rendered `k=v,…` spec, kept as the STRING the row carried: todo's
    /// gate compares it against `catalogue.render_action_args`'s single
    /// rendering, so re-rendering it here would author a second authority.
    arg_spec: []const u8,
};

/// `bytes <fid> <engine> <mode> <relName> <offset> <hex>` — an assertion against
/// the CAPTURED POST bytes, never a pre-open patch (contract §2.3). Q8's input
/// segment is 186 bytes and its assertion is at offset 187, so a pre-open
/// reading is not merely wrong, it is out of range.
pub const V2Bytes = struct {
    fixture: []const u8,
    engine: []const u8,
    mode: []const u8,
    rel: []const u8,
    offset: u64,
    hex: []const u8,
};

/// `reopen <fid> <engine> <mode> <family>` — after the cell's actions have run
/// and the store has been closed, a SECOND open must fail with this family.
pub const V2Reopen = struct {
    fixture: []const u8,
    engine: []const u8,
    mode: []const u8,
    family: []const u8,
};

pub const V1 = struct {
    fixtures: std.ArrayListUnmanaged(FixtureRow) = .empty,
    files: std.ArrayListUnmanaged(FileRow) = .empty,
    expects: std.ArrayListUnmanaged(V1Expect) = .empty,
    recids: std.ArrayListUnmanaged(RecidRow) = .empty,
    owned: Strings = .{},

    pub fn deinit(self: *V1, alloc: Allocator) void {
        self.fixtures.deinit(alloc);
        self.files.deinit(alloc);
        self.expects.deinit(alloc);
        self.recids.deinit(alloc);
        self.owned.deinit(alloc);
    }
};

pub const V2 = struct {
    fixtures: std.ArrayListUnmanaged(FixtureRow) = .empty,
    files: std.ArrayListUnmanaged(FileRow) = .empty,
    applies: std.ArrayListUnmanaged(V2Applies) = .empty,
    expects: std.ArrayListUnmanaged(V2Expect) = .empty,
    posts: std.ArrayListUnmanaged(V2Post) = .empty,
    actions: std.ArrayListUnmanaged(V2Action) = .empty,
    byte_rows: std.ArrayListUnmanaged(V2Bytes) = .empty,
    reopens: std.ArrayListUnmanaged(V2Reopen) = .empty,
    recids: std.ArrayListUnmanaged(RecidRow) = .empty,
    owned: Strings = .{},

    pub fn deinit(self: *V2, alloc: Allocator) void {
        self.fixtures.deinit(alloc);
        self.files.deinit(alloc);
        self.applies.deinit(alloc);
        self.expects.deinit(alloc);
        self.posts.deinit(alloc);
        self.actions.deinit(alloc);
        self.byte_rows.deinit(alloc);
        self.reopens.deinit(alloc);
        self.recids.deinit(alloc);
        self.owned.deinit(alloc);
    }

    /// The `action` rows addressed to one cell, in manifest order. Returned by
    /// POINTER: the consumption accountant identifies a row by its address, so
    /// a handler that grades a copy is a handler that graded a different object.
    pub fn actionsOf(self: *const V2, fixture: []const u8, engine: []const u8, mode: []const u8, out: *std.ArrayListUnmanaged(*const V2Action), alloc: Allocator) !void {
        for (self.actions.items) |*a| {
            if (eql(a.fixture, fixture) and eql(a.engine, engine) and eql(a.mode, mode))
                try out.append(alloc, a);
        }
    }

    pub fn bytesOfCell(self: *const V2, fixture: []const u8, engine: []const u8, mode: []const u8, out: *std.ArrayListUnmanaged(*const V2Bytes), alloc: Allocator) !void {
        for (self.byte_rows.items) |*b| {
            if (eql(b.fixture, fixture) and eql(b.engine, engine) and eql(b.mode, mode))
                try out.append(alloc, b);
        }
    }

    pub fn reopensOf(self: *const V2, fixture: []const u8, engine: []const u8, mode: []const u8, out: *std.ArrayListUnmanaged(*const V2Reopen), alloc: Allocator) !void {
        for (self.reopens.items) |*r| {
            if (eql(r.fixture, fixture) and eql(r.engine, engine) and eql(r.mode, mode))
                try out.append(alloc, r);
        }
    }

    pub fn postsOf(self: *const V2, fixture: []const u8, engine: []const u8, mode: []const u8, out: *std.ArrayListUnmanaged(*const V2Post), alloc: Allocator) !void {
        for (self.posts.items) |*p| {
            if (eql(p.fixture, fixture) and eql(p.engine, engine) and eql(p.mode, mode))
                try out.append(alloc, p);
        }
    }
};

pub const Loaded = union(enum) {
    v1: V1,
    v2: V2,

    pub fn deinit(self: *Loaded, alloc: Allocator) void {
        switch (self.*) {
            .v1 => |*m| m.deinit(alloc),
            .v2 => |*m| m.deinit(alloc),
        }
    }

    pub fn version(self: *const Loaded) u32 {
        return switch (self.*) {
            .v1 => 1,
            .v2 => 2,
        };
    }
};

fn addRecid(ctx: *Ctx, into: *std.ArrayListUnmanaged(RecidRow), r: RecidRow, line: []const u8) Error!void {
    for (into.items) |prior| {
        if (eql(prior.fixture, r.fixture) and prior.recid == r.recid)
            return ctx.err("duplicate recid {d} in fixture {s}: {s}", .{ r.recid, r.fixture, line });
    }
    try into.append(ctx.alloc, r);
}

fn pushRange(
    ctx: *Ctx,
    into: *std.ArrayListUnmanaged(RecidRow),
    owned: *Strings,
    t: Fields,
    line: []const u8,
) Error!void {
    const from = try nat(ctx, t.f[3], line);
    const to = try nat(ctx, t.f[4], line);
    const state = try parseState(ctx, t.f[5], line);
    const base = try nat(ctx, t.f[6], line);
    const len = try nat(ctx, t.f[7], line);
    if (from > to) return ctx.err("empty recidrange: {s}", .{line});
    if (to - from >= MAX_RANGE_SPAN)
        return ctx.err("recidrange spans {d} recids: {s}", .{ to - from + 1, line });
    // Terminal break rather than `r <= to`: `from == to == maxInt(u64)` passes the
    // span check above and then `r += 1` overflows, which traps in Debug and wraps
    // in ReleaseFast — neither of them a messaged refusal. Same for the payload id,
    // which is an independent addition and can overflow on a two-row range.
    var r = from;
    while (true) {
        const label = try owned.add(ctx.alloc, "{s}[{d}]", .{ t.f[2], r - from });
        const pid = std.math.add(u64, base, r - from) catch
            return ctx.err("payloadId {d} + {d} overflows: {s}", .{ base, r - from, line });
        try addRecid(ctx, into, .{
            .fixture = t.f[1],
            .label = label,
            .recid = r,
            .state = state,
            .payload_id = pid,
            .len = @intCast(len),
        }, line);
        if (r == to) break;
        r += 1;
    }
}

/// `unchanged` | `deleted` | `truncated:<len>:<sha>` | `created:<len>:<sha>` |
/// `modified:<len>:<sha>` — the sized verbs carry exactly two arguments.
fn parseDisposition(ctx: *Ctx, s: []const u8, line: []const u8) Error!V2Post {
    var it = std.mem.splitScalar(u8, s, ':');
    const verb = it.next().?;
    const want_args: usize = if (eql(verb, "unchanged") or eql(verb, "deleted"))
        0
    else if (eql(verb, "truncated") or eql(verb, "created") or eql(verb, "modified"))
        2
    else
        return ctx.err("unknown post disposition verb `{s}` in: {s}", .{ verb, line });

    var args: [3][]const u8 = undefined;
    var n: usize = 0;
    while (it.next()) |a| {
        if (n < args.len) args[n] = a;
        n += 1;
    }
    if (n != want_args)
        return ctx.err("post disposition {s} takes {d} argument(s), got {d}: {s}", .{ verb, want_args, n, line });
    if (want_args == 0) return .{ .fixture = "", .engine = "", .mode = "", .rel = "", .verb = verb };

    const len = try nat(ctx, args[0], line);
    const sha = try sha256Field(ctx, args[1], line);
    return .{ .fixture = "", .engine = "", .mode = "", .rel = "", .verb = verb, .len = len, .sha = sha };
}

/// Every fixture id a row REFERS to must be DECLARED by exactly one `fixture`
/// row, and every declared fixture must be referred to.
///
/// Without this, one coordinated deletion defeats the exact-cell-set rule of
/// §6.1: drop a `fixture` row together with this engine's `expect` rows for it
/// and the executor sees a consistently smaller world — `want` shrinks by the
/// same fixture that `ran` lost. The `file` and `recid` rows stay behind, the
/// golden comparisons still decode them, and the resource inventory is
/// unchanged. The C3r review found that one.
fn referentialIntegrity(
    ctx: *Ctx,
    declared: []const FixtureRow,
    referenced: []const []const u8,
) Error!void {
    for (referenced) |r| {
        var found = false;
        for (declared) |d| {
            if (eql(d.id, r)) found = true;
        }
        if (!found) return ctx.err("a row refers to fixture `{s}`, which has no `fixture` row", .{r});
    }
    for (declared) |d| {
        var used = false;
        for (referenced) |r| {
            if (eql(d.id, r)) used = true;
        }
        if (!used) return ctx.err("fixture `{s}` is declared but no row refers to it", .{d.id});
    }
}

/// `edit <fid> <relName> <offset> <before> <after>` — provenance for a derived
/// reject image; nothing here executes it.
///
/// Java arity-checks it and stops. Two things are added: the row NAMES a fixture,
/// so it is a reference like every other row's first column (the C3z review found
/// `edit ghost ...` parsing against no declaration), and its scalars get the same
/// canonical forms the rest of the grammar uses. Being stricter than the frozen
/// reference is not a disagreement with it — the live manifest's three edit rows
/// satisfy both rules.
fn editRow(ctx: *Ctx, t: Fields, line: []const u8, referenced: *std.ArrayListUnmanaged([]const u8)) Error!void {
    try arity(ctx, t, 6, line);
    _ = try relName(ctx, t.f[2], line);
    _ = try nat(ctx, t.f[3], line);
    _ = try hexBytes(ctx, t.f[4], line);
    _ = try hexBytes(ctx, t.f[5], line);
    try referenced.append(ctx.alloc, t.f[1]);
}

fn declareFixture(ctx: *Ctx, m: *std.ArrayListUnmanaged(FixtureRow), t: Fields, line: []const u8) Error!void {
    for (m.items) |prior| {
        if (eql(prior.id, t.f[1]))
            return ctx.err("duplicate fixture row for {s}: {s}", .{ t.f[1], line });
    }
    try m.append(ctx.alloc, .{ .id = t.f[1], .kind = t.f[2] });
}

fn addFile(ctx: *Ctx, files: *std.ArrayListUnmanaged(FileRow), t: Fields, line: []const u8) Error!void {
    const f = FileRow{
        .fixture = t.f[1],
        .rel = try relName(ctx, t.f[2], line),
        .raw_len = try nat(ctx, t.f[3], line),
        .raw_sha = try sha256Field(ctx, t.f[4], line),
        .gz_sha = try sha256Field(ctx, t.f[5], line),
    };
    for (files.items) |prior| {
        if (eql(prior.fixture, f.fixture) and eql(prior.rel, f.rel))
            return ctx.err("duplicate file row for {s}/{s}: {s}", .{ f.fixture, f.rel, line });
    }
    try files.append(ctx.alloc, f);
}

/// Dispatches on the version line, then parses with the grammar that line names.
///
/// **The two grammars collide on arity.** A v1 `expect` row and a v2 `expect`
/// row both have seven fields, and v1's third column is a verdict where v2's is
/// a mode. Guessing the schema from a row's shape would therefore read `accept`
/// as a mode and `wal3` as a verdict without any arity check firing, so the
/// version line is authoritative and an unknown version is refused rather than
/// assumed to be the newest.
pub fn parse(ctx: *Ctx, text: []const u8) Error!Loaded {
    var lines = std.mem.splitScalar(u8, text, '\n');
    const head = while (lines.next()) |raw| {
        const line = std.mem.trimRight(u8, raw, "\r");
        if (line.len == 0 or line[0] == '#') continue;
        break line;
    } else return ctx.err("MANIFEST.tsv has no version line", .{});

    const t = split(head);
    if (t.n != 2 or !eql(t.f[0], "version"))
        return ctx.err("the first data line must be `version<TAB><n>`, not: {s}", .{head});
    if (eql(t.f[1], "1")) return .{ .v1 = try parseV1(ctx, &lines) };
    if (eql(t.f[1], "2")) return .{ .v2 = try parseV2(ctx, &lines) };
    return ctx.err(
        "unsupported manifest schema version {s} — this reader speaks 1 and 2, and refuses rather " ++
            "than guessing: the two grammars share row arities, so a newer schema would be misread " ++
            "field by field without a single check firing",
        .{t.f[1]},
    );
}

const LineIter = std.mem.SplitIterator(u8, .scalar);

fn parseV1(ctx: *Ctx, lines: *LineIter) Error!V1 {
    var m = V1{};
    errdefer m.deinit(ctx.alloc);
    var referenced: std.ArrayListUnmanaged([]const u8) = .empty;
    defer referenced.deinit(ctx.alloc);

    while (lines.next()) |raw| {
        const line = std.mem.trimRight(u8, raw, "\r");
        if (line.len == 0 or line[0] == '#') continue;
        const t = split(line);
        const tag = t.f[0];
        if (eql(tag, "version")) {
            return ctx.err("a second version row: {s}", .{line});
        } else if (eql(tag, "fixture")) {
            try arity(ctx, t, 5, line);
            _ = try oneOf(ctx, t.f[2], &V1_KINDS, "fixture kind", line);
            _ = try oneOf(ctx, t.f[3], &ENGINES, "generatorEngine", line);
            try declareFixture(ctx, &m.fixtures, t, line);
        } else if (eql(tag, "file")) {
            try arity(ctx, t, 6, line);
            try addFile(ctx, &m.files, t, line);
            try referenced.append(ctx.alloc, t.f[1]);
        } else if (eql(tag, "expect")) {
            try arity(ctx, t, 7, line);
            const e = V1Expect{
                .fixture = t.f[1],
                .engine = try oneOf(ctx, t.f[2], &ENGINES, "engine", line),
                .verdict = try oneOf(ctx, t.f[3], &VERDICTS, "verdict", line),
                .opener = try oneOf(ctx, t.f[4], &V1_OPENERS, "opener", line),
                .place_as = try relName(ctx, t.f[5], line),
                .open_arg = try relName(ctx, t.f[6], line),
            };
            // A v1 cell is identified by (fixture, engine, opener, placeAs), NOT
            // by (fixture, engine): the live tree has both a `direct` and a `wal`
            // cell for the same engine on `wal-v1-rust-tail`, which is exactly
            // what the v1 `opener` column is for. A narrower key rejects the real
            // manifest.
            for (m.expects.items) |p| {
                if (eql(p.fixture, e.fixture) and eql(p.engine, e.engine) and
                    eql(p.opener, e.opener) and eql(p.place_as, e.place_as))
                    return ctx.err("duplicate expect row for {s}/{s}/{s}: {s}", .{ e.fixture, e.engine, e.opener, line });
            }
            try m.expects.append(ctx.alloc, e);
            try referenced.append(ctx.alloc, t.f[1]);
        } else if (eql(tag, "recid")) {
            try arity(ctx, t, 7, line);
            try addRecid(ctx, &m.recids, .{
                .fixture = t.f[1],
                .label = t.f[2],
                .recid = try nat(ctx, t.f[3], line),
                .state = try parseState(ctx, t.f[4], line),
                .payload_id = try nat(ctx, t.f[5], line),
                .len = @intCast(try nat(ctx, t.f[6], line)),
            }, line);
            try referenced.append(ctx.alloc, t.f[1]);
        } else if (eql(tag, "recidrange")) {
            try arity(ctx, t, 8, line);
            try pushRange(ctx, &m.recids, &m.owned, t, line);
            try referenced.append(ctx.alloc, t.f[1]);
        } else if (eql(tag, "edit")) {
            try editRow(ctx, t, line, &referenced);
        } else {
            return ctx.err("unknown v1 manifest row type `{s}`: {s}", .{ tag, line });
        }
    }
    if (m.files.items.len == 0) return ctx.err("a v1 manifest with no file rows", .{});
    try referentialIntegrity(ctx, m.fixtures.items, referenced.items);
    return m;
}

fn parseV2(ctx: *Ctx, lines: *LineIter) Error!V2 {
    var m = V2{};
    errdefer m.deinit(ctx.alloc);
    var referenced: std.ArrayListUnmanaged([]const u8) = .empty;
    defer referenced.deinit(ctx.alloc);
    // Contract §2, amendment 3: a fixture whose generatorEngine is `derived` MUST
    // have exactly one `derived` row, and no other fixture may have one.
    var wants_derived: std.ArrayListUnmanaged([]const u8) = .empty;
    defer wants_derived.deinit(ctx.alloc);
    var has_derived: std.ArrayListUnmanaged([]const u8) = .empty;
    defer has_derived.deinit(ctx.alloc);

    while (lines.next()) |raw| {
        const line = std.mem.trimRight(u8, raw, "\r");
        if (line.len == 0 or line[0] == '#') continue;
        const t = split(line);
        const tag = t.f[0];
        if (eql(tag, "version")) {
            return ctx.err("a second version row: {s}", .{line});
        } else if (eql(tag, "fixture")) {
            try arity(ctx, t, 5, line);
            _ = try oneOf(ctx, t.f[2], &V2_KINDS, "fixture kind", line);
            if (eql(try oneOf(ctx, t.f[3], &V2_GENERATORS, "generatorEngine", line), "derived"))
                try wants_derived.append(ctx.alloc, t.f[1]);
            try declareFixture(ctx, &m.fixtures, t, line);
        } else if (eql(tag, "derived")) {
            try arity(ctx, t, 5, line);
            // `derived <fid> <src> <deriverVersion> <recipe>` — PROVENANCE for a
            // fixture that also has its own `fixture` row, not a second way to
            // declare one. Reading t[2] as a kind (the shape of the `fixture` row
            // above) would file a fixture id in the kind column and never be
            // noticed, because nothing here consumes kinds.
            _ = try nat(ctx, t.f[3], line);
            for (has_derived.items) |p| {
                if (eql(p, t.f[1])) return ctx.err("two derived rows for {s}: {s}", .{ t.f[1], line });
            }
            try has_derived.append(ctx.alloc, t.f[1]);
            try referenced.append(ctx.alloc, t.f[1]);
            // The SOURCE fixture is a reference too — `manifest_v2.py`'s
            // `fixture_unknown_ref` says so, and without it a fixture may
            // legally derive from a fixture that does not exist. The C3z review
            // found the referential-integrity rule silently exempting the one
            // row type whose whole purpose is to name another fixture.
            try referenced.append(ctx.alloc, t.f[2]);
        } else if (eql(tag, "file")) {
            try arity(ctx, t, 6, line);
            try addFile(ctx, &m.files, t, line);
            try referenced.append(ctx.alloc, t.f[1]);
        } else if (eql(tag, "applies")) {
            try arity(ctx, t, 4, line);
            const ap = V2Applies{
                .fixture = t.f[1],
                .engine = try oneOf(ctx, t.f[2], &ENGINES, "engine", line),
                .mode = try oneOf(ctx, t.f[3], &MODES, "mode", line),
            };
            for (m.applies.items) |prior| {
                if (cellEq(.{ prior.fixture, prior.engine, prior.mode }, .{ ap.fixture, ap.engine, ap.mode }))
                    return ctx.err("duplicate applies row: {s}", .{line});
            }
            try m.applies.append(ctx.alloc, ap);
            try referenced.append(ctx.alloc, t.f[1]);
        } else if (eql(tag, "expect")) {
            try arity(ctx, t, 7, line);
            const e = V2Expect{
                .fixture = t.f[1],
                .engine = try oneOf(ctx, t.f[2], &ENGINES, "engine", line),
                .mode = try oneOf(ctx, t.f[3], &MODES, "mode", line),
                .verdict = try oneOf(ctx, t.f[4], &VERDICTS, "verdict", line),
                .opener = try oneOf(ctx, t.f[5], &V2_OPENERS, "opener", line),
                .open_arg = try relName(ctx, t.f[6], line),
            };
            for (m.expects.items) |p| {
                if (eql(p.fixture, e.fixture) and eql(p.engine, e.engine) and eql(p.mode, e.mode))
                    return ctx.err("duplicate expect row for {s}/{s}/{s}: {s}", .{ e.fixture, e.engine, e.mode, line });
            }
            try m.expects.append(ctx.alloc, e);
            try referenced.append(ctx.alloc, t.f[1]);
        } else if (eql(tag, "post")) {
            try arity(ctx, t, 6, line);
            var p = try parseDisposition(ctx, t.f[5], line);
            p.fixture = t.f[1];
            p.engine = try oneOf(ctx, t.f[2], &ENGINES, "engine", line);
            p.mode = try oneOf(ctx, t.f[3], &MODES, "mode", line);
            p.rel = try relName(ctx, t.f[4], line);
            for (m.posts.items) |q| {
                if (eql(q.fixture, p.fixture) and eql(q.engine, p.engine) and
                    eql(q.mode, p.mode) and eql(q.rel, p.rel))
                    return ctx.err("duplicate post row for {s}/{s}/{s}/{s}: {s}", .{ p.fixture, p.engine, p.mode, p.rel, line });
            }
            try m.posts.append(ctx.alloc, p);
            try referenced.append(ctx.alloc, t.f[1]);
        } else if (eql(tag, "recid")) {
            try arity(ctx, t, 7, line);
            try addRecid(ctx, &m.recids, .{
                .fixture = t.f[1],
                .label = t.f[2],
                .recid = try nat(ctx, t.f[3], line),
                .state = try parseState(ctx, t.f[4], line),
                .payload_id = try nat(ctx, t.f[5], line),
                .len = @intCast(try nat(ctx, t.f[6], line)),
            }, line);
            try referenced.append(ctx.alloc, t.f[1]);
        } else if (eql(tag, "recidrange")) {
            try arity(ctx, t, 8, line);
            try pushRange(ctx, &m.recids, &m.owned, t, line);
            try referenced.append(ctx.alloc, t.f[1]);
        } else if (eql(tag, "edit")) {
            try editRow(ctx, t, line, &referenced);
        } else if (eql(tag, "action")) {
            try arity(ctx, t, 6, line);
            const a = V2Action{
                .fixture = t.f[1],
                .engine = try oneOf(ctx, t.f[2], &ENGINES, "engine", line),
                .mode = try oneOf(ctx, t.f[3], &MODES, "mode", line),
                // The VERB is not vocabulary-checked here, for the reason the
                // `reopen` family is not: `catalogue.ACTION_VERBS` is the
                // authority, this engine implements a subset, and a parser list
                // would accept a verb the executor then cannot run while going
                // stale on its own. `runAction` refuses an unimplemented verb,
                // which is both stricter and the refusal that matters.
                .verb = t.f[4],
                .arg_spec = try actionArgs(ctx, t.f[5], line),
            };
            // One row per cell per VERB, not per cell: `catalogue.actions` holds
            // a list, so a second verb on one cell is a legal future shape and
            // refusing it would refuse the corpus, not a defect.
            for (m.actions.items) |prior| {
                if (cellEq(.{ prior.fixture, prior.engine, prior.mode }, .{ a.fixture, a.engine, a.mode }) and eql(prior.verb, a.verb))
                    return ctx.err("duplicate action row: {s}", .{line});
            }
            try m.actions.append(ctx.alloc, a);
            try referenced.append(ctx.alloc, t.f[1]);
        } else if (eql(tag, "reopen")) {
            try arity(ctx, t, 5, line);
            const r = V2Reopen{
                .fixture = t.f[1],
                .engine = try oneOf(ctx, t.f[2], &ENGINES, "engine", line),
                .mode = try oneOf(ctx, t.f[3], &MODES, "mode", line),
                // Not vocabulary-checked: `catalogue.FAMILIES` has eighteen
                // members and this engine has a predicate for a handful, so a
                // list here would accept a family `assertFamily` then refuses —
                // two lists, one of which goes stale.
                .family = t.f[4],
            };
            for (m.reopens.items) |prior| {
                if (cellEq(.{ prior.fixture, prior.engine, prior.mode }, .{ r.fixture, r.engine, r.mode }))
                    return ctx.err("duplicate reopen row: {s}", .{line});
            }
            try m.reopens.append(ctx.alloc, r);
            try referenced.append(ctx.alloc, t.f[1]);
        } else if (eql(tag, "bytes")) {
            try arity(ctx, t, 7, line);
            const b = V2Bytes{
                .fixture = t.f[1],
                .engine = try oneOf(ctx, t.f[2], &ENGINES, "engine", line),
                .mode = try oneOf(ctx, t.f[3], &MODES, "mode", line),
                .rel = try relName(ctx, t.f[4], line),
                .offset = try nat(ctx, t.f[5], line),
                .hex = try hexBytes(ctx, t.f[6], line),
            };
            // Keyed by cell AND (file, offset): a cell may assert several ranges,
            // and two rows for the same range are a contradiction.
            for (m.byte_rows.items) |prior| {
                if (cellEq(.{ prior.fixture, prior.engine, prior.mode }, .{ b.fixture, b.engine, b.mode }) and
                    eql(prior.rel, b.rel) and prior.offset == b.offset)
                    return ctx.err("duplicate bytes row: {s}", .{line});
            }
            try m.byte_rows.append(ctx.alloc, b);
            try referenced.append(ctx.alloc, t.f[1]);
        } else {
            return ctx.err("unknown v2 manifest row type `{s}`: {s}", .{ tag, line });
        }
    }
    if (m.files.items.len == 0) return ctx.err("a v2 manifest with no file rows", .{});
    for (wants_derived.items) |w| {
        if (!contains(has_derived.items, w))
            return ctx.err("fixture {s} declares generatorEngine=derived but carries no derived row", .{w});
    }
    for (has_derived.items) |h| {
        if (!contains(wants_derived.items, h))
            return ctx.err("fixture {s} carries a derived row but its generatorEngine is not `derived`", .{h});
    }
    try referentialIntegrity(ctx, m.fixtures.items, referenced.items);
    return m;
}

// ---------------------------------------------------------------------------
// C-D4 — the generated embed table, graded by three-way SET EQUALITY
// ---------------------------------------------------------------------------

/// The three sets that must agree about which blobs exist.
///
/// `@embedFile` needs comptime-known paths, so the table is generated from
/// MANIFEST.tsv by `todo/store-cross/gen_zig_embed.py`. Revision 1 of C-D4
/// proposed asserting "the table covers every manifest file row" and codex
/// refused it as tautological: the table and the manifest come off the same
/// list, so that compares a generator's output with its own input. The adopted
/// invariant is **set equality across three independently derived sets** —
/// the manifest's `file` rows, the generated table's keys, and the `*.gz`
/// basenames `build.zig` reads off the distributed directory. A missing physical
/// blob is already a compile error; this is the direction nothing else reaches.
pub fn checkBlobSets(
    ctx: *Ctx,
    from_manifest: []const []const u8,
    from_table: []const []const u8,
    distributed: []const []const u8,
) Error!void {
    const sets = [_]struct { name: []const u8, items: []const []const u8 }{
        .{ .name = "the manifest's file rows", .items = from_manifest },
        .{ .name = "the generated embed table", .items = from_table },
        .{ .name = "the distributed .gz files", .items = distributed },
    };
    for (sets) |s| {
        if (s.items.len == 0) return ctx.err("{s} is empty", .{s.name});
        for (s.items, 0..) |a, i| {
            if (a.len == 0 or std.mem.indexOfAny(u8, a, "/\\\x00") != null or
                eql(a, ".") or eql(a, "..") or a[0] == '-')
                return ctx.err("{s} contains the unsafe name `{s}`", .{ s.name, a });
            for (s.items[i + 1 ..]) |b| {
                if (eql(a, b)) return ctx.err("{s} names `{s}` twice", .{ s.name, a });
            }
        }
    }
    for (sets) |a| {
        for (sets) |b| {
            for (a.items) |x| {
                if (!contains(b.items, x))
                    return ctx.err("`{s}` is in {s} but not in {s}", .{ x, a.name, b.name });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// loading the distributed sample
// ---------------------------------------------------------------------------

pub const RawFile = struct {
    fixture: []const u8,
    rel: []const u8,
    blob: []const u8,
    bytes: []u8,
};

/// A schema-v2 sample root: the parsed manifest plus every file's verified raw
/// bytes.
pub const SampleV2 = struct {
    manifest: V2,
    files: std.ArrayListUnmanaged(RawFile) = .empty,
    blob_names: Strings = .{},

    pub fn deinit(self: *SampleV2, alloc: Allocator) void {
        for (self.files.items) |f| alloc.free(f.bytes);
        self.files.deinit(alloc);
        self.blob_names.deinit(alloc);
        self.manifest.deinit(alloc);
    }

    /// Files in the canonical dump order — `(fixtureId, relName)`, which is what
    /// `GOLDEN-BODY.tsv` and `GOLDEN-DECODE.tsv` are sorted by. The manifest's
    /// own order is bundle-by-bundle as generated, which is NOT that order.
    pub fn ordered(self: *const SampleV2, alloc: Allocator) ![]RawFile {
        const v = try alloc.dupe(RawFile, self.files.items);
        std.mem.sort(RawFile, v, {}, struct {
            fn lt(_: void, a: RawFile, b: RawFile) bool {
                if (!eql(a.fixture, b.fixture)) return std.mem.lessThan(u8, a.fixture, b.fixture);
                return std.mem.lessThan(u8, a.rel, b.rel);
            }
        }.lt);
        return v;
    }

    pub fn bytesOf(self: *const SampleV2, fixture: []const u8, rel: []const u8) ?[]const u8 {
        for (self.files.items) |f| {
            if (eql(f.fixture, fixture) and eql(f.rel, rel)) return f.bytes;
        }
        return null;
    }
};

pub const Blob = struct { name: []const u8, gz: []const u8 };

/// Loads the v2 sample from an embedded manifest + blob table, verifying every
/// blob's gz sha, raw length and raw sha BEFORE anything decodes or opens it. A
/// dump taken from bytes that were never checked against their pins describes
/// whatever happened to be on disk.
pub fn loadSampleV2(ctx: *Ctx, manifest_tsv: []const u8, table: []const Blob) Error!SampleV2 {
    // ONE owner at every point. Copying `loaded.v2` into `sample.manifest` leaves
    // two values holding the same array lists, and an `errdefer` on each ran both
    // destructors on every refusal after this line — a missing blob, a bad hash, a
    // short gunzip. The C3z review reproduced the double free as a segfault, and
    // the green suite could not see it because nothing ever asked this function to
    // refuse. So the version check is handled before the transfer, and after the
    // transfer only `sample` has a destructor.
    var loaded = try parse(ctx, manifest_tsv);
    if (loaded.version() != 2) {
        loaded.deinit(ctx.alloc);
        return ctx.err("the v2 sample root is schema v1", .{});
    }
    var sample = SampleV2{ .manifest = loaded.v2 };
    errdefer sample.deinit(ctx.alloc);

    for (sample.manifest.files.items) |f| {
        const blob = sample.blob_names.add(ctx.alloc, "{s}.{s}.gz", .{ f.fixture, f.rel }) catch
            return error.OutOfMemory;
        const gz: []const u8 = for (table) |b| {
            if (eql(b.name, blob)) break b.gz;
        } else return ctx.err("no embedded blob `{s}` (regenerate the embed table)", .{blob});

        const gz_sha = sha256Hex(gz);
        if (!eql(&gz_sha, f.gz_sha))
            return ctx.err("gzSha256 mismatch for {s}: manifest {s}, embedded {s}", .{ blob, f.gz_sha, &gz_sha });
        const bytes = try gunzip(ctx, gz, f.raw_len, blob);
        errdefer ctx.alloc.free(bytes);
        if (bytes.len != f.raw_len)
            return ctx.err("rawLen mismatch for {s}: manifest {d}, got {d}", .{ blob, f.raw_len, bytes.len });
        const raw_sha = sha256Hex(bytes);
        if (!eql(&raw_sha, f.raw_sha))
            return ctx.err("rawSha256 mismatch for {s}: manifest {s}, got {s}", .{ blob, f.raw_sha, &raw_sha });
        try sample.files.append(ctx.alloc, .{ .fixture = f.fixture, .rel = f.rel, .blob = blob, .bytes = bytes });
    }
    return sample;
}

// ---------------------------------------------------------------------------
// the two §11.2 comparisons, rendered as rows
// ---------------------------------------------------------------------------

/// `GOLDEN-DECODE.tsv`'s rows, re-derived by THIS reader.
///
/// This is the half `GOLDEN.tsv` cannot do: a raw sha attests which bytes were
/// read and says nothing about the parse. Note in particular that the section
/// COUNT is not CRC-protected — both section CRCs bind a section's own bytes to
/// its offset, so a reader that stops one section early still validates every
/// section it did read. Only this comparison reaches that.
pub fn renderFraming(ctx: *Ctx, sample: *const SampleV2, out: *Strings) Error!void {
    const files = try sample.ordered(ctx.alloc);
    defer ctx.alloc.free(files);
    // Context strings go in their own list: `out` holds the ROWS the comparison
    // sees, and nothing else may end up in it.
    var scratch: Strings = .{};
    defer scratch.deinit(ctx.alloc);
    for (files) |f| {
        const where = try scratch.add(ctx.alloc, "{s}/{s}", .{ f.fixture, f.rel });
        var seg = Segment{};
        defer seg.deinit(ctx.alloc);
        try decodeComplete(ctx, f.bytes, where, &seg);
        _ = try out.add(ctx.alloc, "hdr\t{s}\t{s}\t{d}\t{d}\t{d}\t{d}\t{x:0>8}", .{
            f.fixture,      f.rel,                seg.header.version,    seg.header.flags,
            seg.header.seq, seg.header.first_lsn, seg.header.header_crc,
        });
        for (seg.sections.items) |s| {
            _ = try out.add(ctx.alloc, "sec\t{s}\t{s}\t{d}\t{d}\t{c}\t{d}\t{d}\t{x:0>8}\t{x:0>8}", .{
                f.fixture, f.rel, s.index, s.offset, s.tag, s.lsn, s.body_len, s.hdr_crc, s.body_crc,
            });
        }
    }
}

/// The content column, and the decode's own self-check.
///
/// Three independent things are asserted before a sha is emitted: the content
/// length agrees with `lenPlus`, the capacity satisfies the engine's `capValid`
/// rule ([`checkCap`]), and the bytes lie in the payload language
/// ([`checkPayload`]). None of the three is a corpus-membership proof on its
/// own; together they refuse the streams a mis-framed decode actually produces.
/// The shape rules an entry must satisfy before its content is hashed.
///
/// Split out from [`contentSha`] and made `pub` because inside that function they
/// were unreachable: `entries` slices exactly `lenPlus - 1` bytes and sets `cap`
/// only for records, so every value it produces satisfies them by construction,
/// and the C3z review deleted the NULL-cap rule with the whole suite still green.
/// A rule that only ever sees values built to satisfy it is not a check. Fed
/// hand-built entries, these are.
pub fn checkEntryShape(ctx: *Ctx, e: Entry, where: []const u8) Error!void {
    if (!e.isRecord() or e.len_plus.? == 0) {
        if (e.content != null)
            return ctx.err("{s}: a non-record or NULL entry carries content", .{where});
        // `cap == 0` is how the writer encodes NULL content; any other capacity
        // means the entry stream was framed some other way than it was written.
        if (e.isRecord() and e.cap.? != 0)
            return ctx.err("{s}: a NULL record's cap must be 0, not {d}", .{ where, e.cap.? });
        return;
    }
    const c = e.content orelse return ctx.err("{s}: a sized record carries no content", .{where});
    if (c.len != e.len_plus.? - 1)
        return ctx.err("{s}: content length {d} disagrees with lenPlus {d}", .{ where, c.len, e.len_plus.? });
    try checkCap(ctx, e.cap.?, c.len, where);
    try checkPayload(ctx, c, where);
}

fn contentSha(ctx: *Ctx, e: Entry, where: []const u8, out: *[64]u8) Error!?[]const u8 {
    try checkEntryShape(ctx, e, where);
    if (!e.isRecord() or e.len_plus.? == 0) return null;
    out.* = sha256Hex(e.content.?);
    return out[0..];
}

/// `GOLDEN-BODY.tsv`'s rows, re-derived by THIS reader.
///
/// Java authored that file with the frozen reader; this is the
/// engine-against-engine half of contract §11.2, and Java is authoritative by
/// construction.
pub fn renderBody(ctx: *Ctx, sample: *const SampleV2, out: *Strings) Error!void {
    const files = try sample.ordered(ctx.alloc);
    defer ctx.alloc.free(files);
    // Context strings go in their own list: `out` holds the ROWS the comparison
    // sees, and nothing else may end up in it.
    var scratch: Strings = .{};
    defer scratch.deinit(ctx.alloc);

    var bundle: []const u8 = "";
    var seen: std.ArrayListUnmanaged(u64) = .empty;
    defer seen.deinit(ctx.alloc);

    for (files) |f| {
        if (!eql(bundle, f.fixture)) {
            if (bundle.len != 0) try checkRecidsAgainstManifest(ctx, &sample.manifest, bundle, seen.items);
            bundle = f.fixture;
            seen.clearRetainingCapacity();
        }
        const where = try scratch.add(ctx.alloc, "{s}/{s}", .{ f.fixture, f.rel });
        var seg = Segment{};
        defer seg.deinit(ctx.alloc);
        try decodeComplete(ctx, f.bytes, where, &seg);

        for (seg.sections.items) |s| {
            if (s.tag == TAG_MARK) {
                const m = try mark(ctx, &s, where);
                const mctx = try scratch.add(ctx.alloc, "{s} section {d}", .{ where, s.index });
                try checkMark(ctx, m, seg.header.seq, s.lsn, mctx);
                _ = try out.add(ctx.alloc, "sec\t{s}\t{s}\t{d}\t{c}\t-", .{ f.fixture, f.rel, s.index, s.tag });
                _ = try out.add(ctx.alloc, "mark\t{s}\t{s}\t{d}\t{d}\t{d}", .{ f.fixture, f.rel, s.index, m.through, m.log_start });
                continue;
            }
            var es: std.ArrayListUnmanaged(Entry) = .empty;
            defer es.deinit(ctx.alloc);
            try entries(ctx, &s, where, &es);
            _ = try out.add(ctx.alloc, "sec\t{s}\t{s}\t{d}\t{c}\t{d}", .{ f.fixture, f.rel, s.index, s.tag, es.items.len });
            for (es.items, 0..) |e, i| {
                if (e.recid == 0)
                    return ctx.err("{s} section {d}: an entry references the reserved recid 0", .{ where, s.index });
                if (!contains64(seen.items, e.recid)) try seen.append(ctx.alloc, e.recid);
                const ectx = try scratch.add(ctx.alloc, "{s} section {d} entry {d}", .{ where, s.index, i });
                var shabuf: [64]u8 = undefined;
                const sha = try contentSha(ctx, e, ectx, &shabuf);
                var capbuf: [24]u8 = undefined;
                var lenbuf: [24]u8 = undefined;
                _ = try out.add(ctx.alloc, "ent\t{s}\t{s}\t{d}\t{d}\t{s}\t{d}\t{s}\t{s}\t{s}", .{
                    f.fixture,
                    f.rel,
                    s.index,
                    i,
                    e.kind(),
                    e.recid,
                    optNum(&capbuf, e.cap),
                    optNum(&lenbuf, e.len_plus),
                    sha orelse "-",
                });
            }
        }
    }
    if (bundle.len == 0) return ctx.err("the sample has no file rows", .{});
    try checkRecidsAgainstManifest(ctx, &sample.manifest, bundle, seen.items);
}

fn optNum(buf: []u8, v: ?u64) []const u8 {
    const n = v orelse return "-";
    return std.fmt.bufPrint(buf, "{d}", .{n}) catch unreachable;
}

fn contains64(haystack: []const u64, needle: u64) bool {
    for (haystack) |h| if (h == needle) return true;
    return false;
}

/// Cross-checks the recids the entry stream mentions against the ones the
/// manifest names. The manifest's rows were folded out of these same bytes by an
/// independent (python) reader, so the two agree only if both unpacked the same
/// varints.
///
/// **The relation is ONE-WAY, and that is not laxness.** Plan §5 forbids
/// asserting that a log contains only the recids the manifest names — a
/// rolled-back put need only be invisible through the API, and `wal3-java-tail`
/// already carries recids beyond the ones §5.2 describes. Set equality would
/// quietly assert the forbidden direction and pass only because these three
/// bundles happen to have equal sets.
pub fn checkRecidsAgainstManifest(ctx: *Ctx, m: *const V2, fixture: []const u8, seen: []const u64) Error!void {
    var rows: usize = 0;
    for (m.recids.items) |r| {
        if (!eql(r.fixture, fixture)) continue;
        rows += 1;
        if (!contains64(seen, r.recid))
            return ctx.err(
                "{s}: the manifest names recid {d} ({s}) that the decoded entry stream never mentions",
                .{ fixture, r.recid, r.label },
            );
    }
    if (rows == 0) return ctx.err("{s}: no recid rows to cross-check against", .{fixture});
}

// ---------------------------------------------------------------------------
// running cells
// ---------------------------------------------------------------------------

/// Raw-bytes serializer: record content == logical value, so gets compare
/// directly against the contract payloads.
pub const RawSer = struct {
    pub const Elem = []const u8;
    pub const instance: RawSer = .{};
    pub fn serialize(_: RawSer, out: *DataOutput2, v: []const u8) DbError!void {
        try out.writeAll(v);
    }
    pub fn deserialize(_: RawSer, alloc: Allocator, input: *DataInput2, size: ?usize) DbError![]const u8 {
        const n = size orelse return error.DataCorruption;
        const b = try alloc.alloc(u8, n);
        errdefer alloc.free(b);
        try input.readFully(b);
        return b;
    }
    pub fn cloneElem(_: RawSer, alloc: Allocator, v: []const u8) DbError![]const u8 {
        return alloc.dupe(u8, v);
    }
    pub fn deinitElem(_: RawSer, alloc: Allocator, v: []const u8) void {
        alloc.free(v);
    }
    pub fn equals(_: RawSer, a: []const u8, b: []const u8) bool {
        return eql(a, b);
    }
    pub fn compare(_: RawSer, a: []const u8, b: []const u8) std.math.Order {
        return std.mem.order(u8, a, b);
    }
    pub fn fixedSize(_: @This()) ?usize {
        return null;
    }
    pub fn equalsBySerializedBytes(_: @This()) bool {
        return true;
    }
};
pub const R = RawSer.instance;

/// The reader contract: `verify()`, every named recid in its declared state, and
/// `getAllRecids()` EXACTLY equal to the live+null set. Prealloc and deleted
/// recids are excluded from that set by construction, which the equality (not a
/// containment) is what enforces.
pub fn assertReaderContract(
    ctx: *Ctx,
    s: anytype,
    recids: []const RecidRow,
    fixture: []const u8,
    cell: []const u8,
) Error!void {
    s.verify() catch |e| return ctx.err("[{s}] verify() failed: {s}", .{ cell, @errorName(e) });

    var want_all: std.ArrayListUnmanaged(u64) = .empty;
    defer want_all.deinit(ctx.alloc);

    for (recids) |row| {
        if (!eql(row.fixture, fixture)) continue;
        switch (row.state) {
            .live => {
                const want = try payload(ctx.alloc, row.payload_id, row.len);
                defer ctx.alloc.free(want);
                const got = (s.get([]const u8, ctx.alloc, row.recid, R) catch |e|
                    return ctx.err("[{s}] recid {d} ({s}): get failed: {s}", .{ cell, row.recid, row.label, @errorName(e) })) orelse
                    return ctx.err("[{s}] recid {d} ({s}): expected {d} live bytes, got null", .{ cell, row.recid, row.label, row.len });
                defer ctx.alloc.free(got);
                if (!eql(want, got))
                    return ctx.err("[{s}] recid {d} ({s}): content mismatch (len {d} vs {d})", .{ cell, row.recid, row.label, got.len, want.len });
                try want_all.append(ctx.alloc, row.recid);
            },
            .null_rec, .prealloc => {
                const got = s.get([]const u8, ctx.alloc, row.recid, R) catch |e|
                    return ctx.err("[{s}] recid {d} ({s}): get failed: {s}", .{ cell, row.recid, row.label, @errorName(e) });
                if (got) |g| {
                    ctx.alloc.free(g);
                    return ctx.err("[{s}] recid {d} ({s}): expected null content", .{ cell, row.recid, row.label });
                }
                if (row.state == .null_rec) try want_all.append(ctx.alloc, row.recid);
            },
            .deleted => {
                if (s.get([]const u8, ctx.alloc, row.recid, R)) |got| {
                    if (got) |g| ctx.alloc.free(g);
                    return ctx.err("[{s}] recid {d} ({s}): expected error.GetVoid (deleted)", .{ cell, row.recid, row.label });
                } else |e| if (e != error.GetVoid)
                    return ctx.err("[{s}] recid {d} ({s}): expected error.GetVoid, got {s}", .{ cell, row.recid, row.label, @errorName(e) });
            },
        }
    }
    std.mem.sort(u64, want_all.items, {}, std.sort.asc(u64));
    const all = s.getAllRecids(ctx.alloc) catch |e|
        return ctx.err("[{s}] getAllRecids failed: {s}", .{ cell, @errorName(e) });
    defer ctx.alloc.free(all);
    if (!std.mem.eql(u64, want_all.items, all))
        return ctx.err(
            "[{s}] getAllRecids must equal the manifest's live+null set: got {d} recids, want {d}",
            .{ cell, all.len, want_all.items.len },
        );
}

/// The completeness half of the recid oracle: every recid the LOG mentions is
/// either named by the manifest or VOID according to the engine.
///
/// Without this, deleting a `prealloc` (or `deleted`) recid row from the
/// manifest is invisible — measured, not assumed. [`assertReaderContract`]
/// derives its `getAllRecids` set from the manifest's own live+null rows, so
/// dropping a row that is excluded from that set by construction removes an
/// assertion and adds none; and [`checkRecidsAgainstManifest`] is one-way, so a
/// shorter manifest satisfies it more easily. Both directions of the existing
/// pair get WEAKER when a row disappears, which is the shape a completeness rule
/// has to fix from outside.
///
/// **This is not the direction plan §5 forbids.** §5 forbids asserting that a
/// log contains only the recids the manifest names, because §5.2's rolled-back
/// put need only be invisible through the API. That case is exactly what the
/// escape hatch here admits: a rolled-back recid was never committed, so the
/// engine answers `GetVoid` for it, and the row stays legal without being named.
/// What is refused is the other thing — a recid the log mentions that the engine
/// still ANSWERS for, and that the manifest describes nowhere.
pub fn assertEveryLoggedRecidIsClassified(
    ctx: *Ctx,
    s: anytype,
    sample: *const SampleV2,
    fixture: []const u8,
    cell: []const u8,
) Error!void {
    var mentioned: std.ArrayListUnmanaged(u64) = .empty;
    defer mentioned.deinit(ctx.alloc);

    for (sample.files.items) |f| {
        if (!eql(f.fixture, fixture)) continue;
        var seg = Segment{};
        defer seg.deinit(ctx.alloc);
        try decodeComplete(ctx, f.bytes, f.blob, &seg);
        for (seg.sections.items) |sec| {
            if (sec.tag == TAG_MARK) continue;
            var es: std.ArrayListUnmanaged(Entry) = .empty;
            defer es.deinit(ctx.alloc);
            try entries(ctx, &sec, f.blob, &es);
            for (es.items) |e| {
                if (!contains64(mentioned.items, e.recid)) try mentioned.append(ctx.alloc, e.recid);
            }
        }
    }

    for (mentioned.items) |recid| {
        var named = false;
        for (sample.manifest.recids.items) |r| {
            if (eql(r.fixture, fixture) and r.recid == recid) named = true;
        }
        if (named) continue;
        if (s.get([]const u8, ctx.alloc, recid, R)) |got| {
            if (got) |g| ctx.alloc.free(g);
            return ctx.err(
                "[{s}] recid {d} appears in the log, the store still answers for it, and no " ++
                    "manifest recid row says what it is",
                .{ cell, recid },
            );
        } else |e| if (e != error.GetVoid) {
            return ctx.err("[{s}] recid {d}: expected error.GetVoid, got {s}", .{ cell, recid, @errorName(e) });
        }
    }
}

pub const InputFile = struct { rel: []const u8, bytes: []const u8 };

/// Everything in the cell directory, by name, after the cell has run.
///
/// The post-state rule reads THIS rather than the directory, because the cell's
/// `reopen` step is an open: it happens not to rewrite a segment today, and
/// "happens not to" is not a property to hash a corpus against. Presence is
/// decided by the capture's key set.
///
/// A name that is present but is not a REGULAR file is refused here rather than
/// read as absent — `readFile(..) catch null` would turn a permission error, or
/// a file replaced by a directory of the same name, into "the file is gone", so
/// a `deleted` row would pass on something very much still there in another
/// shape. The C3r review named that one.
pub const Capture = struct {
    items: std.ArrayListUnmanaged(struct { name: []const u8, bytes: []u8 }) = .empty,
    names: Strings = .{},

    pub fn deinit(self: *Capture, alloc: Allocator) void {
        for (self.items.items) |f| alloc.free(f.bytes);
        self.items.deinit(alloc);
        self.names.deinit(alloc);
    }

    pub fn get(self: *const Capture, name: []const u8) ?[]const u8 {
        for (self.items.items) |f| {
            if (eql(f.name, name)) return f.bytes;
        }
        return null;
    }
};

pub fn capture(ctx: *Ctx, dir: std.fs.Dir, cell: []const u8) Error!Capture {
    var out = Capture{};
    errdefer out.deinit(ctx.alloc);
    var it = dir.iterate();
    while (it.next() catch |e| return ctx.err("[{s}] cannot list the cell dir: {s}", .{ cell, @errorName(e) })) |entry| {
        const st = std.posix.fstatat(dir.fd, entry.name, std.posix.AT.SYMLINK_NOFOLLOW) catch |e|
            return ctx.err("[{s}] cannot stat {s}: {s}", .{ cell, entry.name, @errorName(e) });
        if (!std.posix.S.ISREG(st.mode))
            return ctx.err("[{s}] {s} is not a regular file", .{ cell, entry.name });
        const name = try out.names.add(ctx.alloc, "{s}", .{entry.name});
        const bytes = dir.readFileAlloc(ctx.alloc, entry.name, 256 * 1024 * 1024) catch |e|
            return ctx.err("[{s}] cannot read {s}: {s}", .{ cell, entry.name, @errorName(e) });
        try out.items.append(ctx.alloc, .{ .name = name, .bytes = bytes });
    }
    return out;
}

/// The oracle rows one cell owes, and which of them a handler actually ran.
///
/// It is the ONE mechanism standing between "executes" and "parses and drops"
/// for three of the four addressed oracle row types — every one except `action`,
/// which has a failure of its own. The whole-file `post` hash subsumes a
/// byte-at-offset assertion, the two-sided unnamed-input rule silently
/// re-verifies a file whose **`unchanged`** row was dropped, and *nothing at
/// all* observes a dropped `reopen`.
///
/// A row is identified by a key AND by its ADDRESS: consuming the right key with
/// a different row is how a handler that grades the wrong object still balances
/// the books.
pub const Consumption = struct {
    const Row = struct { key: []const u8, at: usize, done: bool };

    ctx_label: []const u8,
    owed: std.ArrayListUnmanaged(Row) = .empty,
    keys: Strings = .{},

    pub fn init(label: []const u8) Consumption {
        return .{ .ctx_label = label };
    }

    pub fn deinit(self: *Consumption, alloc: Allocator) void {
        self.owed.deinit(alloc);
        self.keys.deinit(alloc);
    }

    pub fn owe(self: *Consumption, ctx: *Ctx, comptime fmt: []const u8, args: anytype, row: anytype) Error!void {
        const key = try self.keys.add(ctx.alloc, fmt, args);
        for (self.owed.items) |o| {
            if (eql(o.key, key)) return ctx.err("[{s}] two oracle rows share the key {s}", .{ self.ctx_label, key });
        }
        try self.owed.append(ctx.alloc, .{ .key = key, .at = @intFromPtr(row), .done = false });
    }

    pub fn consume(self: *Consumption, ctx: *Ctx, comptime fmt: []const u8, args: anytype, row: anytype) Error!void {
        var buf: [256]u8 = undefined;
        const key = std.fmt.bufPrint(&buf, fmt, args) catch return ctx.err("[{s}] consumption key too long", .{self.ctx_label});
        for (self.owed.items) |*o| {
            if (!eql(o.key, key)) continue;
            if (o.at != @intFromPtr(row))
                return ctx.err("[{s}] consumed {s} with a different row", .{ self.ctx_label, key });
            if (o.done) return ctx.err("[{s}] consumed {s} twice", .{ self.ctx_label, key });
            o.done = true;
            return;
        }
        return ctx.err("[{s}] consumed {s}, which was never owed", .{ self.ctx_label, key });
    }

    pub fn requireAllConsumed(self: *const Consumption, ctx: *Ctx) Error!void {
        for (self.owed.items) |o| {
            if (!o.done)
                return ctx.err(
                    "[{s}] no handler consumed: {s}. A parsed-and-dropped assertion is a green cell that checked nothing",
                    .{ self.ctx_label, o.key },
                );
        }
    }
};

/// The two-sided D6 post-state rule.
///
/// One side is the obvious one: every file a `post` row names must be in the
/// state that row declares. The other side is the amendment that makes the rule
/// total — **files not named by a `post` row are implicitly `unchanged`** — so an
/// unnamed input must still be there byte for byte, and a file that is neither an
/// input nor named must not exist at all. Without the second side a cell that
/// deleted a segment and wrote three new ones would pass by saying nothing about
/// them.
/// **Each sized verb states a RELATION to the input, and grading the length and
/// hash alone leaves that relation as decoration.** C5r's round-3 review found
/// exactly that in the rust executor — a file that GREW satisfied `truncated`
/// and a file that did not change at all satisfied `modified` — and `NEXT.md`
/// rev 26 item 8 hands the same two relations to this engine. `truncated` means
/// the post bytes are a PROPER PREFIX of the input (contract §10.1: "truncated
/// back to its last valid section end"), and `modified` means the bytes changed
/// AND are not a pure truncation, because two verbs that can describe the same
/// shape are two verbs neither of which is a claim.
///
/// Each relation is ONE statement, not two. Written as a pair, the shrink half
/// has no red of its own: a file that grew fails the prefix comparison anyway,
/// so deleting the length half changes nothing. But the collapse buys freedom
/// from masking and not coverage — round 4 measured `<` regressing to `<=` with
/// a whole gate green — so each half is given its OWN input in the battery and
/// its own mutant.
pub fn assertPostState(
    ctx: *Ctx,
    before: []const InputFile,
    after: *const Capture,
    posts: []const *const V2Post,
    cell: []const u8,
    owed: *Consumption,
) Error!void {
    for (posts) |p| {
        var was_input: ?[]const u8 = null;
        for (before) |b| {
            if (eql(b.rel, p.rel)) was_input = b.bytes;
        }
        const now_opt = after.get(p.rel);
        if (eql(p.verb, "deleted")) {
            // §2.1: a post row is an explicit OVERRIDE of an input or an explicit
            // NEW file. `deleted` is an override, so it must name something the
            // cell actually started with.
            if (was_input == null)
                return ctx.err("[{s}] `deleted` names {s}, which was never an input", .{ cell, p.rel });
            if (now_opt != null)
                return ctx.err("[{s}] {s} must not exist after the cell", .{ cell, p.rel });
        } else if (eql(p.verb, "unchanged")) {
            const was = was_input orelse
                return ctx.err("[{s}] `unchanged` names {s}, which was never an input", .{ cell, p.rel });
            // Absent-before/absent-after is its own quadrant: `null == null`, so
            // an equality alone cannot establish that an `unchanged` row names an
            // input file at all. The check above is what refuses it, and the
            // battery gives it an input.
            const now = now_opt orelse
                return ctx.err("[{s}] `unchanged` names {s}, which is gone after the cell", .{ cell, p.rel });
            if (!eql(now, was))
                return ctx.err("[{s}] {s} must be byte-unchanged", .{ cell, p.rel });
        } else {
            // The other half of §2.1's split: `created` is the NEW-file verb, so
            // naming an input with it is as wrong as `modified` naming a
            // non-input. A cell that overwrote a segment could otherwise describe
            // it as `created` and pass.
            if (eql(p.verb, "created")) {
                if (was_input != null)
                    return ctx.err(
                        "[{s}] `created` names {s}, which WAS an input — an existing file the cell " ++
                            "rewrote is `modified` or `truncated`",
                        .{ cell, p.rel },
                    );
            } else if (was_input == null) {
                return ctx.err(
                    "[{s}] `{s}` names {s}, which was never an input — only `created` may name a " ++
                        "file the cell did not start with",
                    .{ cell, p.verb, p.rel },
                );
            }
            const now = now_opt orelse
                return ctx.err("[{s}] {s} must exist after the cell", .{ cell, p.rel });
            if (now.len != p.len.?)
                return ctx.err("[{s}] {s} length after the cell: {d}, want {d}", .{ cell, p.rel, now.len, p.len.? });
            const sha = sha256Hex(now);
            if (!eql(&sha, p.sha.?))
                return ctx.err("[{s}] {s} content after the cell: {s}, want {s}", .{ cell, p.rel, &sha, p.sha.? });
            if (eql(p.verb, "truncated")) {
                const was = was_input.?;
                if (!(now.len < was.len and eql(was[0..now.len], now)))
                    return ctx.err(
                        "[{s}] `truncated` must name a PROPER PREFIX of the input — {s} was {d} bytes and is now {d}",
                        .{ cell, p.rel, was.len, now.len },
                    );
            } else if (eql(p.verb, "modified")) {
                const was = was_input.?;
                if (eql(now, was))
                    return ctx.err("[{s}] `modified` names {s}, whose bytes did not change", .{ cell, p.rel });
                if (now.len < was.len and eql(was[0..now.len], now))
                    return ctx.err("[{s}] `modified` names {s}, which is a pure truncation — that is `truncated`", .{ cell, p.rel });
            }
        }
        try owed.consume(ctx, "post {s}", .{p.rel}, p);
    }

    for (before) |b| {
        var named = false;
        for (posts) |p| {
            if (eql(p.rel, b.rel)) named = true;
        }
        if (named) continue;
        const now = after.get(b.rel) orelse
            return ctx.err("[{s}] {s} is named by no post row, so it must still be there", .{ cell, b.rel });
        if (!eql(now, b.bytes))
            return ctx.err("[{s}] unnamed input {s} changed", .{ cell, b.rel });
    }

    for (after.items.items) |entry| {
        var known = false;
        for (before) |b| {
            if (eql(b.rel, entry.name)) known = true;
        }
        for (posts) |p| {
            if (eql(p.rel, entry.name)) known = true;
        }
        if (!known)
            return ctx.err("[{s}] {s} is neither an input nor named by a post row", .{ cell, entry.name });
    }
}

/// The one thing that makes the manifest's `mode` column OBSERVABLE.
///
/// Until the C3z review both modes did the same reads and asserted the same post
/// state, so `mode` was validated by the parser and then selected a flag whose
/// effect nothing looked at: setting `read_only = false` unconditionally left the
/// whole suite green, and all six `ro` cells were writable opens. That is the
/// acceptance question's own shape — a field the comparison never reaches — sitting
/// in the executor rather than in the decoder.
///
/// `preallocate` is the probe because it is the cheapest thing behind the write
/// gate. The `rw` half rolls back rather than committing, and the post-state rule
/// that runs immediately afterwards is what proves the rollback left no trace: if
/// an uncommitted preallocate ever reached the log, this cell would fail there.
/// The branch the probe actually took.
///
/// It is RETURNED rather than recorded by the caller from the mode it passed in,
/// so the executor's `ro_probed` bookkeeping cannot run unless this function did:
/// C5j's round 2 found the java form of that bookkeeping recording that its own
/// housekeeping had run rather than that the probe had, and the answer here is to
/// make the witness a value the probe produces.
pub const WriteGate = enum { rw_rolled_back, ro_refused };

pub fn assertWriteGate(ctx: *Ctx, s: *StoreWAL, mode: []const u8, cell: []const u8) Error!WriteGate {
    if (eql(mode, "ro")) {
        if (s.preallocate()) |recid| {
            return ctx.err("[{s}] a read-only handle preallocated recid {d}", .{ cell, recid });
        } else |e| if (e != error.ReadOnly) {
            return ctx.err("[{s}] a read-only handle refused a write with {s}, not ReadOnly", .{ cell, @errorName(e) });
        }
        return .ro_refused;
    } else {
        _ = s.preallocate() catch |e|
            return ctx.err("[{s}] a read-write handle refused a preallocate: {s}", .{ cell, @errorName(e) });
        s.rollback() catch |e|
            return ctx.err("[{s}] rollback failed: {s}", .{ cell, @errorName(e) });
        return .rw_rolled_back;
    }
}

// ---------------------------------------------------------------------------
// The oracle rows — C5z
// ---------------------------------------------------------------------------

/// The action verb this engine implements, and the arguments it takes.
///
/// **This engine ACCEPTS AND ACCOUNTS; it is not addressed.** `Cell.actions`,
/// `Cell.byte_assertions` and `Cell.reopen` exist on exactly one cell of the
/// corpus and are keyed `("java", "rw")`, so no corpus will ever carry an
/// `action`, `bytes` or `reopen` row addressed to zig (C5 plan §5.3 item 2).
/// Manufacturing one in the fixture root to give this code an input would be
/// fixture theatre; the inputs come from SYNTHETIC manifests in the test file,
/// routed through the production path.
///
/// **Every refusal below is its own SITE with its own input.** C5r needed to be
/// told twice that one case per METHOD is not one case per BRANCH: the five
/// per-key reads and the two integer parses are separate sites, and one mutation
/// of a shared helper is proof for none of them.
///
/// **That claim used to be FALSE here, and the C5z review measured it.** The
/// first draft re-checked the argument GRAMMAR — a pair that is not `k=v`, a
/// repeated key, an implausible number of pairs — and all three were dead:
/// `actionArgs` refuses a malformed pair and requires keys sorted AND distinct
/// before this function is ever reached, and with five known keys the
/// unknown-key refusal fires long before any count bound. Three refusals with no
/// input, sitting directly under a sentence claiming each had one.
///
/// The repair is to make the sentence TRUE rather than to weaken it: the
/// argument grammar has exactly ONE authority, the parser, and this function
/// checks only what the parser deliberately does not — the verb, the key
/// VOCABULARY (`catalogue.ACTION_VERBS` is the authority and this engine
/// implements a subset, so a parser list would go stale), the five required
/// keys, the two integer parses, and the two value semantics. Eleven sites,
/// eleven inputs. A key with no `=` cannot register, so it simply fails the
/// required-key read rather than needing a refusal of its own.
///
/// `recid_label`'s VALUE is deliberately unobserved: §5.2 pins labels and not
/// the numbers an engine hands out, so the label travels into the result line
/// and nothing here compares it to anything.
pub fn runAction(ctx: *Ctx, s: *StoreWAL, verb: []const u8, arg_spec: []const u8) Error!void {
    if (!eql(verb, "commit_one_record"))
        return ctx.err("unknown action verb: {s}", .{verb});
    const known = [_][]const u8{ "op", "payload_id", "payload_len", "recid_label", "serializer" };

    var it = std.mem.splitScalar(u8, arg_spec, ',');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (!contains(&known, pair[0..eq]))
            return ctx.err("unknown argument {s} for {s}; it takes op,payload_id,payload_len,recid_label,serializer", .{ pair[0..eq], verb });
    }

    const op = try argValue(ctx, arg_spec, "op", verb);
    const label = try argValue(ctx, arg_spec, "recid_label", verb);
    const payload_id_s = try argValue(ctx, arg_spec, "payload_id", verb);
    const payload_len_s = try argValue(ctx, arg_spec, "payload_len", verb);
    const ser = try argValue(ctx, arg_spec, "serializer", verb);
    const payload_id = std.fmt.parseInt(u64, payload_id_s, 10) catch
        return ctx.err("payload_id is not an integer: {s}", .{payload_id_s});
    const payload_len = std.fmt.parseInt(usize, payload_len_s, 10) catch
        return ctx.err("payload_len is not an integer: {s}", .{payload_len_s});
    if (!eql(op, "put")) return ctx.err("commit_one_record: unimplemented op {s}", .{op});
    if (!eql(ser, "raw")) return ctx.err("commit_one_record: unimplemented serializer {s}", .{ser});
    _ = label;

    const content = try payload(ctx.alloc, payload_id, payload_len);
    defer ctx.alloc.free(content);
    _ = s.put([]const u8, ctx.alloc, content, R) catch |e|
        return ctx.err("commit_one_record: put failed: {s}", .{@errorName(e)});
    s.commit() catch |e|
        return ctx.err("commit_one_record: commit failed: {s}", .{@errorName(e)});
}

/// One key's value out of a parser-validated spec. FIVE separate call sites, and
/// a mutant on each: replacing one with a constant is invisible to a mutation of
/// the others (C5r round 2).
fn argValue(ctx: *Ctx, arg_spec: []const u8, k: []const u8, verb: []const u8) Error![]const u8 {
    var it = std.mem.splitScalar(u8, arg_spec, ',');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (eql(pair[0..eq], k)) return pair[eq + 1 ..];
    }
    return ctx.err("action argument {s} is required by {s}", .{ k, verb });
}

/// A refused open, with the typed diagnostic the refusal carried.
///
/// **This is the zig deviation, and it is the stronger reading.** rust's
/// `assert_family` matches the S2 rule's rendered MESSAGE, because `DbError`
/// there carries a formatted payload. Here `DbError` carries no payload and the
/// engine has a typed side channel instead (B1's `Diag`), so the family
/// predicate asserts the reason by IDENTITY against the engine's own constant
/// rather than by parsing prose.
pub const Refusal = struct { err: DbError, diag: recover.Diag };

/// Opens through the named opener and returns the refusal, or `null` if the
/// store opened (and closed).
fn refusalOf(ctx: *Ctx, opener: []const u8, mode: []const u8, base: []const u8, cell: []const u8) Error!?Refusal {
    if (eql(opener, "direct")) {
        if (!eql(mode, "rw"))
            return ctx.err("[{s}] the direct opener has no read-only mode here", .{cell});
        if (StoreDirect.openFile(ctx.alloc, base, false)) |*opened| {
            var d = opened.*;
            d.close() catch {};
            d.deinit();
            return null;
        } else |e| return Refusal{ .err = e, .diag = .{} };
    }
    var diag: recover.Diag = .{};
    const opts = wal_mod.WalOptions{ .read_only = eql(mode, "ro"), .diag = &diag };
    if (StoreWAL.openCfg(ctx.alloc, base, opts)) |*opened| {
        var s = opened.*;
        s.close() catch {};
        s.deinit();
        return null;
    } else |e| return Refusal{ .err = e, .diag = diag };
}

/// Asserts a refusal belongs to the named contract family.
///
/// The family is READ FROM THE MANIFEST ROW, never hard-coded, so editing
/// `catalogue.reopen` stops the run instead of being graded against a constant
/// this file happens to agree with. A family this engine has no predicate for is
/// a **failure**: the alternative is a green cell whose reopen was checked by
/// nothing.
///
/// **The `opener` is a parameter because it is the only thing that separates two
/// of the five families.** C5t's `reopen` rows brought `direct-magic` and `D1`
/// here, and in this engine both are a bare `error.DataCorruption` with no
/// diagnostic: one from `StoreDirect.openFile`'s magic check, one from
/// `WalSegmentSet`'s legacy-boundary rows. Nothing in the `Refusal` tells them
/// apart, so the predicate is given the thing that does.
pub fn assertFamily(ctx: *Ctx, where: []const u8, opener: []const u8, family: []const u8, r: Refusal) Error!void {
    // The three corruption families, and what actually discriminates them.
    //
    // C5z's review recorded the D1 refusal's `Diag` as EMPTY — it happens inside
    // `WalSegmentSet.openWithIo`, before `wr.recover` ever runs — and plan §3.12
    // wrote that down as a CONSTRAINT on C5t: a `diag.reason` predicate cannot
    // be written for it. What it is instead is the discriminator. A refusal from
    // the segment-set opener has no reason BECAUSE recovery never ran, and every
    // refusal recovery produces notes one before it returns. So:
    //
    //     direct-magic     the DIRECT opener refused          (no diag exists there)
    //     D1               the wal3 opener refused BEFORE recovery   reason == ""
    //     DataCorruption   recovery refused, reason unpinned         reason != ""
    //     S2               recovery refused with H_LSN_BACK exactly
    //
    // Each pair is separated by something, which is what makes the family
    // READING falsifiable — the property C5r and C5z both wrote down as the
    // reason a one-member predicate proves nothing. `D1` and `DataCorruption`
    // are exact complements on purpose: a predicate for the one that admitted
    // the other would be a family column that grades nothing.
    if (eql(family, "direct-magic")) {
        if (!(eql(opener, "direct") and r.err == error.DataCorruption))
            return ctx.err(
                "{s}: `direct-magic` is StoreDirect's magic/min-length refusal — it must come from the direct opener as a corruption verdict, and this is {s}/{s}",
                .{ where, opener, @errorName(r.err) },
            );
        return;
    }
    if (eql(family, "D1")) {
        if (!(eql(opener, "wal3") and r.err == error.DataCorruption and r.diag.reason.len == 0))
            return ctx.err(
                "{s}: `D1` is the legacy boundary, refused by the WAL opener BEFORE recovery runs — a corruption verdict with an empty diagnostic, and this is {s}/{s}/`{s}`",
                .{ where, opener, @errorName(r.err), r.diag.reason },
            );
        return;
    }
    if (eql(family, "DataCorruption")) {
        if (!(eql(opener, "wal3") and r.err == error.DataCorruption and r.diag.reason.len != 0))
            return ctx.err(
                "{s}: `DataCorruption` is a refusal RECOVERY diagnosed — a corruption verdict carrying a reason, and this is {s}/{s}/`{s}`",
                .{ where, opener, @errorName(r.err), r.diag.reason },
            );
        return;
    }
    if (eql(family, "S2")) {
        // ONE statement for a claim with two halves: the refusal is a corruption
        // verdict AND the diagnostic beside it is the S2 rule's reason. Written
        // as two, either half can be deleted with the other refusing the same
        // input — which is lesson (h) inside the predicate. Each half is given
        // its own input by `theReopenFamilyPredicateDiscriminates`, because the
        // collapse buys freedom from masking and not coverage.
        if (!(r.err == error.DataCorruption and eql(r.diag.reason, recover.H_LSN_BACK)))
            return ctx.err(
                "{s}: not the S2 rule's refusal — it must be a corruption verdict whose diagnostic reason is `{s}`, and this is {s}/`{s}`",
                .{ where, recover.H_LSN_BACK, @errorName(r.err), r.diag.reason },
            );
        return;
    }
    if (eql(family, "StoreFull")) {
        // Q8's family in this engine, and the one the corpus's own reject verdict
        // for `div-wal3-lsn-exhausted` produces — MEASURED, not inherited: a WAL
        // segment namespace with no sequence number left is a capacity ceiling
        // with nothing damaged, so the port refuses to call an intact store
        // corrupt. Contract §10.1 pins it. A second family is also what makes
        // the family READING falsifiable: a predicate with one member cannot be
        // shown to read the row.
        if (r.err != error.StoreFull)
            return ctx.err("{s}: StoreFull is a capacity verdict, got {s}", .{ where, @errorName(r.err) });
        return;
    }
    return ctx.err(
        "{s}: error family {s} has no predicate in this engine. Refusing rather than accepting any refusal at all — an unimplemented family graded as `it threw something` is the check not running",
        .{ where, family },
    );
}

/// Grades every `bytes` row against the CAPTURED post bytes (contract §2.3).
///
/// Never a pre-open patch: Q8's input segment is 186 bytes and its assertion is
/// at offset 187, so a pre-open reading is not merely wrong, it is out of range.
/// An assertion whose range cannot be reached is a failure, never a skip.
fn assertBytesRows(
    ctx: *Ctx,
    m: *const V2,
    e: V2Expect,
    after: *const Capture,
    cell: []const u8,
    owed: *Consumption,
) Error!void {
    var rows: std.ArrayListUnmanaged(*const V2Bytes) = .empty;
    defer rows.deinit(ctx.alloc);
    try m.bytesOfCell(e.fixture, ENGINE, e.mode, &rows, ctx.alloc);
    for (rows.items) |b| {
        const now = after.get(b.rel) orelse
            return ctx.err("[{s}] bytes[{s}@{d}]: names a file the cell directory does not hold", .{ cell, b.rel, b.offset });
        const len = b.hex.len / 2;
        const end = b.offset + len;
        if (end > now.len)
            return ctx.err("[{s}] bytes[{s}@{d}]: the range ends at {d} and the post state is {d} bytes", .{ cell, b.rel, b.offset, end, now.len });
        var got_buf: [64]u8 = undefined;
        if (len > got_buf.len / 2)
            return ctx.err("[{s}] bytes[{s}@{d}]: assertion longer than this reader renders", .{ cell, b.rel, b.offset });
        const got = std.fmt.bufPrint(&got_buf, "{x}", .{now[b.offset..end]}) catch
            return ctx.err("[{s}] bytes[{s}@{d}]: the rendered assertion does not fit", .{ cell, b.rel, b.offset });
        if (!eql(got, b.hex))
            return ctx.err("[{s}] bytes[{s}@{d}]: the asserted bytes are {s}, want {s}", .{ cell, b.rel, b.offset, got, b.hex });
        try owed.consume(ctx, "bytes {s}@{d}", .{ b.rel, b.offset }, b);
    }
}

/// After the cell's actions have run and the store has been closed, a SECOND
/// open must fail with the family the row names.
fn assertReopen(
    ctx: *Ctx,
    m: *const V2,
    e: V2Expect,
    opener: []const u8,
    base: []const u8,
    cell: []const u8,
    owed: *Consumption,
) Error!void {
    var rows: std.ArrayListUnmanaged(*const V2Reopen) = .empty;
    defer rows.deinit(ctx.alloc);
    try m.reopensOf(e.fixture, ENGINE, e.mode, &rows, ctx.alloc);
    for (rows.items) |r| {
        var where_buf: [256]u8 = undefined;
        const where = std.fmt.bufPrint(&where_buf, "[{s}] reopen[{s}]", .{ cell, r.family }) catch cell;
        // A reopen is a WRITABLE open whatever the cell's own mode was: the claim
        // is that the store is permanently unopenable, and a read-only probe
        // would be a weaker one.
        //
        // Through the cell's OWN opener, not a hard-coded `wal3`. Until C5t only
        // Q8 had a reopen row and Q8 is a wal3 cell, so the constant was right by
        // accident; `reject-wal3-segment-at-direct` now carries one too, and
        // sending it to the WAL opener would grade a `direct-magic` family
        // against a refusal StoreDirect never made.
        const refusal = try refusalOf(ctx, opener, "rw", base, where) orelse
            return ctx.err("{s}: the store opened again", .{where});
        try assertFamily(ctx, where, opener, r.family, refusal);
        try owed.consume(ctx, "reopen {s}", .{r.family}, r);
    }
}

/// Which opener a cell is dispatched through.
///
/// `always_wal3` exists for §3.11's mutant and for nothing else: routing the
/// `direct` row through the WAL opener must turn the suite red, and a deletion
/// that merely restores an `opener == wal3` refusal proves only parser branching.
///
/// **C5z measured both halves of §3.11 rather than inheriting them, and zig is
/// the ports' case exactly as the section predicts.** `StoreDirect.openFile`
/// refuses the bare segment (`DataCorruption`, bad magic) and leaves the
/// directory holding `{x}` — it takes no `<base>.lock`, so
/// `catalogue.DIRECT_OPENER_LOCKS["zig"] = False` is now a measurement.
/// `StoreWAL.openCfg` on the same path refuses it as D1 — a regular file at the
/// WAL base path — but takes the lock BEFORE the check and leaves `{x, x.lock}`.
/// Both openers reject, so the verdict discriminates nothing; the stray lock
/// does, against the two-sided file-set rule.
pub const Dispatch = enum { by_manifest, always_wal3 };

/// Runs schema-v2 cells against this engine — the single executor for BOTH v2
/// roots.
///
/// **Why one type and not two.** `data-v2/` is the static `v2-core` sample and
/// `data-v2-corpus/` is the `v2-oracle` preflight root; they differ in which rows
/// they carry, not in what a cell means. Two executors would be two
/// implementations of the post-state rule, the opener dispatch and the reader
/// contract, and this workstream has already shipped the consequence twice — a
/// fix applied to one of two copies is a fix that did not happen (C2j's
/// B-finding). What legitimately differs is the CARDINALITY rule, and that lives
/// in the callers.
pub const Cells = struct {
    sample: *const SampleV2,
    /// The `fixtureId/mode` of every `ro` accept cell whose read-only handle was
    /// actually probed with a write.
    ///
    /// This exists so the probe is not a LEAF. Deleting the `if (ro) probe` call
    /// leaves nothing to observe: the standalone discriminating test opens the
    /// read-only handle itself, so it cannot see the executor skipping the call.
    /// A set the caller compares against the cells it ran turns the deletion into
    /// an empty set and a red gate.
    ro_probed: std.ArrayListUnmanaged([]const u8) = .empty,
    owned: Strings = .{},

    pub fn deinit(self: *Cells, alloc: Allocator) void {
        self.ro_probed.deinit(alloc);
        self.owned.deinit(alloc);
    }

    /// Every `action`/`bytes`/`reopen`/`post` row addressed to this engine in
    /// `mode` must name a cell the engine actually runs.
    ///
    /// **Per-cell consumption cannot see this**, and both C5j reviewers proved it
    /// independently: the accountant is built from the rows addressed to the cell
    /// BEING RUN, so a row addressed to a `(fixture, mode)` with no `expect` row
    /// is owed by nobody, consumed by nobody and graded by nobody. Contract §2.3
    /// says an addressed row no handler consumed is a failure, and this is the
    /// half of that sentence per-cell accounting cannot reach.
    pub fn requireEveryOracleRowAddressesARunCell(
        self: *const Cells,
        ctx: *Ctx,
        mode: []const u8,
        ran: []const []const u8,
    ) Error!void {
        const m = &self.sample.manifest;
        for (m.actions.items) |a| {
            if (eql(a.engine, ENGINE) and eql(a.mode, mode) and !contains(ran, a.fixture))
                return ctx.err("an oracle row addressed to {s} whose cell this engine never ran: action {s}/{s} {s}", .{ ENGINE, a.fixture, a.mode, a.verb });
        }
        for (m.byte_rows.items) |b| {
            if (eql(b.engine, ENGINE) and eql(b.mode, mode) and !contains(ran, b.fixture))
                return ctx.err("an oracle row addressed to {s} whose cell this engine never ran: bytes {s}/{s} {s}", .{ ENGINE, b.fixture, b.mode, b.rel });
        }
        for (m.reopens.items) |r| {
            if (eql(r.engine, ENGINE) and eql(r.mode, mode) and !contains(ran, r.fixture))
                return ctx.err("an oracle row addressed to {s} whose cell this engine never ran: reopen {s}/{s} {s}", .{ ENGINE, r.fixture, r.mode, r.family });
        }
        // `post` is the FOURTH addressed row type. C5j's round 2 found that
        // nothing on either side of the fence caught one addressed to a cell no
        // engine runs; §2.3 names it now, and it has a per-cell debt as well.
        for (m.posts.items) |p| {
            if (eql(p.engine, ENGINE) and eql(p.mode, mode) and !contains(ran, p.fixture))
                return ctx.err("an oracle row addressed to {s} whose cell this engine never ran: post {s}/{s} {s}", .{ ENGINE, p.fixture, p.mode, p.rel });
        }
    }

    /// Runs ONE cell: stage the inputs, open through the opener the `expect` row
    /// names, grade every oracle row addressed here, and account for all of them.
    pub fn runCell(
        self: *Cells,
        ctx: *Ctx,
        e: V2Expect,
        cell_dir: std.fs.Dir,
        dispatch: Dispatch,
    ) Error!void {
        const m = &self.sample.manifest;
        var cell_buf: [256]u8 = undefined;
        const cell = std.fmt.bufPrint(&cell_buf, "v2 cell[{s} {s} {s} {s} {s}]", .{
            e.fixture, ENGINE, e.mode, e.verdict, e.opener,
        }) catch "v2 cell";

        // Every oracle row addressed to this cell, and nothing else. Rows are
        // struck off as they are consumed; what is left at the end is a claim the
        // executor was handed and dropped.
        var owed = Consumption.init(cell);
        defer owed.deinit(ctx.alloc);

        var actions: std.ArrayListUnmanaged(*const V2Action) = .empty;
        defer actions.deinit(ctx.alloc);
        try m.actionsOf(e.fixture, ENGINE, e.mode, &actions, ctx.alloc);
        for (actions.items) |a| try owed.owe(ctx, "action {s}", .{a.verb}, a);

        var byte_rows: std.ArrayListUnmanaged(*const V2Bytes) = .empty;
        defer byte_rows.deinit(ctx.alloc);
        try m.bytesOfCell(e.fixture, ENGINE, e.mode, &byte_rows, ctx.alloc);
        for (byte_rows.items) |b| try owed.owe(ctx, "bytes {s}@{d}", .{ b.rel, b.offset }, b);

        var reopens: std.ArrayListUnmanaged(*const V2Reopen) = .empty;
        defer reopens.deinit(ctx.alloc);
        try m.reopensOf(e.fixture, ENGINE, e.mode, &reopens, ctx.alloc);
        for (reopens.items) |r| try owed.owe(ctx, "reopen {s}", .{r.family}, r);

        var posts: std.ArrayListUnmanaged(*const V2Post) = .empty;
        defer posts.deinit(ctx.alloc);
        try m.postsOf(e.fixture, ENGINE, e.mode, &posts, ctx.alloc);
        for (posts.items) |p| try owed.owe(ctx, "post {s}", .{p.rel}, p);

        var before: std.ArrayListUnmanaged(InputFile) = .empty;
        defer before.deinit(ctx.alloc);
        for (self.sample.files.items) |f| {
            if (!eql(f.fixture, e.fixture)) continue;
            cell_dir.writeFile(.{ .sub_path = f.rel, .data = f.bytes }) catch |err|
                return ctx.err("[{s}] cannot place {s}: {s}", .{ cell, f.rel, @errorName(err) });
            try before.append(ctx.alloc, .{ .rel = f.rel, .bytes = f.bytes });
        }
        if (before.items.len == 0) return ctx.err("[{s}] fixture has no file rows", .{cell});

        // absolute paths — the store openers resolve relative to cwd
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const cell_abs = cell_dir.realpath(".", &path_buf) catch |err|
            return ctx.err("[{s}] realpath failed: {s}", .{ cell, @errorName(err) });
        const base = try std.fs.path.join(ctx.alloc, &.{ cell_abs, e.open_arg });
        defer ctx.alloc.free(base);

        const opener = switch (dispatch) {
            .always_wal3 => "wal3",
            .by_manifest => e.opener,
        };
        if (eql(e.verdict, "accept")) {
            try self.runAccept(ctx, e, opener, base, cell, &owed, actions.items);
        } else if (eql(e.verdict, "reject")) {
            // A `reject` cell asserts that the open FAILED, and this line does not
            // assert WHICH failure — but since C5t it is no longer the whole
            // story, and the difference is the point of plan §3.12.
            //
            // The v2 `expect` row still has no family column. What it has now is
            // a `reopen` row per eligible reject arm, derived in `catalogue.py`
            // from the family that was already pinned there, and `assertReopen`
            // below opens the same tree again and hands the family to
            // `assertFamily`. So the family reaches this engine after all, and
            // the refusal is additionally graded as STABLE — a store that
            // refuses once and opens on the retry now fails, and passed before.
            //
            // What is NOT covered: the eleven WAL-recovery families outside
            // `catalogue.REOPEN_FAMILIES`, which stay graded by "it refused"
            // alone. That is L15's remainder and its owner is C8.
            _ = try refusalOf(ctx, opener, e.mode, base, cell) orelse
                return ctx.err("[{s}] expected a refusal, but the store opened", .{cell});
        }
        // No `else` arm: the verdict vocabulary is pinned to {accept, reject} by
        // `oneOf` at parse time and both are handled above, so an unsupported
        // verdict cannot reach here. Round 2 of review measured the arm deletable
        // with the gate green; C2j's rule is that a check no input can reach goes
        // rather than stays as a guard nothing can trip.

        // THE CAPTURE, taken before the reopen — see `assertPostState`.
        var after = try capture(ctx, cell_dir, cell);
        defer after.deinit(ctx.alloc);
        try assertBytesRows(ctx, m, e, &after, cell, &owed);
        // The post-cardinality guard runs BEFORE the rule it guards, not after: a
        // cell whose post rows were all removed also loses the row naming the lock
        // it creates, so the two-sided file-set rule fires first and this guard
        // would report a red it did not produce (lesson h).
        //
        // It keys on the MANIFEST's opener rather than the dispatched one. Plan
        // §5.3 item 5's second relaxation is what this engine needs and java did
        // not: `StoreDirect` here takes no `<base>.lock` — measured — so the
        // direct cell legitimately leaves the directory as it found it and
        // carries no post row. Keying on the DISPATCHED opener would make this
        // guard fire first under `always_wal3` and §3.11's mutant would report a
        // red for the wrong rule.
        if (posts.items.len == 0 and eql(e.opener, "wal3"))
            return ctx.err("[{s}] a wal3 cell with no post rows asserts nothing about the directory it just opened, which is not a check", .{cell});
        try assertPostState(ctx, before.items, &after, posts.items, cell, &owed);
        try assertReopen(ctx, m, e, opener, base, cell, &owed);
        try owed.requireAllConsumed(ctx);
    }

    fn runAccept(
        self: *Cells,
        ctx: *Ctx,
        e: V2Expect,
        opener: []const u8,
        base: []const u8,
        cell: []const u8,
        owed: *Consumption,
        actions: []const *const V2Action,
    ) Error!void {
        if (!eql(opener, "wal3"))
            return ctx.err("[{s}] an accept cell through a non-wal3 opener is a shape no corpus has and no executor here implements", .{cell});
        const m = &self.sample.manifest;
        const opts = wal_mod.WalOptions{ .read_only = eql(e.mode, "ro") };
        var s = StoreWAL.openCfg(ctx.alloc, base, opts) catch |err|
            return ctx.err("[{s}] accept cell failed to open: {s}", .{ cell, @errorName(err) });
        defer s.deinit();
        for (actions) |a| {
            // Deliberately not swallowed: a store that opened and then failed its
            // action is a different fact from one that refused to open, and
            // collapsing the two lets a broken action be read as the verdict.
            try runAction(ctx, &s, a.verb, a.arg_spec);
            try owed.consume(ctx, "action {s}", .{a.verb}, a);
        }
        var has_recids = false;
        for (m.recids.items) |r| {
            if (eql(r.fixture, e.fixture)) has_recids = true;
        }
        try self.requireSomeOracle(ctx, e, has_recids, cell);
        if (has_recids) {
            try assertReaderContract(ctx, &s, m.recids.items, e.fixture, cell);
            try assertEveryLoggedRecidIsClassified(ctx, &s, self.sample, e.fixture, cell);
        }
        // D7's read-only mode is observable, in the direction that matters: a
        // write through the `ro` handle must be refused, and it must be refused
        // for the MODE. C3z's review found the general shape this closes — `mode`
        // was parsed, vocabulary-checked and used to select an opener, and then
        // nothing observed the difference, so every `ro` cell in java and rust was
        // an ordinary writable open wearing a label.
        //
        // The witness is the value the probe RETURNS. Deleting the call takes the
        // recording with it and `ro_probed` goes empty, which is the red the call
        // did not have on its own (lesson (i): a rule can be correct, directly
        // tested, and never called).
        switch (try assertWriteGate(ctx, &s, e.mode, cell)) {
            .ro_refused => try self.ro_probed.append(ctx.alloc, try self.owned.add(ctx.alloc, "{s}/{s}", .{ e.fixture, e.mode })),
            .rw_rolled_back => {},
        }
        s.close() catch |err| return ctx.err("[{s}] close failed: {s}", .{ cell, @errorName(err) });
    }

    /// An accept cell must assert SOMETHING about the store it just opened — the
    /// C3j guard, as the disjunction plan §5.3 item 5 asked for.
    ///
    /// C5j's first draft deleted this guard for the sealed root and offered the
    /// distribution seal as its replacement. Both reviewers refused, and proving
    /// them right took one doctored manifest: strip a fixture's recid rows and its
    /// accept cell passes on nothing but the universal `x.lock` post row. **The
    /// seal proves copy fidelity and the guard proves assertion adequacy**;
    /// artifact identity cannot buy a semantic property.
    fn requireSomeOracle(self: *const Cells, ctx: *Ctx, e: V2Expect, has_recids: bool, cell: []const u8) Error!void {
        const m = &self.sample.manifest;
        var any = has_recids or eql(e.mode, "ro");
        for (m.actions.items) |a| {
            if (cellEq(.{ a.fixture, a.engine, a.mode }, .{ e.fixture, ENGINE, e.mode })) any = true;
        }
        for (m.reopens.items) |r| {
            if (cellEq(.{ r.fixture, r.engine, r.mode }, .{ e.fixture, ENGINE, e.mode })) any = true;
        }
        if (!any)
            return ctx.err("[{s}] an accept cell with no recid rows, no action, no reopen and a writable handle asserts nothing about the store it opened, which is not a check", .{cell});
    }
};

/// Runs every schema-v2 cell addressed to this engine in `mode`, and asserts the
/// set that ran is **exactly** the set the `fixture` rows call for.
///
/// This is the STATIC SAMPLE's cardinality rule. It derives what should run from
/// a different row type than the one that says what will: a count, or the set of
/// modes actually seen, is a projection of the already-truncated input, and the
/// C3j review deleted one `expect` row and left the java suite green because
/// another fixture still supplied that mode.
///
/// The preflight corpus cannot use this rule — its cell set is legitimately
/// partial — which is what [`runV2CorpusCells`] and `applies` are for.
///
/// C-D3 costs this port nothing: `WalOptions.read_only` is `pub` and this suite
/// is in-package, so both modes run here and neither needs new public surface.
pub fn runV2Cells(ctx: *Ctx, sample: *const SampleV2, mode: []const u8, tmp: std.fs.Dir) Error!void {
    const m = &sample.manifest;
    if (m.fixtures.items.len == 0) return ctx.err("the v2 sample declares no fixtures", .{});
    // The sample is `v2-core`, in BOTH directions. A root that grew an oracle row
    // would be running assertions this rule never bought, and since C5 moved the
    // profile split into the grammar that is a refusal, not a widening.
    if (m.applies.items.len != 0 or m.actions.items.len != 0 or
        m.byte_rows.items.len != 0 or m.reopens.items.len != 0)
        return ctx.err("the static sample carries an oracle row; it is v2-core through C7", .{});

    var cells = Cells{ .sample = sample };
    defer cells.deinit(ctx.alloc);
    var ran: std.ArrayListUnmanaged([]const u8) = .empty;
    defer ran.deinit(ctx.alloc);
    try runCells(ctx, &cells, mode, tmp, &ran, .by_manifest);
    try assertCellSetExact(ctx, m.fixtures.items, ran.items, mode);
}

/// Runs the preflight CORPUS's cells for this engine in `mode`, under the
/// cardinality rule its partial cell set needs, plus every rule that is about the
/// SET of cells rather than about one of them.
///
/// Two row types emitted from one catalogue is a pair that moves together, so
/// this also requires `applies == expect` per cell, in both directions. That
/// check is deliberately absent from `manifest_v2.py` — there both sets are
/// compared to the catalogue a few lines apart, so a third comparison could only
/// fire after one of those already had. An engine has no catalogue, so for an
/// engine the disagreement is the only detectable inconsistency, and without it a
/// manifest could have this suite run a cell it holds no verdict for.
///
/// Every doctored-manifest case enters HERE rather than calling the rules
/// directly. That distinction is the entire finding both C5j reviewers made: a
/// test that calls the suite-wide check itself proves the METHOD and leaves its
/// CALL unobserved, so deleting the call from the suite stays green.
pub fn runV2CorpusCells(
    ctx: *Ctx,
    sample: *const SampleV2,
    mode: []const u8,
    tmp: std.fs.Dir,
    dispatch: Dispatch,
) Error!void {
    const m = &sample.manifest;
    var want: std.ArrayListUnmanaged([]const u8) = .empty;
    defer want.deinit(ctx.alloc);
    for (m.applies.items) |a| {
        if (eql(a.engine, ENGINE) and eql(a.mode, mode)) try want.append(ctx.alloc, a.fixture);
    }
    if (want.items.len == 0)
        return ctx.err("the corpus declares no {s} applies rows for mode {s}", .{ ENGINE, mode });
    for (m.expects.items) |e| {
        if (eql(e.engine, ENGINE) and eql(e.mode, mode) and !contains(want.items, e.fixture))
            return ctx.err("the {s}/{s} `expect` row for {s} has no `applies` row", .{ ENGINE, mode, e.fixture });
    }
    for (want.items) |w| {
        var found = false;
        for (m.expects.items) |e| {
            if (eql(e.engine, ENGINE) and eql(e.mode, mode) and eql(e.fixture, w)) found = true;
        }
        if (!found) return ctx.err("the {s}/{s} `applies` row for {s} has no `expect` row", .{ ENGINE, mode, w });
    }

    var cells = Cells{ .sample = sample };
    defer cells.deinit(ctx.alloc);
    var ran: std.ArrayListUnmanaged([]const u8) = .empty;
    defer ran.deinit(ctx.alloc);
    // No `want == ran` comparison here, and its absence is deliberate. The two
    // loops above force `applies` and `expect` to be the same set in both
    // directions, and `runCells` runs exactly one cell per matching `expect` row
    // or refuses — so `ran == want` holds by construction and a third comparison
    // could never fire. The C5z review MEASURED that: deleting it left the whole
    // suite green. C2j's rule applies — a check no input can reach is deleted
    // rather than decorated, because leaving it in claims a guard that is not
    // there.
    try runCells(ctx, &cells, mode, tmp, &ran, dispatch);

    // The other half of contract §2.3's consumption rule.
    try cells.requireEveryOracleRowAddressesARunCell(ctx, mode, ran.items);

    // …and the ro write probe really ran on every ro ACCEPT cell. Deleting the
    // call inside the executor leaves this list empty, which is the red that call
    // did not have. In `rw` the expected set is empty, and comparing it is not
    // decoration: a probe that fired on a writable handle would land here.
    var ro_cells: std.ArrayListUnmanaged([]const u8) = .empty;
    defer ro_cells.deinit(ctx.alloc);
    var keys = Strings{};
    defer keys.deinit(ctx.alloc);
    for (m.expects.items) |e| {
        if (eql(e.engine, ENGINE) and eql(e.mode, mode) and eql(mode, "ro") and eql(e.verdict, "accept"))
            try ro_cells.append(ctx.alloc, try keys.add(ctx.alloc, "{s}/{s}", .{ e.fixture, e.mode }));
    }
    if (eql(mode, "ro") and ro_cells.items.len == 0)
        return ctx.err("the corpus has no {s} ro accept cell, so the read-only probe has no input", .{ENGINE});
    if (ro_cells.items.len != cells.ro_probed.items.len)
        return ctx.err("the {s}/{s} ro cells whose handle was probed with a write: {d} probed, {d} expected", .{ ENGINE, mode, cells.ro_probed.items.len, ro_cells.items.len });
    for (ro_cells.items) |c| {
        if (!contains(cells.ro_probed.items, c))
            return ctx.err("the {s}/{s} ro accept cell {s} was never probed with a write", .{ ENGINE, mode, c });
    }
}

fn runCells(
    ctx: *Ctx,
    cells: *Cells,
    mode: []const u8,
    tmp: std.fs.Dir,
    ran: *std.ArrayListUnmanaged([]const u8),
    dispatch: Dispatch,
) Error!void {
    const m = &cells.sample.manifest;
    for (m.expects.items, 0..) |e, i| {
        if (!eql(e.engine, ENGINE) or !eql(e.mode, mode)) continue;
        var name_buf: [64]u8 = undefined;
        const cell_name = std.fmt.bufPrint(&name_buf, "v2-{s}-{d}", .{ mode, i }) catch unreachable;
        var cell_dir = tmp.makeOpenPath(cell_name, .{ .iterate = true }) catch |err|
            return ctx.err("cannot create the cell dir for {s}/{s}: {s}", .{ e.fixture, mode, @errorName(err) });
        defer cell_dir.close();
        try cells.runCell(ctx, e, cell_dir, dispatch);
        // No duplicate-fixture check: the parser already refuses a second
        // `expect` row for the same (fixture, engine, mode), which is exactly the
        // key this loop filters on. Measured dead by the C5z review and removed
        // rather than kept as a guard nothing can trip.
        try ran.append(ctx.alloc, e.fixture);
    }
}

/// The cells that RAN must be exactly the ones the `fixture` rows call for.
///
/// Split out from [`runV2Cells`] so it can be addressed directly. The sample
/// declares three fixtures and runs three cells, so on the real corpus this rule
/// never fires and deleting it was invisible — the C3z campaign measured that
/// too. Both directions are stated: a declared fixture with no cell, and a cell
/// for a fixture nothing declares.
pub fn assertCellSetExact(
    ctx: *Ctx,
    declared: []const FixtureRow,
    ran: []const []const u8,
    mode: []const u8,
) Error!void {
    for (declared) |f| {
        if (!contains(ran, f.id))
            return ctx.err(
                "fixture `{s}` is declared but no {s}/{s} cell ran for it",
                .{ f.id, ENGINE, mode },
            );
    }
    for (ran) |r| {
        var is_declared = false;
        for (declared) |f| {
            if (eql(f.id, r)) is_declared = true;
        }
        if (!is_declared)
            return ctx.err("a {s}/{s} cell ran for undeclared fixture `{s}`", .{ ENGINE, mode, r });
    }
}
