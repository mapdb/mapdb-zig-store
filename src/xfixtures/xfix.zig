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
//! Borrowing those makes the §11.2 comparisons *stronger*, not weaker. The two
//! golden tables are written by python (framing) and by the frozen java reader
//! (bodies), so they are external authorities: if the engine's own domain, its
//! section-header parse or its packed-long reader disagreed with java's, this
//! suite would report it as a golden mismatch. A second in-repo transcription
//! would only ever grade this file against itself.
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
    expects: std.ArrayListUnmanaged(V2Expect) = .empty,
    posts: std.ArrayListUnmanaged(V2Post) = .empty,
    recids: std.ArrayListUnmanaged(RecidRow) = .empty,
    owned: Strings = .{},

    pub fn deinit(self: *V2, alloc: Allocator) void {
        self.fixtures.deinit(alloc);
        self.files.deinit(alloc);
        self.expects.deinit(alloc);
        self.posts.deinit(alloc);
        self.recids.deinit(alloc);
        self.owned.deinit(alloc);
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
    var r = from;
    while (r <= to) : (r += 1) {
        const label = try owned.add(ctx.alloc, "{s}[{d}]", .{ t.f[2], r - from });
        try addRecid(ctx, into, .{
            .fixture = t.f[1],
            .label = label,
            .recid = r,
            .state = state,
            .payload_id = base + (r - from),
            .len = @intCast(len),
        }, line);
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
    const sha = args[1];
    if (sha.len != 64) return ctx.err("not a lowercase sha256 hex digest: {s} in: {s}", .{ sha, line });
    for (sha) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return ctx.err("not a lowercase sha256 hex digest: {s} in: {s}", .{ sha, line });
    }
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
        .raw_sha = t.f[4],
        .gz_sha = t.f[5],
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
            try arity(ctx, t, 6, line);
            // provenance for a derived reject image; nothing here executes it.
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
        } else if (eql(tag, "file")) {
            try arity(ctx, t, 6, line);
            try addFile(ctx, &m.files, t, line);
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
            try arity(ctx, t, 6, line);
        } else if (eql(tag, "bytes")) {
            try arity(ctx, t, 7, line);
            _ = try oneOf(ctx, t.f[2], &ENGINES, "engine", line);
            _ = try oneOf(ctx, t.f[3], &MODES, "mode", line);
            _ = try relName(ctx, t.f[4], line);
            _ = try nat(ctx, t.f[5], line);
            return ctx.err(
                "a v2 `bytes` row, which this reader does not execute yet (C4 introduces the " ++
                    "derived fixtures it describes): {s}",
                .{line},
            );
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
    var loaded = try parse(ctx, manifest_tsv);
    errdefer loaded.deinit(ctx.alloc);
    if (loaded.version() != 2) return ctx.err("the v2 sample root is schema v1", .{});

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
        try decode(ctx, f.bytes, where, &seg);
        if (seg.trailing != 0)
            return ctx.err("{s}: {d} bytes follow the last section", .{ where, seg.trailing });
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
fn contentSha(ctx: *Ctx, e: Entry, where: []const u8, out: *[64]u8) Error!?[]const u8 {
    if (!e.isRecord() or e.len_plus.? == 0) {
        if (e.content != null)
            return ctx.err("{s}: a non-record or NULL entry carries content", .{where});
        if (e.isRecord() and e.cap.? != 0)
            return ctx.err("{s}: a NULL record's cap must be 0, not {d}", .{ where, e.cap.? });
        return null;
    }
    const c = e.content orelse return ctx.err("{s}: a sized record carries no content", .{where});
    if (c.len != e.len_plus.? - 1)
        return ctx.err("{s}: content length {d} disagrees with lenPlus {d}", .{ where, c.len, e.len_plus.? });
    try checkCap(ctx, e.cap.?, c.len, where);
    try checkPayload(ctx, c, where);
    out.* = sha256Hex(c);
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
        try decode(ctx, f.bytes, where, &seg);

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
        try decode(ctx, f.bytes, f.blob, &seg);
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

/// Presence, symlinks NOT followed — the same discipline `wal_segments.isRegularFile`
/// uses. `readFile(..) catch false` would turn a permission error, or the target
/// having been replaced by a DIRECTORY, into "absent", so a `deleted` row would
/// pass on a file that is very much still there in another shape.
fn exists(dir: std.fs.Dir, name: []const u8) bool {
    _ = std.posix.fstatat(dir.fd, name, std.posix.AT.SYMLINK_NOFOLLOW) catch return false;
    return true;
}

pub const InputFile = struct { rel: []const u8, bytes: []const u8 };

/// The two-sided D6 post-state rule.
///
/// One side is the obvious one: every file a `post` row names must be in the
/// state that row declares. The other side is the amendment that makes the rule
/// total — **files not named by a `post` row are implicitly `unchanged`** — so an
/// unnamed input must still be there byte for byte, and a file that is neither an
/// input nor named must not exist at all. Without the second side a cell that
/// deleted a segment and wrote three new ones would pass by saying nothing about
/// them.
pub fn assertPostState(
    ctx: *Ctx,
    dir: std.fs.Dir,
    before: []const InputFile,
    posts: []const V2Post,
    cell: []const u8,
) Error!void {
    for (posts) |p| {
        const present = exists(dir, p.rel);
        var was_input: ?[]const u8 = null;
        for (before) |b| {
            if (eql(b.rel, p.rel)) was_input = b.bytes;
        }
        if (eql(p.verb, "deleted")) {
            // §2.1: a post row is an explicit OVERRIDE of an input or an explicit
            // NEW file. `deleted` is an override, so it must name something the
            // cell actually started with.
            if (was_input == null)
                return ctx.err("[{s}] `deleted` names {s}, which was never an input", .{ cell, p.rel });
            if (present)
                return ctx.err("[{s}] {s} must not exist after the cell", .{ cell, p.rel });
        } else if (eql(p.verb, "unchanged")) {
            const was = was_input orelse
                return ctx.err("[{s}] `unchanged` names {s}, which was never an input", .{ cell, p.rel });
            const now = dir.readFileAlloc(ctx.alloc, p.rel, 256 * 1024 * 1024) catch |e|
                return ctx.err("[{s}] cannot read {s}: {s}", .{ cell, p.rel, @errorName(e) });
            defer ctx.alloc.free(now);
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
            if (!present) return ctx.err("[{s}] {s} must exist after the cell", .{ cell, p.rel });
            const now = dir.readFileAlloc(ctx.alloc, p.rel, 256 * 1024 * 1024) catch |e|
                return ctx.err("[{s}] cannot read {s}: {s}", .{ cell, p.rel, @errorName(e) });
            defer ctx.alloc.free(now);
            if (now.len != p.len.?)
                return ctx.err("[{s}] {s} length after the cell: {d}, want {d}", .{ cell, p.rel, now.len, p.len.? });
            const sha = sha256Hex(now);
            if (!eql(&sha, p.sha.?))
                return ctx.err("[{s}] {s} content after the cell: {s}, want {s}", .{ cell, p.rel, &sha, p.sha.? });
        }
    }

    for (before) |b| {
        var named = false;
        for (posts) |p| {
            if (eql(p.rel, b.rel)) named = true;
        }
        if (named) continue;
        const now = dir.readFileAlloc(ctx.alloc, b.rel, 256 * 1024 * 1024) catch |e|
            return ctx.err("[{s}] {s} is named by no post row, so it must still be there: {s}", .{ cell, b.rel, @errorName(e) });
        defer ctx.alloc.free(now);
        if (!eql(now, b.bytes))
            return ctx.err("[{s}] unnamed input {s} changed", .{ cell, b.rel });
    }

    var it = dir.iterate();
    while (it.next() catch |e| return ctx.err("[{s}] cannot list the cell dir: {s}", .{ cell, @errorName(e) })) |entry| {
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

/// Runs every schema-v2 cell addressed to this engine in `mode`, and asserts the
/// set that ran is **exactly** the set the `fixture` rows call for.
///
/// The expected set comes from the `fixture` rows, NOT from the `expect` rows the
/// executor is about to run: a count, or the set of modes actually seen, is a
/// projection of the already-truncated input, and the C3j review deleted one
/// `expect` row and left the java suite green because another fixture still
/// supplied that mode.
///
/// C-D3 costs this port nothing: `WalOptions.read_only` is `pub` and this suite
/// is in-package, so both modes run here and neither needs new public surface.
pub fn runV2Cells(ctx: *Ctx, sample: *const SampleV2, mode: []const u8, tmp: std.fs.Dir) Error!void {
    const m = &sample.manifest;
    if (m.fixtures.items.len == 0) return ctx.err("the v2 sample declares no fixtures", .{});

    var ran: std.ArrayListUnmanaged([]const u8) = .empty;
    defer ran.deinit(ctx.alloc);

    for (m.expects.items, 0..) |e, i| {
        if (!eql(e.engine, ENGINE) or !eql(e.mode, mode)) continue;

        var cell_buf: [256]u8 = undefined;
        const cell = std.fmt.bufPrint(&cell_buf, "v2 cell {d}: fixture={s} mode={s} verdict={s} opener={s} openArg={s}", .{
            i, e.fixture, e.mode, e.verdict, e.opener, e.open_arg,
        }) catch "v2 cell";
        if (!eql(e.opener, "wal3"))
            return ctx.err("[{s}] the only v2 opener this reader executes is `wal3`", .{cell});

        var name_buf: [64]u8 = undefined;
        const cell_name = std.fmt.bufPrint(&name_buf, "v2-{s}-{d}", .{ mode, i }) catch unreachable;
        var cell_dir = tmp.makeOpenPath(cell_name, .{ .iterate = true }) catch |err|
            return ctx.err("[{s}] cannot create the cell dir: {s}", .{ cell, @errorName(err) });
        defer cell_dir.close();

        var before: std.ArrayListUnmanaged(InputFile) = .empty;
        defer before.deinit(ctx.alloc);
        for (sample.files.items) |f| {
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

        const opts = wal_mod.WalOptions{ .read_only = eql(mode, "ro") };
        if (eql(e.verdict, "accept")) {
            var s = StoreWAL.openCfg(ctx.alloc, base, opts) catch |err|
                return ctx.err("[{s}] accept cell failed to open: {s}", .{ cell, @errorName(err) });
            defer s.deinit();
            try assertReaderContract(ctx, &s, m.recids.items, e.fixture, cell);
            try assertEveryLoggedRecidIsClassified(ctx, &s, sample, e.fixture, cell);
            s.close() catch |err| return ctx.err("[{s}] close failed: {s}", .{ cell, @errorName(err) });
        } else if (eql(e.verdict, "reject")) {
            if (StoreWAL.openCfg(ctx.alloc, base, opts)) |*opened| {
                var s = opened.*;
                s.deinit();
                return ctx.err("[{s}] reject cell opened successfully", .{cell});
            } else |err| if (err != error.DataCorruption) {
                return ctx.err("[{s}] expected error.DataCorruption, got {s}", .{ cell, @errorName(err) });
            }
        } else {
            return ctx.err("[{s}] unsupported verdict {s}", .{ cell, e.verdict });
        }

        var posts: std.ArrayListUnmanaged(V2Post) = .empty;
        defer posts.deinit(ctx.alloc);
        for (m.posts.items) |p| {
            if (eql(p.fixture, e.fixture) and eql(p.engine, ENGINE) and eql(p.mode, mode))
                try posts.append(ctx.alloc, p);
        }
        try assertPostState(ctx, cell_dir, before.items, posts.items, cell);

        if (contains(ran.items, e.fixture))
            return ctx.err("[{s}] two {s} cells for the same fixture", .{ cell, mode });
        try ran.append(ctx.alloc, e.fixture);
    }

    for (m.fixtures.items) |f| {
        if (!contains(ran.items, f.id))
            return ctx.err(
                "fixture `{s}` is declared but no {s}/{s} cell ran for it",
                .{ f.id, ENGINE, mode },
            );
    }
    for (ran.items) |r| {
        var declared = false;
        for (m.fixtures.items) |f| {
            if (eql(f.id, r)) declared = true;
        }
        if (!declared) return ctx.err("a {s}/{s} cell ran for undeclared fixture `{s}`", .{ ENGINE, mode, r });
    }
}
