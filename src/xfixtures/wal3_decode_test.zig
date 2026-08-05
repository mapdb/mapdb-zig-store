//! The synthetic battery for the shared WAL v3 decoder — **lessons (g) and (h)**.
//!
//! C3j's lesson (g) is: **a comparison can only see the variation its inputs
//! contain.** The C3j review measured three decoder defects that the sample
//! corpus cannot possibly catch, because the corpus is CONSTANT in the field
//! each one touches:
//!
//! - every sample segment's `flags` word is zero, because the writer emits the
//!   constant, so `flags = 0` hard-coded in a decoder is unfalsifiable by any
//!   bundle;
//! - every sample section's entries happen to be in ascending recid order, so a
//!   decoder that SORTED them would publish a correct-looking file — and for
//!   this port, would be graded against java's file and agree with it;
//! - the two `'K'` mark longs are both longs, so swapping them is invisible to
//!   everything downstream.
//!
//! C3r's lesson (h) is the neighbouring one: **an input that several checks
//! reject measures the first one only.** The CRC domains chain — the segment
//! header CRC covers the first 32 bytes, and every section CRC is taken over ALL
//! 36 header bytes followed by `be64(sectionOffset)` — so flipping a magic byte
//! in a finished segment breaks the header CRC and every section CRC too, and
//! deleting the magic check outright leaves the input refused anyway. The C3r
//! review measured exactly that on four checks. The answer is [`SegBuilder`],
//! which BUILDS from fields and RESEALS: each case differs from the control in
//! one semantic field, and only the rule it is named for can refuse it.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const xfix = @import("xfix.zig");
const io = @import("../io.zig");
const DataOutput2 = io.DataOutput2;
const Crc32 = std.hash.crc.Crc32;

/// Well-formed sha256 columns — see the note in conformance_test.zig.
const SHAS = "\t" ++ "a" ** 64 ++ "\t" ++ "b" ** 64;

// ---------------------------------------------------------------------------
// builders
// ---------------------------------------------------------------------------

const Sec = struct { tag: u8, lsn: i64, body: []const u8 };

/// Builds a segment the way the writer does — and, unlike a byte-poking mutator,
/// RESEALS everything from the fields it is given.
const SegBuilder = struct {
    alloc: Allocator,
    magic: [8]u8 = xfix.MAGIC,
    version: i32 = xfix.FORMAT_VERSION,
    flags: i32 = 0,
    seq: i64 = 1,
    first_lsn: i64 = 1,
    /// Replaces the computed header CRC, to test the header-CRC check ALONE: the
    /// sections are then sealed against these header bytes, so they stay valid
    /// and only the header check can fire.
    header_crc: ?u32 = null,
    sections: std.ArrayListUnmanaged(Sec) = .empty,

    fn init(alloc: Allocator, seq: i64, first_lsn: i64, flags: i32) SegBuilder {
        return .{ .alloc = alloc, .seq = seq, .first_lsn = first_lsn, .flags = flags };
    }

    fn deinit(self: *SegBuilder) void {
        self.sections.deinit(self.alloc);
    }

    fn push(self: *SegBuilder, tag: u8, lsn: i64, body: []const u8) !void {
        try self.sections.append(self.alloc, .{ .tag = tag, .lsn = lsn, .body = body });
    }

    fn header(self: *const SegBuilder) [xfix.SEG_HDR]u8 {
        var h: [xfix.SEG_HDR]u8 = undefined;
        @memcpy(h[0..8], &self.magic);
        std.mem.writeInt(i32, h[8..12], self.version, .big);
        std.mem.writeInt(i32, h[12..16], self.flags, .big);
        std.mem.writeInt(i64, h[16..24], self.seq, .big);
        std.mem.writeInt(i64, h[24..32], self.first_lsn, .big);
        const crc = self.header_crc orelse Crc32.hash(h[0..xfix.SEG_HDR_CRC_LEN]);
        std.mem.writeInt(u32, h[32..36], crc, .big);
        return h;
    }

    /// The sealed segment. Owned by the caller.
    fn bytes(self: *const SegBuilder) ![]u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.alloc);
        const head = self.header();
        try out.appendSlice(self.alloc, &head);
        for (self.sections.items) |s| {
            const off: u64 = out.items.len;
            var hdr: [xfix.SEC_HDR]u8 = undefined;
            hdr[0] = s.tag;
            std.mem.writeInt(i64, hdr[1..9], s.lsn, .big);
            std.mem.writeInt(i64, hdr[9..17], @intCast(s.body.len), .big);

            var hc = Crc32.init();
            @import("../store/wal_segments.zig").crcDomainOf(&hc, &head, off);
            hc.update(hdr[0..xfix.SEC_HDR_CRC_LEN]);
            std.mem.writeInt(u32, hdr[17..21], hc.final(), .big);

            var bc = Crc32.init();
            @import("../store/wal_segments.zig").crcDomainOf(&bc, &head, off);
            bc.update(s.body);
            std.mem.writeInt(u32, hdr[21..25], bc.final(), .big);

            try out.appendSlice(self.alloc, &hdr);
            try out.appendSlice(self.alloc, s.body);
        }
        return out.toOwnedSlice(self.alloc);
    }
};

/// A `T_RECORD` entry. `content == null` is NULL content (`lenPlus == 0`);
/// an empty slice is zero-length content (`lenPlus == 1`).
fn record(alloc: Allocator, recid: u64, cap: u64, content: ?[]const u8) ![]u8 {
    var o = DataOutput2.init(alloc);
    defer o.deinit();
    try o.writeU8(xfix.T_RECORD);
    try o.packLong(recid);
    try o.packLong(cap);
    try o.packLong(if (content) |c| c.len + 1 else 0);
    if (content) |c| try o.writeAll(c);
    return o.copyBytes(alloc);
}

fn tagged(alloc: Allocator, tag: u8, recid: u64) ![]u8 {
    var o = DataOutput2.init(alloc);
    defer o.deinit();
    try o.writeU8(tag);
    try o.packLong(recid);
    return o.copyBytes(alloc);
}

fn markBody(through: i64, log_start: i64) [16]u8 {
    var b: [16]u8 = undefined;
    std.mem.writeInt(i64, b[0..8], through, .big);
    std.mem.writeInt(i64, b[8..16], log_start, .big);
    return b;
}

fn oneSection(alloc: Allocator, tag: u8, body: []const u8) ![]u8 {
    var b = SegBuilder.init(alloc, 1, 1, 0);
    defer b.deinit();
    try b.push(tag, 1, body);
    return b.bytes();
}

/// Decode a segment into a caller-owned `Segment`; the test frees it.
fn decodeInto(ctx: *xfix.Ctx, raw: []const u8, where: []const u8, seg: *xfix.Segment) !void {
    try xfix.decode(ctx, raw, where, seg);
}

// ---------------------------------------------------------------------------
// the constant-field checks
// ---------------------------------------------------------------------------

test "wal3 decode: entries come back in WIRE order, not sorted" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    // Every entry stream in the sample happens to be in ascending recid order,
    // so a decoder that sorted its output would match GOLDEN-BODY.tsv exactly.
    // These recids descend, which no corpus section does.
    const p9 = try xfix.payload(a, 9, 3);
    defer a.free(p9);
    const p2 = try xfix.payload(a, 2, 1);
    defer a.free(p2);
    const e1 = try record(a, 9, 16, p9);
    defer a.free(e1);
    const e2 = try tagged(a, xfix.T_DELETE, 4);
    defer a.free(e2);
    const e3 = try record(a, 2, 16, p2);
    defer a.free(e3);
    const body = try std.mem.concat(a, u8, &.{ e1, e2, e3 });
    defer a.free(body);

    const raw = try oneSection(a, xfix.TAG_SECTION, body);
    defer a.free(raw);
    var seg = xfix.Segment{};
    defer seg.deinit(a);
    try decodeInto(&ctx, raw, "wire-order", &seg);

    var es: std.ArrayListUnmanaged(xfix.Entry) = .empty;
    defer es.deinit(a);
    try xfix.entries(&ctx, &seg.sections.items[0], "wire-order", &es);

    try testing.expectEqual(@as(usize, 3), es.items.len);
    try testing.expectEqual(@as(u64, 9), es.items[0].recid);
    try testing.expectEqual(@as(u64, 4), es.items[1].recid);
    try testing.expectEqual(@as(u64, 2), es.items[2].recid);
    try testing.expectEqualStrings("RECORD", es.items[0].kind());
    try testing.expectEqualStrings("DELETE", es.items[1].kind());
    try testing.expectEqualStrings("RECORD", es.items[2].kind());
}

test "wal3 decode: NULL and zero-length content stay distinct in both columns" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    // `lenPlus == 0` is NULL and `lenPlus == 1` is a zero-length record. A
    // decoder that turned lenPlus into a length would report 0 for both, and two
    // engines that both did it would agree forever.
    const e1 = try record(a, 1, 0, null);
    defer a.free(e1);
    const e2 = try record(a, 2, 16, &.{});
    defer a.free(e2);
    const body = try std.mem.concat(a, u8, &.{ e1, e2 });
    defer a.free(body);

    const raw = try oneSection(a, xfix.TAG_SECTION, body);
    defer a.free(raw);
    var seg = xfix.Segment{};
    defer seg.deinit(a);
    try decodeInto(&ctx, raw, "null-vs-empty", &seg);

    var es: std.ArrayListUnmanaged(xfix.Entry) = .empty;
    defer es.deinit(a);
    try xfix.entries(&ctx, &seg.sections.items[0], "null-vs-empty", &es);

    try testing.expectEqual(@as(?u64, 0), es.items[0].len_plus);
    try testing.expect(es.items[0].content == null);
    try testing.expectEqual(@as(?u64, 0), es.items[0].cap);

    try testing.expectEqual(@as(?u64, 1), es.items[1].len_plus);
    try testing.expect(es.items[1].content != null);
    try testing.expectEqual(@as(usize, 0), es.items[1].content.?.len);
}

test "wal3 decode: the two 'K' mark longs come back in wire order" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    // Both fields are longs in one 16-byte body, so a swap is invisible to every
    // consumer downstream of the decoder. (3, 4) is asymmetric and the segment's
    // own sequence is 7, so the swap is detectable here and only here.
    var b = SegBuilder.init(a, 7, 4, 0);
    defer b.deinit();
    const body = markBody(3, 4);
    try b.push(xfix.TAG_MARK, 4, &body);
    const raw = try b.bytes();
    defer a.free(raw);

    var seg = xfix.Segment{};
    defer seg.deinit(a);
    try decodeInto(&ctx, raw, "mark-order", &seg);
    const m = try xfix.mark(&ctx, &seg.sections.items[0], "mark-order");
    try testing.expectEqual(@as(i64, 3), m.through);
    try testing.expectEqual(@as(i64, 4), m.log_start);
}

test "wal3 decode: every header field is actually read out of the bytes" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    // `flags` is the one the corpus cannot check at all: the writer emits the
    // constant 0, so `flags = 0` hard-coded in a decoder matches every bundle
    // that exists. seq and firstLsn get byte patterns a truncation to 32 bits
    // would make look wrong.
    var b = SegBuilder.init(a, 0x0102_0304_0506_0708, 0x1112_1314_1516_1718, 0x2A);
    defer b.deinit();
    const p = try xfix.payload(a, 1, 2);
    defer a.free(p);
    const e = try record(a, 1, 16, p);
    defer a.free(e);
    try b.push(xfix.TAG_SECTION, 1, e);
    const raw = try b.bytes();
    defer a.free(raw);

    var seg = xfix.Segment{};
    defer seg.deinit(a);
    try decodeInto(&ctx, raw, "header", &seg);
    try testing.expectEqual(xfix.FORMAT_VERSION, seg.header.version);
    try testing.expectEqual(@as(i32, 0x2A), seg.header.flags);
    try testing.expectEqual(@as(i64, 0x0102_0304_0506_0708), seg.header.seq);
    try testing.expectEqual(@as(i64, 0x1112_1314_1516_1718), seg.header.first_lsn);
    try testing.expectEqual(Crc32.hash(raw[0..xfix.SEG_HDR_CRC_LEN]), seg.header.header_crc);
}

// ---------------------------------------------------------------------------
// framing
// ---------------------------------------------------------------------------

test "wal3 decode: section offsets advance, and a section is not relocatable" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    const p1 = try xfix.payload(a, 1, 5);
    defer a.free(p1);
    const p2 = try xfix.payload(a, 2, 40);
    defer a.free(p2);
    const s1 = try record(a, 1, 16, p1);
    defer a.free(s1);
    const s2 = try record(a, 2, 64, p2);
    defer a.free(s2);

    var b = SegBuilder.init(a, 1, 1, 0);
    defer b.deinit();
    try b.push(xfix.TAG_SECTION, 1, s1);
    try b.push(xfix.TAG_SECTION, 2, s2);
    const raw = try b.bytes();
    defer a.free(raw);

    var seg = xfix.Segment{};
    defer seg.deinit(a);
    try decodeInto(&ctx, raw, "offsets", &seg);
    try testing.expectEqual(@as(usize, 2), seg.sections.items.len);
    try testing.expectEqual(xfix.SEG_HDR, seg.sections.items[0].offset);
    try testing.expectEqual(xfix.SEG_HDR + xfix.SEC_HDR + s1.len, seg.sections.items[1].offset);
    try testing.expectEqual(@as(usize, 0), seg.sections.items[0].index);
    try testing.expectEqual(@as(usize, 1), seg.sections.items[1].index);
    try testing.expectEqual(@as(usize, 0), seg.trailing);

    // The same section bytes at a different offset must fail: the offset is in
    // the CRC domain, which is what makes a section un-relocatable. Sixteen
    // filler bytes are spliced in ahead of the second section, moving it.
    const cut = seg.sections.items[1].offset;
    const moved = try std.mem.concat(a, u8, &.{ raw[0..cut], &[_]u8{0} ** 16, raw[cut..] });
    defer a.free(moved);
    var seg2 = xfix.Segment{};
    defer seg2.deinit(a);
    try xfix.expectRefused(&ctx, "a section whose bytes were moved to another offset", decodeInto, .{ &ctx, moved, "moved", &seg2 });
}

test "wal3 decode: each header check is refused on an input only IT rejects" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    const p = try xfix.payload(a, 1, 9);
    defer a.free(p);
    const entry = try record(a, 1, 16, p);
    defer a.free(entry);

    // the control: identical in every respect but the one field each case moves.
    {
        var b = SegBuilder.init(a, 1, 1, 0);
        defer b.deinit();
        try b.push(xfix.TAG_SECTION, 1, entry);
        const raw = try b.bytes();
        defer a.free(raw);
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try decodeInto(&ctx, raw, "control", &seg);
    }

    // (a) bad magic, everything else sealed around it.
    {
        var b = SegBuilder.init(a, 1, 1, 0);
        defer b.deinit();
        b.magic = "MDBS.XXX".*;
        try b.push(xfix.TAG_SECTION, 1, entry);
        const raw = try b.bytes();
        defer a.free(raw);
        // The isolation is the point, so it is asserted rather than assumed: a
        // poked magic byte would break this CRC and be refused by it instead.
        try testing.expectEqual(
            Crc32.hash(raw[0..xfix.SEG_HDR_CRC_LEN]),
            std.mem.readInt(u32, raw[32..36], .big),
        );
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try xfix.expectRefused(&ctx, "bad magic, with every CRC valid", decodeInto, .{ &ctx, raw, "bad-magic", &seg });
    }

    // (b) a future format version, everything else sealed around it.
    {
        var b = SegBuilder.init(a, 1, 1, 0);
        defer b.deinit();
        b.version = xfix.FORMAT_VERSION + 1;
        try b.push(xfix.TAG_SECTION, 1, entry);
        const raw = try b.bytes();
        defer a.free(raw);
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try xfix.expectRefused(&ctx, "a future format version, with every CRC valid", decodeInto, .{ &ctx, raw, "future-version", &seg });
    }

    // (c) a wrong header CRC — and the sections resealed against the header bytes
    // that carry it, so the section CRCs are valid and only the header check can
    // fire.
    {
        var b = SegBuilder.init(a, 1, 1, 0);
        defer b.deinit();
        b.header_crc = 0xDEAD_BEEF;
        try b.push(xfix.TAG_SECTION, 1, entry);
        const raw = try b.bytes();
        defer a.free(raw);
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try xfix.expectRefused(&ctx, "a wrong header CRC, with valid section CRCs", decodeInto, .{ &ctx, raw, "bad-header-crc", &seg });
    }

    // (d) an unknown section tag, with its own section-header CRC recomputed over
    // the new tag. Poking the tag byte alone would break that CRC.
    {
        var b = SegBuilder.init(a, 1, 1, 0);
        defer b.deinit();
        try b.push('Z', 1, entry);
        const raw = try b.bytes();
        defer a.free(raw);
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try xfix.expectRefused(&ctx, "an unknown section tag, correctly sealed", decodeInto, .{ &ctx, raw, "bad-tag", &seg });
    }

    // (e) a 'K' body that is not 16 bytes, correctly sealed.
    {
        var b = SegBuilder.init(a, 7, 4, 0);
        defer b.deinit();
        try b.push(xfix.TAG_MARK, 4, &[_]u8{0} ** 8);
        const raw = try b.bytes();
        defer a.free(raw);
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try xfix.expectRefused(&ctx, "a 'K' section whose body is not 16 bytes", decodeInto, .{ &ctx, raw, "short-mark", &seg });
    }

    // (f) shorter than a segment header at all.
    {
        var b = SegBuilder.init(a, 1, 1, 0);
        defer b.deinit();
        try b.push(xfix.TAG_SECTION, 1, entry);
        const raw = try b.bytes();
        defer a.free(raw);
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try xfix.expectRefused(&ctx, "a file shorter than a segment header", decodeInto, .{ &ctx, raw[0 .. xfix.SEG_HDR - 1], "short", &seg });
    }
}

test "wal3 decode: the two section CRCs are checked" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    // These two ARE isolated by byte-poking, and that is not an accident: each
    // stored CRC field sits OUTSIDE its own domain (the section-header CRC covers
    // bytes 0..17 of the header, the body CRC covers the body), so overwriting one
    // invalidates that check and no other.
    const p = try xfix.payload(a, 1, 9);
    defer a.free(p);
    const entry = try record(a, 1, 16, p);
    defer a.free(entry);
    var b = SegBuilder.init(a, 1, 1, 0);
    defer b.deinit();
    try b.push(xfix.TAG_SECTION, 1, entry);
    const good = try b.bytes();
    defer a.free(good);

    const cases = [_]struct { what: []const u8, at: usize }{
        .{ .what = "a wrong section-header CRC", .at = xfix.SEG_HDR + 17 },
        .{ .what = "a wrong section-body CRC", .at = xfix.SEG_HDR + 21 },
        .{ .what = "a flipped content byte", .at = good.len - 1 },
    };
    for (cases) |c| {
        const raw = try a.dupe(u8, good);
        defer a.free(raw);
        raw[c.at] ^= 0xFF;
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try xfix.expectRefused(&ctx, c.what, decodeInto, .{ &ctx, raw, "damaged", &seg });
    }
}

test "wal3 decode: an INCOMPLETE FINAL SECTION is reported, not refused" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    // **This is not the engine's torn-tail policy, and the name says so on
    // purpose.** `wal_recover` decides tornness with context this decoder does
    // not have: it also treats a damaged final section header or body CRC as a
    // torn active tail when no valid later section proves mid-log corruption, and
    // it treats an overrunning body BELOW the highest segment as corruption
    // rather than tornness. This helper has no segment-position context and
    // refuses on any CRC failure, so the two disagree in both directions on
    // inputs the published fixtures do not contain. That is a deliberate scope
    // choice for a comparison-only decoder — every pinned file is required to
    // have `trailing == 0` and is separately opened by the real engine.
    //
    // What IS covered: the two shapes where framing simply runs out.
    const p1 = try xfix.payload(a, 1, 9);
    defer a.free(p1);
    const p2 = try xfix.payload(a, 2, 9);
    defer a.free(p2);
    const s1 = try record(a, 1, 16, p1);
    defer a.free(s1);
    const s2 = try record(a, 2, 16, p2);
    defer a.free(s2);

    var b = SegBuilder.init(a, 1, 1, 0);
    defer b.deinit();
    try b.push(xfix.TAG_SECTION, 1, s1);
    try b.push(xfix.TAG_SECTION, 2, s2);
    const raw = try b.bytes();
    defer a.free(raw);

    // (a) a body that is not all there
    {
        const torn = raw[0 .. raw.len - 4];
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try decodeInto(&ctx, torn, "torn-body", &seg);
        try testing.expectEqual(@as(usize, 1), seg.sections.items.len);
        const consumed = seg.sections.items[0].offset + xfix.SEC_HDR + @as(usize, @intCast(seg.sections.items[0].body_len));
        try testing.expectEqual(torn.len - consumed, seg.trailing);
        try testing.expect(seg.trailing > 0);
    }
    // (b) not even a whole section header
    {
        const torn = raw[0 .. raw.len - 30];
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try decodeInto(&ctx, torn, "torn-header", &seg);
        try testing.expectEqual(@as(usize, 1), seg.sections.items.len);
        try testing.expect(seg.trailing > 0 and seg.trailing < xfix.SEC_HDR);
    }
}

// ---------------------------------------------------------------------------
// entry streams
// ---------------------------------------------------------------------------

fn decodeEntries(ctx: *xfix.Ctx, raw: []const u8, where: []const u8) xfix.Error!void {
    var seg = xfix.Segment{};
    defer seg.deinit(ctx.alloc);
    try xfix.decode(ctx, raw, where, &seg);
    var es: std.ArrayListUnmanaged(xfix.Entry) = .empty;
    defer es.deinit(ctx.alloc);
    try xfix.entries(ctx, &seg.sections.items[0], where, &es);
}

fn decodeCompleteInto(ctx: *xfix.Ctx, raw: []const u8, where: []const u8, seg: *xfix.Segment) !void {
    try xfix.decodeComplete(ctx, raw, where, seg);
}

// A PINNED file must be framed to its last byte, and the corpus cannot say so.
//
// `decode` reports a torn tail rather than refusing it, and the rule that every
// pinned file has `trailing == 0` therefore lives in `decodeComplete`. No sample
// bundle has a torn tail, so deleting that rule left the whole suite green — the
// C3z campaign measured it. Lesson (g): the input has to be built.
test "wal3 decode: a pinned segment must be framed to its last byte" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    const p = try xfix.payload(a, 1, 9);
    defer a.free(p);
    const entry = try record(a, 1, 16, p);
    defer a.free(entry);
    var b = SegBuilder.init(a, 1, 1, 0);
    defer b.deinit();
    try b.push(xfix.TAG_SECTION, 1, entry);
    const raw = try b.bytes();
    defer a.free(raw);

    {
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try decodeCompleteInto(&ctx, raw, "whole", &seg);
        try testing.expectEqual(@as(usize, 0), seg.trailing);
    }
    // One byte of junk after the last section: `decode` REPORTS it...
    {
        const with_junk = try std.mem.concat(a, u8, &.{ raw, &[_]u8{0x7f} });
        defer a.free(with_junk);
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try decodeInto(&ctx, with_junk, "junk", &seg);
        try testing.expectEqual(@as(usize, 1), seg.trailing);
    }
    // ...and the pinned-file rule REFUSES it. The two halves are separate on
    // purpose: reporting is the decoder's job, refusing is this slice's policy.
    {
        const with_junk = try std.mem.concat(a, u8, &.{ raw, &[_]u8{0x7f} });
        defer a.free(with_junk);
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try xfix.expectRefused(&ctx, "a pinned segment with bytes after its last section", decodeCompleteInto, .{ &ctx, with_junk, "junk", &seg });
    }
}

// The recid cross-check is ONE-WAY, and it fires.
//
// Every recid the manifest names must be witnessed in the decoded history, never
// the reverse. Plan §5 forbids the reverse — a rolled-back put need only be
// invisible through the API, and `wal3-java-tail` already carries recids beyond
// the six §5.2 describes — so set equality would be a violation waiting for the
// first legal fixture. Both halves are asserted: the surplus direction must be
// TOLERATED, the missing direction REFUSED. Without this the whole rule could be
// made vacuous with the suite still green, because the engine-level recid
// assertions never look at the decoded entry stream.
test "wal3 decode: the recid cross-check is one-way and can fail" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    const text = "version\t2\nfixture\tf\twal3-namespace\tjava\tc\n" ++
        "file\tf\tx.wal.0000000000000001\t36" ++ SHAS ++ "\n" ++
        "recid\tf\tr1\t1\tlive\t1\t8\n" ++
        "recid\tf\tr2\t2\tnull\t0\t0\n";
    var loaded = try xfix.parse(&ctx, text);
    defer loaded.deinit(a);
    const m = &loaded.v2;

    // exactly the named recids, and a superset: both fine.
    try xfix.checkRecidsAgainstManifest(&ctx, m, "f", &.{ 1, 2 });
    try xfix.checkRecidsAgainstManifest(&ctx, m, "f", &.{ 1, 2, 7, 99 });

    const cases = [_]struct { seen: []const u64, what: []const u8 }{
        .{ .seen = &.{1}, .what = "a decode that never mentions recid 2" },
        .{ .seen = &.{}, .what = "a decode that mentions no recid at all" },
        .{ .seen = &.{ 3, 4 }, .what = "a decode whose recids are all shifted" },
    };
    for (cases) |c| {
        try xfix.expectRefused(&ctx, c.what, xfix.checkRecidsAgainstManifest, .{ &ctx, m, "f", c.seen });
    }
    try xfix.expectRefused(&ctx, "a fixture with no recid rows to check against", xfix.checkRecidsAgainstManifest, .{ &ctx, m, "nonexistent", @as([]const u64, &.{}) });
}

// The four entry opcodes, pinned as LITERALS — the one place this suite does not
// borrow from the engine.
//
// Borrowing is strong where the pinned corpus exercises the borrowed thing: a
// wrong CRC domain or a wrong varint reader disagrees with python's or java's
// file. It is weak where the corpus exercises NOTHING. `T_APPEND` is that case —
// no golden row contains one, `entries` refuses it before decoding its remaining
// fields, and the builder here encodes it with the same imported constant the
// decoder compares against, so the two would drift together in silence. Rust
// catches this class with its transcription-equality test; this is the zig
// equivalent, narrowed to the values that need it.
test "wal3 decode: the entry opcodes are pinned, not just borrowed" {
    try testing.expectEqual(@as(u8, 1), xfix.T_PREALLOC);
    try testing.expectEqual(@as(u8, 2), xfix.T_RECORD);
    try testing.expectEqual(@as(u8, 3), xfix.T_APPEND);
    try testing.expectEqual(@as(u8, 4), xfix.T_DELETE);
    // ...and the section tags, which the golden files DO pin as characters, so
    // these are belt and braces rather than the only witness.
    try testing.expectEqual(@as(u8, 'S'), xfix.TAG_SECTION);
    try testing.expectEqual(@as(u8, 'C'), xfix.TAG_IMAGE);
    try testing.expectEqual(@as(u8, 'K'), xfix.TAG_MARK);
}

// The entry-shape rules are reachable, which inside `contentSha` they were not.
//
// `entries` slices exactly `lenPlus - 1` content bytes and sets `cap` only for
// records, so every entry it produces satisfies these rules by construction: the
// C3z review deleted the NULL-cap rule and the whole suite stayed green. A rule
// that only ever sees values built to satisfy it is not a check. These entries
// are hand-built to violate one rule each.
test "wal3 decode: the entry-shape witness rejects entries the writer never wrote" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    const p = try xfix.payload(a, 7, 8);
    defer a.free(p);

    // the shapes a conforming writer does produce
    try xfix.checkEntryShape(&ctx, .{ .tag = xfix.T_RECORD, .recid = 1, .cap = 0, .len_plus = 0 }, "a NULL record");
    try xfix.checkEntryShape(&ctx, .{ .tag = xfix.T_RECORD, .recid = 1, .cap = 16, .len_plus = 1, .content = &.{} }, "a zero-length record");
    try xfix.checkEntryShape(&ctx, .{ .tag = xfix.T_RECORD, .recid = 1, .cap = 16, .len_plus = 9, .content = p }, "an ordinary record");
    try xfix.checkEntryShape(&ctx, .{ .tag = xfix.T_PREALLOC, .recid = 1 }, "a prealloc");
    try xfix.checkEntryShape(&ctx, .{ .tag = xfix.T_DELETE, .recid = 1 }, "a delete");

    const cases = [_]struct { e: xfix.Entry, what: []const u8 }{
        .{
            .e = .{ .tag = xfix.T_RECORD, .recid = 1, .cap = 16, .len_plus = 0 },
            .what = "a NULL record with a nonzero capacity",
        },
        .{
            .e = .{ .tag = xfix.T_RECORD, .recid = 1, .cap = 0, .len_plus = 0, .content = &.{} },
            .what = "a NULL record carrying content",
        },
        .{
            .e = .{ .tag = xfix.T_PREALLOC, .recid = 1, .content = &.{} },
            .what = "a prealloc carrying content",
        },
        .{
            .e = .{ .tag = xfix.T_RECORD, .recid = 1, .cap = 16, .len_plus = 9 },
            .what = "a sized record with no content",
        },
        .{
            .e = .{ .tag = xfix.T_RECORD, .recid = 1, .cap = 16, .len_plus = 5, .content = p },
            .what = "a content length that disagrees with lenPlus",
        },
        .{
            .e = .{ .tag = xfix.T_RECORD, .recid = 1, .cap = 15, .len_plus = 9, .content = p },
            .what = "a capacity that is not 16-aligned",
        },
    };
    for (cases) |c| {
        try xfix.expectRefused(&ctx, c.what, xfix.checkEntryShape, .{ &ctx, c.e, c.what });
    }
}

// The exact-cell-set rule fires in both directions.
//
// The sample declares three fixtures and runs three cells, so the rule never
// fires on the real corpus and deleting it was invisible — measured, not
// assumed. Its whole purpose is the case the corpus cannot contain: an `expect`
// row deleted while its `fixture` row stays.
test "wal3 decode: the exact-cell-set rule fires in both directions" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    const declared = [_]xfix.FixtureRow{
        .{ .id = "a", .kind = "wal3-namespace" },
        .{ .id = "b", .kind = "wal3-namespace" },
    };
    try xfix.assertCellSetExact(&ctx, &declared, &.{ "a", "b" }, "rw");
    try xfix.expectRefused(&ctx, "a declared fixture with no cell", xfix.assertCellSetExact, .{ &ctx, @as([]const xfix.FixtureRow, &declared), @as([]const []const u8, &.{"a"}), "rw" });
    try xfix.expectRefused(&ctx, "a cell for a fixture nothing declares", xfix.assertCellSetExact, .{ &ctx, @as([]const xfix.FixtureRow, &declared), @as([]const []const u8, &.{ "a", "b", "c" }), "rw" });
}

test "wal3 decode: a malformed entry stream is refused, not truncated" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    const p = try xfix.payload(a, 1, 40);
    defer a.free(p);
    const full = try record(a, 1, 64, p);
    defer a.free(full);

    for ([_]usize{ 1, 2, 4, full.len - 1 }) |cut| {
        const raw = try oneSection(a, xfix.TAG_SECTION, full[0..cut]);
        defer a.free(raw);
        var buf: [64]u8 = undefined;
        const what = try std.fmt.bufPrint(&buf, "an entry stream cut to {d} bytes", .{cut});
        try xfix.expectRefused(&ctx, what, decodeEntries, .{ &ctx, raw, "cut" });
    }

    {
        const e = try tagged(a, 9, 1);
        defer a.free(e);
        const raw = try oneSection(a, xfix.TAG_SECTION, e);
        defer a.free(raw);
        try xfix.expectRefused(&ctx, "an unknown entry tag", decodeEntries, .{ &ctx, raw, "unknown-tag" });
    }

    // T_APPEND is a real engine op that no fixture exercises and the body dump
    // has no columns for. Refusing by name is the honest answer: decoding it into
    // a row shape that was never designed would be a silent guess.
    {
        const e = try tagged(a, xfix.T_APPEND, 1);
        defer a.free(e);
        const raw = try oneSection(a, xfix.TAG_SECTION, e);
        defer a.free(raw);
        try xfix.expectRefused(&ctx, "a T_APPEND entry", decodeEntries, .{ &ctx, raw, "append" });
    }

    // A 'K' body is a mark, not an entry stream, and must not be decoded as one.
    {
        var b = SegBuilder.init(a, 7, 4, 0);
        defer b.deinit();
        const body = markBody(3, 4);
        try b.push(xfix.TAG_MARK, 4, &body);
        const raw = try b.bytes();
        defer a.free(raw);
        try xfix.expectRefused(&ctx, "a 'K' body read as an entry stream", decodeEntries, .{ &ctx, raw, "k-as-entries" });
    }
}

test "wal3 decode: 'C' sections carry an ordinary entry stream" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    // The two tags differ in what recovery DOES with the section, not in how a
    // body is framed (StoreWAL.java:850), so a decoder that special-cased 'C'
    // would silently drop the cleaner image — which is the entire content of the
    // wal3-java-cleaned bundle.
    const p = try xfix.payload(a, 1, 4);
    defer a.free(p);
    const e1 = try record(a, 1, 16, p);
    defer a.free(e1);
    const e2 = try tagged(a, xfix.T_PREALLOC, 3);
    defer a.free(e2);
    const body = try std.mem.concat(a, u8, &.{ e1, e2 });
    defer a.free(body);

    var out: [2]std.ArrayListUnmanaged(xfix.Entry) = .{ .empty, .empty };
    defer for (&out) |*o| o.deinit(a);
    for ([_]u8{ xfix.TAG_SECTION, xfix.TAG_IMAGE }, 0..) |tag, i| {
        const raw = try oneSection(a, tag, body);
        defer a.free(raw);
        var seg = xfix.Segment{};
        defer seg.deinit(a);
        try decodeInto(&ctx, raw, "s-vs-c", &seg);
        try xfix.entries(&ctx, &seg.sections.items[0], "s-vs-c", &out[i]);
    }
    try testing.expectEqual(out[0].items.len, out[1].items.len);
    for (out[0].items, out[1].items) |x, y| {
        try testing.expectEqual(x.tag, y.tag);
        try testing.expectEqual(x.recid, y.recid);
        try testing.expectEqual(x.cap, y.cap);
        try testing.expectEqual(x.len_plus, y.len_plus);
    }
}

// ---------------------------------------------------------------------------
// the independent witnesses
// ---------------------------------------------------------------------------

test "wal3 decode: the cap witness accepts only real capacities" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    // The plain-record ceiling, restated so the boundary cases below read as
    // boundaries. It is IMPORTED from the engine, so this is a pin on the
    // engine's constant rather than a second copy of it.
    const MAX = xfix.MAX_CAPACITY;
    try testing.expectEqual(@as(u64, 1_048_528), MAX);

    try xfix.checkCap(&ctx, 16, 0, "the smallest plain capacity");
    try xfix.checkCap(&ctx, 128, 121, "4 + 121 = 125, rounded up to 128");
    try xfix.checkCap(&ctx, MAX, MAX - 4, "the largest plain record");
    // cap 0 means the content was too big for a plain record and went linked. The
    // smallest length for which that is true is the one where 4 + len first
    // exceeds the ceiling.
    try xfix.checkCap(&ctx, 0, MAX - 3, "the smallest genuinely oversize record");

    const cases = [_]struct { cap: u64, len: usize, what: []const u8 }{
        // The case that made rust's witness weaker than the engine: cap 0 claims
        // the content was stored linked, but 1_000_004 fits a plain record, so
        // recovery rejects precisely what an unconditional accept blesses.
        .{ .cap = 0, .len = 1_000_000, .what = "a zero cap on content that fits a plain record" },
        .{ .cap = 0, .len = MAX - 4, .what = "a zero cap on content that exactly fills the ceiling" },
        .{ .cap = MAX + 16, .len = 0, .what = "a capacity above the plain-record ceiling" },
        .{ .cap = 127, .len = 121, .what = "a capacity that is not 16-aligned" },
        .{ .cap = 112, .len = 121, .what = "a 16-aligned capacity with no room for the content" },
        .{ .cap = 128, .len = 125, .what = "a 16-aligned capacity with no room for the 4-byte header" },
    };
    for (cases) |c| {
        try xfix.expectRefused(&ctx, c.what, xfix.checkCap, .{ &ctx, c.cap, c.len, c.what });
    }
    // rust's witness also has a negative-capacity case; this port has no
    // counterpart, and that is a property of the encoding rather than a gap:
    // `cap` arrives from `unpackLong`, whose domain is u64.
}

// The NAME says language, not corpus, and that is all the inputs support: the
// witness consults no fixture history. The inherited wording claimed corpus
// membership, which is this workstream's recurring defect; the C3z review caught
// it surviving the port.
test "wal3 decode: the payload witness rejects bytes outside the payload language" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    // It is a language-membership test, not a corpus-membership test: it accepts
    // any (id, len) pair without consulting a fixture's history, so it proves
    // these bytes are *a* payload, not that this bundle issued *this* payload.
    // What it is for is the one thing nothing else here reaches — the engine's
    // replay never shows content bytes to the suite, and the golden sha column
    // grades them against a file another engine wrote.
    const p0 = try xfix.payload(a, 0, 32);
    defer a.free(p0);
    try xfix.checkPayload(&ctx, p0, "id 0");
    const p255 = try xfix.payload(a, 255, 700);
    defer a.free(p255);
    try xfix.checkPayload(&ctx, p255, "the largest id");
    try xfix.checkPayload(&ctx, &.{}, "zero-length content carries no id");

    {
        const c = try xfix.payload(a, 103, 120);
        defer a.free(c);
        c[7] ^= 0x01;
        try xfix.expectRefused(&ctx, "a single corrupted content byte", xfix.checkPayload, .{ &ctx, c, "corrupted" });
    }
    {
        // The shape a mis-framed entry stream actually produces: a run that begins
        // on the entry's varint bytes and only then reaches the payload.
        const p = try xfix.payload(a, 103, 20);
        defer a.free(p);
        const framed = try std.mem.concat(a, u8, &.{ &[_]u8{ 0x81, 0x90, 0x02 }, p });
        defer a.free(framed);
        try xfix.expectRefused(&ctx, "content read starting on an entry's varint bytes", xfix.checkPayload, .{ &ctx, framed, "framed" });
    }
    {
        // ...and a run that spans the boundary between two records' payloads.
        const x = try xfix.payload(a, 50, 10);
        defer a.free(x);
        const y = try xfix.payload(a, 60, 10);
        defer a.free(y);
        const spliced = try std.mem.concat(a, u8, &.{ x, y });
        defer a.free(spliced);
        try xfix.expectRefused(&ctx, "content spanning two records' payloads", xfix.checkPayload, .{ &ctx, spliced, "spliced" });
    }

    // WHAT THIS WITNESS DOES NOT CATCH, measured rather than assumed. `payload` is
    // an arithmetic progression in i, so EVERY suffix of a payload is itself a
    // payload under a different id: payload(id, n)[k..] == payload((id + 131k) &
    // 0xff, n - k). A decode shifted by k bytes WITHIN one record's content is
    // therefore invisible here — it is caught instead by the lenPlus length check
    // next to the call, and by the sha column of GOLDEN-BODY.tsv. This is a
    // property of the corpus's payload function, so it is the same in all three
    // ports; stating it is cheaper than each of them rediscovering it.
    {
        const k: usize = 3;
        const whole = try xfix.payload(a, 103, 120);
        defer a.free(whole);
        const shifted = try xfix.payload(a, (103 + 131 * k) & 0xff, 120 - k);
        defer a.free(shifted);
        try testing.expectEqualSlices(u8, whole[k..], shifted);
    }
}

test "wal3 decode: the mark witness enforces S8 and K4" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    // Both fields are longs, so the decoder cannot tell a swap from a legal pair
    // on its own. These are the engine's own S8/K4 rules restated over what the
    // dump can see, and they are what makes the wire-order test more than a
    // tautology on the real corpus: the sample's (2, 9) in segment 4 becomes
    // (9, 2) under a swap, and K4 rejects it.
    try xfix.checkMark(&ctx, .{ .through = 2, .log_start = 9 }, 4, 10, "the sample's own mark");

    const cases = [_]struct { m: xfix.Mark, seq: i64, lsn: i64, what: []const u8 }{
        .{ .m = .{ .through = 9, .log_start = 2 }, .seq = 4, .lsn = 10, .what = "the sample's mark with its two longs swapped" },
        .{ .m = .{ .through = 0, .log_start = 9 }, .seq = 4, .lsn = 10, .what = "a cleanedThroughSeq of zero" },
        .{ .m = .{ .through = 4, .log_start = 9 }, .seq = 4, .lsn = 10, .what = "a mark authorizing the removal of its own segment (K4)" },
        .{ .m = .{ .through = 5, .log_start = 9 }, .seq = 4, .lsn = 10, .what = "a mark authorizing the removal of a later segment (K4)" },
        .{ .m = .{ .through = 2, .log_start = 0 }, .seq = 4, .lsn = 10, .what = "a logStartLsn of zero (S8)" },
        .{ .m = .{ .through = 2, .log_start = 11 }, .seq = 4, .lsn = 10, .what = "a logStartLsn beyond the mark's own LSN (S8)" },
    };
    for (cases) |c| {
        try xfix.expectRefused(&ctx, c.what, xfix.checkMark, .{ &ctx, c.m, c.seq, c.lsn, c.what });
    }
}
