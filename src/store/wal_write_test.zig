//! Tests for the WAL v3 section writer (slice B2, `wal_write.zig`).
//!
//! The writer is tested against the READER wherever it can be: a section this
//! module wrote and `wal_recover` read back proves the two agree about the format
//! in a way that neither module's own suite can. The rest — W3's rollover
//! condition, the force flavours, the order the operations happen in — leaves no
//! trace in the resulting bytes, and is observed through the `wal_io` seam.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const DbError = @import("../errors.zig").DbError;
const direct = @import("direct.zig");
const StoreDirect = direct.StoreDirect;
const ws = @import("wal_segments.zig");
const WalSegmentSet = ws.WalSegmentSet;
const SEG_HDR = ws.SEG_HDR;
const wal_io = @import("wal_io.zig");
const WalIo = wal_io.WalIo;
const WalOpKind = wal_io.WalOpKind;
const RecordingIo = wal_io.RecordingIo;
const wr = @import("wal_recover.zig");
const SEC_HDR = wr.SEC_HDR;
const TAG_SECTION = wr.TAG_SECTION;
const TAG_IMAGE = wr.TAG_IMAGE;
const TAG_MARK = wr.TAG_MARK;
const Diag = wr.Diag;
const io_mod = @import("../io.zig");
const DataOutput2 = io_mod.DataOutput2;
const ww = @import("wal_write.zig");
const appendSection = ww.appendSection;
const BodySink = ww.BodySink;
/// B1's one-shot, alloc-only failing allocator — shared rather than re-derived,
/// so this suite inherits its rule that refusing a growing resize/remap is not
/// an allocation failure.
const FailingAllocator = @import("wal_recover_test.zig").FailingAllocator;

const BUF: usize = 1 << 20;
/// A segment that can hold a header and one section header, and nothing more —
/// the floor B2's config surface enforces. Every rollover test uses it so a
/// single small section is already "past" the size.
const TINY: u64 = SEG_HDR + SEC_HDR;

// ------------------------------------------------------------------ test kit

var scratch_n: std.atomic.Value(u64) = .init(0);

const Scratch = struct {
    alloc: Allocator,
    dir: []u8,
    base: []u8,

    fn init(alloc: Allocator, tag: []const u8) !Scratch {
        const n = scratch_n.fetchAdd(1, .monotonic);
        const dir = try std.fmt.allocPrint(
            alloc,
            "/tmp/mapdb5_walwrite_{d}_{s}_{d}",
            .{ std.os.linux.getpid(), tag, n },
        );
        errdefer alloc.free(dir);
        std.fs.cwd().deleteTree(dir) catch {};
        try std.fs.cwd().makePath(dir);
        const base = try std.fmt.allocPrint(alloc, "{s}/store.db", .{dir});
        return .{ .alloc = alloc, .dir = dir, .base = base };
    }

    fn deinit(self: *Scratch) void {
        std.fs.cwd().deleteTree(self.dir) catch {};
        self.alloc.free(self.base);
        self.alloc.free(self.dir);
    }
};

const T_RECORD: u8 = 2;
const T_DELETE: u8 = 4;

/// A section body carrying real entries. An `'S'` body is NOT opaque: pass 2
/// hands it to the entry decoder, so a round-trip through recovery only proves
/// anything if the bytes are ones the decoder accepts. Owned; caller frees.
fn deleteBody(alloc: Allocator, recid: u64) ![]u8 {
    var out = DataOutput2.init(alloc);
    errdefer out.deinit();
    try out.writeU8(T_DELETE);
    try out.packLong(recid);
    return out.toOwnedSlice();
}

/// A `T_RECORD` entry with `content`, at the capacity a conforming writer records.
fn recordBody(alloc: Allocator, recid: u64, content: []const u8) ![]u8 {
    var out = DataOutput2.init(alloc);
    errdefer out.deinit();
    try out.writeU8(T_RECORD);
    try out.packLong(recid);
    const need: u64 = 4 + @as(u64, content.len);
    try out.packLong(((need + 15) / 16) * 16);
    try out.packLong(@as(u64, content.len) + 1);
    try out.writeAll(content);
    return out.toOwnedSlice();
}

/// The bytes one section's body carries, emitted from a fixed slice. Deterministic
/// by construction, which is what `appendSection` requires of every real caller.
const Fixed = struct {
    body: []const u8,
    /// Chunks the emitter splits its body into, to exercise the sink's coalescing
    /// and its bypass. 0 = one write.
    chunk: usize = 0,
    /// Incremented per emit call, so a test can see that BOTH passes ran.
    calls: *usize,

    fn emit(self: *const Fixed, sink: *BodySink) DbError!void {
        self.calls.* += 1;
        if (self.chunk == 0) return sink.write(self.body);
        var i: usize = 0;
        while (i < self.body.len) : (i += self.chunk) {
            const end = @min(i + self.chunk, self.body.len);
            try sink.write(self.body[i..end]);
        }
    }
};

fn emitFixed(ctx: *const Fixed, sink: *BodySink) DbError!void {
    return ctx.emit(sink);
}

/// An emitter that writes MORE bytes on its second pass — four then five, the
/// genuine length divergence (rust's test emits an extra fifth byte the same
/// way). Both halves of the check can see this one; the half that ONLY the
/// length comparison can see is `ResidueDrift` below.
const Drifting = struct {
    calls: usize = 0,

    fn emit(self: *Drifting, sink: *BodySink) DbError!void {
        self.calls += 1;
        if (self.calls == 1) return sink.write("aaaa");
        return sink.write("aaaab");
    }
};

fn emitDrifting(ctx: *Drifting, sink: *BodySink) DbError!void {
    return ctx.emit(sink);
}

/// An emitter whose passes differ in LENGTH but agree in CRC, so only the length
/// operand of the divergence check can refuse it. Each pass ends by emitting the
/// little-endian FINALIZED running CRC: for this CRC (reflected, init and xorout
/// both all-ones) that drives any stream's final value to the fixed residue
/// constant, whatever came before — so both passes finalize identically while
/// one is two bytes longer. The finals are recorded so the test can prove the
/// collision happened rather than assume it.
const ResidueDrift = struct {
    calls: usize = 0,
    finals: [2]u32 = .{ 0, 1 },

    fn emit(self: *ResidueDrift, sink: *BodySink) DbError!void {
        self.calls += 1;
        const body: []const u8 = if (self.calls == 1) "aaaa" else "aaaabb";
        try sink.write(body);
        var c = sink.crc;
        var le: [4]u8 = undefined;
        std.mem.writeInt(u32, &le, c.final(), .little);
        try sink.write(&le);
        var f = sink.crc;
        if (self.calls <= 2) self.finals[self.calls - 1] = f.final();
    }
};

fn emitResidue(ctx: *ResidueDrift, sink: *BodySink) DbError!void {
    return ctx.emit(sink);
}

/// An emitter whose second pass produces the same LENGTH but different BYTES, so
/// only the CRC half of the divergence check can catch it.
const SameLength = struct {
    calls: usize = 0,

    fn emit(self: *SameLength, sink: *BodySink) DbError!void {
        self.calls += 1;
        if (self.calls == 1) return sink.write("aaaa");
        return sink.write("aaab");
    }
};

fn emitSameLength(ctx: *SameLength, sink: *BodySink) DbError!void {
    return ctx.emit(sink);
}

/// Opens a namespace with a fresh segment 1, as recovery would leave it.
const Fixture = struct {
    alloc: Allocator,
    set: WalSegmentSet,
    calls: usize = 0,

    fn init(alloc: Allocator, sc: *const Scratch, io: ?*const WalIo) !Fixture {
        var set = try WalSegmentSet.openWithIo(alloc, sc.base, false, io, null);
        errdefer set.deinit();
        _ = try set.createSegment(1);
        return .{ .alloc = alloc, .set = set };
    }

    fn deinit(self: *Fixture) void {
        self.set.deinit();
    }

    /// Appends one `'S'` section carrying `body`.
    fn append(self: *Fixture, segment_bytes: u64, lsn: i64, body: []const u8, chunk: usize) DbError!void {
        const ctx = Fixed{ .body = body, .chunk = chunk, .calls = &self.calls };
        return appendSection(
            &self.set,
            segment_bytes,
            self.set.io,
            TAG_SECTION,
            lsn,
            self.alloc,
            &ctx,
            emitFixed,
        );
    }

    fn seqs(self: *Fixture, alloc: Allocator) ![]i64 {
        const segs = self.set.segmentsSlice();
        const out = try alloc.alloc(i64, segs.len);
        for (segs, 0..) |s, i| out[i] = s.seq;
        return out;
    }
};

/// Re-reads the whole namespace through recovery and returns the recovered
/// `next_lsn`, proving the writer's bytes are ones the reader accepts.
fn recoverBack(alloc: Allocator, sc: *const Scratch) DbError!struct { next_lsn: i64, seqs: usize } {
    var set = try WalSegmentSet.open(alloc, sc.base, false);
    defer set.deinit();
    var inner = try StoreDirect.init(alloc, true);
    defer inner.deinit();
    var diag: Diag = .{};
    var rec = try wr.recover(&set, &inner, BUF, alloc, &diag);
    defer rec.deinit(alloc);
    return .{ .next_lsn = rec.next_lsn, .seqs = set.segmentsSlice().len };
}

// ------------------------------------------------------------------- the round trip

test "wal3 B2: a section this writer emits is one the reader accepts" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "roundtrip");
    defer sc.deinit();
    {
        var f = try Fixture.init(a, &sc, null);
        defer f.deinit();
        // Real entries, not opaque bytes: an `'S'` body is handed to the entry
        // decoder in pass 2, so a body that is not a valid entry framing proves
        // only that recovery refuses it. This is the assertion that the framing,
        // the domain-bound CRCs, the offsets AND the entry encoding are all ones
        // the reader accepts.
        const b1 = try recordBody(a, 10, "hello");
        defer a.free(b1);
        try f.append(1 << 20, 1, b1, 0);
        const b2 = try deleteBody(a, 10);
        defer a.free(b2);
        try f.append(1 << 20, 2, b2, 0);
    }
    const back = try recoverBack(a, &sc);
    try testing.expectEqual(@as(i64, 3), back.next_lsn);
    try testing.expectEqual(@as(usize, 1), back.seqs);
}

test "wal3 B2: a body far larger than the sink buffer round-trips" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "bigbody");
    defer sc.deinit();
    const payload = try a.alloc(u8, 300_000);
    defer a.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast(i & 0xff);
    const big = try recordBody(a, 10, payload);
    defer a.free(big);
    {
        var f = try Fixture.init(a, &sc, null);
        defer f.deinit();
        // Emitted in 1 KiB chunks, so the body crosses the 64 KiB sink buffer many
        // times and never takes the bypass; the second append emits it whole,
        // which does take the bypass (a write at or past the buffer size is
        // written where it lies rather than copied through it).
        try f.append(1 << 30, 1, big, 1024);
        try f.append(1 << 30, 2, big, 0);
    }
    const back = try recoverBack(a, &sc);
    try testing.expectEqual(@as(i64, 3), back.next_lsn);
}

test "wal3 B2: the emitter runs exactly twice — measure, then write" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "twopass");
    defer sc.deinit();
    var f = try Fixture.init(a, &sc, null);
    defer f.deinit();
    try f.append(1 << 20, 1, "abc", 0);
    // The measure pass and the write pass, and nothing else: a writer that
    // materialized the body once would show 1, and one that re-emitted per
    // syscall would show more.
    try testing.expectEqual(@as(usize, 2), f.calls);
}

// ------------------------------------------------------------------ W3, rollover

test "wal3 B2: rollover happens past the size, at a section boundary" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "roll");
    defer sc.deinit();
    var rec = RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    {
        var f = try Fixture.init(a, &sc, &seam);
        defer f.deinit();
        // Segment 1 is empty, so the first append does NOT roll however small the
        // limit is — a segment is never sealed with nothing in it. The second
        // finds it past the limit and rolls first.
        const b = try deleteBody(a, 10);
        defer a.free(b);
        try f.append(TINY, 1, b, 0);
        const seqs1 = try f.seqs(a);
        defer a.free(seqs1);
        try testing.expectEqualSlices(i64, &.{1}, seqs1);
        try f.append(TINY, 2, b, 0);
        const seqs2 = try f.seqs(a);
        defer a.free(seqs2);
        try testing.expectEqualSlices(i64, &.{ 1, 2 }, seqs2);
    }
    // The seal is a FULL force and it precedes the create: a data-only sync could
    // lose the sealed segment's tail extent, and recovery would then see a torn
    // NON-FINAL segment and refuse a legitimate image (D5/W3).
    const kinds = try rec.kinds(a);
    defer a.free(kinds);
    if (indexOfSubsequence(kinds, &.{ .force_full, .create }) == null) {
        return error.TestExpectedSealBeforeCreate;
    }
    // And the sealed segment ends EXACTLY at its last section boundary: recovery
    // reading it back is the assertion that matters, since S6 refuses trailing
    // bytes below the highest name.
    const back = try recoverBack(a, &sc);
    try testing.expectEqual(@as(i64, 3), back.next_lsn);
    try testing.expectEqual(@as(usize, 2), back.seqs);
}

test "wal3 B2: an oversize section gets a segment to itself rather than being split" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "oversize");
    defer sc.deinit();
    const payload = try a.alloc(u8, 8192);
    defer a.free(payload);
    @memset(payload, 0x5A);
    const big = try recordBody(a, 10, payload);
    defer a.free(big);
    {
        var f = try Fixture.init(a, &sc, null);
        defer f.deinit();
        // Each of these is far past `TINY` on its own. W3 rolls only at a section
        // boundary, so each lands whole in a segment of its own — a section is
        // never split across two files, which is what makes a segment's byte range
        // self-describing.
        try f.append(TINY, 1, big, 0);
        try f.append(TINY, 2, big, 0);
        try f.append(TINY, 3, big, 0);
        const seqs = try f.seqs(a);
        defer a.free(seqs);
        try testing.expectEqualSlices(i64, &.{ 1, 2, 3 }, seqs);
    }
    const back = try recoverBack(a, &sc);
    try testing.expectEqual(@as(i64, 4), back.next_lsn);
    try testing.expectEqual(@as(usize, 3), back.seqs);
}

test "wal3 B2: a segment landing exactly ON the limit rolls at the next append" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "exact");
    defer sc.deinit();
    var f = try Fixture.init(a, &sc, null);
    defer f.deinit();
    const b = try deleteBody(a, 10);
    defer a.free(b);
    // The limit is chosen so the first append ends EXACTLY at it. W3's condition
    // is `>=`, as Java's: a segment that has REACHED the limit rolls, not only
    // one past it — `>` would keep appending into a segment sitting exactly at
    // its configured size forever.
    const limit = SEG_HDR + SEC_HDR + @as(u64, b.len);
    try f.append(limit, 1, b, 0);
    try testing.expectEqual(limit, f.set.active().?.file_len);
    const seqs1 = try f.seqs(a);
    defer a.free(seqs1);
    try testing.expectEqualSlices(i64, &.{1}, seqs1);
    try f.append(limit, 2, b, 0);
    const seqs2 = try f.seqs(a);
    defer a.free(seqs2);
    try testing.expectEqualSlices(i64, &.{ 1, 2 }, seqs2);
}

test "wal3 B2: the rolled-to segment states the LSN of the section that rolled it" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "rollfirst");
    defer sc.deinit();
    var f = try Fixture.init(a, &sc, null);
    defer f.deinit();
    const b = try deleteBody(a, 10);
    defer a.free(b);
    try f.append(TINY, 1, b, 0);
    try f.append(TINY, 2, b, 0);
    // R4's chain equality is what consumes this: the successor's stated start must
    // equal where its predecessor ended, and the predecessor ended after LSN 1.
    try testing.expectEqual(@as(i64, 2), f.set.active().?.headerFirstLsn());
}

// -------------------------------------------------------- the ordering claims

test "wal3 B2: one section reports header, body, then a DATA force" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "order");
    defer sc.deinit();
    var rec = RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    var f = try Fixture.init(a, &sc, &seam);
    defer f.deinit();
    const before = rec.events.items.len;
    try f.append(1 << 20, 1, "abc", 0);

    const kinds = try rec.kinds(a);
    defer a.free(kinds);
    try testing.expectEqualSlices(WalOpKind, &.{ .sec_header, .sec_body, .force_data }, kinds[before..]);
    // W1/W4: the header is written FIRST and final — never reserved and
    // back-patched — so a tear mid-body leaves a valid header over a short or
    // CRC-bad body, which is exactly the shape S3/S4/S5 classify. And the force is
    // a DATA sync: the file's size is metadata fdatasync is required to persist,
    // where a segment CREATE or a rollover SEAL makes the size itself the payload
    // and takes a full force instead.
    const hdr_ev = rec.events.items[before];
    const body_ev = rec.events.items[before + 1];
    try testing.expectEqual(SEG_HDR, hdr_ev.off);
    try testing.expectEqual(SEC_HDR, hdr_ev.len);
    try testing.expectEqual(TAG_SECTION, hdr_ev.tag);
    try testing.expectEqual(SEG_HDR + SEC_HDR, body_ev.off);
    try testing.expectEqual(@as(u64, 3), body_ev.len);
}

test "wal3 B2: the section's tag reaches the seam, so a mark is distinguishable" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "tags");
    defer sc.deinit();
    var rec = RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    var f = try Fixture.init(a, &sc, &seam);
    defer f.deinit();
    var calls: usize = 0;
    const ctx = Fixed{ .body = "xy", .calls = &calls };
    // B3's cleaner appends `'C'` images and `'K'` marks through this same
    // function; a seam that reported them all as `'S'` could not witness W5 (the
    // mark is forced BEFORE any unlink).
    for ([_]u8{ TAG_SECTION, TAG_IMAGE, TAG_MARK }, 1..) |tag, lsn| {
        try appendSection(&f.set, 1 << 20, f.set.io, tag, @intCast(lsn), a, &ctx, emitFixed);
    }
    var seen: [3]u8 = .{ 0, 0, 0 };
    var n: usize = 0;
    for (rec.events.items) |e| {
        if (e.kind == .sec_header) {
            seen[n] = e.tag;
            n += 1;
        }
    }
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualSlices(u8, &.{ TAG_SECTION, TAG_IMAGE, TAG_MARK }, &seen);
}

// ------------------------------------------------- the two-pass divergence check

test "wal3 B2: an emitter whose passes disagree in length is refused before the force" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "drift_len");
    defer sc.deinit();
    var rec = RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    var f = try Fixture.init(a, &sc, &seam);
    defer f.deinit();
    var d = Drifting{};
    try testing.expectError(
        DbError.DataCorruption,
        appendSection(&f.set, 1 << 20, f.set.io, TAG_SECTION, 1, a, &d, emitDrifting),
    );
    // BEFORE the force is the whole point: a stored `bodyCrc` describing bytes
    // other than the ones on the device is what replay reads as bit rot, and an
    // acknowledged section that fails its own checksum is unrecoverable rather
    // than merely wrong.
    try testing.expectEqual(@as(usize, 0), rec.count(.force_data));
}

test "wal3 B2: a length divergence the CRC cannot see is still refused" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "drift_residue");
    defer sc.deinit();
    var rec = RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    var f = try Fixture.init(a, &sc, &seam);
    defer f.deinit();
    var d = ResidueDrift{};
    try testing.expectError(
        DbError.DataCorruption,
        appendSection(&f.set, 1 << 20, f.set.io, TAG_SECTION, 1, a, &d, emitResidue),
    );
    // The collision really happened — both passes finalized to the same CRC — so
    // the refusal above can only have come from the LENGTH half of the check.
    // This is the test that pins that operand; the CONTENT test below pins the
    // CRC half, and neither can stand in for the other.
    try testing.expectEqual(d.finals[0], d.finals[1]);
    try testing.expectEqual(@as(usize, 0), rec.count(.force_data));
}

test "wal3 B2: an emitter whose passes disagree only in CONTENT is refused too" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "drift_crc");
    defer sc.deinit();
    var rec = RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    var f = try Fixture.init(a, &sc, &seam);
    defer f.deinit();
    var d = SameLength{};
    // The length half of the check cannot see this one; only the CRC half can. A
    // port that compared lengths alone would acknowledge it.
    try testing.expectError(
        DbError.DataCorruption,
        appendSection(&f.set, 1 << 20, f.set.io, TAG_SECTION, 1, a, &d, emitSameLength),
    );
    try testing.expectEqual(@as(usize, 0), rec.count(.force_data));
}

// -------------------------------------------------------------- accounting

test "wal3 B2: file_len and valid_end move only after the force" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "accounting");
    defer sc.deinit();
    var rec = RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    var f = try Fixture.init(a, &sc, &seam);
    defer f.deinit();

    // Fail the force itself. The bytes reached the device, but nothing has
    // acknowledged them — so the in-memory end must NOT have moved, or a retry
    // would append past a section the store never promised.
    rec.fail_at = rec.calls + 2; // sec_header, sec_body, then force_data
    try testing.expectError(DbError.Io, f.append(1 << 20, 1, "abc", 0));
    try testing.expectEqual(SEG_HDR, f.set.active().?.file_len);
    try testing.expectEqual(SEG_HDR, f.set.active().?.valid_end);

    // The success half runs in a FRESH namespace, deliberately not as a retry of
    // the failed one: appending again after a failed force is exactly the
    // operation W9 forbids (the caller closes the store instead), and a test
    // that retried would normalize it.
    var sc2 = try Scratch.init(a, "accounting_ok");
    defer sc2.deinit();
    var f2 = try Fixture.init(a, &sc2, null);
    defer f2.deinit();
    try f2.append(1 << 20, 1, "abc", 0);
    const end = SEG_HDR + SEC_HDR + 3;
    try testing.expectEqual(end, f2.set.active().?.file_len);
    try testing.expectEqual(end, f2.set.active().?.valid_end);
    try testing.expectEqual(end, f2.set.logBytes());
    try testing.expectEqual(f2.set.logBytesExact(), f2.set.logBytes());
}

test "wal3 B2: a failure at any reported step propagates rather than acknowledging" {
    const a = testing.allocator;
    // W9's precondition: every one of these must reach the caller as an error, so
    // the caller can fail the store closed. A step that swallowed its failure
    // would leave a partial section and let the next append run past it.
    var n: usize = 0;
    while (n < 3) : (n += 1) {
        var sc = try Scratch.init(a, "w9");
        defer sc.deinit();
        var rec = RecordingIo.init(a);
        defer rec.deinit();
        const seam = rec.io();
        var f = try Fixture.init(a, &sc, &seam);
        defer f.deinit();
        rec.fail_at = rec.calls + n;
        try testing.expectError(DbError.Io, f.append(1 << 20, 1, "abc", 0));
    }
}

test "wal3 B2: a rollover that cannot seal fails rather than creating a successor" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "seal_fail");
    defer sc.deinit();
    var rec = RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    var f = try Fixture.init(a, &sc, &seam);
    defer f.deinit();
    const b = try deleteBody(a, 10);
    defer a.free(b);
    try f.append(TINY, 1, b, 0);
    // Counted from HERE: the fixture's own `createSegment(1)` already reported a
    // create, so an absolute count would pass against an implementation that
    // created the successor anyway.
    const creates_before = rec.count(.create);
    // The seal force is the next reported operation; failing it must abandon the
    // rollover entirely. A successor created over an unsealed predecessor is a
    // non-final segment whose tail extent may not be durable — the S6/S3 shape
    // recovery refuses on a legitimate image.
    rec.fail_at = rec.calls;
    try testing.expectError(DbError.Io, f.append(TINY, 2, b, 0));
    const seqs = try f.seqs(a);
    defer a.free(seqs);
    try testing.expectEqualSlices(i64, &.{1}, seqs);
    try testing.expectEqual(creates_before, rec.count(.create));
}

test "wal3 B2: allocation failure after the header is on disk is OutOfMemory, not corruption" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "oom");
    defer sc.deinit();
    var rec = RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    {
        var f = try Fixture.init(a, &sc, &seam);
        defer f.deinit();
        // The sink buffer is allocated AFTER the section header is written (pass 1
        // allocates nothing at all), so its failure is the zig-only crash shape
        // rust cannot produce: bytes are on disk that the acknowledgement path
        // never reached — written and visible to a reopen, though nothing has
        // been forced yet. Risk 14 classifies it: operational, never corruption.
        var fa = FailingAllocator{ .inner = a, .fail_at = 0 };
        var calls: usize = 0;
        const ctx = Fixed{ .body = "abc", .calls = &calls };
        try testing.expectError(
            DbError.OutOfMemory,
            appendSection(&f.set, 1 << 20, f.set.io, TAG_SECTION, 1, fa.allocator(), &ctx, emitFixed),
        );
        // Exactly the buffer allocation was attempted, EXACTLY `OutOfMemory` came
        // back — not `DataCorruption`, not a torn-tail verdict — and nothing
        // forced or advanced: the failure is refused where it happened.
        try testing.expectEqual(@as(usize, 1), fa.calls);
        try testing.expectEqual(@as(usize, 1), rec.count(.sec_header));
        try testing.expectEqual(@as(usize, 0), rec.count(.force_data));
        try testing.expectEqual(SEG_HDR, f.set.active().?.file_len);
        try testing.expectEqual(SEG_HDR, f.set.active().?.valid_end);
    }
    // The device may hold the orphaned section header. That is a TORN TAIL — the
    // crash shape recovery already classifies (S3/S4) — so a reopen succeeds and
    // truncates it away rather than refusing the image. TWO segments after: W7
    // rotates on an actual truncation (truncate, force, create a fresh active),
    // so later appends never reuse the truncated segment's checksum domain.
    const back = try recoverBack(a, &sc);
    try testing.expectEqual(@as(i64, 1), back.next_lsn);
    try testing.expectEqual(@as(usize, 2), back.seqs);
}

// ---------------------------------------------------------------- no segment

test "wal3 B2: a namespace with no active segment refuses rather than panicking" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "noactive");
    defer sc.deinit();
    // A read-only open creates nothing, so the set is empty. Reaching the writer
    // in that state is a sequencing bug in the caller rather than anything about
    // the store, and it must say so instead of unwrapping a null.
    var set = try WalSegmentSet.open(a, sc.base, true);
    defer set.deinit();
    var calls: usize = 0;
    const ctx = Fixed{ .body = "x", .calls = &calls };
    try testing.expectError(
        DbError.WrongConfiguration,
        appendSection(&set, 1 << 20, null, TAG_SECTION, 1, a, &ctx, emitFixed),
    );
}

// ------------------------------------------------------------------- helpers

fn indexOfSubsequence(haystack: []const WalOpKind, needle: []const WalOpKind) ?usize {
    if (needle.len == 0 or haystack.len < needle.len) return null;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.mem.eql(WalOpKind, haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}
