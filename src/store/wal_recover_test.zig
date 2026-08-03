//! Tests for the WAL v3 codec and two-pass recovery (slice B1).
//!
//! Mirrors `mapdb-rust-store/src/store/wal_recover.rs`'s test module, which is
//! itself the Rust half of Java's `WalTestKit`. The byte-level recipe for a
//! segment, a section, a mark and an entry lives here once, so a hand-built image
//! cannot drift from what the codec reads — and, through [`SegImage.section`],
//! from what B2's writer will emit.
//!
//! Rust asserts on substrings of its formatted corruption messages. `DbError`
//! carries no payload, so the equivalent assertions here compare `Diag.reason`
//! against the named constant by identity: a test cannot pass because two rules
//! happen to share a word.
//!
//! Kept in its own file, like `wal_segments_test.zig`.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataOutput2 = io.DataOutput2;
const iv = @import("index_val.zig");
const direct = @import("direct.zig");
const StoreDirect = direct.StoreDirect;
const ws = @import("wal_segments.zig");
const WalSegmentSet = ws.WalSegmentSet;
const Segment = ws.Segment;
const SEG_HDR = ws.SEG_HDR;
const buildHeader = ws.buildHeader;
const wr = @import("wal_recover.zig");
const SEC_HDR = wr.SEC_HDR;
const TAG_SECTION = wr.TAG_SECTION;
const TAG_IMAGE = wr.TAG_IMAGE;
const TAG_MARK = wr.TAG_MARK;
const Diag = wr.Diag;
const Identities = wr.Identities;

const Crc32 = std.hash.crc.Crc32;
const SEGH: usize = @as(usize, SEG_HDR);
const SECH: usize = @as(usize, SEC_HDR);

const T_PREALLOC: u8 = 1;
const T_RECORD: u8 = 2;
const T_APPEND: u8 = 3;
const T_DELETE: u8 = 4;

const BUF: usize = 1 << 20;

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
            "/tmp/mapdb5_walrec_{d}_{s}_{d}",
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

    /// `<base>.wal.<seq:016x>`; owned. Spelled out rather than borrowed from the
    /// module under test — a name grammar the test agrees with because it calls
    /// the same function is not a test of the grammar.
    fn segPath(self: *const Scratch, seq: i64) ![]u8 {
        return std.fmt.allocPrint(
            self.alloc,
            "{s}.wal.{x:0>16}",
            .{ self.base, @as(u64, @bitCast(seq)) },
        );
    }

    fn writeSegment(self: *const Scratch, seq: i64, bytes: []const u8) !void {
        const p = try self.segPath(seq);
        defer self.alloc.free(p);
        const f = try std.fs.cwd().createFile(p, .{ .truncate = true });
        defer f.close();
        try f.writeAll(bytes);
    }

    fn fileLen(self: *const Scratch, seq: i64) !u64 {
        const p = try self.segPath(seq);
        defer self.alloc.free(p);
        const f = try std.fs.cwd().openFile(p, .{});
        defer f.close();
        return (try f.stat()).size;
    }

    /// The sequence numbers present in the directory, ascending. Owned.
    fn onDisk(self: *const Scratch) ![]i64 {
        var d = try std.fs.cwd().openDir(self.dir, .{ .iterate = true });
        defer d.close();
        var out: std.ArrayListUnmanaged(i64) = .empty;
        errdefer out.deinit(self.alloc);
        var it = d.iterate();
        while (try it.next()) |e| {
            const pfx = "store.db.wal.";
            if (!std.mem.startsWith(u8, e.name, pfx)) continue;
            const hex = e.name[pfx.len..];
            const v = std.fmt.parseInt(u64, hex, 16) catch continue;
            try out.append(self.alloc, @bitCast(v));
        }
        const items = try out.toOwnedSlice(self.alloc);
        std.mem.sort(i64, items, {}, std.sort.asc(i64));
        return items;
    }
};

fn expectOnDisk(sc: *const Scratch, want: []const i64) !void {
    const got = try sc.onDisk();
    defer sc.alloc.free(got);
    try testing.expectEqualSlices(i64, want, got);
}

/// One segment file under construction.
const SegImage = struct {
    alloc: Allocator,
    seq: i64,
    header: [SEGH]u8,
    bytes: std.ArrayListUnmanaged(u8) = .empty,
    /// Offset of every section appended, in order.
    offsets: std.ArrayListUnmanaged(u64) = .empty,

    fn init(alloc: Allocator, seq: i64, first_lsn: i64) !SegImage {
        var self = SegImage{ .alloc = alloc, .seq = seq, .header = buildHeader(seq, first_lsn) };
        try self.bytes.appendSlice(alloc, &self.header);
        return self;
    }

    fn deinit(self: *SegImage) void {
        self.bytes.deinit(self.alloc);
        self.offsets.deinit(self.alloc);
    }

    /// A section of any tag, sealed in its own domain at the offset it actually
    /// lands on.
    fn section(self: *SegImage, tag: u8, lsn: i64, body: []const u8) !void {
        const at: u64 = self.bytes.items.len;
        const hdr = wr.buildSecHdr(&self.header, at, tag, lsn, body);
        try self.offsets.append(self.alloc, at);
        try self.bytes.appendSlice(self.alloc, &hdr);
        try self.bytes.appendSlice(self.alloc, body);
    }

    fn commit(self: *SegImage, lsn: i64, body: *const Body) !void {
        try self.section(TAG_SECTION, lsn, body.bytes());
    }

    fn image(self: *SegImage, lsn: i64, body: *const Body) !void {
        try self.section(TAG_IMAGE, lsn, body.bytes());
    }

    fn mark(self: *SegImage, lsn: i64, through: i64, log_start: i64) !void {
        const b = wr.buildMarkBody(through, log_start);
        try self.section(TAG_MARK, lsn, &b);
    }

    /// The single-record commit that most of these images are built from.
    fn commitRec(self: *SegImage, lsn: i64, recid: u64, content: ?[]const u8) !void {
        var b = Body.init(self.alloc);
        defer b.deinit();
        try b.record(recid, content);
        try self.commit(lsn, &b);
    }

    fn imageRec(self: *SegImage, lsn: i64, recid: u64, content: ?[]const u8) !void {
        var b = Body.init(self.alloc);
        defer b.deinit();
        try b.record(recid, content);
        try self.image(lsn, &b);
    }

    /// Bytes appended past the last section — a torn tail, or S6's trailing bytes
    /// below the highest name.
    fn raw(self: *SegImage, bytes: []const u8) !void {
        try self.bytes.appendSlice(self.alloc, bytes);
    }

    /// Truncates the image: the shape a crash mid-append leaves.
    fn cutTo(self: *SegImage, n: usize) void {
        self.bytes.shrinkRetainingCapacity(n);
    }

    /// Flips a bit at an absolute file offset.
    fn damage(self: *SegImage, at: u64) void {
        self.bytes.items[@intCast(at)] ^= 0x40;
    }

    fn off(self: *const SegImage, i: usize) u64 {
        return self.offsets.items[i];
    }

    fn len(self: *const SegImage) usize {
        return self.bytes.items.len;
    }

    fn write(self: *const SegImage, sc: *const Scratch) !void {
        try sc.writeSegment(self.seq, self.bytes.items);
    }
};

/// A section body: entries in the packLong framing, built through the port's own
/// `DataOutput2` so the test kit cannot encode a long differently from the writer.
const Body = struct {
    out: DataOutput2,

    fn init(alloc: Allocator) Body {
        return .{ .out = DataOutput2.init(alloc) };
    }

    fn deinit(self: *Body) void {
        self.out.deinit();
    }

    fn bytes(self: *const Body) []const u8 {
        return self.out.bytes();
    }

    fn prealloc(self: *Body, recid: u64) !void {
        try self.out.writeU8(T_PREALLOC);
        try self.out.packLong(recid);
    }

    fn delete(self: *Body, recid: u64) !void {
        try self.out.writeU8(T_DELETE);
        try self.out.packLong(recid);
    }

    /// `content == null` is the null record (`len+1 == 0`, capacity 0).
    fn record(self: *Body, recid: u64, content: ?[]const u8) !void {
        if (content) |d| {
            try self.recordCap(recid, capFor(d.len), d);
        } else {
            try self.recordCap(recid, 0, null);
        }
    }

    /// A record with a hand-chosen capacity, for the `capValid` rows.
    fn recordCap(self: *Body, recid: u64, cap: u64, content: ?[]const u8) !void {
        try self.out.writeU8(T_RECORD);
        try self.out.packLong(recid);
        try self.out.packLong(cap);
        if (content) |d| {
            try self.out.packLong(@as(u64, d.len) + 1);
            try self.out.writeAll(d);
        } else {
            try self.out.packLong(0);
        }
    }

    /// `delta` is `sectionLsn - baseLsn`, exactly as the format stores it.
    fn append(self: *Body, recid: u64, delta: u64, data: []const u8) !void {
        try self.out.writeU8(T_APPEND);
        try self.out.packLong(recid);
        try self.out.packLong(delta);
        try self.out.packLong(@as(u64, data.len));
        try self.out.writeAll(data);
    }

    fn raw(self: *Body, bytes_: []const u8) !void {
        try self.out.writeAll(bytes_);
    }
};

/// The capacity a conforming writer records for `len` content bytes.
fn capFor(n: usize) u64 {
    const need: u64 = 4 + @as(u64, n);
    return ((need + 15) / 16) * 16;
}

/// A completed recovery, and everything it borrows.
const Rec = struct {
    alloc: Allocator,
    set: WalSegmentSet,
    inner: StoreDirect,
    next_lsn: i64,
    ids: Identities,

    fn deinit(self: *Rec) void {
        self.ids.deinit(self.alloc);
        self.inner.deinit();
        self.set.deinit();
    }

    /// Owned content, or `null` for a null/preallocated record. Errors on void.
    fn content(self: *Rec, recid: u64) DbError!?[]u8 {
        return self.inner.rawGet(self.alloc, recid);
    }

    fn isVoid(self: *Rec, recid: u64) bool {
        const r = self.inner.rawGet(self.alloc, recid) catch |e| return e == error.GetVoid;
        if (r) |b| self.alloc.free(b);
        return false;
    }

    fn expectContent(self: *Rec, recid: u64, want: []const u8) !void {
        const got = (try self.content(recid)) orelse return error.TestExpectedContent;
        defer self.alloc.free(got);
        try testing.expectEqualSlices(u8, want, got);
    }

    fn expectNullContent(self: *Rec, recid: u64) !void {
        const got = try self.content(recid);
        if (got) |b| {
            defer self.alloc.free(b);
            return error.TestExpectedNull;
        }
    }

    fn seqs(self: *Rec, alloc: Allocator) ![]i64 {
        const segs = self.set.segmentsSlice();
        const out = try alloc.alloc(i64, segs.len);
        for (segs, 0..) |s, i| out[i] = s.seq;
        return out;
    }
};

fn tryRecover(
    alloc: Allocator,
    sc: *const Scratch,
    read_only: bool,
    replay_buf: usize,
    diag: *Diag,
) DbError!Rec {
    var set = try WalSegmentSet.open(alloc, sc.base, read_only);
    errdefer set.deinit();
    var inner = try StoreDirect.init(alloc, true);
    errdefer inner.deinit();
    var rec = try wr.recover(&set, &inner, replay_buf, alloc, diag);
    errdefer rec.deinit(alloc);
    return .{
        .alloc = alloc,
        .set = set,
        .inner = inner,
        .next_lsn = rec.next_lsn,
        .ids = rec.identities,
    };
}

fn openRw(alloc: Allocator, sc: *const Scratch, diag: *Diag) DbError!Rec {
    return tryRecover(alloc, sc, false, BUF, diag);
}

fn openRo(alloc: Allocator, sc: *const Scratch, diag: *Diag) DbError!Rec {
    return tryRecover(alloc, sc, true, BUF, diag);
}

/// The image must refuse as `DataCorruption`, naming exactly `reason`.
fn expectRefusal(alloc: Allocator, sc: *const Scratch, reason: []const u8) !void {
    var diag: Diag = .{};
    const r = openRw(alloc, sc, &diag);
    if (r) |ok| {
        var m = ok;
        m.deinit();
        return error.TestExpectedCorruption;
    } else |e| {
        try testing.expectEqual(DbError.DataCorruption, e);
        try testing.expectEqualStrings(reason, diag.reason);
    }
}

// ------------------------------------------------- the cross-engine vector

/// A segment file **written by the Java implementation**, verbatim: the
/// `reject-wal-java-v3.walseg` fixture. 36-byte header for seq 1 / firstLsn 1,
/// followed by one complete `'S'` section at LSN 1 carrying a single `T_RECORD`:
/// recid 1, capacity 112 — Java's `(4 + 100 + 15) & ~15` for a first fresh put —
/// and 100 bytes of content.
///
/// Embedded rather than loaded from the fixture file on purpose. These bytes are
/// the VECTOR; the fixture is scheduled to be retired and re-derived at Stage C,
/// and a vector that moves with the artifact it was copied from proves nothing.
const JAVA_SEGMENT = [_]u8{
    0x4d, 0x44, 0x42, 0x53, 0x2e, 0x57, 0x41, 0x4c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x4a, 0x4d, 0x90, 0x4b, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x9d, 0x82, 0x80, 0xb3, 0xe7, 0xf6, 0xab,
    0xe9, 0x02, 0x81, 0xf0, 0xe5, 0x33, 0xb6, 0x39, 0xbc, 0x3f, 0xc2, 0x45, 0xc8, 0x4b, 0xce,
    0x51, 0xd4, 0x57, 0xda, 0x5d, 0xe0, 0x63, 0xe6, 0x69, 0xec, 0x6f, 0xf2, 0x75, 0xf8, 0x7b,
    0xfe, 0x81, 0x04, 0x87, 0x0a, 0x8d, 0x10, 0x93, 0x16, 0x99, 0x1c, 0x9f, 0x22, 0xa5, 0x28,
    0xab, 0x2e, 0xb1, 0x34, 0xb7, 0x3a, 0xbd, 0x40, 0xc3, 0x46, 0xc9, 0x4c, 0xcf, 0x52, 0xd5,
    0x58, 0xdb, 0x5e, 0xe1, 0x64, 0xe7, 0x6a, 0xed, 0x70, 0xf3, 0x76, 0xf9, 0x7c, 0xff, 0x82,
    0x05, 0x88, 0x0b, 0x8e, 0x11, 0x94, 0x17, 0x9a, 0x1d, 0xa0, 0x23, 0xa6, 0x29, 0xac, 0x2f,
    0xb2, 0x35, 0xb8, 0x3b, 0xbe, 0x41, 0xc4, 0x47, 0xca, 0x4d, 0xd0, 0x53, 0xd6, 0x59, 0xdc,
};

test "wal3 B1: a Java-written section decodes to the record Java put in it" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "java_vector");
    defer sc.deinit();
    try sc.writeSegment(1, &JAVA_SEGMENT);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
    try testing.expectEqual(@as(?i64, 1), r.ids.content_base_lsn.get(1));

    // What the Java side actually stored, derived from its generator rather than
    // from these bytes: `payload(51, 100)` is `(i * 131 + 51) & 0xff`. Checking the
    // recovered CONTENT against that formula tests the vector's meaning
    // independently of its transcription.
    const recovered = (try r.content(1)).?;
    defer a.free(recovered);
    try testing.expectEqual(@as(usize, 100), recovered.len);
    for (recovered, 0..) |b, i| {
        try testing.expectEqual(@as(u8, @intCast((i * 131 + 51) & 0xff)), b);
    }
}

test "wal3 B1: this port's encoder reproduces the Java bytes exactly" {
    // The test that catches PAIRED drift, which nothing else here can: every other
    // image in this module is built by the same code that reads it, so moving both
    // sides to a different endianness, CRC polynomial or domain recipe would leave
    // the whole suite green. These 165 bytes came from the other implementation.
    const a = testing.allocator;
    const payload = JAVA_SEGMENT[65..];
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    var b = Body.init(a);
    defer b.deinit();
    try b.recordCap(1, 112, payload);
    try img.commit(1, &b);
    try testing.expectEqualSlices(u8, &JAVA_SEGMENT, img.bytes.items);
}

// ------------------------------------------------------------- the CRC domain

test "wal3 B1: a section is bound to its segment" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "dom_seg");
    defer sc.deinit();
    // Two segments whose sections sit at identical offsets. Segment 2's section is
    // byte-copied from segment 1's, which is what an operator "repairing" a log by
    // copying a good segment over a bad one does.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "one");
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.commitRec(2, 10, "one");
    try testing.expectEqual(one.len(), two.len());
    @memcpy(two.bytes.items[SEGH..], one.bytes.items[SEGH..]);
    try one.write(&sc);
    try two.write(&sc);

    // The forged section fails its header CRC in segment 2's domain. Segment 2 is
    // the highest name, so that reads as a torn tail: discarded, not replayed.
    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(SEG_HDR, r.set.segmentsSlice()[1].valid_end);
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
}

test "wal3 B1: a section is bound to its offset" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "dom_off");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "b");
    // Move the FIRST section's bytes over the second one's: same segment, same
    // length, different offset.
    const x: usize = @intCast(img.off(0));
    const y: usize = @intCast(img.off(1));
    const n = y - x;
    const first = try a.dupe(u8, img.bytes.items[x..y]);
    defer a.free(first);
    @memcpy(img.bytes.items[y .. y + n], first);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
    try r.expectContent(10, "a");
    try testing.expect(r.isVoid(11));
}

test "wal3 B1: the CRC domain covers the segment's stated start" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "dom_first");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    // Restate firstLsn as 2 and RESEAL, so the header itself stays valid and the
    // edit is only visible through the section CRCs it invalidates.
    std.mem.writeInt(i64, img.bytes.items[24..32], 2, .big);
    var h = Crc32.init();
    h.update(img.bytes.items[0..32]);
    std.mem.writeInt(i32, img.bytes.items[32..36], @bitCast(h.final()), .big);
    try img.write(&sc);

    // The section no longer verifies, so the segment reads as empty — and an empty
    // segment must then satisfy the floor with its restated start, which says 2
    // where an unmarked log must begin at 1.
    try expectRefusal(a, &sc, wr.R_FLOOR);
}

test "wal3 B1: a body larger than the replay window verifies and replays" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "stream");
    defer sc.deinit();
    const big = try a.alloc(u8, 300_000);
    defer a.free(big);
    @memset(big, 0xA5);
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, big);
    try img.write(&sc);

    // A window far smaller than the body forces refills in both the CRC pass and
    // the entry decoder.
    var diag: Diag = .{};
    var r = try tryRecover(a, &sc, false, 64, &diag);
    defer r.deinit();
    try r.expectContent(10, big);
}

// ------------------------------------------------------------------- table S

test "wal3 B1: a torn tail in the active segment truncates, forces and rotates" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "torn");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "b");
    img.cutTo(@as(usize, @intCast(img.off(1))) + 12); // half of the second header
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectContent(10, "a");
    try testing.expect(r.isVoid(11));
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
    // W7: truncated to the valid prefix, and a successor created so the old CRC
    // domain is never appended to again.
    try expectOnDisk(&sc, &.{ 1, 2 });
    try testing.expectEqual(SEG_HDR + SEC_HDR + 5, try sc.fileLen(1));
    try testing.expectEqual(@as(i64, 2), r.set.active().?.seq);
    try testing.expectEqual(@as(i64, 2), r.set.active().?.headerFirstLsn());
}

test "wal3 B1: W7 leaves no stale descriptor and no stale accounting" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "w7_state");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "b");
    img.cutTo(@as(usize, @intCast(img.off(1))) + 12);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    // The cached length must follow the truncation, or `createSegment` charges the
    // PRE-truncate length into `sealed_bytes` and every later reader of `logBytes`
    // — B3's cleaning trigger — works from an inflated log size. Compared against
    // the bytes actually on disk, because the set's own two accessors read the same
    // cached field and would agree with each other while both being wrong.
    const seqs = try sc.onDisk();
    defer a.free(seqs);
    var on_device: u64 = 0;
    for (seqs) |s| on_device += try sc.fileLen(s);
    try testing.expectEqual(on_device, r.set.logBytes());
    try testing.expectEqual(r.set.logBytesExact(), r.set.logBytes());
    // And the deliberate divergence: the reference keeps the truncated
    // predecessor's channel open here.
    try testing.expectEqual(@as(usize, 0), r.set.openFileCount());
}

test "wal3 B1: an untorn open does not rotate" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "no_rotate");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    // Rotating on every open would burn a sequence number per open and demote a
    // legitimately empty highest segment to non-highest (H8).
    try expectOnDisk(&sc, &.{1});
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
}

test "wal3 B1: a damaged header followed by the exact next section is corruption" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s3_exact");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "b");
    try img.commitRec(3, 12, "c");
    // Rot the second section's TAG. Its declared bodyLen survives, so the walk
    // starts exactly at section 3, which carries lastLsn+2 == 3.
    img.damage(img.off(1));
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.H_MIDLOG_HDR);
}

test "wal3 B1: a damaged header with nothing after it is a torn tail" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s3_tail");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "b");
    img.damage(img.off(1));
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
    try testing.expect(r.isVoid(11));
}

test "wal3 B1: the lookahead wants exactly the next LSN after a damaged header" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s3_wrong_lsn");
    defer sc.deinit();
    // Sections 1, 2, then a section carrying LSN 9: valid in itself, but not the
    // LSN that would have followed the damaged one. The reference calls that a torn
    // tail — the untrusted anchor makes "something valid is over there" too weak a
    // proof on its own.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "b");
    try img.commitRec(9, 12, "c");
    img.damage(img.off(1));
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
}

test "wal3 B1: a body CRC mismatch followed by any future LSN is corruption" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s4_mid");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "bbbb");
    try img.commitRec(3, 12, "c");
    // Rot a BODY byte: the header still seals the section's end, so the lookahead
    // anchor is trusted and any strictly future LSN proves rot.
    img.damage(img.off(1) + SEC_HDR + 2);
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.H_MIDLOG_BODY);
}

test "wal3 B1: a body CRC mismatch at the end is a torn tail" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s4_tail");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "bbbb");
    img.damage(img.off(1) + SEC_HDR + 2);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
    try testing.expect(r.isVoid(11));
}

test "wal3 B1: a clean mark counts as proof that sections follow" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "k_lookahead");
    defer sc.deinit();
    // THE flagged trap: a port whose validTag is v1's two-tag set does not see the
    // 'K' here, reports "nothing valid follows", and silently truncates deliberate
    // mid-log rot away as a torn tail.
    var two = try SegImage.init(a, 2, 3);
    defer two.deinit();
    try two.commitRec(3, 10, "a");
    try two.commitRec(4, 11, "b");
    try two.mark(5, 1, 3);
    two.damage(two.off(1) + SEC_HDR);
    try two.write(&sc);
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 1, "x");
    try one.commitRec(2, 2, "y");
    try one.write(&sc);
    try expectRefusal(a, &sc, wr.H_MIDLOG_BODY);
}

test "wal3 B1: a damaged section below the highest name is corruption without a lookahead" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s3_nonfinal");
    defer sc.deinit();
    // Nothing follows the damaged section inside segment 1, so in the active
    // segment this shape would be a legal torn tail. Below the highest name W3
    // rules that out: a sealed segment ends exactly at a section boundary.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.commitRec(2, 11, "b");
    one.damage(one.off(1));
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 3);
    defer two.deinit();
    try two.commitRec(3, 12, "c");
    try two.write(&sc);
    try expectRefusal(a, &sc, wr.H_HDR_DAMAGED);
}

test "wal3 B1: trailing bytes below the highest name are corruption" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s6");
    defer sc.deinit();
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.raw(&[_]u8{0} ** 7);
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.commitRec(2, 11, "b");
    try two.write(&sc);
    try expectRefusal(a, &sc, wr.H_TRAILING);
}

test "wal3 B1: trailing bytes in the active segment are a torn tail" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s6_active");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    const valid = img.len();
    try img.raw(&[_]u8{0} ** 7);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
    try testing.expectEqual(@as(u64, valid), try sc.fileLen(1));
    try expectOnDisk(&sc, &.{ 1, 2 });
}

test "wal3 B1: a body running past the end is a torn tail in the active segment" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s5");
    defer sc.deinit();
    // A CRC-valid header whose body was never written: the crash shape a
    // header-first writer produces.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "bbbbbbbbbb");
    img.cutTo(@as(usize, @intCast(img.off(1))) + SECH);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
}

test "wal3 B1: a CRC-valid section under an unknown tag is not a section" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s3_tag");
    defer sc.deinit();
    // Sealed correctly in its own domain, so only `validTag` separates it from a
    // real section. A scanner that accepted it would hand its body to the entry
    // decoder and replay data the reference discards as a damaged active tail.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    var b = Body.init(a);
    defer b.deinit();
    try b.record(11, "b");
    try img.section('X', 2, b.bytes());
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectContent(10, "a");
    try testing.expect(r.isVoid(11));
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
}

test "wal3 B1: the trusted anchor accepts any future LSN not just the next" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s4_distant");
    defer sc.deinit();
    // The damaged section's own header sealed where its body ends, so the walk
    // starts at a REAL section boundary and does not need the exact next LSN — this
    // is what separates the trusted anchor from the untrusted one, and LSN 9
    // satisfies only the relaxed rule.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "bbbb");
    try img.commitRec(9, 12, "c");
    img.damage(img.off(1) + SEC_HDR + 2);
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.H_MIDLOG_BODY);
}

test "wal3 B1: the lookahead walks past a framed candidate that does not qualify" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s4_walk");
    defer sc.deinit();
    // A framed candidate carrying a stale LSN does not end the search: the walk
    // advances by that candidate's own length and keeps looking. A port that
    // returned false at the first non-qualifying frame would call this a torn tail
    // and truncate committed sections away.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "bbbb");
    try img.commitRec(2, 12, "stale");
    try img.commitRec(5, 13, "c");
    img.damage(img.off(1) + SEC_HDR + 2);
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.H_MIDLOG_BODY);
}

test "wal3 B1: a lookahead candidate must pass its own body CRC too" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s4_cand_body");
    defer sc.deinit();
    // The clause that says a candidate proves nothing unless its BODY also
    // verifies. Section 3 is framed correctly and carries a qualifying LSN, so a
    // walk that stopped at the LSN test would call this mid-log corruption; its
    // body is damaged too, so nothing here is a durable section and the reference
    // truncates the pair as a torn tail.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "bbbb");
    try img.commitRec(3, 12, "cccc");
    img.damage(img.off(1) + SEC_HDR + 2);
    img.damage(img.off(2) + SEC_HDR + 2);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
    try r.expectContent(10, "a");
    try testing.expect(r.isVoid(12));
}

test "wal3 B1: a body CRC mismatch below the highest name is corruption" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s4_nonfinal");
    defer sc.deinit();
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "aaaa");
    try one.commitRec(2, 11, "b");
    one.damage(one.off(0) + SEC_HDR + 2);
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 3);
    defer two.deinit();
    try two.commitRec(3, 12, "c");
    try two.write(&sc);
    try expectRefusal(a, &sc, wr.H_BODY_CRC);
}

test "wal3 B1: a body past the end below the highest name is corruption" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s5_nonfinal");
    defer sc.deinit();
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.commitRec(2, 11, "bbbbbbbbbb");
    one.cutTo(@as(usize, @intCast(one.off(1))) + SECH);
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 3);
    defer two.deinit();
    try two.commitRec(3, 12, "c");
    try two.write(&sc);
    try expectRefusal(a, &sc, wr.H_BODY_PAST_END);
}

test "wal3 B1: a repeated LSN is held even in the active segment" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s2");
    defer sc.deinit();
    // CRC-valid means deliberate: a writer-defect class, refused rather than
    // truncated away, even at the very end of the highest segment.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(1, 11, "b");
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.H_LSN_BACK);
}

test "wal3 B1: an LSN gap is held even in the active segment" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "s9");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(3, 11, "b");
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.H_LSN_GAP);
}

// ------------------------------------------------------------------- table K

test "wal3 B1: every malformed mark is held" {
    const a = testing.allocator;
    const Case = struct { tag: []const u8, wrong_len: bool, through: i64, log_start: i64, want: []const u8 };
    const cases = [_]Case{
        .{ .tag = "len", .wrong_len = true, .through = 0, .log_start = 0, .want = wr.H_MARK_LEN },
        .{ .tag = "through0", .wrong_len = false, .through = 0, .log_start = 1, .want = wr.H_MARK_THROUGH },
        .{ .tag = "through_neg", .wrong_len = false, .through = -4, .log_start = 1, .want = wr.H_MARK_THROUGH },
        .{ .tag = "start0", .wrong_len = false, .through = 1, .log_start = 0, .want = wr.H_MARK_START },
        .{ .tag = "start_above", .wrong_len = false, .through = 1, .log_start = 4, .want = wr.H_MARK_START },
        .{ .tag = "k4_self", .wrong_len = false, .through = 2, .log_start = 1, .want = wr.H_MARK_SELF },
    };
    for (cases) |c| {
        var sc = try Scratch.init(a, c.tag);
        defer sc.deinit();
        var one = try SegImage.init(a, 1, 1);
        defer one.deinit();
        try one.commitRec(1, 10, "a");
        try one.write(&sc);
        var two = try SegImage.init(a, 2, 2);
        defer two.deinit();
        try two.commitRec(2, 11, "b");
        if (c.wrong_len) {
            try two.section(TAG_MARK, 3, &[_]u8{0} ** 8);
        } else {
            try two.mark(3, c.through, c.log_start);
        }
        try two.write(&sc);
        try expectRefusal(a, &sc, c.want);
    }
}

test "wal3 B1: a valid mark unlinks the segments below it and fsyncs once" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "k_unlink");
    defer sc.deinit();
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "gone");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.commitRec(2, 11, "gone too");
    try two.write(&sc);
    // Segment 3 is self-contained: it re-states recid 10 as a 'C' image, and its
    // mark says the log now begins at its own LSN 3.
    var three = try SegImage.init(a, 3, 3);
    defer three.deinit();
    try three.imageRec(3, 10, "kept");
    try three.mark(4, 2, 3);
    try three.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try expectOnDisk(&sc, &.{3});
    const seqs = try r.seqs(a);
    defer a.free(seqs);
    try testing.expectEqualSlices(i64, &.{3}, seqs);
    try r.expectContent(10, "kept");
    try testing.expect(r.isVoid(11));
    try testing.expectEqual(@as(i64, 5), r.next_lsn);
    try testing.expectEqual(@as(u64, 1), r.set.dir_fsyncs);
}

test "wal3 B1: a mark below the active segment still wins" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "k_below_active");
    defer sc.deinit();
    // The conforming shape a clean followed by a rotation leaves: the winning mark
    // is NOT in the highest segment. Worth its own test because every other mark
    // test here puts the mark in the active segment, so "the last scan wins" and
    // "the maximum wins" would agree on all of them.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "gone");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.imageRec(2, 11, "kept");
    try two.mark(3, 1, 2);
    try two.write(&sc);
    var three = try SegImage.init(a, 3, 4);
    defer three.deinit();
    try three.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try expectOnDisk(&sc, &.{ 2, 3 });
    try r.expectContent(11, "kept");
    try testing.expectEqual(@as(i64, 4), r.next_lsn);
}

test "wal3 B1: within one segment the greatest mark wins, not the newest" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "k_greatest");
    defer sc.deinit();
    for ([_]i64{ 1, 2 }) |seq| {
        var s = try SegImage.init(a, seq, seq);
        defer s.deinit();
        try s.commitRec(seq, @intCast(seq), "x");
        try s.write(&sc);
    }
    var three = try SegImage.init(a, 3, 3);
    defer three.deinit();
    try three.imageRec(3, 9, "i");
    try three.mark(4, 2, 3); // greater
    try three.mark(5, 1, 1); // newer, but lesser: does not displace it
    try three.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try expectOnDisk(&sc, &.{3});
    try testing.expectEqual(@as(i64, 6), r.next_lsn);
}

test "wal3 B1: a later greater mark in the same segment does displace the first" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "k_later_greater");
    defer sc.deinit();
    // The mirror of the equal-mark test, and it moves BOTH halves of the reduction:
    // the greater mark raises the removal boundary (segment 2 goes as well as
    // segment 1) and re-points the log start (2 -> 3, which is what the retained
    // header states).
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 1, "x");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.commitRec(2, 2, "y");
    try two.write(&sc);
    var three = try SegImage.init(a, 3, 3);
    defer three.deinit();
    try three.imageRec(3, 9, "i");
    try three.mark(4, 1, 2);
    try three.mark(5, 2, 3);
    try three.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try expectOnDisk(&sc, &.{3});
    try testing.expectEqual(@as(i64, 6), r.next_lsn);
}

test "wal3 B1: an equal mark does not displace the first one" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "k_equal");
    defer sc.deinit();
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 1, "x");
    try one.write(&sc);
    // Two marks attesting the SAME through. The reduction is strict
    // (`through > local`), so the FIRST one's logStartLsn stands — and here the two
    // disagree, so the floor check is what observes which won.
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.imageRec(2, 9, "i");
    try two.mark(3, 1, 2);
    try two.mark(4, 1, 3);
    try two.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try expectOnDisk(&sc, &.{2});
    try testing.expectEqual(@as(i64, 5), r.next_lsn);
}

test "wal3 B1: the log start comes from the last segment holding a mark" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "k_last_seg");
    defer sc.deinit();
    // The reduction is per-SEGMENT-SCAN: `segThrough` restarts at 0 in every
    // segment, so a later segment's mark sets markLogStartLsn even when its
    // `through` merely EQUALS the global maximum. Both marks here attest through 1;
    // they disagree about where the log starts, and only the later segment's answer
    // (2) matches the lowest retained header. A port that re-derived the field from
    // the global reduction would take the first mark's 1 and refuse this image.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.imageRec(1, 9, "i");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.mark(2, 1, 1);
    try two.write(&sc);
    var three = try SegImage.init(a, 3, 3);
    defer three.deinit();
    try three.mark(3, 1, 2);
    try three.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try expectOnDisk(&sc, &.{ 2, 3 });
    try testing.expectEqual(@as(i64, 4), r.next_lsn);
}

test "wal3 B1: a hold stops the segment's scan where it stands" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "k_hold_stops");
    defer sc.deinit();
    // The image: an S2 fault, then a mark AFTER it in the same segment. The mark
    // must never be collected and the valid prefix must end at the fault. Both
    // facts feed decisions taken elsewhere (which segments R5 removes, where W7
    // truncates), so they are pinned here rather than left to a fixture that cannot
    // see them: the mark would have authorized removing segments 1 and 2, neither
    // of which exists, so a scan that ran past the fault would have produced a
    // DIFFERENT verdict rather than merely a different message.
    var img = try SegImage.init(a, 3, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(1, 11, "repeat"); // S2: held
    try img.mark(2, 1, 1);
    try img.write(&sc);
    const fault_at = img.off(1);

    var diag: Diag = .{};
    const r = openRw(a, &sc, &diag);
    if (r) |ok| {
        var m = ok;
        m.deinit();
        return error.TestExpectedCorruption;
    } else |e| {
        try testing.expectEqual(DbError.DataCorruption, e);
        try testing.expectEqualStrings(wr.H_LSN_BACK, diag.reason);
        try testing.expectEqual(fault_at, diag.at);
        try testing.expectEqual(@as(i64, 3), diag.seq);
    }
}

// ----------------------------------------------------------------------- R4

test "wal3 B1: a held verdict in a superseded segment is discarded" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r4_discard");
    defer sc.deinit();
    // Segment 1 is rotten in a way that is corruption on its own (an LSN gap in a
    // CRC-valid section). It is below the mark, so refusing here would brick a
    // store over bytes about to be deleted.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.commitRec(7, 11, "b");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 8);
    defer two.deinit();
    try two.imageRec(8, 10, "kept");
    try two.mark(9, 1, 8);
    try two.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try expectOnDisk(&sc, &.{2});
    try r.expectContent(10, "kept");
}

test "wal3 B1: a held verdict in a retained segment refuses" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r4_retained");
    defer sc.deinit();
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.imageRec(1, 10, "i");
    try one.mark(2, 0, 0); // malformed: held, and this segment is retained
    try one.write(&sc);
    try expectRefusal(a, &sc, wr.H_MARK_THROUGH);
}

test "wal3 B1: an unmarked log must begin at LSN 1" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r4_floor");
    defer sc.deinit();
    var one = try SegImage.init(a, 1, 5);
    defer one.deinit();
    try one.commitRec(5, 10, "a");
    try one.write(&sc);
    try expectRefusal(a, &sc, wr.R_FLOOR);
}

test "wal3 B1: the floor refuses a retained log that starts below the mark" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r4_floor_mark");
    defer sc.deinit();
    // The mark says the log begins at 3, but the lowest retained segment states 2:
    // the image the mark was issued against is not there. Nothing else notices —
    // the chain is satisfied, because segment 1's data is below the mark and no LSN
    // is missing.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.commitRec(2, 11, "b");
    try two.mark(3, 1, 3);
    try two.write(&sc);

    var diag: Diag = .{};
    const r = openRw(a, &sc, &diag);
    if (r) |ok| {
        var m = ok;
        m.deinit();
        return error.TestExpectedCorruption;
    } else |e| {
        try testing.expectEqual(DbError.DataCorruption, e);
        try testing.expectEqualStrings(wr.R_FLOOR, diag.reason);
        try testing.expectEqual(@as(i64, 3), diag.detail); // the mark's logStartLsn
    }
}

test "wal3 B1: the chain refuses a segment whose sections are gone" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r4_chain");
    defer sc.deinit();
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(&sc);
    // Segment 2 states it begins at 4: LSNs 2 and 3 are accounted for by nobody. A
    // missing sequence NUMBER needs no rule — this is how the loss surfaces.
    var two = try SegImage.init(a, 2, 4);
    defer two.deinit();
    try two.commitRec(4, 11, "b");
    try two.write(&sc);
    try expectRefusal(a, &sc, wr.R_CHAIN);
}

test "wal3 B1: an empty segment chains by its stated start" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r4_empty");
    defer sc.deinit();
    // W7's rotate target: created, never appended to. It must chain by what it SAID
    // it would start at, which is what separates "always empty" from "its sections
    // vanished" (H8).
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.write(&sc);
    var three = try SegImage.init(a, 3, 2);
    defer three.deinit();
    try three.commitRec(2, 11, "b");
    try three.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(i64, 3), r.next_lsn);
    try r.expectContent(11, "b");
}

test "wal3 B1: the self check refuses a segment missing its leading sections" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r4_self");
    defer sc.deinit();
    // Header says the segment starts at 1; its first section is 2. Under the chain
    // alone this passes at the head of the log, so the self check catches it.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(2, 10, "a");
    try one.write(&sc);
    try expectRefusal(a, &sc, wr.R_SELF);
}

test "wal3 B1: the self check runs on every retained segment, not just the first" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r4_self_later");
    defer sc.deinit();
    // Segment 2's stated start chains correctly off segment 1, so the chain is
    // satisfied and only the self check sees that its own first section is not the
    // one it promised.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.commitRec(3, 11, "b");
    try two.write(&sc);

    var diag: Diag = .{};
    const r = openRw(a, &sc, &diag);
    if (r) |ok| {
        var m = ok;
        m.deinit();
        return error.TestExpectedCorruption;
    } else |e| {
        try testing.expectEqual(DbError.DataCorruption, e);
        try testing.expectEqualStrings(wr.R_SELF, diag.reason);
        try testing.expectEqual(@as(i64, 2), diag.seq); // the SECOND segment
    }
}

test "wal3 B1: the next LSN comes from the retained set, not from every valid section" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r7_retained_max");
    defer sc.deinit();
    // A superseded segment carrying a spuriously high LSN. Reading the maximum
    // globally would set nextLsn to 51 and leave a gap that fails S9 on the NEXT
    // open; the reference takes it over the retained set.
    var one = try SegImage.init(a, 1, 50);
    defer one.deinit();
    try one.commitRec(50, 10, "a");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 3);
    defer two.deinit();
    try two.imageRec(3, 11, "i");
    try two.mark(4, 1, 3);
    try two.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try expectOnDisk(&sc, &.{2});
    try testing.expectEqual(@as(i64, 5), r.next_lsn);
}

test "wal3 B1: an exhausted LSN space refuses instead of wrapping" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r7_exhausted");
    defer sc.deinit();
    // A RECORDED divergence from the frozen reference, and the image that reaches
    // it: one segment stating firstLsn = i64 maxint whose single 'K' sits at that
    // LSN passes K4, the floor and the self check. The reference opens with
    // nextLsn = i64 minint — a store that takes one more commit, at a negative LSN,
    // and is then unopenable because the next scan reads that section as S2.
    // `StoreFull` is the honest answer: the bytes are intact, the LSN space is used
    // up. Nothing a conforming writer can produce reaches here (2^63 transactions).
    var img = try SegImage.init(a, 2, std.math.maxInt(i64));
    defer img.deinit();
    try img.mark(std.math.maxInt(i64), 1, std.math.maxInt(i64));
    try img.write(&sc);

    var diag: Diag = .{};
    const r = openRw(a, &sc, &diag);
    if (r) |ok| {
        var m = ok;
        m.deinit();
        return error.TestExpectedStoreFull;
    } else |e| {
        try testing.expectEqual(DbError.StoreFull, e);
    }
}

test "wal3 B1: an LSN at the top of the range does not panic the chain" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r4_maxlsn");
    defer sc.deinit();
    // Reachable, not theoretical: the density checks do not apply to a segment's
    // FIRST section, so one crafted section can carry i64 maxint, and a mark
    // attesting `logStartLsn = i64 maxint` makes the floor accept the header that
    // states it. The chain then computes `last_lsn + 1` on i64 maxint — a wrap in
    // the reference and a PANIC in a safe Zig build, which is the difference
    // between refusing an image and taking the process down with it.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, std.math.maxInt(i64));
    defer two.deinit();
    try two.mark(std.math.maxInt(i64), 1, std.math.maxInt(i64));
    try two.write(&sc);
    var three = try SegImage.init(a, 3, 1);
    defer three.deinit();
    try three.write(&sc);
    try expectRefusal(a, &sc, wr.R_CHAIN);
}

test "wal3 B1: an LSN at the top of the range does not panic the lookahead" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "look_maxlsn");
    defer sc.deinit();
    // The lookahead's own wrapping site, which the chain test above does NOT reach:
    // `anyValidSectionFrom` wants `lookLastLsn + 2` exactly, and its panic would
    // fire in PASS 1 — before R4 could refuse the image, so no adjudication test
    // can stand in for this one (design §6 risk 13; the A1 round-3 review
    // demonstrated the same site in Rust by building an image).
    //
    // Reaching it needs three things at once: an anchor at the top of the range, a
    // damaged header whose declared bodyLen survives so the walk starts at a framed
    // candidate, and a candidate to compare against. The mark supplies the anchor
    // legitimately — the density checks never apply to a segment's FIRST section —
    // and also makes the floor accept the header that states it, so the image OPENS
    // rather than merely refusing: the wrapped answer "no proof follows" is what
    // classifies this as a torn tail.
    const max = std.math.maxInt(i64);
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "gone");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, max - 1);
    defer two.deinit();
    try two.mark(max - 1, 1, max - 1);
    try two.commitRec(max, 11, "damaged");
    try two.commitRec(max, 12, "candidate");
    two.damage(two.off(1)); // the TAG, so the declared bodyLen survives
    try two.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    // Torn tail: nothing after the damage proved durable, so the pair is truncated
    // and a successor rotated in at the next LSN.
    try testing.expectEqual(max, r.next_lsn);
    try expectOnDisk(&sc, &.{ 2, 3 });
    try testing.expect(r.isVoid(11));
    try testing.expect(r.isVoid(12));
}

test "wal3 B1: an append base delta cannot overflow the section LSN" {
    // The decoder's bounds are compared in i64 with the reference's bits and wrap
    // where it wraps. R4's self check happens to gate every negative `lsn` out of
    // pass 2 today, so this exercises the arithmetic directly rather than through
    // an image — the guard is there because that gating is a property of a
    // DIFFERENT rule, not of this function.
    //
    // The reference's own answer on the extreme: `lsn - 1` wraps to i64 maxint, so
    // the delta passes its bound and the base wraps too. Pinned as-is — a port that
    // "fixed" it by refusing would accept a different set of images than the
    // reference on a doctored one.
    var d: Diag = .{};
    const min = std.math.minInt(i64);
    const max = std.math.maxInt(i64);
    const umax = std.math.maxInt(u64);
    try testing.expectEqual(max, try wr.decodeBaseLsn(1, min, 10, &d));
    // A delta above i64 maxint is negative in the reference's arithmetic, and that
    // is what rejects it — not an unsigned comparison.
    try testing.expectError(DbError.DataCorruption, wr.decodeBaseLsn(umax, min, 10, &d));
    try testing.expectError(DbError.DataCorruption, wr.decodeBaseLsn(0, 5, 10, &d));
    try testing.expectError(DbError.DataCorruption, wr.decodeBaseLsn(5, 5, 10, &d));
    try testing.expectError(DbError.DataCorruption, wr.decodeBaseLsn(umax, 5, 10, &d));
    try testing.expectEqual(@as(i64, 1), try wr.decodeBaseLsn(4, 5, 10, &d));
    try testing.expectEqual(max - 1, try wr.decodeBaseLsn(1, max, 10, &d));
}

// -------------------------- the frozen lsn==0 sentinel edge (J0 pins these)

test "wal3 B1: a leading run of lsn zero sections is accepted and replayed" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "z_run");
    defer sc.deinit();
    // Both density checks live under `last_lsn != 0`, so a whole LEADING RUN of
    // crafted lsn==0 sections is accepted — and replayed. Ports must reproduce
    // this, not fix it.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(0, 10, "zero");
    try img.commitRec(0, 11, "also zero");
    try img.commitRec(1, 12, "real");
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectContent(10, "zero");
    try r.expectContent(11, "also zero");
    try r.expectContent(12, "real");
    try testing.expectEqual(@as(i64, 2), r.next_lsn);
}

test "wal3 B1: an lsn zero section after a real one is corruption" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "z_after");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(0, 11, "b");
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.H_LSN_BACK);
}

test "wal3 B1: an lsn-zero-only segment chains by its stated start and does not advance it" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "z_chain");
    defer sc.deinit();
    // Segment 2 holds sections but no LSN the chain can see: it is "empty" for
    // chaining purposes, so segment 3 must state what SEGMENT 2 said it would start
    // at — 2, not 3.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.commitRec(0, 11, "z");
    try two.write(&sc);
    var three = try SegImage.init(a, 3, 2);
    defer three.deinit();
    try three.commitRec(2, 12, "c");
    try three.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectContent(11, "z");
    try testing.expectEqual(@as(i64, 3), r.next_lsn);
}

test "wal3 B1: the self check is skipped for an lsn-zero-only segment" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "z_self");
    defer sc.deinit();
    // first_lsn stays 0, and the gate is `first_lsn != 0` rather than "the segment
    // is nonempty" — a port transcribing "nonempty" refuses an image the reference
    // accepts.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(0, 10, "z");
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectContent(10, "z");
    // All-empty retained set: nextLsn counts from the header, not from 0+1.
    try testing.expectEqual(@as(i64, 1), r.next_lsn);
}

test "wal3 B1: an accepted lsn zero does move the scan-local anchor" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "z_local_anchor");
    defer sc.deinit();
    // The other half of the two-level anchor, and it points the opposite way from
    // the carry test: WITHIN a segment scan, an accepted zero updates the lookahead
    // anchor to 0. Segment 1 ends at LSN 5, so the anchor enters segment 2 at 5;
    // the accepted zero drops it to 0, and the damaged header that follows is then
    // proven corrupt by a section carrying 0 + 2. Had the anchor stayed at 5 the
    // walk would have wanted 7, found nothing, and truncated the tail away.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 1, "a");
    try one.commitRec(2, 2, "b");
    try one.commitRec(3, 3, "c");
    try one.commitRec(4, 4, "d");
    try one.commitRec(5, 5, "e");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 6);
    defer two.deinit();
    try two.commitRec(0, 10, "z");
    try two.commitRec(1, 11, "damaged");
    try two.commitRec(2, 12, "proof");
    two.damage(two.off(1));
    try two.write(&sc);
    try expectRefusal(a, &sc, wr.H_MIDLOG_HDR);
}

test "wal3 B1: an append inside an lsn zero section refuses on its delta" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "z_append");
    defer sc.deinit();
    // There IS an image-level route into the decoder with `lsn == 0`: leading
    // zero-LSN sections replay, and one may carry a `T_APPEND`. Both bounds of the
    // delta rule are total at zero — `delta >= 1` and `delta <= lsn - 1 == -1`
    // cannot both hold — so the reference refuses, and so does this port.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(0, 10, "a");
    var b = Body.init(a);
    defer b.deinit();
    try b.append(10, 1, "b");
    try img.commit(0, &b);
    try img.commitRec(1, 11, "c");
    try img.write(&sc);

    var diag: Diag = .{};
    const r = openRw(a, &sc, &diag);
    if (r) |ok| {
        var m = ok;
        m.deinit();
        return error.TestExpectedCorruption;
    } else |e| {
        try testing.expectEqual(DbError.DataCorruption, e);
        try testing.expectEqualStrings(wr.R_APPEND_DELTA, diag.reason);
        try testing.expectEqual(@as(i64, 1), diag.detail);
        try testing.expectEqual(@as(u64, 10), diag.recid);
    }
}

test "wal3 B1: a leading zero does not excuse the first nonzero from the header" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "z_first_nonzero");
    defer sc.deinit();
    // The zeros are invisible to `first_lsn`, so the first NONZERO section becomes
    // both recorded endpoints and must answer to the header like any other. Here it
    // does not.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(0, 10, "z");
    try img.commitRec(2, 11, "b");
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.R_SELF);
}

test "wal3 B1: an lsn-zero-only segment does not erase the cross-segment anchor" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "z_anchor");
    defer sc.deinit();
    // Segment 2 ends with an accepted lsn==0 section, so the carry stays at segment
    // 1's last LSN. The anchor is only observable through the lookahead, so segment
    // 3 carries a damaged header followed by exactly carry+2 == 3: corruption if
    // the anchor survived, torn tail if not.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.commitRec(0, 11, "z");
    try two.write(&sc);
    var three = try SegImage.init(a, 3, 2);
    defer three.deinit();
    try three.commitRec(2, 12, "c");
    try three.commitRec(3, 13, "d");
    three.damage(three.off(0));
    try three.write(&sc);
    try expectRefusal(a, &sc, wr.H_MIDLOG_HDR);
}

// ------------------------------------------------------- R6, the §4.2 table

test "wal3 B1: a content record sets both identities" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_content");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(?i64, 1), r.ids.content_base_lsn.get(10));
    try testing.expectEqual(@as(?i64, 1), r.ids.state_lsn.get(10));
}

test "wal3 B1: a null record clears the content base but keeps the state" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_null");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 10, null);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectNullContent(10); // null content, not void
    try testing.expectEqual(@as(?i64, null), r.ids.content_base_lsn.get(10));
    try testing.expectEqual(@as(?i64, 2), r.ids.state_lsn.get(10));
}

test "wal3 B1: prealloc over a content-live record refuses" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_prealloc_live");
    defer sc.deinit();
    // walPrealloc no-ops on a set slot, so applying it here would leave a live
    // record while the identities describe a preallocated one.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    var b = Body.init(a);
    defer b.deinit();
    try b.prealloc(10);
    try img.commit(2, &b);
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.R_PREALLOC_LIVE);
}

test "wal3 B1: prealloc over a null record is allowed and state only" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_prealloc_null");
    defer sc.deinit();
    // The precondition is "not content-live", stated to be TOTAL: a null-content
    // target is neither void nor already preallocated, and a port phrasing it
    // "void or P" diverges here.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, null);
    var b = Body.init(a);
    defer b.deinit();
    try b.prealloc(10);
    try img.commit(2, &b);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(?i64, null), r.ids.content_base_lsn.get(10));
    try testing.expectEqual(@as(?i64, 2), r.ids.state_lsn.get(10));
}

test "wal3 B1: delete clears both identities" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_delete");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    var b = Body.init(a);
    defer b.deinit();
    try b.delete(10);
    try img.commit(2, &b);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expect(r.isVoid(10));
    try testing.expectEqual(@as(?i64, null), r.ids.content_base_lsn.get(10));
    try testing.expectEqual(@as(?i64, null), r.ids.state_lsn.get(10));
}

test "wal3 B1: deleting a record that was never established is a no-op" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_delete_void");
    defer sc.deinit();
    // The shape a cleaned log leaves: the section that created recid 10 is gone,
    // and this delete is the only surviving mention of it. Refusing here would turn
    // a correctly cleaned log into an unopenable store.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    var b = Body.init(a);
    defer b.deinit();
    try b.delete(10);
    try b.record(11, "b");
    try img.commit(1, &b);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expect(r.isVoid(10));
    try r.expectContent(11, "b");
}

test "wal3 B1: an append on its stated base applies" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_append");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    var b = Body.init(a);
    defer b.deinit();
    try b.append(10, 1, "bc");
    try img.commit(2, &b);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectContent(10, "abc");
    // Neither identity moves: an append is not a self-contained state.
    try testing.expectEqual(@as(?i64, 1), r.ids.content_base_lsn.get(10));
    try testing.expectEqual(@as(?i64, 1), r.ids.state_lsn.get(10));
}

test "wal3 B1: an append whose base is gone is skipped and then audited" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_skip");
    defer sc.deinit();
    // The mark retires the segment holding recid 10's image, and nothing
    // re-establishes it: the store cannot be reconstructed, so the open refuses
    // rather than return a record missing acknowledged bytes.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.imageRec(2, 9, "i");
    try two.mark(3, 1, 2);
    var b = Body.init(a);
    defer b.deinit();
    try b.append(10, 3, "bc");
    try two.commit(4, &b);
    try two.write(&sc);

    var diag: Diag = .{};
    const r = openRw(a, &sc, &diag);
    if (r) |ok| {
        var m = ok;
        m.deinit();
        return error.TestExpectedCorruption;
    } else |e| {
        try testing.expectEqual(DbError.DataCorruption, e);
        try testing.expectEqualStrings(wr.R_AUDIT, diag.reason);
        try testing.expectEqual(@as(u64, 10), diag.recid);
        try testing.expectEqual(@as(i64, 1), diag.detail);
    }
    // R5 ran BEFORE R6, so this refusal observes a namespace already pruned. "A
    // failed open leaves the files untouched" is NOT a v3 invariant, and pretending
    // otherwise is how a port ends up asserting it somewhere.
    try expectOnDisk(&sc, &.{2});
}

test "wal3 B1: the audit refuses before W7 touches the torn tail" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "audit_before_w7");
    defer sc.deinit();
    // The ordering rule needs BOTH faults in one image to be visible: a stranded
    // append (which the audit refuses) and a torn active tail (which W7 would
    // truncate). Running W7 first would leave the same file SET, so only the active
    // segment's LENGTH can witness the order.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.imageRec(2, 9, "i");
    try two.mark(3, 1, 2);
    var b = Body.init(a);
    defer b.deinit();
    try b.append(10, 3, "stranded");
    try two.commit(4, &b);
    try two.commitRec(5, 12, "tail");
    two.cutTo(@as(usize, @intCast(two.off(3))) + 9);
    try two.write(&sc);
    const before: u64 = two.len();

    var diag: Diag = .{};
    const r = openRw(a, &sc, &diag);
    if (r) |ok| {
        var m = ok;
        m.deinit();
        return error.TestExpectedCorruption;
    } else |e| {
        try testing.expectEqual(DbError.DataCorruption, e);
        try testing.expectEqualStrings(wr.R_AUDIT, diag.reason);
    }
    try expectOnDisk(&sc, &.{2});
    try testing.expectEqual(before, try sc.fileLen(2));
}

test "wal3 B1: a mark before a torn tail still authorizes its unlinks" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "k_torn_mark");
    defer sc.deinit();
    // K3: a mark living in the torn-tail-prone active segment may itself be
    // truncated, and that only under-collects. The converse needs pinning too — a
    // mark that survived AHEAD of the tear must still drive R5. An implementation
    // that discarded the segment-local maximum on the torn-tail return would
    // silently stop cleaning at recovery, and no other assertion here would notice.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "gone");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.imageRec(2, 11, "kept");
    try two.mark(3, 1, 2);
    try two.commitRec(4, 12, "tail");
    two.cutTo(@as(usize, @intCast(two.off(2))) + 9);
    try two.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try expectOnDisk(&sc, &.{ 2, 3 });
    try r.expectContent(11, "kept");
    try testing.expect(r.isVoid(12));
    try testing.expectEqual(@as(i64, 4), r.next_lsn);
}

test "wal3 B1: a skipped append is discharged by a later self-contained entry" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_skip_ok");
    defer sc.deinit();
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.imageRec(2, 9, "i");
    try two.mark(3, 1, 2);
    var b = Body.init(a);
    defer b.deinit();
    try b.append(10, 3, "bc");
    try two.commit(4, &b);
    try two.commitRec(5, 10, "whole");
    try two.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectContent(10, "whole");
    try testing.expectEqual(@as(i64, 6), r.next_lsn);
}

test "wal3 B1: a skipped append's payload is still consumed" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_skip_frame");
    defer sc.deinit();
    // The entry after the skipped append must decode, which it only can if the skip
    // consumed its payload: the frame is still framed.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.imageRec(2, 9, "i");
    try two.mark(3, 1, 2);
    var b = Body.init(a);
    defer b.deinit();
    try b.append(10, 3, "payload-that-must-be-skipped");
    try b.record(12, "after");
    try two.commit(4, &b);
    try two.commitRec(5, 10, "whole");
    try two.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectContent(12, "after");
}

test "wal3 B1: prealloc over a void record establishes it" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_prealloc_void");
    defer sc.deinit();
    // The row that proves `walPrealloc` actually ACTS; the other two prealloc tests
    // only prove what it refuses and what it tolerates.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    var b = Body.init(a);
    defer b.deinit();
    try b.prealloc(10);
    try img.commit(1, &b);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectNullContent(10); // preallocated: present, no content
    try testing.expect(!r.isVoid(10));
    try testing.expectEqual(@as(?i64, 1), r.ids.state_lsn.get(10));
    try testing.expectEqual(@as(?i64, null), r.ids.content_base_lsn.get(10));
}

test "wal3 B1: every self-contained entry discharges a pending skip" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_skip_discharge");
    defer sc.deinit();
    // Three stranded appends, discharged three different ways — a null record, a
    // prealloc and a delete. Only the content-record path was covered before, and
    // the audit is a refusal channel: a row that failed to clear the set would turn
    // a recoverable log into a refused open.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    var b0 = Body.init(a);
    defer b0.deinit();
    try b0.record(10, "a");
    try b0.record(11, "b");
    try b0.record(12, "c");
    try one.commit(1, &b0);
    try one.write(&sc);

    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.imageRec(2, 9, "i");
    try two.mark(3, 1, 2);
    var b1 = Body.init(a);
    defer b1.deinit();
    try b1.append(10, 3, "x");
    try b1.append(11, 3, "y");
    try b1.append(12, 3, "z");
    try two.commit(4, &b1);
    var b2 = Body.init(a);
    defer b2.deinit();
    try b2.record(10, null);
    try b2.prealloc(11);
    try b2.delete(12);
    try two.commit(5, &b2);
    try two.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectNullContent(10);
    try r.expectNullContent(11);
    try testing.expect(r.isVoid(12));
}

test "wal3 B1: an append citing a base below the applied one refuses" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_append_low");
    defer sc.deinit();
    // recid 10's applied image is LSN 1; the append at LSN 3 cites base 2.
    // Unreachable in a conforming set — retirement is a prefix in LSN order, so a
    // base ABOVE the applied one cannot be the missing part — and defence in depth
    // over the density rule.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.commitRec(2, 11, "filler");
    var b = Body.init(a);
    defer b.deinit();
    try b.append(10, 1, "c");
    try img.commit(3, &b);
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.R_APPEND_BASE_HIGH);
}

test "wal3 B1: an append delta outside its bounds refuses" {
    const a = testing.allocator;
    const rows = [_]struct { delta: u64, lsn: i64 }{
        .{ .delta = 0, .lsn = 2 },
        .{ .delta = 2, .lsn = 2 },
    };
    for (rows) |row| {
        var sc = try Scratch.init(a, "id_delta");
        defer sc.deinit();
        var img = try SegImage.init(a, 1, 1);
        defer img.deinit();
        try img.commitRec(1, 10, "a");
        var b = Body.init(a);
        defer b.deinit();
        try b.append(10, row.delta, "c");
        try img.commit(row.lsn, &b);
        try img.write(&sc);
        try expectRefusal(a, &sc, wr.R_APPEND_DELTA);
    }
}

test "wal3 B1: a superseded record is reapplied" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_resupply");
    defer sc.deinit();
    // Idempotent, so replay does not try to be clever about which image "wins" — it
    // applies them all in LSN order and the last one stands.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "first");
    try img.commitRec(2, 10, "second");
    try img.commitRec(3, 10, "third");
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectContent(10, "third");
    try testing.expectEqual(@as(?i64, 3), r.ids.content_base_lsn.get(10));
}

test "wal3 B1: two entries for one recid in one section refuse" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_twice");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    var b = Body.init(a);
    defer b.deinit();
    try b.record(10, "a");
    try b.record(10, "b");
    try img.commit(1, &b);
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.R_RECID_TWICE);
}

test "wal3 B1: the one-entry rule covers image sections too" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_twice_c");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    var b = Body.init(a);
    defer b.deinit();
    try b.record(10, "a");
    try b.delete(10);
    try img.image(1, &b);
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.R_RECID_TWICE);
}

test "wal3 B1: an unknown entry tag refuses" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_tag");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    var b = Body.init(a);
    defer b.deinit();
    try b.raw(&[_]u8{ 9, 0x81 });
    try img.commit(1, &b);
    try img.write(&sc);

    var diag: Diag = .{};
    const r = openRw(a, &sc, &diag);
    if (r) |ok| {
        var m = ok;
        m.deinit();
        return error.TestExpectedCorruption;
    } else |e| {
        try testing.expectEqual(DbError.DataCorruption, e);
        try testing.expectEqualStrings(wr.R_ENTRY_TAG, diag.reason);
        try testing.expectEqual(@as(i64, 9), diag.detail);
    }
}

test "wal3 B1: an entry overrunning its section body refuses" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_overrun");
    defer sc.deinit();
    // A record claiming 40 bytes of payload inside a body that holds none:
    // CRC-valid, so it is a writer defect, not a torn tail.
    var out = DataOutput2.init(a);
    defer out.deinit();
    try out.writeU8(T_RECORD);
    try out.packLong(10);
    try out.packLong(48);
    try out.packLong(41);
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.section(TAG_SECTION, 1, out.bytes());
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.R_RECORD_LEN);
}

test "wal3 B1: a capacity no conforming writer would record refuses" {
    const a = testing.allocator;
    // capValid in full. The rule is not "any plausible number": the writer records
    // 0 for null content AND for an oversize (linked) record, whose chunk chain has
    // no plain capacity, and a 16-aligned capacity big enough for the 4-byte header
    // plus content otherwise.
    const over: u64 = @as(u64, iv.MAX_CAPACITY);
    const twelve = [_]u8{0} ** 12;
    const thirteen = [_]u8{0} ** 13;
    const Row = struct { cap: u64, content: ?[]const u8, ok: bool };
    const rows = [_]Row{
        .{ .cap = 0, .content = null, .ok = true }, // the null record
        .{ .cap = 16, .content = null, .ok = false }, // null content never carries one
        .{ .cap = 16, .content = "a", .ok = true }, // 16 >= 4 + 1, aligned
        // EXACT fit, and the row a conforming writer actually emits for 12 bytes:
        // `capFor(12) == 16 == 4 + 12`. Without it, tightening the bound to
        // `cap > 4 + len` refuses images Java accepts and the whole matrix stays
        // green.
        .{ .cap = 16, .content = &twelve, .ok = true },
        .{ .cap = 0, .content = "a", .ok = false }, // 0 is reserved for oversize
        .{ .cap = 4, .content = "a", .ok = false }, // big enough, not 16-aligned
        .{ .cap = 16, .content = &thirteen, .ok = false }, // aligned, too small for 4 + 13
        .{ .cap = over + 16, .content = "a", .ok = false }, // past the plain-record limit
        .{ .cap = 16, .content = "", .ok = true }, // zero-length content is content
    };
    for (rows) |row| {
        var sc = try Scratch.init(a, "id_cap");
        defer sc.deinit();
        var img = try SegImage.init(a, 1, 1);
        defer img.deinit();
        var b = Body.init(a);
        defer b.deinit();
        try b.recordCap(10, row.cap, row.content);
        try img.commit(1, &b);
        try img.write(&sc);
        if (row.ok) {
            var diag: Diag = .{};
            var r = try openRw(a, &sc, &diag);
            r.deinit();
        } else {
            try expectRefusal(a, &sc, wr.R_RECORD_CAP);
        }
    }
}

test "wal3 B1: an oversize record replays through the linked path" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_oversize");
    defer sc.deinit();
    // The other arm of `capValid`: a record too large for the plain capacity model
    // is written with capacity 0, because a chunk chain has no plain capacity and
    // the layout is re-chosen on replay. Nothing else in this module exercises
    // either that arm or the inner store's linked write, and both are on the
    // ordinary path for any large value.
    const big = try a.alloc(u8, iv.MAX_CAPACITY - 3);
    defer a.free(big);
    @memset(big, 0x5A);
    try testing.expect(4 + big.len > iv.MAX_CAPACITY);
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    var b = Body.init(a);
    defer b.deinit();
    try b.recordCap(10, 0, big);
    try img.commit(1, &b);
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectContent(10, big);
}

test "wal3 B1: an append the inner store refuses is corruption" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_refused");
    defer sc.deinit();
    // An exact-fit record has no headroom, so the append cannot be applied in
    // place. The log says it was; the log is therefore not one this writer produced.
    const twelve = [_]u8{7} ** 12;
    const forty = [_]u8{9} ** 40;
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    var b0 = Body.init(a);
    defer b0.deinit();
    try b0.recordCap(10, 16, &twelve);
    try img.commit(1, &b0);
    var b1 = Body.init(a);
    defer b1.deinit();
    try b1.append(10, 1, &forty);
    try img.commit(2, &b1);
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.R_APPEND_REFUSED);
}

test "wal3 B1: an overlong packed long refuses rather than running on" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_packlong");
    defer sc.deinit();
    // The port's 10-byte cap, which the reference does not have: it loops to the
    // terminator. A recorded strictness difference, so it gets a test that names it
    // rather than living only in a comment.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    var b = Body.init(a);
    defer b.deinit();
    try b.raw(&[_]u8{ T_RECORD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
    try img.commit(1, &b);
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.R_PACKLONG);
}

test "wal3 B1: a revived recid is not handed out again after replay" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r7_freelist");
    defer sc.deinit();
    // Delete-then-revive leaves the deleted recid on the allocator's free list while
    // the later section makes it live again. Without R7's `rebuildFreeRecids` the
    // next allocation hands out a LIVE recid and overwrites it — a silent corruption
    // channel that no other assertion in this module can see, because it only shows
    // up on the first allocation AFTER recovery.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    var b = Body.init(a);
    defer b.deinit();
    try b.delete(10);
    try img.commit(2, &b);
    try img.commitRec(3, 10, "revived");
    try img.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try r.expectContent(10, "revived");
    const fresh = try r.inner.preallocate();
    try testing.expect(fresh != 10);
    try r.expectContent(10, "revived");
}

test "wal3 B1: a reserved recid zero refuses" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "id_recid0");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 1, "a");
    var b = Body.init(a);
    defer b.deinit();
    try b.append(0, 1, "x");
    try img.commit(2, &b);
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.R_RECID_ZERO);
}

test "wal3 B1: a mark body is never handed to the entry decoder" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "k_not_entries");
    defer sc.deinit();
    // A mark whose 16 bytes begin with 0x00 — not a valid entry tag. If the decoder
    // ever saw a 'K' body the open would refuse with an entry verdict; K4 holds it
    // instead (segment 1 cannot authorize removing segment 1), which is a MARK
    // verdict.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.imageRec(1, 10, "i");
    try img.mark(2, 1, 1);
    try img.write(&sc);
    try expectRefusal(a, &sc, wr.H_MARK_SELF);
}

// ----------------------------------------------------------------------- R7

test "wal3 B1: next LSN follows the highest retained section" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r7_next");
    defer sc.deinit();
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.commitRec(2, 11, "b");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 3);
    defer two.deinit();
    try two.commitRec(3, 12, "c");
    try two.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(i64, 4), r.next_lsn);
}

test "wal3 B1: an all-empty retained set counts from the header" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r7_empty");
    defer sc.deinit();
    // "0 + 1" would restart the log at 1 and reissue LSNs a mark already accounted
    // for, which is why firstLsn is in the header. Note what this test can and
    // cannot show: the fallback is only REACHABLE in an unmarked log — K4 keeps a
    // mark's own segment retained, and that segment is never empty — and the floor
    // then forces the lowest header to state 1, so "count from the header" and
    // "0 + 1" agree on every image that survives R4. The branch is kept because the
    // reference has it, not because a fixture can separate the two readings.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 1);
    defer two.deinit();
    try two.write(&sc);

    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(i64, 1), r.next_lsn);
    try expectOnDisk(&sc, &.{ 1, 2 }); // empty is not torn: no rotate
}

test "wal3 B1: a fresh store creates its first segment and starts at LSN 1" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r7_fresh");
    defer sc.deinit();
    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try expectOnDisk(&sc, &.{1});
    try testing.expectEqual(@as(i64, 1), r.next_lsn);
    try testing.expectEqual(@as(i64, 1), r.set.active().?.headerFirstLsn());
}

test "wal3 B1: a fresh store beside burnt residue uses the burnt successor" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r7_burnt");
    defer sc.deinit();
    // W6: the residue's name is burned even though the file is removed, so a stale
    // directory entry can never alias a segment a later create reuses.
    try sc.writeSegment(7, &[_]u8{0} ** 4);
    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try expectOnDisk(&sc, &.{8});
    try testing.expectEqual(@as(i64, 1), r.next_lsn);
}

// ------------------------------------------------------------ read-only mode

test "wal3 B1: a read-only recovery mutates nothing" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "ro_nothing");
    defer sc.deinit();
    // Every mutation R5/R7 could make is armed here: a superseded segment to unlink,
    // create-crash residue to delete, and a torn tail to truncate and rotate.
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "gone");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.imageRec(2, 11, "kept");
    try two.mark(3, 1, 2);
    try two.commitRec(4, 12, "tail");
    two.cutTo(@as(usize, @intCast(two.off(2))) + 9);
    try two.write(&sc);
    try sc.writeSegment(3, &[_]u8{0} ** 4);

    const before = try sc.onDisk();
    defer a.free(before);
    const before_lens = try a.alloc(u64, before.len);
    defer a.free(before_lens);
    for (before, 0..) |s, i| before_lens[i] = try sc.fileLen(s);

    var diag: Diag = .{};
    var r = try openRo(a, &sc, &diag);
    defer r.deinit();
    try r.expectContent(11, "kept");
    try testing.expect(r.isVoid(10)); // superseded segments are not replayed
    try testing.expectEqual(@as(i64, 4), r.next_lsn);

    const after = try sc.onDisk();
    defer a.free(after);
    try testing.expectEqualSlices(i64, before, after);
    for (after, 0..) |s, i| try testing.expectEqual(before_lens[i], try sc.fileLen(s));
    try testing.expectEqual(@as(u64, 0), r.set.dir_fsyncs);
}

test "wal3 B1: a read-only recovery reaches the same answers as a writable one" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "ro_same");
    defer sc.deinit();
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(&sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.imageRec(2, 10, "kept");
    try two.mark(3, 1, 2);
    try two.write(&sc);

    var ro_next: i64 = 0;
    {
        var diag: Diag = .{};
        var ro = try openRo(a, &sc, &diag);
        defer ro.deinit();
        ro_next = ro.next_lsn;
        try ro.expectContent(10, "kept");
    }
    var diag: Diag = .{};
    var rw = try openRw(a, &sc, &diag);
    defer rw.deinit();
    try testing.expectEqual(rw.next_lsn, ro_next);
    try rw.expectContent(10, "kept");
}

test "wal3 B1: a read-only fresh store creates no segment" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "ro_fresh");
    defer sc.deinit();
    var diag: Diag = .{};
    var r = try openRo(a, &sc, &diag);
    defer r.deinit();
    try expectOnDisk(&sc, &.{});
    try testing.expectEqual(@as(i64, 1), r.next_lsn);
    try testing.expect(r.set.active() == null);
}

test "wal3 B1: a read-only recovery refuses the same images" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "ro_refuse");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(2, 10, "a");
    try img.write(&sc);

    var diag: Diag = .{};
    const r = openRo(a, &sc, &diag);
    if (r) |ok| {
        var m = ok;
        m.deinit();
        return error.TestExpectedCorruption;
    } else |e| {
        try testing.expectEqual(DbError.DataCorruption, e);
        try testing.expectEqualStrings(wr.R_SELF, diag.reason);
    }
}

// ------------------------------------------------------------- descriptors

test "wal3 B1: recovery leaves one descriptor open whatever the segment count" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "fds");
    defer sc.deinit();
    const n: i64 = 40;
    var seq: i64 = 1;
    while (seq <= n) : (seq += 1) {
        var s = try SegImage.init(a, seq, seq);
        defer s.deinit();
        try s.commitRec(seq, @intCast(seq), "x");
        try s.write(&sc);
    }
    var diag: Diag = .{};
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqual(@as(usize, @intCast(n)), r.set.segmentsSlice().len);
    // Both passes release as they go: nothing reads a segment after recovery, and a
    // store is allowed to reach thousands of them.
    try testing.expectEqual(@as(usize, 1), r.set.openFileCount());
}

// -------------------------------------------------- the windowed reader itself

test "wal3 B1: the hard limit lets one window span several sections" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "secin_hard");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "aaaa");
    try img.commitRec(2, 11, "bbbb");
    try img.commitRec(3, 12, "cccc");
    try img.write(&sc);

    const p = try sc.segPath(1);
    defer a.free(p);
    const f = try std.fs.cwd().openFile(p, .{});
    defer f.close();

    var diag: Diag = .{};
    // The replay shape: `reset` makes both bounds the section's end, so a window
    // never reads past the section it is decoding — one read per section.
    var in = try wr.SecIn.init(f, a, 4096, &diag);
    defer in.deinit();
    in.reset(img.off(0) + SEC_HDR, img.off(1));
    _ = try in.readByte();
    try testing.expectEqual(@as(u64, 1), in.reads);
    in.reset(img.off(1) + SEC_HDR, img.off(2));
    _ = try in.readByte();
    try testing.expectEqual(@as(u64, 2), in.reads);

    // B3's scan shape: one hard bound over the whole segment, then `rebound` per
    // section. The second and third sections come out of the window the first read
    // already filled — which is the entire point of the split, and the difference
    // Java measured as ~148k reads to walk 34 MB.
    var scan = try wr.SecIn.init(f, a, 4096, &diag);
    defer scan.deinit();
    scan.resetHard(img.off(0) + SEC_HDR, img.len());
    scan.rebound(img.off(0) + SEC_HDR, img.off(1));
    _ = try scan.readByte();
    try testing.expectEqual(@as(u64, 1), scan.reads);
    scan.rebound(img.off(1) + SEC_HDR, img.off(2));
    _ = try scan.readByte();
    scan.rebound(img.off(2) + SEC_HDR, img.len());
    _ = try scan.readByte();
    try testing.expectEqual(@as(u64, 1), scan.reads);

    // And `seek` keeps the window when it covers the target: the payload skip that
    // makes a scan cost entries rather than bytes.
    scan.rebound(img.off(0) + SEC_HDR, img.len());
    scan.seek(img.off(2) + SEC_HDR);
    _ = try scan.readByte();
    try testing.expectEqual(@as(u64, 1), scan.reads);
}

test "wal3 B1: a read past the section's soft limit is corruption, not a torn tail" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "secin_overrun");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "aaaa");
    try img.write(&sc);

    const p = try sc.segPath(1);
    defer a.free(p);
    const f = try std.fs.cwd().openFile(p, .{});
    defer f.close();

    var diag: Diag = .{};
    var in = try wr.SecIn.init(f, a, 4096, &diag);
    defer in.deinit();
    // A one-byte section window: the second read has nowhere to go, and pass 1
    // already proved these bytes whole, so the framing — not the file — is wrong.
    in.reset(img.off(0) + SEC_HDR, img.off(0) + SEC_HDR + 1);
    _ = try in.readByte();
    try testing.expectError(DbError.DataCorruption, in.readByte());
    try testing.expectEqualStrings(wr.R_ENTRY_OVERRUN, diag.reason);
}

// ------------------------------------------------- risk 14: allocator failure

/// Fails EXACTLY the `fail_at`-th allocation and no other.
///
/// One-shot rather than latched, deliberately. A latched allocator makes every
/// later allocation fail too, so an implementation that swallowed the first
/// failure and carried on would still return *some* error, and a test that
/// accepts any error would pass it. One-shot makes the observed result the one
/// that allocation produced.
///
/// **Growing `resize`/`remap` are always refused, and are not counted.** Refusing
/// one is a legal answer that `ArrayList` and friends recover from by allocating
/// and copying — it is NOT an allocation failure, and injecting there would test a
/// path that cannot fail in production. Refusing them unconditionally instead
/// routes every growth through `alloc`, which is the only call that can fail, and
/// keeps the counting run's indices identical to the injected runs'.
pub const FailingAllocator = struct {
    inner: Allocator,
    /// Index of the allocation that fails, or `null` to fail none (counting run).
    fail_at: ?usize,
    calls: usize = 0,

    pub fn allocator(self: *FailingAllocator) Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = allocFn,
            .resize = resizeFn,
            .remap = remapFn,
            .free = freeFn,
        } };
    }

    fn allocFn(ctx: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        defer self.calls += 1;
        if (self.fail_at) |n| if (n == self.calls) return null;
        return self.inner.rawAlloc(len, al, ra);
    }

    fn resizeFn(ctx: *anyopaque, buf: []u8, al: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len) return false;
        return self.inner.rawResize(buf, al, new_len, ra);
    }

    fn remapFn(ctx: *anyopaque, buf: []u8, al: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len) return null;
        return self.inner.rawRemap(buf, al, new_len, ra);
    }

    fn freeFn(ctx: *anyopaque, buf: []u8, al: std.mem.Alignment, ra: usize) void {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        self.inner.rawFree(buf, al, ra);
    }
};

/// The risk-14 image, written into `sc`: two segments that between them exercise
/// every allocating path a successful recovery has. Segment 1 is superseded (so
/// R5's move-out list allocates), segment 2 carries a `'C'` image, a mark, an
/// append that must be SKIPPED and remembered, and the self-contained entry that
/// discharges the skip — so the open succeeds while `skipped_appends` is
/// populated, which a one-record image never does.
fn writeRisk14Image(a: Allocator, sc: *const Scratch) !void {
    var one = try SegImage.init(a, 1, 1);
    defer one.deinit();
    try one.commitRec(1, 10, "a");
    try one.write(sc);
    var two = try SegImage.init(a, 2, 2);
    defer two.deinit();
    try two.imageRec(2, 9, "i");
    try two.mark(3, 1, 2);
    var b = Body.init(a);
    defer b.deinit();
    try b.append(10, 3, "stranded-payload");
    try two.commit(4, &b);
    try two.commitRec(5, 10, "whole");
    try two.write(sc);
}

test "wal3 B1: an allocation failure during recovery is operational, never a verdict" {
    const a = testing.allocator;

    // Establish how many allocations a successful recovery of this image takes,
    // then fail each one in turn — ONE-SHOT, so the round resumes succeeding
    // afterwards and the result observed is the one that allocation produced, not
    // a later cascade.
    //
    // Every round must answer `OutOfMemory`. That is the assertion risk 14 needs
    // and a permanently-failing allocator cannot make: with the failure latched
    // on, an implementation that caught an allocation failure and treated it as a
    // short read — a torn tail, silently truncating the log — would simply fail
    // later on some other allocation, and a test that accepted any error would
    // call that a pass. The empty `Diag` is the second half: an allocation failure
    // is operational and must never be recorded as a verdict about the bytes.
    var budget: usize = 0;
    {
        var sc = try Scratch.init(a, "risk14budget");
        defer sc.deinit();
        try writeRisk14Image(a, &sc);
        var counting = FailingAllocator{ .inner = a, .fail_at = null };
        const ca = counting.allocator();
        var diag: Diag = .{};
        var r = try openRw(ca, &sc, &diag);
        // Counted BEFORE the teardown: `deinit` allocates too, and injecting there
        // would fail a round whose OPEN legitimately succeeded.
        budget = counting.calls;
        r.deinit();
    }
    try testing.expect(budget > 8);

    var n: usize = 0;
    while (n < budget) : (n += 1) {
        var sc2 = try Scratch.init(a, "risk14n");
        defer sc2.deinit();
        // A fresh namespace per round: R5 unlinks segment 1, so a round cannot run
        // against the image an earlier one already pruned.
        try writeRisk14Image(a, &sc2);
        var fa = FailingAllocator{ .inner = a, .fail_at = n };
        const ca = fa.allocator();
        var diag: Diag = .{};
        const r = openRw(ca, &sc2, &diag);
        if (r) |ok| {
            var m = ok;
            m.deinit();
            std.debug.print("round {d}/{d} did not fail\n", .{ n, budget });
            return error.TestExpectedOutOfMemory;
        } else |e| {
            testing.expectEqual(DbError.OutOfMemory, e) catch |fail| {
                std.debug.print("round {d}/{d}: {s}\n", .{ n, budget, diag.reason });
                return fail;
            };
            try testing.expectEqualStrings("", diag.reason);
        }
    }
}

test "wal3 B1: an inner-store verdict raised during replay reaches the caller with a reason" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "inner_fault");
    defer sc.deinit();
    // The one refusal channel replay does not own: the inner store validates the
    // slot it is about to overwrite and answers `DataCorruption` when its parity
    // is broken. No hand-built WAL image can produce that — `capValid` mirrors
    // `walPut`'s capacity domain exactly and the identity table only applies an
    // append to a record it has just seen established — so the fault is injected
    // into the store instead, which is the only way to prove the reason is wired
    // to the right call rather than merely declared.
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    var b = Body.init(a);
    defer b.deinit();
    try b.delete(10);
    try img.commit(1, &b);
    try img.write(&sc);

    var set = try WalSegmentSet.open(a, sc.base, false);
    defer set.deinit();
    var inner = try StoreDirect.init(a, true);
    defer inner.deinit();
    try inner.walPut(10, 16, "seed");
    try inner.corruptIndexSlotForTest(10);

    // Seeded with a reason from an imaginary earlier open: `recover` must clear it,
    // so the caller cannot mistake a stale explanation for this refusal's.
    var diag: Diag = .{ .reason = wr.R_CHAIN, .seq = 99 };
    try testing.expectError(DbError.DataCorruption, wr.recover(&set, &inner, BUF, a, &diag));
    try testing.expectEqualStrings(wr.R_INNER_STORE, diag.reason);
    try testing.expectEqual(@as(u64, 10), diag.recid);
    try testing.expectEqual(@as(i64, 0), diag.seq);
}

test "wal3 B1: a successful recovery leaves no reason behind" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "diag_cleared");
    defer sc.deinit();
    var img = try SegImage.init(a, 1, 1);
    defer img.deinit();
    try img.commitRec(1, 10, "a");
    try img.write(&sc);

    var diag: Diag = .{ .reason = wr.R_SELF, .seq = 7, .at = 36, .recid = 3, .detail = 9 };
    var r = try openRw(a, &sc, &diag);
    defer r.deinit();
    try testing.expectEqualStrings("", diag.reason);
    try testing.expectEqual(@as(i64, 0), diag.seq);
    try testing.expectEqual(@as(u64, 0), diag.at);
}
