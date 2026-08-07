//! Tests for the WAL v3 segment-set namespace layer (slice B0).
//!
//! Mirrors `mapdb-rust-store/src/store/wal_segments.rs`'s test module, which is
//! itself the Rust half of Java's `WalTestKit`. The byte-level recipes live in
//! one place here too, so a hand-built image cannot drift from the writer's.
//!
//! Kept in its own file, like `store_wal_test.zig` and `store_direct_test.zig`:
//! `wal_segments.zig` is already long, and the suite is the larger half.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const DbError = @import("../errors.zig").DbError;
const ws = @import("wal_segments.zig");
const wal_io = @import("wal_io.zig");
const WalSegmentSet = ws.WalSegmentSet;
const Segment = ws.Segment;
const SEG_HDR = ws.SEG_HDR;
const SEG_HDR_CRC_LEN = ws.SEG_HDR_CRC_LEN;
const FIRST_SEQ = ws.FIRST_SEQ;
const buildHeader = ws.buildHeader;
const Crc32 = std.hash.crc.Crc32;

// ------------------------------------------------------------------ test kit

var scratch_n: std.atomic.Value(u64) = .init(0);

/// A scratch directory plus the `store.db` base inside it, and the byte-level
/// recipes that build images under it. `deinit` removes the tree.
const Scratch = struct {
    alloc: Allocator,
    dir: []u8,
    base: []u8,

    fn init(alloc: Allocator, tag: []const u8) !Scratch {
        const n = scratch_n.fetchAdd(1, .monotonic);
        const dir = try std.fmt.allocPrint(
            alloc,
            "/tmp/mapdb5_walseg_{d}_{s}_{d}",
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

    /// `<dir>/<name>`; owned.
    fn path(self: *const Scratch, name: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.alloc, "{s}/{s}", .{ self.dir, name });
    }

    /// `<base><suffix>`; owned.
    fn sibling(self: *const Scratch, suffix: []const u8) ![]u8 {
        return std.mem.concat(self.alloc, u8, &.{ self.base, suffix });
    }

    /// `<base>.wal.<seq:016x>`; owned. Written out by hand rather than borrowed
    /// from the module under test — a name grammar the test agrees with because
    /// it calls the same function is not a test of the grammar.
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
        try writeFile(p, bytes);
    }

    fn writeNamed(self: *const Scratch, name: []const u8, bytes: []const u8) !void {
        const p = try self.path(name);
        defer self.alloc.free(p);
        try writeFile(p, bytes);
    }

    fn exists(self: *const Scratch, name: []const u8) !bool {
        const p = try self.path(name);
        defer self.alloc.free(p);
        return pathExists(p);
    }

    fn segExists(self: *const Scratch, seq: i64) !bool {
        const p = try self.segPath(seq);
        defer self.alloc.free(p);
        return pathExists(p);
    }

    fn open(self: *const Scratch, read_only: bool) DbError!WalSegmentSet {
        return WalSegmentSet.open(self.alloc, self.base, read_only);
    }

    fn openIo(self: *const Scratch, read_only: bool, io: ?*const wal_io.WalIo) DbError!WalSegmentSet {
        return WalSegmentSet.openWithIo(self.alloc, self.base, read_only, io, null);
    }
};

fn writeFile(path: []const u8, bytes: []const u8) !void {
    const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer f.close();
    try f.writeAll(bytes);
}

fn pathExists(path: []const u8) bool {
    _ = std.posix.fstatat(std.posix.AT.FDCWD, path, std.posix.AT.SYMLINK_NOFOLLOW) catch
        return false;
    return true;
}

fn setMode(path: []const u8, mode: std.posix.mode_t) !void {
    try std.posix.fchmodat(std.posix.AT.FDCWD, path, mode, 0);
}

/// A whole-file OFD lock attempt from an INDEPENDENT description — the test-side
/// twin of the module's private `tryOfdLock`, written out rather than exported so
/// a probe and the thing it probes cannot agree by sharing a bug.
fn probeOfdLock(file: std.fs.File, exclusive: bool) !bool {
    var fl: std.posix.Flock = std.mem.zeroes(std.posix.Flock);
    fl.type = if (exclusive) std.posix.F.WRLCK else std.posix.F.RDLCK;
    fl.whence = std.posix.SEEK.SET;
    fl.start = 0;
    fl.len = 0;
    const F_OFD_SETLK: i32 = 37;
    const rc = std.os.linux.fcntl(file.handle, F_OFD_SETLK, @intFromPtr(&fl));
    return switch (std.os.linux.E.init(rc)) {
        .SUCCESS => true,
        .ACCES, .AGAIN => false,
        else => error.Io,
    };
}

/// The permission-dependent rungs of the lock ladder prove nothing when the test
/// runs as root, which ignores the mode bits they turn on.
fn runningAsRoot() bool {
    return std.os.linux.geteuid() == 0;
}

/// A valid segment image: header only (H8), which is all B0 can produce —
/// sections arrive with the codec in B1. Owned.
fn headerImage(alloc: Allocator, seq: i64, first_lsn: i64) ![]u8 {
    return alloc.dupe(u8, &buildHeader(seq, first_lsn));
}

/// Recomputes `headerCrc` in place, so a doctored header stays CRC-valid and
/// reaches the semantic rows H5-H7/H9 instead of H3.
fn reseal(hdr: []u8) void {
    const crc: i32 = @bitCast(Crc32.hash(hdr[0..SEG_HDR_CRC_LEN]));
    std.mem.writeInt(i32, hdr[SEG_HDR_CRC_LEN..][0..4], crc, .big);
}

const TornShape = struct { tag: []const u8, bytes: []u8 };

/// Every shape of table H's torn-create class, for a segment named `seq`:
/// H1 empty, H2 short, H3 CRC mismatch, H4 CRC-valid wrong magic. Shared by the
/// highest-name (residue) and below-the-highest (corruption) tests so the two
/// cannot drift apart on which shapes they cover.
fn tornShapes(alloc: Allocator, seq: i64) ![4]TornShape {
    const h1 = try alloc.dupe(u8, "");
    const h2 = try alloc.alloc(u8, 16);
    @memset(h2, 0);
    const h3 = try headerImage(alloc, seq, 1);
    h3[24] ^= 0x01; // firstLsn edited without resealing
    const h4 = try headerImage(alloc, seq, 1);
    h4[0] = 'X';
    reseal(h4);
    return .{
        .{ .tag = "h1", .bytes = h1 },
        .{ .tag = "h2", .bytes = h2 },
        .{ .tag = "h3", .bytes = h3 },
        .{ .tag = "h4", .bytes = h4 },
    };
}

fn freeShapes(alloc: Allocator, shapes: []const TornShape) void {
    for (shapes) |s| alloc.free(s.bytes);
}

/// An allocator that fails the n-th allocation and every one after it. The two
/// paths that must not turn `OutOfMemory` into a wrong answer — enumeration, and
/// the list slot a create needs — have no other way to be reached.
const FailingAllocator = struct {
    inner: Allocator,
    /// Allocations still to be served before failing. Counts allocations only,
    /// not frees or resizes.
    budget: usize,

    fn allocator(self: *FailingAllocator) Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc_,
            .resize = resize_,
            .remap = remap_,
            .free = free_,
        } };
    }

    fn alloc_(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        if (self.budget == 0) return null;
        self.budget -= 1;
        return self.inner.rawAlloc(len, a, ra);
    }
    fn resize_(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        // A resize that GROWS is an allocation for our purposes; refusing it
        // sends the ArrayList down its realloc path, which `alloc_` then fails.
        if (new_len > buf.len and self.budget == 0) return false;
        return self.inner.rawResize(buf, a, new_len, ra);
    }
    fn remap_(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len and self.budget == 0) return null;
        return self.inner.rawRemap(buf, a, new_len, ra);
    }
    fn free_(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
        self.inner.rawFree(buf, a, ra);
    }
};

fn seqList(alloc: Allocator, set: *WalSegmentSet) ![]i64 {
    const out = try alloc.alloc(i64, set.segmentsSlice().len);
    for (set.segmentsSlice(), 0..) |s, i| out[i] = s.seq;
    return out;
}

fn expectSeqs(alloc: Allocator, set: *WalSegmentSet, want: []const i64) !void {
    const got = try seqList(alloc, set);
    defer alloc.free(got);
    try testing.expectEqualSlices(i64, want, got);
}

// ------------------------------------------------------------------ H: header

// The byte-level cross-check against the reference implementation: these 36
// bytes are the header of `reject-wal-java-v3.walseg`, a segment produced by
// the Java writer (xfixtures, Stage 2), and they are the same 36 the Rust port
// pins. If this port's builder and Java's disagree by one byte, every section
// CRC in the file differs too, because the header IS the CRC domain.
test "wal3 B0: header bytes match the Java writer" {
    const java = [_]u8{
        0x4d, 0x44, 0x42, 0x53, 0x2e, 0x57, 0x41, 0x4c, // "MDBS.WAL"
        0x00, 0x00, 0x00, 0x03, // version 3
        0x00, 0x00, 0x00, 0x00, // flags 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // seq 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // firstLsn 1
        0x4a, 0x4d, 0x90, 0x4b, // headerCrc
    };
    try testing.expectEqualSlices(u8, &java, &buildHeader(1, 1));
}

// The CRC domain, cross-checked against the same Java artifact: its first
// section sits at offset 36 and carries tag 'S', lsn 1, bodyLen 104, and Java
// sealed its header CRC as 0x9d8280b3 over
// `segmentHeader[0,36) || be64(36) || sectionHeader[0,17)`. A port that seeds a
// register instead of feeding a prefix, or that uses the 28 bytes the Java
// javadoc claims, fails here.
test "wal3 B0: the CRC domain matches the Java writer" {
    const hdr = buildHeader(1, 1);
    var sec_hdr = [_]u8{0} ** 17;
    sec_hdr[0] = 'S';
    std.mem.writeInt(i64, sec_hdr[1..9], 1, .big);
    std.mem.writeInt(i64, sec_hdr[9..17], 104, .big);
    var crc = Crc32.init();
    ws.crcDomainOf(&crc, &hdr, SEG_HDR);
    crc.update(&sec_hdr);
    try testing.expectEqual(@as(u32, 0x9d82_80b3), crc.final());
}

// The domain binds a section to its segment AND to its offset: the same 17
// header bytes seal differently at another offset and in another segment.
test "wal3 B0: the CRC domain binds segment identity and offset" {
    const a = buildHeader(1, 1);
    const b = buildHeader(2, 1);
    const at = struct {
        fn f(h: *const [36]u8, off: u64) u32 {
            var c = Crc32.init();
            ws.crcDomainOf(&c, h, off);
            c.update("the same seventeen");
            return c.final();
        }
    }.f;
    try testing.expect(at(&a, 36) != at(&a, 61)); // offset must be bound
    try testing.expect(at(&a, 36) != at(&b, 36)); // segment identity must be bound
}

// ------------------------------------------------------------- N: enumeration

test "wal3 B0: enumeration ignores everything that is not a segment name" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "enum");
    defer sc.deinit();

    const img1 = try headerImage(a, 1, 1);
    defer a.free(img1);
    try sc.writeSegment(1, img1);
    const img2a = try headerImage(a, 0x2a, 1);
    defer a.free(img2a);
    try sc.writeSegment(0x2a, img2a);

    // near misses, all ignored rather than rejected
    try sc.writeNamed("store.db.wal.000000000000000", "short");
    try sc.writeNamed("store.db.wal.00000000000000001", "long");
    try sc.writeNamed("store.db.wal.00000000000000AB", "upper");
    try sc.writeNamed("store.db.wal.zzzzzzzzzzzzzzzz", "nonhex");
    try sc.writeNamed("store.db.wal.ffffffffffffffff", "negative i64");
    try sc.writeNamed("other.db.wal.0000000000000001", "another store");
    try sc.writeNamed("notes.txt", "unrelated");
    {
        const d = try sc.path("store.db.wal.0000000000000009");
        defer a.free(d);
        try std.fs.cwd().makeDir(d);
    }
    // A SYMLINK at an exact segment name, pointing at a valid segment: the name
    // matches, the file type does not. The directory entry answers for the link
    // itself, which is the whole reason it is consulted.
    {
        const target = try sc.segPath(1);
        defer a.free(target);
        const link = try sc.path("store.db.wal.0000000000000003");
        defer a.free(link);
        try std.posix.symlink(target, link);
    }

    var set = try sc.open(false);
    defer set.deinit();
    try expectSeqs(a, &set, &.{ 1, 0x2a }); // gaps are legal, order ascending
    // W6: nextSeq is one above the highest NAME, not the count.
    try testing.expectEqual(@as(i64, 0x2b), set.nextSeq());
    // an ignored entry is ignored, not removed
    try testing.expect(try sc.exists("store.db.wal.0000000000000003"));
    try testing.expect(try sc.exists("store.db.wal.0000000000000009"));
}

// W6 has no successor to burn: the refusal is explicit, not a wrap into a
// negative name.
test "wal3 B0: a sequence number at the maximum is refused rather than wrapping" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "w6max");
    defer sc.deinit();
    const img = try headerImage(a, std.math.maxInt(i64), 1);
    defer a.free(img);
    try sc.writeSegment(std.math.maxInt(i64), img);
    try testing.expectError(error.StoreFull, sc.open(false));
}

// A base path is a byte string, not text: a namespace under a name that is not
// valid UTF-8 is still a namespace.
test "wal3 B0: a base path that is not UTF-8 still enumerates" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "nonutf8");
    defer sc.deinit();
    const base = try std.fmt.allocPrint(a, "{s}/db\xff", .{sc.dir});
    defer a.free(base);
    for ([_]i64{ 1, 2 }) |seq| {
        const p = try std.fmt.allocPrint(a, "{s}.wal.{x:0>16}", .{ base, @as(u64, @bitCast(seq)) });
        defer a.free(p);
        const img = try headerImage(a, seq, 1);
        defer a.free(img);
        try writeFile(p, img);
    }
    var set = try WalSegmentSet.open(a, base, false);
    defer set.deinit();
    try expectSeqs(a, &set, &.{ 1, 2 });
    try testing.expectEqual(@as(i64, 3), set.nextSeq());
}

// A base carrying a trailing separator is not a supported spelling, and it fails
// at the lock rather than half-working: `<base>.lock` is composed by appending to
// the base verbatim, so it lands INSIDE a directory that does not exist. The Rust
// port composes that path the same way and fails the same way. Pinned so the
// refusal is a recorded property rather than an accident nobody noticed —
// `segmentFile` is composed from `dir` and `prefix`, which would otherwise let
// this case limp along far enough to create files under two different names.
test "wal3 B0: a base with a trailing separator is refused, not half-opened" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "trailsep");
    defer sc.deinit();
    const img = try headerImage(a, 1, 1);
    defer a.free(img);
    try sc.writeSegment(1, img); // <dir>/store.db.wal.0000000000000001

    const slashed = try std.fmt.allocPrint(a, "{s}/", .{sc.base});
    defer a.free(slashed);
    try testing.expectError(error.Io, WalSegmentSet.open(a, slashed, false));
    try testing.expect(try sc.segExists(1)); // and it touched nothing
}

// R1. Sequence 0 is reserved for "no clean mark" and is never a segment — a
// file at that name is corruption, not residue.
test "wal3 B0: sequence zero is refused" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "seq0");
    defer sc.deinit();
    const img = try headerImage(a, 0, 1);
    defer a.free(img);
    try sc.writeSegment(0, img);
    try testing.expectError(error.DataCorruption, sc.open(false));
}

// ------------------------------------------------------- D1: legacy boundary

// N6. The v1 single-file log refuses the open before any segment is enumerated,
// created or deleted. Not before ANY file appears: the store lock is taken
// first, so a writable open leaves `<base>.lock` behind. The design permits that
// sidecar explicitly — what D1 forbids is a fresh segment set beside the old
// log, and a zero-byte lock file is not one.
test "wal3 B0: a v1 single-file log is refused, not migrated" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "n6");
    defer sc.deinit();
    const v1 = try sc.sibling(".wal");
    defer a.free(v1);
    try writeFile(v1, "MDBS.WAL\x00\x00\x00\x01\x00\x00\x00\x00");
    try testing.expectError(error.DataCorruption, sc.open(false));
    try testing.expect(pathExists(v1)); // the refusal must not delete the evidence
}

// The other two D1 rows: a regular file at the BASE itself (the shape the v1
// call site produces after the cutover, and the one N6 alone would miss), and a
// `.ckpt` left by v1's rename-checkpoint.
test "wal3 B0: a regular file at the base path and a .ckpt each refuse the open" {
    const a = testing.allocator;
    for ([_][]const u8{ "", ".ckpt" }) |suffix| {
        var sc = try Scratch.init(a, "d1");
        defer sc.deinit();
        const p = try sc.sibling(suffix);
        defer a.free(p);
        try writeFile(p, "old data");
        try testing.expectError(error.DataCorruption, sc.open(false));
        try testing.expect(pathExists(p));
        // And with the artifact gone the same directory opens.
        try std.fs.cwd().deleteFile(p);
        var set = try sc.open(false);
        set.deinit();
    }
}

// N6's accepting side, which is the half a "does `<base>.wal` exist?"
// implementation gets wrong: only a REGULAR file is a v1 log. A directory at
// that name is not one, and neither is a symlink — the same NOFOLLOW discipline
// N4 applies to segment names.
test "wal3 B0: only a regular file at the v1 name refuses the open" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "n6nonfile");
    defer sc.deinit();
    const img = try headerImage(a, 1, 1);
    defer a.free(img);
    try sc.writeSegment(1, img);
    const v1 = try sc.sibling(".wal");
    defer a.free(v1);

    try std.fs.cwd().makeDir(v1);
    {
        var set = try sc.open(false); // a directory is not a v1 log
        defer set.deinit();
        try expectSeqs(a, &set, &.{1});
    }
    try std.fs.cwd().deleteDir(v1);

    const target = try sc.segPath(1);
    defer a.free(target);
    try std.posix.symlink(target, v1);
    {
        var set = try sc.open(false); // a symlink is not a v1 log
        defer set.deinit();
        try expectSeqs(a, &set, &.{1});
    }
    // neither is removed by an open that accepted it
    try testing.expect(pathExists(v1));
}

// `.ckpt` is the one row of the three that refuses on EXISTENCE rather than on
// being a regular file: after a v1 crash it may be the only recoverable copy,
// and "there is something at that name and I cannot tell what" is not a reason
// to create a fresh store beside it.
test "wal3 B0: a .ckpt of any kind refuses the open" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "ckptdir");
    defer sc.deinit();
    const ck = try sc.sibling(".ckpt");
    defer a.free(ck);

    try std.fs.cwd().makeDir(ck);
    try testing.expectError(error.DataCorruption, sc.open(false));
    try std.fs.cwd().deleteDir(ck);

    // A DANGLING symlink too: nothing can be read through it, which is exactly
    // the case a `.exists()` that follows links would wave through.
    try std.posix.symlink("/nonexistent/target", ck);
    try testing.expectError(error.DataCorruption, sc.open(false));
}

// ------------------------------------------------------------ H: header table

// H1-H4 on the highest name are create-crash residue: a writable open unlinks
// them, and W6 has already burnt the sequence number so the fresh segment
// cannot reuse it.
test "wal3 B0: torn-create residue on the highest name is removed" {
    const a = testing.allocator;
    const shapes = try tornShapes(a, 2);
    defer freeShapes(a, &shapes);
    for (shapes) |shape| {
        var sc = try Scratch.init(a, shape.tag);
        defer sc.deinit();
        const img = try headerImage(a, 1, 1);
        defer a.free(img);
        try sc.writeSegment(1, img);
        try sc.writeSegment(2, shape.bytes);

        var set = try sc.open(false);
        defer set.deinit();
        try expectSeqs(a, &set, &.{1}); // residue is not in the set
        try testing.expect(!try sc.segExists(2)); // residue is unlinked
        try testing.expectEqual(@as(i64, 3), set.nextSeq()); // W6 burnt its number
    }
}

// The same shapes anywhere below the highest name are corruption: a segment
// exists above them, so their create completed once. Every shape is tried,
// because the highest-only forgiveness is a property of the POSITION, and an
// implementation that special-cased one shape rather than the position would
// survive a single-shape test.
test "wal3 B0: torn-create shapes below the highest name are corruption" {
    const a = testing.allocator;
    const shapes = try tornShapes(a, 1);
    defer freeShapes(a, &shapes);
    for (shapes) |shape| {
        var sc = try Scratch.init(a, shape.tag);
        defer sc.deinit();
        try sc.writeSegment(1, shape.bytes);
        const img = try headerImage(a, 2, 1);
        defer a.free(img);
        try sc.writeSegment(2, img);
        try testing.expectError(error.DataCorruption, sc.open(false));
        try testing.expect(try sc.segExists(1)); // corruption deletes nothing
        try testing.expect(try sc.segExists(2));
    }
}

// The header is validated CRC FIRST, semantics second, and the order is
// load-bearing: an unsealed edit to a semantic field is a torn create (the
// bytes never became a header), while the SAME edit resealed is corruption.
// One image differing only in whether the CRC was recomputed.
test "wal3 B0: an unsealed semantic edit is torn and the resealed one is corruption" {
    const a = testing.allocator;
    // The edit: version 3 -> 2, an H5 fault once the CRC agrees with it.
    {
        var sc = try Scratch.init(a, "unsealed");
        defer sc.deinit();
        const img = try headerImage(a, 1, 1);
        defer a.free(img);
        std.mem.writeInt(i32, img[8..12], 2, .big);
        try sc.writeSegment(1, img); // highest name, CRC now wrong -> H3 residue
        var set = try sc.open(false);
        defer set.deinit();
        try testing.expectEqual(@as(usize, 0), set.segmentsSlice().len);
        try testing.expect(!try sc.segExists(1));
    }
    {
        var sc = try Scratch.init(a, "resealed");
        defer sc.deinit();
        const img = try headerImage(a, 1, 1);
        defer a.free(img);
        std.mem.writeInt(i32, img[8..12], 2, .big);
        reseal(img);
        try sc.writeSegment(1, img); // same name, same edit, CRC agrees -> H5
        try testing.expectError(error.DataCorruption, sc.open(false));
        try testing.expect(try sc.segExists(1));
    }
}

// H5-H7/H9: a CRC-valid header carrying wrong content is a writer defect or a
// copied file, never a torn create, so it is corruption EVEN on the highest
// name — the position forgiveness applies to the torn class only.
test "wal3 B0: resealed semantic faults are corruption even on the highest name" {
    const a = testing.allocator;
    const Case = struct { tag: []const u8, off: usize, width: u8, val: i64 };
    const cases = [_]Case{
        .{ .tag = "h5-version", .off = 8, .width = 4, .val = 4 },
        .{ .tag = "h6-flags", .off = 12, .width = 4, .val = 1 },
        .{ .tag = "h7-seq", .off = 16, .width = 8, .val = 99 },
        .{ .tag = "h9-firstlsn-zero", .off = 24, .width = 8, .val = 0 },
        .{ .tag = "h9-firstlsn-negative", .off = 24, .width = 8, .val = -1 },
    };
    for (cases) |c| {
        var sc = try Scratch.init(a, c.tag);
        defer sc.deinit();
        const img = try headerImage(a, 1, 1);
        defer a.free(img);
        if (c.width == 4) {
            std.mem.writeInt(i32, img[c.off..][0..4], @intCast(c.val), .big);
        } else {
            std.mem.writeInt(i64, img[c.off..][0..8], c.val, .big);
        }
        reseal(img);
        try sc.writeSegment(1, img);
        try testing.expectError(error.DataCorruption, sc.open(false));
        try testing.expect(try sc.segExists(1));
    }
}

// H8. A segment holding nothing but its header is legitimate — that is what a
// segment looks like between its create and its first section — at the highest
// name and below it alike.
test "wal3 B0: a valid header-only segment is legitimate at any position" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "h8");
    defer sc.deinit();
    for ([_]i64{ 1, 2, 3 }) |seq| {
        const img = try headerImage(a, seq, seq * 10);
        defer a.free(img);
        try sc.writeSegment(seq, img);
    }
    var set = try sc.open(false);
    defer set.deinit();
    try expectSeqs(a, &set, &.{ 1, 2, 3 });
    for (set.segmentsSlice(), 0..) |*s, i| {
        try testing.expect(s.empty());
        try testing.expectEqual(@as(u64, SEG_HDR), s.valid_end);
        try testing.expectEqual(@as(i64, @intCast(i + 1)) * 10, s.headerFirstLsn());
    }
}

// A read-only open excludes residue from the set but must not remove it: the
// medium may be genuinely read-only, and the next writable open is the one that
// tidies up.
test "wal3 B0: a read-only open excludes residue but keeps it" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "ro-residue");
    defer sc.deinit();
    const img = try headerImage(a, 1, 1);
    defer a.free(img);
    try sc.writeSegment(1, img);
    try sc.writeSegment(2, ""); // H1 on the highest name

    {
        var set = try sc.open(true);
        defer set.deinit();
        try expectSeqs(a, &set, &.{1});
        try testing.expectEqual(@as(i64, 3), set.nextSeq());
        try testing.expect(try sc.segExists(2)); // kept
    }
    // The next writable open removes it.
    var set = try sc.open(false);
    defer set.deinit();
    try testing.expect(!try sc.segExists(2));
}

// A read-only open reaches the same corrupt verdicts: read-only is about what
// may be WRITTEN, never about what counts as damage.
test "wal3 B0: a read-only open reaches the same corrupt verdicts" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "ro-corrupt");
    defer sc.deinit();
    const img = try headerImage(a, 1, 1);
    defer a.free(img);
    std.mem.writeInt(i64, img[16..24], 99, .big); // H7
    reseal(img);
    try sc.writeSegment(1, img);
    try testing.expectError(error.DataCorruption, sc.open(true));
    try testing.expect(try sc.segExists(1));
}

// ------------------------------------------------------- W2/W5/W6: mutations

test "wal3 B0: createSegment writes a valid header at the burnt successor" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "w2");
    defer sc.deinit();
    const img = try headerImage(a, 7, 1);
    defer a.free(img);
    try sc.writeSegment(7, img);

    {
        var set = try sc.open(false);
        defer set.deinit();
        try testing.expectEqual(@as(i64, 8), set.nextSeq());
        const seg = try set.createSegment(4242);
        try testing.expectEqual(@as(i64, 8), seg.seq);
        try testing.expectEqual(@as(i64, 4242), seg.headerFirstLsn());
        try testing.expectEqual(@as(u64, SEG_HDR), seg.file_len);
        try testing.expectEqual(@as(i64, 9), set.nextSeq());
    }
    // Re-open: the header is on disk, valid, and enumerates.
    var set = try sc.open(false);
    defer set.deinit();
    try expectSeqs(a, &set, &.{ 7, 8 });
    try testing.expectEqual(@as(i64, 4242), set.active().?.headerFirstLsn());
}

// W6. A number that has been handed out is never handed out again, whether the
// segment that took it still exists or not.
test "wal3 B0: a sequence number is never reused" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "w6");
    defer sc.deinit();
    var set = try sc.open(false);
    defer set.deinit();
    _ = try set.createSegment(1);
    _ = try set.createSegment(2);
    try set.unlinkThrough(2); // both gone from disk
    try testing.expectEqual(@as(usize, 0), set.segmentsSlice().len);
    const seg = try set.createSegment(3);
    try testing.expectEqual(@as(i64, 3), seg.seq); // not 1
}

test "wal3 B0: unlinkThrough removes the prefix and nothing else" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "w5");
    defer sc.deinit();
    for ([_]i64{ 1, 2, 3 }) |seq| {
        const img = try headerImage(a, seq, seq);
        defer a.free(img);
        try sc.writeSegment(seq, img);
    }
    var set = try sc.open(false);
    defer set.deinit();
    try set.unlinkThrough(2);
    try expectSeqs(a, &set, &.{3});
    try testing.expect(!try sc.segExists(1));
    try testing.expect(!try sc.segExists(2));
    try testing.expect(try sc.segExists(3));
}

// `unlinkThrough` is INCLUSIVE and does not require the argument to name a
// segment that exists: a mark authorizing removal through a number that fell in
// a gap retires everything below it.
test "wal3 B0: unlinkThrough a gap retires everything below it" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "w5gap");
    defer sc.deinit();
    for ([_]i64{ 1, 4, 9 }) |seq| {
        const img = try headerImage(a, seq, seq);
        defer a.free(img);
        try sc.writeSegment(seq, img);
    }
    var set = try sc.open(false);
    defer set.deinit();
    try set.unlinkThrough(6); // names nothing on disk
    try expectSeqs(a, &set, &.{9});
    try testing.expect(!try sc.segExists(1));
    try testing.expect(!try sc.segExists(4));
    try testing.expect(try sc.segExists(9));
}

// The no-op shape: a recovered mark whose files an earlier attempt already
// removed must not fsync the directory, because it changed nothing.
test "wal3 B0: unlinkThrough below the lowest name does not fsync" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "w5noop");
    defer sc.deinit();
    const img = try headerImage(a, 9, 1);
    defer a.free(img);
    try sc.writeSegment(9, img);
    var set = try sc.open(false);
    defer set.deinit();
    const before = set.dir_fsyncs;
    try set.unlinkThrough(8);
    try set.unlinkThrough(0); // and the "no mark" value
    try set.unlinkThrough(-1);
    try testing.expectEqual(before, set.dir_fsyncs);
    try expectSeqs(a, &set, &.{9});
}

test "wal3 B0: the log size accounts for segments of unequal length" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "bytes");
    defer sc.deinit();
    // Valid headers with trailing bytes: at B0 a segment's tail is not yet
    // parsed, so the file length is whatever it is.
    for ([_][2]u64{ .{ 1, 0 }, .{ 2, 100 }, .{ 3, 7 } }) |pair| {
        const seq: i64 = @intCast(pair[0]);
        const extra: usize = @intCast(pair[1]);
        const img = try a.alloc(u8, @as(usize, SEG_HDR) + extra);
        defer a.free(img);
        @memcpy(img[0..@as(usize, SEG_HDR)], &buildHeader(seq, 1));
        @memset(img[@as(usize, SEG_HDR)..], 0xab);
        try sc.writeSegment(seq, img);
    }
    var set = try sc.open(false);
    defer set.deinit();
    try testing.expectEqual(3 * SEG_HDR + 107, set.logBytes());
    try testing.expectEqual(set.logBytesExact(), set.logBytes());
    try set.unlinkThrough(1);
    try testing.expectEqual(2 * SEG_HDR + 107, set.logBytes());
    try testing.expectEqual(set.logBytesExact(), set.logBytes());
    try set.unlinkThrough(3);
    try testing.expectEqual(@as(u64, 0), set.logBytes());
    try testing.expectEqual(@as(u64, 0), set.logBytesExact());
}

// W2's durability points are not observable in the resulting bytes: a create
// that skipped both syncs writes the same 36 bytes. Count them, and pin the
// ORDER through the event seam — create, header, full force, directory fsync.
test "wal3 B0: a create forces the segment and then the directory, in that order" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "w2fsync");
    defer sc.deinit();
    var rec = wal_io.RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();

    var set = try sc.openIo(false, &seam);
    defer set.deinit();
    try testing.expectEqual(@as(u64, 0), set.segment_syncs);
    const dir_before = set.dir_fsyncs;
    _ = try set.createSegment(1);
    try testing.expectEqual(@as(u64, 1), set.segment_syncs); // forced WITH its size
    try testing.expectEqual(dir_before + 1, set.dir_fsyncs);

    const kinds = try rec.kinds(a);
    defer a.free(kinds);
    try testing.expectEqualSlices(wal_io.WalOpKind, &.{
        .create, .seg_header, .force_full, .dir_sync,
    }, kinds);
}

// A fresh namespace hands the caller an empty set and the first name; N1's
// create is the caller's to make (`StoreWAL`, slice B2).
test "wal3 B0: a fresh namespace starts empty at sequence one" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "n1");
    defer sc.deinit();
    var set = try sc.open(false);
    defer set.deinit();
    try testing.expectEqual(@as(usize, 0), set.segmentsSlice().len);
    try testing.expectEqual(FIRST_SEQ, set.nextSeq());
    try testing.expectEqual(@as(u64, 0), set.logBytes());
    const seg = try set.createSegment(1);
    try testing.expectEqual(FIRST_SEQ, seg.seq);
    try testing.expectEqual(@as(i64, 1), seg.headerFirstLsn());
}

// A create needs a real LSN; both refusals are caller errors, not damage.
test "wal3 B0: a segment cannot start at a non-positive LSN" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "w2lsn");
    defer sc.deinit();
    var set = try sc.open(false);
    defer set.deinit();
    for ([_]i64{ 0, -1, std.math.minInt(i64) }) |bad| {
        try testing.expectError(error.WrongConfiguration, set.createSegment(bad));
    }
    try testing.expectEqual(FIRST_SEQ, set.nextSeq()); // a refused create burns no name
}

// -------------------------------------------------------------- descriptors

// The descriptor discipline B1's two-pass scanner depends on: classification
// retains no handle, a pass opens one on demand and gives it back, and the
// handle honours the set's read-only mode.
test "wal3 B0: segments open and release their handles on demand" {
    if (runningAsRoot()) return; // root can open a 0444 file read-write
    const a = testing.allocator;
    var sc = try Scratch.init(a, "fds");
    defer sc.deinit();
    for ([_]i64{ 1, 2 }) |seq| {
        const img = try headerImage(a, seq, 1);
        defer a.free(img);
        try sc.writeSegment(seq, img);
    }
    const p1 = try sc.segPath(1);
    defer a.free(p1);
    try setMode(p1, 0o444);
    defer setMode(p1, 0o644) catch {};

    var set = try sc.open(true);
    defer set.deinit();
    try testing.expectEqual(@as(usize, 0), set.openFileCount()); // classification retains nothing

    const seg = &set.segmentsSlice()[0];
    try testing.expect(seg.handle() == null);
    // A read-only set opens read-only, which is the only way this succeeds.
    try seg.ensureOpen();
    try testing.expect(seg.handle() != null);
    try seg.ensureOpen(); // idempotent
    try testing.expectEqual(@as(usize, 1), set.openFileCount());

    set.segmentsSlice()[0].release();
    try testing.expectEqual(@as(usize, 0), set.openFileCount());
    // Reopens after a release, as a second recovery pass does.
    try set.segmentsSlice()[0].ensureOpen();
    try testing.expectEqual(@as(usize, 1), set.openFileCount());
}

// A read-only set never unlinks and never creates.
test "wal3 B0: a read-only set refuses to mutate the namespace" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "romutate");
    defer sc.deinit();
    const img = try headerImage(a, 1, 1);
    defer a.free(img);
    try sc.writeSegment(1, img);
    var set = try sc.open(true);
    defer set.deinit();
    try testing.expectError(error.ReadOnly, set.createSegment(1));
    try set.unlinkThrough(1); // a no-op, not an error
    try testing.expect(try sc.segExists(1));
    try expectSeqs(a, &set, &.{1});
    try testing.expectError(error.ReadOnly, set.deleteNamespace());
}

// ----------------------------------------------------------- the store lock

// Two writable opens of the same namespace cannot coexist — including in ONE
// process, which is where POSIX record locks would have silently admitted the
// second.
test "wal3 B0: a second writable open is refused" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "lockrw");
    defer sc.deinit();
    var first = try sc.open(false);
    try testing.expectError(error.Locked, sc.open(false));
    const lock_path = try sc.sibling(".lock");
    defer a.free(lock_path);
    try testing.expect(pathExists(lock_path));
    first.deinit();
    // The lock is released with the handle, so the next open succeeds.
    var again = try sc.open(false);
    again.deinit();
}

// A second open in THIS process is refused whatever the two modes are —
// including read-only against read-only, which no kernel lock refuses and which
// the process claim exists to catch.
//
// This is Java's rule, not an invention: `tryLock` consults a JVM-wide table
// that does not consider lock mode, so a second `StoreWAL` on one store raises
// `OverlappingFileLockException` even when both opens are read-only
// (`WalSegmentSet.java:267-274`).
test "wal3 B0: a second open in this process is refused whatever the modes" {
    const a = testing.allocator;
    const modes = [_][2]bool{
        .{ false, false }, .{ false, true }, .{ true, false }, .{ true, true },
    };
    for (modes) |m| {
        var sc = try Scratch.init(a, "lockmodes");
        defer sc.deinit();
        // A read-only FIRST open needs something to be read-only about; an empty
        // namespace is legal, so this is only for symmetry with the writable case.
        var first = try sc.open(m[0]);
        try testing.expectError(error.Locked, sc.open(m[1]));
        first.deinit();
        var second = try sc.open(m[1]);
        second.deinit();
    }
}

// The claim is keyed by the lock file's IDENTITY, not by the pathname: two
// opens naming one store through different paths are one store.
test "wal3 B0: the same store reached by two paths is one store" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "twopaths");
    defer sc.deinit();
    const link = try std.fmt.allocPrint(a, "{s}.link", .{sc.dir});
    defer a.free(link);
    defer std.fs.cwd().deleteFile(link) catch {};
    try std.posix.symlink(sc.dir, link);
    const other_base = try std.fmt.allocPrint(a, "{s}/store.db", .{link});
    defer a.free(other_base);

    var first = try sc.open(false);
    defer first.deinit();
    try testing.expectError(error.Locked, WalSegmentSet.open(a, other_base, false));
}

// A refused open must not release the lock the holder still has. The failure
// mode this pins is an unwinding second open that drops the FIRST opener's
// claim on its way out.
test "wal3 B0: a refused open does not release the holder's lock" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "refused");
    defer sc.deinit();
    var first = try sc.open(false);
    defer first.deinit();
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        try testing.expectError(error.Locked, sc.open(false));
    }
    // The holder is still the holder: it can still mutate the namespace.
    _ = try first.createSegment(1);
}

// `close` releases both halves, and the set refuses namespace mutations from
// then on rather than running them without the lock.
test "wal3 B0: close releases the lock and the claim, and closes the namespace" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "close");
    defer sc.deinit();
    var first = try sc.open(false);
    first.close();
    try testing.expectError(error.StoreClosed, first.createSegment(1));
    try testing.expectError(error.StoreClosed, first.unlinkThrough(1));
    try testing.expectError(error.StoreClosed, first.deleteNamespace());
    first.deinit(); // idempotent after close
    var again = try sc.open(false);
    again.deinit();
}

// The kernel half of the lock, proved without a second process: an independent
// descriptor on the same lock file cannot take a conflicting OFD lock while the
// set holds one. A `flock` here would acquire straight through — which is
// exactly why the port does not use one.
test "wal3 B0: the store lock is a record lock another descriptor cannot take" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "ofd");
    defer sc.deinit();
    var set = try sc.open(false);
    defer set.deinit();
    const lock_path = try sc.sibling(".lock");
    defer a.free(lock_path);

    const probe = try std.fs.cwd().openFile(lock_path, .{ .mode = .read_write });
    defer probe.close();
    var fl: std.posix.Flock = std.mem.zeroes(std.posix.Flock);
    fl.type = std.posix.F.WRLCK;
    fl.whence = std.posix.SEEK.SET;
    fl.start = 0;
    fl.len = 0;
    const F_OFD_SETLK: i32 = 37;
    const rc = std.os.linux.fcntl(probe.handle, F_OFD_SETLK, @intFromPtr(&fl));
    const e = std.os.linux.E.init(rc);
    try testing.expect(e == .ACCES or e == .AGAIN);
}

// §3.1 is two-sided, so a read-only open CREATES the lock file when it can: a
// writer must be refused while a reader holds a shared lock.
test "wal3 B0: a read-only open creates the lock file" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "rolock");
    defer sc.deinit();
    const lock_path = try sc.sibling(".lock");
    defer a.free(lock_path);
    try testing.expect(!pathExists(lock_path));
    var set = try sc.open(true);
    defer set.deinit();
    try testing.expect(pathExists(lock_path));

    // And it took a SHARED lock, not an exclusive one. Without this the whole
    // read-only path could pass `exclusive = true` and nothing would notice: an
    // independent reader must still be admitted, while an independent writer
    // must still be refused. Probed on separate descriptions, because the
    // process claim refuses a second `open` before the kernel is consulted.
    const reader = try std.fs.cwd().openFile(lock_path, .{ .mode = .read_write });
    defer reader.close();
    try testing.expect(try probeOfdLock(reader, false)); // readers share
    const writer = try std.fs.cwd().openFile(lock_path, .{ .mode = .read_write });
    defer writer.close();
    try testing.expect(!try probeOfdLock(writer, true)); // a writer is excluded
}

// Rung 2 of the read-only ladder: the read-write create fails, but the lock file
// is THERE, so a shared lock is still attainable on a read-only handle. This is
// not a fallback to lockless at all.
test "wal3 B0: a read-only open falls back to a read-only lock handle" {
    if (runningAsRoot()) return; // root ignores the mode bits this rung turns on
    const a = testing.allocator;
    var sc = try Scratch.init(a, "rung2");
    defer sc.deinit();
    const img = try headerImage(a, 1, 1);
    defer a.free(img);
    try sc.writeSegment(1, img);
    const lock_path = try sc.sibling(".lock");
    defer a.free(lock_path);
    try writeFile(lock_path, "");
    try setMode(lock_path, 0o444);
    defer setMode(lock_path, 0o644) catch {};

    var set = try sc.open(true);
    defer set.deinit();
    try expectSeqs(a, &set, &.{1});
    try testing.expect(set.lock != null); // locked, on a read-only handle
}

// Java's read-only-medium branch: when the lock file cannot be created AND the
// directory is not writable by this uid, the reader goes lockless. That is a
// heuristic, not proof (Q7) — it is ported faithfully and pinned here so a
// later tightening is a deliberate change.
test "wal3 B0: a read-only medium admits a lockless reader and refuses a writer" {
    if (runningAsRoot()) return; // root writes through 0555
    const a = testing.allocator;
    var sc = try Scratch.init(a, "romedium");
    defer sc.deinit();
    const img = try headerImage(a, 1, 1);
    defer a.free(img);
    try sc.writeSegment(1, img);

    try setMode(sc.dir, 0o555);
    defer setMode(sc.dir, 0o755) catch {};
    {
        var set = try sc.open(true);
        defer set.deinit();
        try expectSeqs(a, &set, &.{1});
        try testing.expect(set.lock == null); // lockless, by the documented branch
        const lock_path = try sc.sibling(".lock");
        defer a.free(lock_path);
        try testing.expect(!pathExists(lock_path)); // no lock file was created
    }
    // A WRITER on the same medium cannot even create its lock file, and must not
    // fall through to the lockless branch: it fails.
    try testing.expectError(error.Io, sc.open(false));
}

// Rung 2's failing half: the lock file EXISTS but cannot be opened at all, so
// the "resolve the ambiguity" branch has nothing to resolve it with. An I/O
// refusal — never a lockless open.
test "wal3 B0: an unreadable lock file refuses rather than going lockless" {
    if (runningAsRoot()) return;
    const a = testing.allocator;
    var sc = try Scratch.init(a, "rung2fail");
    defer sc.deinit();
    const lock_path = try sc.sibling(".lock");
    defer a.free(lock_path);
    try writeFile(lock_path, "");
    try setMode(lock_path, 0o000);
    defer setMode(lock_path, 0o644) catch {};
    try testing.expectError(error.Io, sc.open(true));
}

// A DANGLING `.lock` symlink is not a lock file: nothing can be opened through
// it. The ladder must therefore fall through to the writable-directory rung and
// fail closed as inconclusive contention — `Locked`, not the `Io` a no-follow
// existence test would produce by trying an open that cannot succeed. Rust asks
// `Path::exists()` here and Java `File.exists()`, both of which follow; D1's
// `.ckpt` sentinel is the one place that deliberately does not.
test "wal3 B0: a dangling lock symlink takes the inconclusive rung, not the I/O one" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "danglinglock");
    defer sc.deinit();
    const lock_path = try sc.sibling(".lock");
    defer a.free(lock_path);
    try std.posix.symlink("/nonexistent/target", lock_path);
    // Creating through a dangling symlink to a missing directory fails, the
    // target does not exist, and the directory is writable.
    try testing.expectError(error.Locked, sc.open(true));
}

// Rung 4: the create failed, the file does not exist, and the directory IS
// writable — so a writer may be running. Inconclusive fails CLOSED, with
// `Locked` rather than the I/O error that caused it, because the answer the
// caller needs is "someone may hold this store", not "one syscall failed".
test "wal3 B0: an inconclusive read-only lock refuses rather than going lockless" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "rung4");
    defer sc.deinit();
    // A name whose `.lock` sibling exceeds NAME_MAX: the create fails, the path
    // cannot exist, and the directory is plainly writable.
    const long = try a.alloc(u8, 252);
    defer a.free(long);
    @memset(long, 'x');
    const base = try std.fmt.allocPrint(a, "{s}/{s}", .{ sc.dir, long });
    defer a.free(base);
    try testing.expectError(error.Locked, WalSegmentSet.open(a, base, true));
}

// ------------------------------------------------------ D2: delete namespace

// D2. The delete runs while the lock is still held, removes every file this
// base owns — segments by the same enumeration rule the open used, plus the
// lock file — and preserves everything else in the directory.
test "wal3 B0: deleteNamespace removes this base's files and nothing else" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "d2");
    defer sc.deinit();
    for ([_]i64{ 1, 2, 5 }) |seq| {
        const img = try headerImage(a, seq, seq);
        defer a.free(img);
        try sc.writeSegment(seq, img);
    }
    try sc.writeNamed("other.db.wal.0000000000000001", "another store");
    try sc.writeNamed("notes.txt", "unrelated");

    var set = try sc.open(false);
    defer set.deinit();
    try set.deleteNamespace();

    for ([_]i64{ 1, 2, 5 }) |seq| try testing.expect(!try sc.segExists(seq));
    const lock_path = try sc.sibling(".lock");
    defer a.free(lock_path);
    try testing.expect(!pathExists(lock_path));
    try testing.expect(try sc.exists("other.db.wal.0000000000000001"));
    try testing.expect(try sc.exists("notes.txt"));
    // It closes the set as its final act, so nothing can mutate afterwards.
    try testing.expectError(error.StoreClosed, set.createSegment(1));
    // And the namespace is free for a fresh open.
    var fresh = try sc.open(false);
    defer fresh.deinit();
    try testing.expectEqual(FIRST_SEQ, fresh.nextSeq());
}

// D2's ORDERING, which the outcome alone cannot see: a close-before-delete
// implementation removes the same files and passes every assertion above. The
// lock has to still be held WHILE the segments go, or a second opener can
// acquire the namespace and have its live segments deleted underneath it. The
// seam makes the moment observable — at each unlink event, an independent
// description must be unable to take the store lock.
const LockProbe = struct {
    lock_path: []const u8,
    unlinks_seen: usize = 0,
    lock_was_free: bool = false,

    fn io(self: *LockProbe) wal_io.WalIo {
        return .{ .ctx = @ptrCast(self), .beforeFn = before };
    }
    fn before(ctx: *anyopaque, e: *const wal_io.WalIoEvent) DbError!void {
        const self: *LockProbe = @ptrCast(@alignCast(ctx));
        if (e.kind != .unlink) return;
        self.unlinks_seen += 1;
        const f = std.fs.cwd().openFile(self.lock_path, .{ .mode = .read_write }) catch return;
        defer f.close();
        if (probeOfdLock(f, true) catch false) self.lock_was_free = true;
    }
};

test "wal3 B0: deleteNamespace removes the segments while it still holds the lock" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "d2order");
    defer sc.deinit();
    for ([_]i64{ 1, 2 }) |seq| {
        const img = try headerImage(a, seq, seq);
        defer a.free(img);
        try sc.writeSegment(seq, img);
    }
    const lock_path = try sc.sibling(".lock");
    defer a.free(lock_path);

    var probe = LockProbe{ .lock_path = lock_path };
    const seam = probe.io();
    var set = try sc.openIo(false, &seam);
    defer set.deinit();
    try set.deleteNamespace();

    try testing.expectEqual(@as(usize, 2), probe.unlinks_seen);
    try testing.expect(!probe.lock_was_free); // held throughout
}

// The delete also sweeps names the live set never held — residue an earlier
// read-only open left behind, and segments in an interior gap.
test "wal3 B0: deleteNamespace re-enumerates rather than trusting the live set" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "d2enum");
    defer sc.deinit();
    const img = try headerImage(a, 1, 1);
    defer a.free(img);
    try sc.writeSegment(1, img);
    try sc.writeSegment(4, ""); // residue on the highest name

    {
        var set = try sc.open(true); // read-only: keeps the residue, excludes it
        defer set.deinit();
        try expectSeqs(a, &set, &.{1});
    }

    var rw = try sc.open(false);
    defer rw.deinit();
    // The writable open already removed the residue at R2; put a fresh orphan
    // back so the re-enumeration has something the live list does not know.
    try sc.writeSegment(3, "not a header");
    try rw.deleteNamespace();
    try testing.expect(!try sc.segExists(1));
    try testing.expect(!try sc.segExists(3));
}

// ---------------------------------------------------------- the io seam

// A create whose directory fsync fails must not leave the segment behind: the
// namespace would otherwise carry a file whose entry is not durable, and W6 has
// already burnt the name so no retry can reuse it.
test "wal3 B0: a create that fails mid-way removes its partial segment" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "w2fail");
    defer sc.deinit();
    var rec = wal_io.RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    var set = try sc.openIo(false, &seam);
    defer set.deinit();

    // Fail at the directory fsync: the fourth event of the create.
    rec.fail_at = rec.calls + 3;
    try testing.expectError(error.Io, set.createSegment(1));
    try testing.expect(!try sc.segExists(1)); // the partial segment is gone
    try testing.expectEqual(@as(usize, 0), set.segmentsSlice().len);
    // W6: the name is burnt whether the create succeeded or not.
    try testing.expectEqual(@as(i64, 2), set.nextSeq());

    rec.fail_at = null;
    const seg = try set.createSegment(1);
    try testing.expectEqual(@as(i64, 2), seg.seq);
}

// R2's residue removal reports its unlink AND its directory fsync, the same way
// W5 does. Java emits both (`WalSegmentSet.java:376-381`); the Rust port emits
// only the fsync, which is a gap against the frozen reference — the seam was
// added at A2, after A0's `classify` was written, and nothing went back for it.
// The one namespace mutation an OPEN performs has to be observable and
// fault-injectable like every other.
test "wal3 B0: residue removal at open reports its unlink and its fsync" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r2seam");
    defer sc.deinit();
    const img = try headerImage(a, 1, 1);
    defer a.free(img);
    try sc.writeSegment(1, img);
    try sc.writeSegment(2, ""); // H1 residue on the highest name

    var rec = wal_io.RecordingIo.init(a);
    defer rec.deinit();
    const seam = rec.io();
    var set = try sc.openIo(false, &seam);
    defer set.deinit();

    const kinds = try rec.kinds(a);
    defer a.free(kinds);
    try testing.expectEqualSlices(wal_io.WalOpKind, &.{ .unlink, .dir_sync }, kinds);
    try testing.expectEqual(@as(i64, 2), rec.events.items[0].seq);
    try testing.expect(!try sc.segExists(2));
}

// ------------------------------------------------------- allocation failure

// An allocation failure during enumeration must NOT come back as "this namespace
// is empty". Rust reaches its `unwrap_or_default` only for the directory answer,
// because `Vec::push` cannot report OOM; a Zig catch-all would hand the caller a
// fresh-looking namespace over a store that already has segments, and B2 would
// then create segment 1 on top of it. The refusal is the whole point (design §6
// risk 14: allocation failure is operational, never a verdict about bytes).
test "wal3 B0: an allocation failure while enumerating refuses, it does not answer empty" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "oomenum");
    defer sc.deinit();
    for ([_]i64{ 1, 2, 3 }) |seq| {
        const img = try headerImage(a, seq, 1);
        defer a.free(img);
        try sc.writeSegment(seq, img);
    }
    // Walk the budget across the whole open. Every outcome must be either a
    // clean open or a refusal — never a set that reports no segments while three
    // are on disk.
    var budget: usize = 0;
    while (budget < 64) : (budget += 1) {
        var fa = FailingAllocator{ .inner = a, .budget = budget };
        const fal = fa.allocator();
        if (WalSegmentSet.open(fal, sc.base, false)) |*opened| {
            var set = opened.*;
            defer set.deinit();
            // If it opened at all, it saw the truth.
            try testing.expectEqual(@as(usize, 3), set.segmentsSlice().len);
            try testing.expectEqual(@as(i64, 4), set.nextSeq());
            break;
        } else |e| {
            try testing.expect(e == error.OutOfMemory);
        }
    }
    try testing.expect(budget < 64); // it did eventually open
}

// A create must not be able to fail AFTER its segment is durable. The list slot
// is reserved before the create I/O, so the only allocation failure a caller can
// see is one that happened before anything reached the device — which is why a
// refused create can be retried and a successful one is always in the set.
test "wal3 B0: a create never fails with its segment already durable" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "oomcreate");
    defer sc.deinit();
    var budget: usize = 0;
    while (budget < 64) : (budget += 1) {
        var fa = FailingAllocator{ .inner = a, .budget = budget };
        const fal = fa.allocator();
        var set = WalSegmentSet.open(fal, sc.base, false) catch |e| {
            try testing.expect(e == error.OutOfMemory);
            continue;
        };
        defer set.deinit();
        if (set.createSegment(1)) |_| {
            // Success: the segment is on disk AND in the set, and the byte total
            // agrees with the slow count.
            try testing.expectEqual(@as(usize, 1), set.segmentsSlice().len);
            try testing.expect(try sc.segExists(1));
            try testing.expectEqual(set.logBytesExact(), set.logBytes());
            break;
        } else |e| {
            try testing.expect(e == error.OutOfMemory);
            // Refused: nothing durable was left behind, so the set still
            // describes the namespace exactly.
            try testing.expect(!try sc.segExists(1));
            try testing.expectEqual(@as(usize, 0), set.segmentsSlice().len);
            try testing.expectEqual(@as(u64, 0), set.logBytes());
        }
    }
    try testing.expect(budget < 64);
}

// ...and because it is reported, it is injectable: a residue unlink that fails
// fails the OPEN, rather than leaving a set whose namespace was half-tidied.
test "wal3 B0: a residue unlink that fails fails the open" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "r2fail");
    defer sc.deinit();
    const img = try headerImage(a, 1, 1);
    defer a.free(img);
    try sc.writeSegment(1, img);
    try sc.writeSegment(2, "");

    var rec = wal_io.RecordingIo.init(a);
    defer rec.deinit();
    rec.fail_at = 0; // the residue unlink is the first event of the open
    const seam = rec.io();
    try testing.expectError(error.Io, sc.openIo(false, &seam));
    try testing.expect(try sc.segExists(2)); // untouched
    // The refusal released the lock, so the namespace opens again once the seam
    // stops failing.
    var set = try sc.open(false);
    defer set.deinit();
    try testing.expect(!try sc.segExists(2));
}

// The open note is THIS open's answer or nothing.
//
// codex round 2 on C5t. The note is filled from an `errdefer` declared partway
// down `openWithIo`, so an open that fails ABOVE that line — a base with no
// file-name component, an allocation failure — writes nothing, and a caller
// reusing the note would read the previous refusal's reason through it.
// `StoreWAL.openCfg` clears the caller's `Diag` on entry and would mask this,
// which is exactly why the guard belongs here too: `openWithIo` is public and
// its contract is its own.
//
// Two opens through ONE note. The first is D1, refused with a reason; the
// second is refused above every line that could write one.
test "wal3 B0: the open note is this open's answer or nothing" {
    const a = testing.allocator;
    var sc = try Scratch.init(a, "notereset");
    defer sc.deinit();
    {
        const f = try std.fs.cwd().createFile(sc.base, .{});
        defer f.close();
        try f.writeAll("a v1 log where a base belongs");
    }

    var note: WalSegmentSet.OpenNote = .{};
    try testing.expectError(error.DataCorruption,
        WalSegmentSet.openWithIo(a, sc.base, false, null, &note));
    try testing.expect(note.reason.len > 0);

    try testing.expectError(error.WrongConfiguration,
        WalSegmentSet.openWithIo(a, "/", false, null, &note));
    try testing.expectEqualStrings("", note.reason);
}
