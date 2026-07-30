//! Cross-port conformance fixture GENERATOR — Stage 1 (D workload).
//!
//! These fixtures pin the CURRENT state of an UNSTABLE on-disk format for
//! divergence detection between the java/rust/zig store engines. Cross-engine
//! openability is an implementation fact, not a supported feature; any format
//! change regenerates the fixtures as part of that change.
//!
//! Run via the dedicated build step (documented in build.zig):
//!
//! ```
//! zig build fixtures -- --out <dir> [--force] [--commit <hash>]
//! ```
//!
//! Performs the Stage-1 D workload through the PUBLIC StoreDirect API,
//! writes `<out>/direct-v1-zig.db` plus
//! `<out>/fragment.tsv` (fixture/file/recid/recidrange manifest rows; gzSha
//! left empty for the sync script to fill), and self-checks before publishing:
//! churn-recid contiguity, reopen + verify() + every reader assertion, file
//! length == fileTail, byte-stability of the verification reopen, and the E→G
//! extent-reuse assertion via a local index-slot decoder over the raw file
//! bytes. Refuses a nonempty output dir unless `--force`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const mapdb = @import("mapdb_zig_store");
const DbError = mapdb.DbError;
const DataInput2 = mapdb.DataInput2;
const DataOutput2 = mapdb.DataOutput2;
const StoreDirect = mapdb.StoreDirect;

const FIXTURE_ID = "direct-v1-zig";
const DB_NAME = "direct-v1-zig.db";

// ---------------------------------------------------------------- serializer

/// Raw-bytes serializer: content == value (framed by `size`). Same shape as
/// the `RawSer` fixtures in src/store/tck.zig / src/store/store_direct_test.zig
/// (duplicated here because the generator is a separate executable module).
const RawSer = struct {
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
        return std.mem.eql(u8, a, b);
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
const R = RawSer.instance;

// ------------------------------------------------------------------ payloads

/// Contract payload function: `payload(payloadId, len)[i] = (i*131 + payloadId) & 0xff`.
fn payloadAlloc(alloc: Allocator, payload_id: u64, len: usize) ![]u8 {
    const buf = try alloc.alloc(u8, len);
    for (buf, 0..) |*b, i| b.* = @truncate(i * 131 + payload_id);
    return buf;
}

// ------------------------------------------------- local index-slot decoder
//
// Generator-side ONLY (cross-engine consumers stay on the public API). The
// bit ops are copied verbatim from the engine so the decoder cannot drift:
// - MOFFSET / offset field / capUnits shift: src/store/index_val.zig
//   (`MOFFSET = 0x0000_FFFF_FFFF_FFF0`, `offset(iv) = iv & MOFFSET`,
//   `capUnits(iv) = iv >> 48`, `CAP_DELETED = 0xFFFE`).
// - parity1 / parity16 checks: src/store/parity.zig (`p1get`, `p16get`).
// - slot geometry: src/store/direct.zig (`ZERO_SLOTS_START = 524352`,
//   slot for recid r at `ZERO_SLOTS_START + (r-1)*8`, big-endian u64;
//   `O_FILE_TAIL = 40`).

const MOFFSET: u64 = 0x0000_FFFF_FFFF_FFF0; // index_val.zig MOFFSET
const CAP_DELETED: u32 = 0xFFFE; // index_val.zig CAP_DELETED
const ZERO_SLOTS_START: u64 = 524352; // direct.zig ZERO_SLOTS_START
const O_FILE_TAIL: u64 = 40; // direct.zig O_FILE_TAIL
const RECIDS_PER_ZERO_PAGE: u64 = 65528; // direct.zig RECIDS_PER_ZERO_PAGE

/// parity.zig `p1get`: validate and strip parity1.
fn p1get(v: u64) DbError!u64 {
    if (@popCount(v) & 1 != 1) return error.DataCorruption; // parity1 broken
    return v & ~@as(u64, 1);
}

/// parity.zig `p16get`: validate and strip parity16.
fn p16get(v: u64) DbError!u64 {
    const x = v & ~@as(u64, 0xFFFF);
    if ((v & 0xFFFF) != ((@as(u64, @popCount(x)) + 1) & 0xFFFF)) return error.DataCorruption; // parity16 broken
    return x;
}

fn u64At(buf: []const u8, off: u64) u64 {
    return std.mem.readInt(u64, buf[@intCast(off)..][0..8], .big);
}

/// Decoded (parity1-stripped) index slot of `recid` (zero index page only —
/// every Stage-1 fixture recid is far below RECIDS_PER_ZERO_PAGE).
fn indexSlot(file_bytes: []const u8, recid: u64) DbError!u64 {
    std.debug.assert(recid >= 1 and recid <= RECIDS_PER_ZERO_PAGE);
    return p1get(u64At(file_bytes, ZERO_SLOTS_START + (recid - 1) * 8));
}

fn slotOffset(iv: u64) u64 {
    return iv & MOFFSET; // index_val.zig offset()
}

fn slotCapUnits(iv: u64) u32 {
    return @truncate(iv >> 48); // index_val.zig capUnits()
}

// ---------------------------------------------------------------- utilities

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.process.fatal(fmt, args);
}

fn readWholeFile(alloc: Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(alloc, path, 256 * 1024 * 1024);
}

fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn expectPayload(alloc: Allocator, s: *StoreDirect, recid: u64, payload_id: u64, len: usize, label: []const u8) !void {
    const want = try payloadAlloc(alloc, payload_id, len);
    defer alloc.free(want);
    const got = (try s.get([]const u8, alloc, recid, R)) orelse
        fatal("self-check: {s} (recid {d}) is null, expected {d} bytes", .{ label, recid, len });
    defer alloc.free(got);
    if (!std.mem.eql(u8, want, got))
        fatal("self-check: {s} (recid {d}) content mismatch", .{ label, recid });
}

fn expectNull(alloc: Allocator, s: *StoreDirect, recid: u64, label: []const u8) !void {
    if (try s.get([]const u8, alloc, recid, R)) |g| {
        alloc.free(g);
        fatal("self-check: {s} (recid {d}) expected null content", .{ label, recid });
    }
}

fn expectVoid(alloc: Allocator, s: *StoreDirect, recid: u64) !void {
    if (s.get([]const u8, alloc, recid, R)) |g| {
        if (g) |b| alloc.free(b);
        fatal("self-check: recid {d} expected GetVoid (deleted)", .{recid});
    } else |err| {
        if (err != error.GetVoid)
            fatal("self-check: recid {d} expected GetVoid, got {s}", .{ recid, @errorName(err) });
    }
}

// -------------------------------------------------------------------- main

const Recids = struct {
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    f: u64,
    g: u64,
    e: u64,
    churn_from: u64,
    churn_to: u64,
    /// E's data offset decoded after the extra mid-workload commit.
    e_offset: u64,
};

/// D workload, EXACT contract order, public API only. The extra `commit()`
/// between contract steps 8 and 9 is sanctioned by the contract: it flushes
/// the store so E's pre-delete data offset can be captured from the file
/// bytes before E is deleted (commit performs no allocation).
fn runWorkload(alloc: Allocator, db_path: []const u8) !Recids {
    var s = try StoreDirect.openFile(alloc, db_path, true);
    defer s.deinit();

    var r: Recids = undefined;

    // 1..4: A, B (zero-length), C (explicit null via update(recid, null)), D.
    {
        const p = try payloadAlloc(alloc, 1, 100);
        defer alloc.free(p);
        r.a = try s.put([]const u8, alloc, p, R);
    }
    r.b = try s.put([]const u8, alloc, &[_]u8{}, R);
    {
        const p = try payloadAlloc(alloc, 3, 40);
        defer alloc.free(p);
        r.c = try s.put([]const u8, alloc, p, R);
        try s.update([]const u8, alloc, r.c, null, R);
    }
    r.d = try s.preallocate();

    // 5: F = exactly the first-linked payload boundary.
    {
        const p = try payloadAlloc(alloc, 6, 1_048_525);
        defer alloc.free(p);
        r.f = try s.put([]const u8, alloc, p, R);
    }

    // 6..7: G preallocated (updated in step 10), then E.
    r.g = try s.preallocate();
    {
        const p = try payloadAlloc(alloc, 5, 256);
        defer alloc.free(p);
        r.e = try s.put([]const u8, alloc, p, R);
    }

    // 8: churn — 200 puts of E's capacity class, all live simultaneously.
    r.churn_from = 0;
    r.churn_to = 0;
    var churn: [200]u64 = undefined;
    for (&churn, 0..) |*cr, j| {
        const p = try payloadAlloc(alloc, 1000 + j, 256);
        defer alloc.free(p);
        cr.* = try s.put([]const u8, alloc, p, R);
        // contiguity (else abort — the manifest uses a recidrange row)
        if (j > 0 and cr.* != churn[j - 1] + 1)
            fatal("churn recids not contiguous: {d} follows {d}", .{ cr.*, churn[j - 1] });
    }
    r.churn_from = churn[0];
    r.churn_to = churn[churn.len - 1];

    // extra commit (sanctioned, see fn doc): capture E's pre-delete offset.
    try s.commit();
    {
        const bytes = try readWholeFile(alloc, db_path);
        defer alloc.free(bytes);
        r.e_offset = slotOffset(try indexSlot(bytes, r.e));
        if (r.e_offset == 0) fatal("E (recid {d}) has no data offset after commit", .{r.e});
    }

    // 9: delete churn in creation order; then delete E LAST.
    for (churn) |cr| try s.delete(cr);
    try s.delete(r.e);

    // 10: update the preallocated G with an E-sized payload (LIFO free-data
    // stack → G must take E's freed extent; asserted post-close).
    {
        const p = try payloadAlloc(alloc, 7, 256);
        defer alloc.free(p);
        try s.update([]const u8, alloc, r.g, p, R);
    }

    // 11: commit + close, no further operations.
    try s.commit();
    try s.close();
    return r;
}

/// Reopen the published file and run EVERY reader assertion from the contract
/// (the same assertions the conformance suites run in all three engines).
fn selfCheckReaders(alloc: Allocator, db_path: []const u8, r: Recids) !void {
    var s = try StoreDirect.openFile(alloc, db_path, true);
    defer s.deinit();
    try s.verify();

    try expectPayload(alloc, &s, r.a, 1, 100, "A");
    // B: present, zero-length, NOT null (this engine distinguishes the two).
    {
        const got = (try s.get([]const u8, alloc, r.b, R)) orelse
            fatal("self-check: B (recid {d}) is null, expected empty", .{r.b});
        defer alloc.free(got);
        if (got.len != 0) fatal("self-check: B (recid {d}) expected zero-length", .{r.b});
    }
    try expectNull(alloc, &s, r.c, "C");
    try expectNull(alloc, &s, r.d, "D");
    try expectVoid(alloc, &s, r.e);
    var cr = r.churn_from;
    while (cr <= r.churn_to) : (cr += 1) try expectVoid(alloc, &s, cr);
    try expectPayload(alloc, &s, r.f, 6, 1_048_525, "F");
    try expectPayload(alloc, &s, r.g, 7, 256, "G");

    // getAllRecids as a set == {A, B, C, F, G} (D prealloc excluded).
    {
        const all = try s.getAllRecids(alloc);
        defer alloc.free(all);
        var want = [_]u64{ r.a, r.b, r.c, r.f, r.g };
        std.mem.sort(u64, &want, {}, std.sort.asc(u64));
        if (!std.mem.eql(u64, &want, all))
            fatal("self-check: getAllRecids mismatch (got {d} recids, want 5)", .{all.len});
    }
    try s.close();
}

/// Byte-level self-checks on the published file: length == fileTail, E's slot
/// deleted, and G's slot offset == E's captured pre-delete offset (extent reuse).
fn selfCheckBytes(bytes: []const u8, r: Recids) !void {
    const file_tail = try p16get(u64At(bytes, O_FILE_TAIL));
    if (file_tail != bytes.len)
        fatal("file length {d} != fileTail {d}", .{ bytes.len, file_tail });
    const e_slot = try indexSlot(bytes, r.e);
    if (slotCapUnits(e_slot) != CAP_DELETED)
        fatal("E (recid {d}) slot not CAP_DELETED after workload", .{r.e});
    const g_off = slotOffset(try indexSlot(bytes, r.g));
    if (g_off != r.e_offset)
        fatal("extent reuse broken: G offset {d} != E pre-delete offset {d}", .{ g_off, r.e_offset });
}

fn writeFragment(alloc: Allocator, path: []const u8, r: Recids, raw_len: usize, raw_sha: []const u8, commit: []const u8) !void {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(alloc);
    const id = FIXTURE_ID;

    const RecidRow = struct { label: []const u8, recid: u64, state: []const u8, pid: u64, len: u64 };
    const rows = [_]RecidRow{
        .{ .label = "A", .recid = r.a, .state = "live", .pid = 1, .len = 100 },
        .{ .label = "B", .recid = r.b, .state = "live", .pid = 2, .len = 0 },
        .{ .label = "C", .recid = r.c, .state = "null", .pid = 3, .len = 40 },
        .{ .label = "D", .recid = r.d, .state = "prealloc", .pid = 0, .len = 0 },
        .{ .label = "F", .recid = r.f, .state = "live", .pid = 6, .len = 1_048_525 },
        .{ .label = "G", .recid = r.g, .state = "live", .pid = 7, .len = 256 },
        .{ .label = "E", .recid = r.e, .state = "deleted", .pid = 5, .len = 256 },
    };

    var line = try std.fmt.allocPrint(alloc, "fixture\t{s}\tdirect\tzig\t{s}\n", .{ id, commit });
    try out.appendSlice(alloc, line);
    alloc.free(line);
    // gzSha column intentionally empty — the sync script compresses and fills it.
    line = try std.fmt.allocPrint(alloc, "file\t{s}\t{s}\t{d}\t{s}\t\n", .{ id, DB_NAME, raw_len, raw_sha });
    try out.appendSlice(alloc, line);
    alloc.free(line);
    for (rows) |row| {
        line = try std.fmt.allocPrint(alloc, "recid\t{s}\t{s}\t{d}\t{s}\t{d}\t{d}\n", .{ id, row.label, row.recid, row.state, row.pid, row.len });
        try out.appendSlice(alloc, line);
        alloc.free(line);
    }
    line = try std.fmt.allocPrint(alloc, "recidrange\t{s}\tchurn\t{d}\t{d}\tdeleted\t1000\t256\n", .{ id, r.churn_from, r.churn_to });
    try out.appendSlice(alloc, line);
    alloc.free(line);

    const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer f.close();
    try f.writeAll(out.items);
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // ---- CLI: --out <dir> (required), --force, --commit <hash> ----
    var out_dir_arg: ?[]const u8 = null;
    var force = false;
    var commit: []const u8 = "unknown";
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--out")) {
            i += 1;
            if (i >= args.len) fatal("--out needs a directory argument", .{});
            out_dir_arg = args[i];
        } else if (std.mem.eql(u8, arg, "--force")) {
            force = true;
        } else if (std.mem.eql(u8, arg, "--commit")) {
            i += 1;
            if (i >= args.len) fatal("--commit needs a hash argument", .{});
            commit = args[i];
        } else {
            fatal("unknown argument `{s}` (usage: --out <dir> [--force] [--commit <hash>])", .{arg});
        }
    }
    const out_dir = out_dir_arg orelse
        fatal("missing --out <dir> (usage: zig build fixtures -- --out <dir> [--force])", .{});

    // ---- overwrite guard: refuse a nonempty output dir without --force ----
    std.fs.cwd().makePath(out_dir) catch |e|
        fatal("cannot create output dir `{s}`: {s}", .{ out_dir, @errorName(e) });
    {
        var dir = std.fs.cwd().openDir(out_dir, .{ .iterate = true }) catch |e|
            fatal("cannot open output dir `{s}`: {s}", .{ out_dir, @errorName(e) });
        defer dir.close();
        var it = dir.iterate();
        if (try it.next() != null and !force)
            fatal("output dir `{s}` is not empty (pass --force to overwrite)", .{out_dir});
        if (force) {
            dir.deleteFile(DB_NAME) catch |e| if (e != error.FileNotFound)
                fatal("cannot remove stale {s}: {s}", .{ DB_NAME, @errorName(e) });
            dir.deleteFile("fragment.tsv") catch |e| if (e != error.FileNotFound)
                fatal("cannot remove stale fragment.tsv: {s}", .{@errorName(e)});
        }
    }

    const db_path = try std.fs.path.join(alloc, &.{ out_dir, DB_NAME });
    defer alloc.free(db_path);
    const frag_path = try std.fs.path.join(alloc, &.{ out_dir, "fragment.tsv" });
    defer alloc.free(frag_path);

    // ---- workload + self-checks ----
    const r = try runWorkload(alloc, db_path);

    const bytes = try readWholeFile(alloc, db_path);
    defer alloc.free(bytes);
    try selfCheckBytes(bytes, r);
    try selfCheckReaders(alloc, db_path, r);
    {
        // the verification reopen must have left the published bytes unchanged
        const after = try readWholeFile(alloc, db_path);
        defer alloc.free(after);
        if (!std.mem.eql(u8, bytes, after))
            fatal("verification reopen changed the published file bytes", .{});
    }

    const raw_sha = sha256Hex(bytes);
    try writeFragment(alloc, frag_path, r, bytes.len, &raw_sha, commit);

    std.debug.print(
        "wrote {s} ({d} bytes, sha256 {s})\n" ++
            "recids: A={d} B={d} C={d} D={d} F={d} G={d} E={d} churn={d}..{d}\n" ++
            "self-check OK (verify + readers + E->G extent reuse at offset {d})\n",
        .{ db_path, bytes.len, raw_sha, r.a, r.b, r.c, r.d, r.f, r.g, r.e, r.churn_from, r.churn_to, r.e_offset },
    );
}
