//! Cross-port conformance fixture tests — Stage 1 (D accept matrix + the
//! reject rows derivable from D outputs).
//!
//! These fixtures pin the CURRENT state of an UNSTABLE on-disk format for
//! divergence detection between the java/rust/zig store engines. Cross-engine
//! openability is an implementation fact, not a supported feature; any format
//! change regenerates the fixtures as part of that change.
//!
//! Fixture data lives in `src/xfixtures/data/` (`MANIFEST.tsv` + one
//! `<relName>.gz` per fixture file, byte-identical across the three repos)
//! and is consumed via `@embedFile` (no cwd assumption). The suite HARD-FAILS
//! (test failure, not skip) on a manifest whose version is not 1; a MISSING
//! manifest or data file is a COMPILE error by construction of `@embedFile`,
//! which is the strongest possible "sync step was never run" failure.
//!
//! Flow (identical in all three engines, see impl-contract-stage1.md):
//! 1. parse MANIFEST.tsv, assert `version 1`;
//! 2. gunzip every referenced `.gz`, verify rawSha256 + rawLen (and gzSha256);
//! 3. for each `expect` row with engine == zig: fresh per-cell temp dir, copy
//!    the fixture file in as `placeAs`, run the cell (accept: open + verify()
//!    + per-recid assertions + getAllRecids set equality; reject:
//!    `error.DataCorruption` from the opener), then assert the working copy
//!    is byte-identical and no files beyond `.lock` sidecars appeared.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const io = @import("../io.zig");
const DataInput2 = io.DataInput2;
const DataOutput2 = io.DataOutput2;
const store_mod = @import("../store/mod.zig");
const StoreDirect = store_mod.StoreDirect;
const StoreWAL = store_mod.StoreWAL;

const ENGINE = "zig";

const manifest_tsv: []const u8 = @embedFile("data/MANIFEST.tsv");

const EmbeddedGz = struct { rel_name: []const u8, gz: []const u8 };
/// NOTE: this list MUST match the `file` rows of data/MANIFEST.tsv — one
/// entry per row, `rel_name` == the row's relName, embedding `<relName>.gz`.
/// `@embedFile` needs comptime-known names, so the list is static; the
/// runtime lookup below hard-fails on any manifest file row missing here.
const embedded_gz = [_]EmbeddedGz{
    .{ .rel_name = "direct-v1-java.db", .gz = @embedFile("data/direct-v1-java.db.gz") },
    .{ .rel_name = "direct-v1-rust.db", .gz = @embedFile("data/direct-v1-rust.db.gz") },
    .{ .rel_name = "direct-v1-zig.db", .gz = @embedFile("data/direct-v1-zig.db.gz") },
    .{ .rel_name = "reject-mdb5-sd1.db", .gz = @embedFile("data/reject-mdb5-sd1.db.gz") },
    .{ .rel_name = "reject-sd1-badfeatures.db", .gz = @embedFile("data/reject-sd1-badfeatures.db.gz") },
    .{ .rel_name = "reject-sd1-badchecksum.db", .gz = @embedFile("data/reject-sd1-badchecksum.db.gz") },
    .{ .rel_name = "reject-sd1-short.db", .gz = @embedFile("data/reject-sd1-short.db.gz") },
};

// ---------------------------------------------------------------- serializer

/// Raw-bytes serializer: content == value (framed by `size`). Same shape as
/// the `RawSer` fixtures in tck.zig / store_direct_test.zig (the contract
/// mandates a raw byte-array serializer — payload bytes ARE the content).
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

/// Contract payload function: `payload(payloadId, len)[i] = (i*131 + payloadId) & 0xff`.
/// Recomputed per assertion — the >1 MiB payload is never cached globally.
fn payloadAlloc(alloc: Allocator, payload_id: u64, len: usize) ![]u8 {
    const buf = try alloc.alloc(u8, len);
    for (buf, 0..) |*b, i| b.* = @truncate(i * 131 + payload_id);
    return buf;
}

// ------------------------------------------------------------ manifest model

const FileRow = struct {
    fixture: []const u8,
    rel_name: []const u8,
    raw_len: u64,
    raw_sha: []const u8,
    gz_sha: []const u8,
};

const ExpectRow = struct {
    fixture: []const u8,
    engine: []const u8,
    verdict: []const u8,
    opener: []const u8,
    place_as: []const u8,
    open_arg: []const u8,
};

const RecState = enum { live, null_rec, prealloc, deleted };

/// A `recid` row (from == to) or a `recidrange` row; payloadId for recid r in
/// a range = pid_base + (r - from).
const RecidRow = struct {
    fixture: []const u8,
    label: []const u8,
    from: u64,
    to: u64,
    state: RecState,
    pid_base: u64,
    len: u64,
};

const Manifest = struct {
    files: std.ArrayListUnmanaged(FileRow) = .empty,
    expects: std.ArrayListUnmanaged(ExpectRow) = .empty,
    recids: std.ArrayListUnmanaged(RecidRow) = .empty,

    fn deinit(self: *Manifest, alloc: Allocator) void {
        self.files.deinit(alloc);
        self.expects.deinit(alloc);
        self.recids.deinit(alloc);
    }

    /// Stage 1: every fixture has exactly ONE file row (asserted here).
    fn fileFor(self: *const Manifest, fixture: []const u8) !FileRow {
        var found: ?FileRow = null;
        for (self.files.items) |f| {
            if (std.mem.eql(u8, f.fixture, fixture)) {
                if (found != null) {
                    std.debug.print("[xfixtures] fixture {s}: more than one file row (Stage 1 forbids)\n", .{fixture});
                    return error.XFixturesManifest;
                }
                found = f;
            }
        }
        return found orelse {
            std.debug.print("[xfixtures] fixture {s}: no file row\n", .{fixture});
            return error.XFixturesManifest;
        };
    }
};

fn parseState(s: []const u8) !RecState {
    if (std.mem.eql(u8, s, "live")) return .live;
    if (std.mem.eql(u8, s, "null")) return .null_rec;
    if (std.mem.eql(u8, s, "prealloc")) return .prealloc;
    if (std.mem.eql(u8, s, "deleted")) return .deleted;
    std.debug.print("[xfixtures] unknown recid state `{s}`\n", .{s});
    return error.XFixturesManifest;
}

fn parseU64(s: []const u8) !u64 {
    return std.fmt.parseInt(u64, s, 10) catch {
        std.debug.print("[xfixtures] bad number `{s}` in manifest\n", .{s});
        return error.XFixturesManifest;
    };
}

/// Split one manifest line into up to 8 tab-separated fields; `n` fields
/// required (extra fields are a manifest error).
fn fields(line: []const u8, comptime n: usize) ![n][]const u8 {
    var out: [n][]const u8 = undefined;
    var it = std.mem.splitScalar(u8, line, '\t');
    for (&out) |*f| {
        f.* = it.next() orelse {
            std.debug.print("[xfixtures] manifest line has fewer than {d} fields: `{s}`\n", .{ n, line });
            return error.XFixturesManifest;
        };
    }
    if (it.next() != null) {
        std.debug.print("[xfixtures] manifest line has more than {d} fields: `{s}`\n", .{ n, line });
        return error.XFixturesManifest;
    }
    return out;
}

/// Parse MANIFEST.tsv. `#` comments and blank lines ignored; the first data
/// line MUST be `version<TAB>1` — anything else is a HARD test failure.
fn parseManifest(alloc: Allocator) !Manifest {
    var m: Manifest = .{};
    errdefer m.deinit(alloc);
    var saw_version = false;
    var lines = std.mem.splitScalar(u8, manifest_tsv, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trimRight(u8, line_raw, "\r");
        if (line.len == 0 or line[0] == '#') continue;
        var it = std.mem.splitScalar(u8, line, '\t');
        const tag = it.next().?;
        if (!saw_version) {
            const f = try fields(line, 2);
            if (!std.mem.eql(u8, f[0], "version") or !std.mem.eql(u8, f[1], "1")) {
                std.debug.print("[xfixtures] first manifest data line is not `version 1`: `{s}`\n", .{line});
                return error.XFixturesManifest;
            }
            saw_version = true;
            continue;
        }
        if (std.mem.eql(u8, tag, "fixture")) {
            _ = try fields(line, 5); // shape check only (id/kind/engine/commit)
        } else if (std.mem.eql(u8, tag, "file")) {
            const f = try fields(line, 6);
            try m.files.append(alloc, .{
                .fixture = f[1],
                .rel_name = f[2],
                .raw_len = try parseU64(f[3]),
                .raw_sha = f[4],
                .gz_sha = f[5],
            });
        } else if (std.mem.eql(u8, tag, "expect")) {
            const f = try fields(line, 7);
            try m.expects.append(alloc, .{
                .fixture = f[1],
                .engine = f[2],
                .verdict = f[3],
                .opener = f[4],
                .place_as = f[5],
                .open_arg = f[6],
            });
        } else if (std.mem.eql(u8, tag, "recid")) {
            const f = try fields(line, 7);
            const recid = try parseU64(f[3]);
            try m.recids.append(alloc, .{
                .fixture = f[1],
                .label = f[2],
                .from = recid,
                .to = recid,
                .state = try parseState(f[4]),
                .pid_base = try parseU64(f[5]),
                .len = try parseU64(f[6]),
            });
        } else if (std.mem.eql(u8, tag, "recidrange")) {
            const f = try fields(line, 8);
            const from = try parseU64(f[3]);
            const to = try parseU64(f[4]);
            if (from > to) {
                std.debug.print("[xfixtures] empty recidrange: `{s}`\n", .{line});
                return error.XFixturesManifest;
            }
            try m.recids.append(alloc, .{
                .fixture = f[1],
                .label = f[2],
                .from = from,
                .to = to,
                .state = try parseState(f[5]),
                .pid_base = try parseU64(f[6]),
                .len = try parseU64(f[7]),
            });
        } else if (std.mem.eql(u8, tag, "edit")) {
            _ = try fields(line, 6);
            // recorded provenance of derived reject files; not needed to run cells
        } else {
            std.debug.print("[xfixtures] unknown manifest row tag `{s}`\n", .{tag});
            return error.XFixturesManifest;
        }
    }
    if (!saw_version) {
        std.debug.print("[xfixtures] manifest has no data lines (missing `version 1`)\n", .{});
        return error.XFixturesManifest;
    }
    return m;
}

// ---------------------------------------------------------- gunzip + hashing

fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// Decompress an embedded `.gz` (zig 0.15 API: `std.compress.flate.Decompress`
/// over a fixed `std.Io.Reader`, container `.gzip`). Owned result.
fn gunzipAlloc(alloc: Allocator, gz: []const u8, raw_len: u64) ![]u8 {
    var in: std.Io.Reader = .fixed(gz);
    const window = try alloc.alloc(u8, std.compress.flate.max_window_len);
    defer alloc.free(window);
    var dec = std.compress.flate.Decompress.init(&in, .gzip, window);
    return dec.reader.allocRemaining(alloc, .limited64(raw_len + 1)) catch |e| {
        std.debug.print("[xfixtures] gunzip failed: {s}\n", .{@errorName(e)});
        return error.XFixturesGunzip;
    };
}

/// Embedded raw content for a manifest file row: gz lookup by relName, gunzip,
/// gzSha256 + rawSha256 + rawLen verification. Owned result.
fn rawContentFor(alloc: Allocator, row: FileRow) ![]u8 {
    const gz: []const u8 = for (embedded_gz) |e| {
        if (std.mem.eql(u8, e.rel_name, row.rel_name)) break e.gz;
    } else {
        std.debug.print("[xfixtures] file `{s}` not in the embedded_gz list (sync it with MANIFEST.tsv)\n", .{row.rel_name});
        return error.XFixturesManifest;
    };
    const gz_sha = sha256Hex(gz);
    if (!std.mem.eql(u8, &gz_sha, row.gz_sha)) {
        std.debug.print("[xfixtures] {s}.gz sha256 mismatch: manifest {s}, embedded {s}\n", .{ row.rel_name, row.gz_sha, &gz_sha });
        return error.XFixturesChecksum;
    }
    const raw = try gunzipAlloc(alloc, gz, row.raw_len);
    errdefer alloc.free(raw);
    if (raw.len != row.raw_len) {
        std.debug.print("[xfixtures] {s} rawLen mismatch: manifest {d}, got {d}\n", .{ row.rel_name, row.raw_len, raw.len });
        return error.XFixturesChecksum;
    }
    const raw_sha = sha256Hex(raw);
    if (!std.mem.eql(u8, &raw_sha, row.raw_sha)) {
        std.debug.print("[xfixtures] {s} rawSha256 mismatch: manifest {s}, got {s}\n", .{ row.rel_name, row.raw_sha, &raw_sha });
        return error.XFixturesChecksum;
    }
    return raw;
}

const Baseline = struct {
    fixture: []const u8,
    rel_name: []const u8,
    raw: []u8,
};

fn loadBaselines(alloc: Allocator, m: *const Manifest) !std.ArrayListUnmanaged(Baseline) {
    if (embedded_gz.len != m.files.items.len) {
        std.debug.print(
            "[xfixtures] embedded_gz/file-row count mismatch: embedded {d}, manifest {d}\n",
            .{ embedded_gz.len, m.files.items.len },
        );
        return error.XFixturesManifest;
    }
    for (embedded_gz) |embedded| {
        var matches: usize = 0;
        for (m.files.items) |row| {
            if (std.mem.eql(u8, embedded.rel_name, row.rel_name)) matches += 1;
        }
        if (matches != 1) {
            std.debug.print(
                "[xfixtures] embedded file `{s}` has {d} matching manifest file rows, want 1\n",
                .{ embedded.rel_name, matches },
            );
            return error.XFixturesManifest;
        }
    }

    var baselines: std.ArrayListUnmanaged(Baseline) = .empty;
    errdefer {
        for (baselines.items) |base| alloc.free(base.raw);
        baselines.deinit(alloc);
    }
    for (m.files.items) |row| {
        const raw = try rawContentFor(alloc, row);
        baselines.append(alloc, .{
            .fixture = row.fixture,
            .rel_name = row.rel_name,
            .raw = raw,
        }) catch |e| {
            alloc.free(raw);
            return e;
        };
    }
    return baselines;
}

fn baselineFor(baselines: []const Baseline, fixture: []const u8, rel_name: []const u8) ![]const u8 {
    for (baselines) |base| {
        if (std.mem.eql(u8, base.fixture, fixture) and std.mem.eql(u8, base.rel_name, rel_name))
            return base.raw;
    }
    std.debug.print("[xfixtures] no verified baseline for fixture `{s}`, file `{s}`\n", .{ fixture, rel_name });
    return error.XFixturesManifest;
}

// ------------------------------------------------------------------ cells

/// Cell-scoped context prefix for assertion messages.
fn cellFail(cell: ExpectRow, comptime fmt: []const u8, args: anytype) error{XFixturesCell} {
    std.debug.print("[xfixtures] cell fixture={s} verdict={s} opener={s} placeAs={s}: ", .{ cell.fixture, cell.verdict, cell.opener, cell.place_as });
    std.debug.print(fmt ++ "\n", args);
    return error.XFixturesCell;
}

fn checkRecid(alloc: Allocator, s: *StoreDirect, cell: ExpectRow, row: RecidRow, recid: u64) !void {
    switch (row.state) {
        .live => {
            const pid = row.pid_base + (recid - row.from);
            const want = try payloadAlloc(alloc, pid, @intCast(row.len));
            defer alloc.free(want);
            const got = (s.get([]const u8, alloc, recid, R) catch |e|
                return cellFail(cell, "recid {d} ({s}): get failed: {s}", .{ recid, row.label, @errorName(e) })) orelse
                return cellFail(cell, "recid {d} ({s}): expected {d} live bytes, got null", .{ recid, row.label, row.len });
            defer alloc.free(got);
            if (!std.mem.eql(u8, want, got))
                return cellFail(cell, "recid {d} ({s}): content mismatch (len {d} vs {d})", .{ recid, row.label, got.len, want.len });
        },
        .null_rec, .prealloc => {
            const got = s.get([]const u8, alloc, recid, R) catch |e|
                return cellFail(cell, "recid {d} ({s}): get failed: {s}", .{ recid, row.label, @errorName(e) });
            if (got) |g| {
                alloc.free(g);
                return cellFail(cell, "recid {d} ({s}): expected null content", .{ recid, row.label });
            }
        },
        .deleted => {
            if (s.get([]const u8, alloc, recid, R)) |got| {
                if (got) |g| alloc.free(g);
                return cellFail(cell, "recid {d} ({s}): expected error.GetVoid (deleted)", .{ recid, row.label });
            } else |e| if (e != error.GetVoid)
                return cellFail(cell, "recid {d} ({s}): expected error.GetVoid, got {s}", .{ recid, row.label, @errorName(e) });
        },
    }
}

fn runAcceptDirect(alloc: Allocator, cell: ExpectRow, db_path: []const u8, m: *const Manifest) !void {
    var s = StoreDirect.openFile(alloc, db_path, true) catch |e|
        return cellFail(cell, "open failed: {s}", .{@errorName(e)});
    defer s.deinit();
    s.verify() catch |e| return cellFail(cell, "verify() failed: {s}", .{@errorName(e)});

    // per-recid assertions + expected getAllRecids set (live + null rows)
    var want_all: std.ArrayListUnmanaged(u64) = .empty;
    defer want_all.deinit(alloc);
    for (m.recids.items) |row| {
        if (!std.mem.eql(u8, row.fixture, cell.fixture)) continue;
        var recid = row.from;
        while (recid <= row.to) : (recid += 1) {
            try checkRecid(alloc, &s, cell, row, recid);
            if (row.state == .live or row.state == .null_rec) try want_all.append(alloc, recid);
        }
    }
    std.mem.sort(u64, want_all.items, {}, std.sort.asc(u64));
    const all = s.getAllRecids(alloc) catch |e|
        return cellFail(cell, "getAllRecids failed: {s}", .{@errorName(e)});
    defer alloc.free(all);
    if (!std.mem.eql(u64, want_all.items, all))
        return cellFail(cell, "getAllRecids set mismatch: got {d} recids, want {d}", .{ all.len, want_all.items.len });

    s.close() catch |e| return cellFail(cell, "close failed: {s}", .{@errorName(e)});
}

fn runReject(alloc: Allocator, cell: ExpectRow, path: []const u8) !void {
    if (std.mem.eql(u8, cell.opener, "direct")) {
        if (StoreDirect.openFile(alloc, path, true)) |*opened| {
            var s = opened.*;
            s.deinit();
            return cellFail(cell, "StoreDirect open unexpectedly succeeded", .{});
        } else |e| if (e != error.DataCorruption)
            return cellFail(cell, "expected error.DataCorruption, got {s}", .{@errorName(e)});
    } else if (std.mem.eql(u8, cell.opener, "wal")) {
        if (StoreWAL.open(alloc, path, true)) |*opened| {
            var s = opened.*;
            s.deinit();
            return cellFail(cell, "StoreWAL open unexpectedly succeeded", .{});
        } else |e| if (e != error.DataCorruption)
            return cellFail(cell, "expected error.DataCorruption, got {s}", .{@errorName(e)});
    } else {
        return cellFail(cell, "unknown opener", .{});
    }
}

/// Post-cell invariants: working copy byte-identical to the pristine raw, and
/// no files beyond `.lock` sidecars appeared in the cell dir.
fn checkCellDir(alloc: Allocator, cell_dir: std.fs.Dir, cell: ExpectRow, pristine: []const u8) !void {
    const after = cell_dir.readFileAlloc(alloc, cell.place_as, 256 * 1024 * 1024) catch |e|
        return cellFail(cell, "working copy unreadable after cell: {s}", .{@errorName(e)});
    defer alloc.free(after);
    if (!std.mem.eql(u8, pristine, after))
        return cellFail(cell, "working copy bytes changed (len {d} -> {d})", .{ pristine.len, after.len });
    var it = cell_dir.iterate();
    while (it.next() catch |e| return cellFail(cell, "cell dir iteration failed: {s}", .{@errorName(e)})) |entry| {
        if (std.mem.eql(u8, entry.name, cell.place_as)) continue;
        if (std.mem.endsWith(u8, entry.name, ".lock")) continue; // allowed sidecar
        return cellFail(cell, "unexpected new file `{s}` in cell dir", .{entry.name});
    }
}

// ------------------------------------------------------------------- tests

test "xfixtures: Stage-1 cross-port conformance (engine=zig)" {
    const alloc = testing.allocator;
    var m = try parseManifest(alloc);
    defer m.deinit(alloc);

    // Verify the complete embedded bundle before opening any cell. A damaged
    // fixture must fail the preflight even when its expect row appears late.
    var baselines = try loadBaselines(alloc, &m);
    defer {
        for (baselines.items) |base| alloc.free(base.raw);
        baselines.deinit(alloc);
    }

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var cells_run: usize = 0;
    for (m.expects.items, 0..) |cell, idx| {
        if (!std.mem.eql(u8, cell.engine, ENGINE)) continue;
        const file_row = try m.fileFor(cell.fixture);
        const pristine = try baselineFor(baselines.items, cell.fixture, file_row.rel_name);

        // fresh per-cell dir with the fixture file placed as `placeAs`
        var name_buf: [64]u8 = undefined;
        const cell_name = try std.fmt.bufPrint(&name_buf, "cell{d}", .{idx});
        var cell_dir = try tmp.dir.makeOpenPath(cell_name, .{ .iterate = true });
        defer cell_dir.close();
        try cell_dir.writeFile(.{ .sub_path = cell.place_as, .data = pristine });

        // absolute paths — store openers resolve relative to cwd
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const cell_abs = try cell_dir.realpath(".", &path_buf);
        const open_path = try std.fs.path.join(alloc, &.{ cell_abs, cell.open_arg });
        defer alloc.free(open_path);

        if (std.mem.eql(u8, cell.verdict, "accept")) {
            if (!std.mem.eql(u8, cell.opener, "direct"))
                return cellFail(cell, "accept opener `{s}` is Stage 2 (unsupported here)", .{cell.opener});
            try runAcceptDirect(alloc, cell, open_path, &m);
        } else if (std.mem.eql(u8, cell.verdict, "reject")) {
            try runReject(alloc, cell, open_path);
        } else {
            return cellFail(cell, "unknown verdict", .{});
        }
        try checkCellDir(alloc, cell_dir, cell, pristine);
        cells_run += 1;
    }
    // The manifest must drive at least one zig cell — an empty run means the
    // sync step produced a manifest this engine silently ignores.
    try testing.expect(cells_run > 0);
}

test {
    testing.refAllDecls(@This());
}
