//! Cross-port conformance harness — **both manifest schemas**, dispatched on
//! the version line (Stage C slice **C3z**).
//!
//! `src/xfixtures/data/` is the live schema-v1 tree; `src/xfixtures/data-v2/` is
//! the shared static schema-v2 sample (`todo/store-cross/sample-v2/`, byte for
//! byte). Keeping both roots in the suite at once is deliberate: C6 is a data
//! commit, and a reader that only ever saw the schema it was written for would
//! discover the other one on cutover day.
//!
//! What runs here:
//!
//! - **v1 cells** — accept/reject, `direct` and `wal` openers, as before, but
//!   now through the SHARED parser in `xfix.zig` rather than a bespoke one.
//! - **v2 `rw` and `ro` cells** — both here. Decision C-D3 costs this port
//!   nothing: `WalOptions.read_only` is `pub` and this suite is in-package, so
//!   neither mode needs new public surface (rust had to move its `ro` executor
//!   into the crate to say the same thing).
//! - **the two §11.2 comparisons** — framing against `GOLDEN-DECODE.tsv`,
//!   decoded bodies against `GOLDEN-BODY.tsv`, which the frozen Java reader
//!   authored.
//! - **C-D4** — the generated `embedded_v2.zig` table, graded by three-way set
//!   equality against the manifest and against what `build.zig` finds on disk.
//!
//! Fixture data is consumed via `@embedFile` (no cwd assumption). A MISSING
//! manifest or data file is a COMPILE error by construction, which is the
//! strongest possible "the sync step was never run".

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const DbError = @import("../errors.zig").DbError;
const store_mod = @import("../store/mod.zig");
const StoreDirect = store_mod.StoreDirect;
const StoreWAL = store_mod.StoreWAL;

const xfix = @import("xfix.zig");
const embedded_v2 = @import("embedded_v2.zig");
/// What `build.zig` found in `src/xfixtures/data-v2/` — C-D4's third set, and
/// the only one of the three neither the manifest nor the generator can affect.
const distributed = @import("xfix_distributed");

const ENGINE = xfix.ENGINE;

// ---------------------------------------------------------------------------
// schema v1 — the live tree
// ---------------------------------------------------------------------------

const v1_manifest_tsv: []const u8 = @embedFile("data/MANIFEST.tsv");

const EmbeddedGz = struct { rel_name: []const u8, gz: []const u8 };
/// This list MUST cover every `file` row of data/MANIFEST.tsv. `@embedFile`
/// needs comptime-known names, so it is static; the runtime preflight hard-fails
/// on any manifest file row missing here.
///
/// Surplus is TOLERATED on this v1 root and refused on the v2 one, which is not
/// an inconsistency: the v1 tree is live data that the sync step rewrites
/// generation by generation, so a not-yet-referenced fixture needs a placeholder
/// `.gz` and no code change. The v2 sample is STATIC and generated, which is why
/// C-D4 can demand set equality there.
const embedded_gz = [_]EmbeddedGz{
    .{ .rel_name = "direct-v1-java.db", .gz = @embedFile("data/direct-v1-java.db.gz") },
    .{ .rel_name = "direct-v1-rust.db", .gz = @embedFile("data/direct-v1-rust.db.gz") },
    .{ .rel_name = "direct-v1-zig.db", .gz = @embedFile("data/direct-v1-zig.db.gz") },
    .{ .rel_name = "reject-mdb5-sd1.db", .gz = @embedFile("data/reject-mdb5-sd1.db.gz") },
    .{ .rel_name = "reject-sd1-badfeatures.db", .gz = @embedFile("data/reject-sd1-badfeatures.db.gz") },
    .{ .rel_name = "reject-sd1-badchecksum.db", .gz = @embedFile("data/reject-sd1-badchecksum.db.gz") },
    .{ .rel_name = "reject-sd1-short.db", .gz = @embedFile("data/reject-sd1-short.db.gz") },
    .{ .rel_name = "wal-v1-rust-tail.wal", .gz = @embedFile("data/wal-v1-rust-tail.wal.gz") },
    .{ .rel_name = "wal-v1-rust-ckpt.wal", .gz = @embedFile("data/wal-v1-rust-ckpt.wal.gz") },
    .{ .rel_name = "wal-v1-zig-tail.wal", .gz = @embedFile("data/wal-v1-zig-tail.wal.gz") },
    .{ .rel_name = "wal-v1-zig-ckpt.wal", .gz = @embedFile("data/wal-v1-zig-ckpt.wal.gz") },
    .{ .rel_name = "reject-mdb5-wal.wal", .gz = @embedFile("data/reject-mdb5-wal.wal.gz") },
    .{ .rel_name = "reject-wal-v1-badflags.wal", .gz = @embedFile("data/reject-wal-v1-badflags.wal.gz") },
    .{ .rel_name = "reject-wal-java-v3.walseg", .gz = @embedFile("data/reject-wal-java-v3.walseg.gz") },
};

/// The `wal-v1-*` accept cells RETIRE at this engine's WAL v3 cutover: the port
/// refuses format v1 outright (there is no migration, by design) and its opener
/// no longer takes a WAL FILE path at all, so the cell cannot even be expressed.
/// D6 retires these IDs family-wide at Stage C; until the java and zig
/// generators stop emitting v1 rows they stay in the shared manifest for the
/// engines that still speak v1, and this engine skips them. The list is EXACT
/// and asserted below: a new accept row addressed to zig must not be silently
/// dropped by a prefix match, and a retired cell vanishing from the manifest
/// means Stage C has begun and this skip list must go with it.
const retired_v1_accepts = [_][]const u8{
    "wal-v1-rust-tail",
    "wal-v1-rust-ckpt",
    "wal-v1-zig-tail",
    "wal-v1-zig-ckpt",
};

fn v1Baseline(ctx: *xfix.Ctx, row: xfix.FileRow) ![]u8 {
    const gz: []const u8 = for (embedded_gz) |e| {
        if (std.mem.eql(u8, e.rel_name, row.rel)) break e.gz;
    } else {
        std.debug.print("[xfixtures] file `{s}` is not in the embedded_gz list\n", .{row.rel});
        return error.XFixtures;
    };
    const gz_sha = xfix.sha256Hex(gz);
    try testing.expectEqualStrings(row.gz_sha, &gz_sha);
    const raw = try xfix.gunzip(ctx, gz, row.raw_len, row.rel);
    errdefer ctx.alloc.free(raw);
    try testing.expectEqual(row.raw_len, raw.len);
    const raw_sha = xfix.sha256Hex(raw);
    try testing.expectEqualStrings(row.raw_sha, &raw_sha);
    return raw;
}

test "xfixtures v1: cross-port conformance cells (engine=zig)" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    var loaded = try xfix.parse(&ctx, v1_manifest_tsv);
    defer loaded.deinit(a);
    try testing.expectEqual(@as(u32, 1), loaded.version());
    const m = &loaded.v1;

    // gunzip every fixture file ONCE, verifying gz sha, raw length and raw sha
    // before any cell runs: a damaged fixture must fail the preflight even when
    // its expect row appears late.
    var baselines: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (baselines.items) |b| a.free(b);
        baselines.deinit(a);
    }
    for (m.files.items) |f| try baselines.append(a, try v1Baseline(&ctx, f));

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var retired_seen = [_]bool{false} ** retired_v1_accepts.len;
    var ran: usize = 0;

    for (m.expects.items, 0..) |e, idx| {
        if (!std.mem.eql(u8, e.engine, ENGINE)) continue;
        if (std.mem.eql(u8, e.verdict, "accept") and std.mem.eql(u8, e.opener, "wal")) {
            const at = for (retired_v1_accepts, 0..) |r, i| {
                if (std.mem.eql(u8, e.fixture, r)) break i;
            } else {
                std.debug.print(
                    "[xfixtures] accept-wal fixture {s} is not one of the four v1 cells retired at " ++
                        "the v3 cutover — a new WAL accept row needs a v3 (base-path) cell, not a skip\n",
                    .{e.fixture},
                );
                return error.XFixtures;
            };
            retired_seen[at] = true;
            continue;
        }
        ran += 1;

        // a v1 fixture has exactly one file row
        var file: ?xfix.FileRow = null;
        var pristine: []const u8 = undefined;
        for (m.files.items, 0..) |f, i| {
            if (!std.mem.eql(u8, f.fixture, e.fixture)) continue;
            try testing.expect(file == null);
            file = f;
            pristine = baselines.items[i];
        }
        try testing.expect(file != null);

        var name_buf: [64]u8 = undefined;
        const cell_name = try std.fmt.bufPrint(&name_buf, "v1-{d}", .{idx});
        var cell_dir = try tmp.dir.makeOpenPath(cell_name, .{ .iterate = true });
        defer cell_dir.close();
        try cell_dir.writeFile(.{ .sub_path = e.place_as, .data = pristine });

        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const cell_abs = try cell_dir.realpath(".", &path_buf);
        const target = try std.fs.path.join(a, &.{ cell_abs, e.open_arg });
        defer a.free(target);

        var cell_buf: [192]u8 = undefined;
        const cell = try std.fmt.bufPrint(&cell_buf, "v1 cell {d}: fixture={s} verdict={s} opener={s} placeAs={s}", .{
            idx, e.fixture, e.verdict, e.opener, e.place_as,
        });

        if (std.mem.eql(u8, e.verdict, "accept")) {
            try testing.expectEqualStrings("direct", e.opener);
            var s = StoreDirect.openFile(a, target, true) catch |err| {
                std.debug.print("[xfixtures] {s}: open failed: {s}\n", .{ cell, @errorName(err) });
                return error.XFixtures;
            };
            defer s.deinit();
            try xfix.assertReaderContract(&ctx, &s, m.recids.items, e.fixture, cell);
            try s.close();
        } else {
            // The v3 opener takes a BASE path. Every v1 reject row's openArg
            // names a regular file the cell placed there, so each now refuses
            // through D1's bare-base row rather than through a v1 header check —
            // the same verdict for the same image, which is what the cell asserts.
            if (std.mem.eql(u8, e.opener, "direct")) {
                if (StoreDirect.openFile(a, target, true)) |*opened| {
                    var s = opened.*;
                    s.deinit();
                    std.debug.print("[xfixtures] {s}: open unexpectedly succeeded\n", .{cell});
                    return error.XFixtures;
                } else |err| try testing.expectEqual(error.DataCorruption, err);
            } else {
                if (StoreWAL.open(a, target, true)) |*opened| {
                    var s = opened.*;
                    s.deinit();
                    std.debug.print("[xfixtures] {s}: open unexpectedly succeeded\n", .{cell});
                    return error.XFixtures;
                } else |err| try testing.expectEqual(error.DataCorruption, err);
            }
        }

        // working copy byte-identical, and no files beyond `.lock` sidecars.
        // `.ckpt` is deliberately NOT on the allowed list: a clean StoreWAL close
        // must leave no checkpoint temp behind.
        const after = try cell_dir.readFileAlloc(a, e.place_as, 256 * 1024 * 1024);
        defer a.free(after);
        try testing.expectEqualSlices(u8, pristine, after);
        var it = cell_dir.iterate();
        while (try it.next()) |entry| {
            if (std.mem.eql(u8, entry.name, e.place_as)) continue;
            if (std.mem.endsWith(u8, entry.name, ".lock")) continue;
            std.debug.print("[xfixtures] {s}: unexpected new file `{s}`\n", .{ cell, entry.name });
            return error.XFixtures;
        }
    }

    // The manifest must drive at least one zig cell — an empty run means the sync
    // step produced a manifest this engine silently ignores.
    try testing.expect(ran > 0);
    for (retired_seen) |seen| try testing.expect(seen);
}

// ---------------------------------------------------------------------------
// schema v2 — the shared static sample
// ---------------------------------------------------------------------------

const v2_manifest_tsv: []const u8 = @embedFile("data-v2/MANIFEST.tsv");
const golden_decode_tsv: []const u8 = @embedFile("data-v2/GOLDEN-DECODE.tsv");
const golden_body_tsv: []const u8 = @embedFile("data-v2/GOLDEN-BODY.tsv");

fn loadSample(ctx: *xfix.Ctx) !xfix.SampleV2 {
    return xfix.loadSampleV2(ctx, v2_manifest_tsv, &embedded_v2.blobs);
}

test "xfixtures v2: the sample's rw and ro cells pass" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadSample(&ctx);
    defer sample.deinit(a);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Both modes run here. Deleting either engine's `expect` row for a declared
    // fixture fails the set check inside `runV2Cells`, because that set comes
    // from the `fixture` rows and not from the rows about to be executed.
    for (xfix.MODES) |mode| try xfix.runV2Cells(&ctx, &sample, mode, tmp.dir);
}

// The executor really does compare the cell set it ran against the fixture rows.
//
// `assertCellSetExact` has its own direct battery in wal3_decode_test.zig, but a
// rule can be correct and never called. This is the case the corpus cannot
// contain: a fixture DECLARED with no `expect` row addressed to this engine. It
// is built by re-parsing the real manifest with one extra `fixture` row (and a
// `recid` row so referential integrity is satisfied) and handing the executor
// the real sample's bytes.
test "xfixtures v2: a declared fixture with no cell fails the executor" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadSample(&ctx);
    defer sample.deinit(a);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const doctored = v2_manifest_tsv ++
        "fixture\tghost\twal3-namespace\tjava\tc3z\nrecid\tghost\tr1\t1\tlive\t1\t8\n";
    var loaded = try xfix.parse(&ctx, doctored);
    defer loaded.deinit(a);

    var files: std.ArrayListUnmanaged(xfix.RawFile) = .empty;
    defer files.deinit(a);
    try files.appendSlice(a, sample.files.items);

    // `blob_names` stays empty and this value is never deinit'd: it BORROWS the
    // real sample's bytes and `loaded`'s manifest, both of which own themselves.
    const doctored_sample = xfix.SampleV2{ .manifest = loaded.v2, .files = files };
    try xfix.expectRefused(
        &ctx,
        "a fixture declared with no zig cell",
        xfix.runV2Cells,
        .{ &ctx, &doctored_sample, "rw", tmp.dir },
    );
}

// FRAMING, against the python-authored pin.
//
// This is the comparison `GOLDEN.tsv` cannot make: a raw sha attests which
// bytes were read and says nothing about the parse. It is also the only check
// in the slice that reaches the section COUNT — both section CRCs bind a
// section's own bytes to its own offset, so a reader that stopped one section
// early would still validate every section it did read, and would still open
// through the engine.
test "xfixtures v2: framing matches GOLDEN-DECODE.tsv" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadSample(&ctx);
    defer sample.deinit(a);

    var got: xfix.Strings = .{};
    defer got.deinit(a);
    try xfix.renderFraming(&ctx, &sample, &got);

    var want = try xfix.goldenRows(a, golden_decode_tsv);
    defer want.deinit(a);
    try xfix.assertRowsEqual(&ctx, "GOLDEN-DECODE.tsv", want.items, got.slice());

    var saw_hdr = false;
    var saw_sec = false;
    for (want.items) |r| {
        if (std.mem.startsWith(u8, r, "hdr\t")) saw_hdr = true;
        if (std.mem.startsWith(u8, r, "sec\t")) saw_sec = true;
    }
    try testing.expect(saw_hdr and saw_sec);
}

// Both renderers really do require every pinned file to be framed to its last
// byte.
//
// `decodeComplete` carries that rule and has its own direct battery, but a rule
// can be correct and never called: reverting one renderer's call to plain
// `decode` is invisible on a corpus where every file is whole. This builds the
// input the corpus cannot contain — the real sample with one junk byte appended
// to one segment — and points both renderers at it.
test "xfixtures v2: both renderers refuse a segment with trailing bytes" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadSample(&ctx);
    defer sample.deinit(a);

    var files: std.ArrayListUnmanaged(xfix.RawFile) = .empty;
    defer files.deinit(a);
    try files.appendSlice(a, sample.files.items);
    const junked = try std.mem.concat(a, u8, &.{ files.items[0].bytes, &[_]u8{0x7f} });
    defer a.free(junked);
    files.items[0].bytes = junked;

    // BORROWS the real manifest and bytes; never deinit'd, so nothing is freed twice.
    const doctored = xfix.SampleV2{ .manifest = sample.manifest, .files = files };

    var rows: xfix.Strings = .{};
    defer rows.deinit(a);
    try xfix.expectRefused(&ctx, "a trailing byte, seen by the framing renderer", xfix.renderFraming, .{ &ctx, &doctored, &rows });

    var rows2: xfix.Strings = .{};
    defer rows2.deinit(a);
    try xfix.expectRefused(&ctx, "a trailing byte, seen by the body renderer", xfix.renderBody, .{ &ctx, &doctored, &rows2 });
}

// DECODED BODIES, against the file the FROZEN JAVA READER authored.
//
// Contract §11.2 settles body semantics engine-against-engine rather than in a
// python pin, because `walfmt.py` is a structural codec and store record
// semantics written there would be a fifth implementation nobody reviews. Java
// is authoritative by construction: it wrote this file.
test "xfixtures v2: decoded bodies match GOLDEN-BODY.tsv" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadSample(&ctx);
    defer sample.deinit(a);

    var got: xfix.Strings = .{};
    defer got.deinit(a);
    try xfix.renderBody(&ctx, &sample, &got);

    var want = try xfix.goldenRows(a, golden_body_tsv);
    defer want.deinit(a);
    try xfix.assertRowsEqual(&ctx, "GOLDEN-BODY.tsv", want.items, got.slice());

    // The file's own provenance block, which the row comparison drops. Without
    // this the header could be rewritten to claim a different author while every
    // test stayed green — and the authority claim is the reason this port is
    // graded against this file at all.
    var header = try xfix.goldenHeader(a, golden_body_tsv);
    defer header.deinit(a);
    try testing.expectEqual(xfix.GOLDEN_BODY_HEADER.len, header.items.len);
    for (xfix.GOLDEN_BODY_HEADER, header.items) |w, g| try testing.expectEqualStrings(w, g);

    // The distinction the whole file exists for must actually be IN it, or the
    // comparison above is a comparison of two files that never disagree about the
    // interesting case. `lenPlus == 0` is NULL content, `lenPlus == 1` is
    // zero-length content, and they differ in BOTH the lenPlus and the sha column
    // so no single-column bug can hide one as the other.
    var saw_null = false;
    var saw_empty = false;
    var saw_mark = false;
    var empty_suffix_buf: [80]u8 = undefined;
    const empty_suffix = try std.fmt.bufPrint(&empty_suffix_buf, "\t1\t{s}", .{xfix.EMPTY_SHA});
    for (want.items) |r| {
        if (std.mem.indexOf(u8, r, "\tRECORD\t12\t0\t0\t-") != null) saw_null = true;
        if (std.mem.endsWith(u8, r, empty_suffix)) saw_empty = true;
        if (std.mem.startsWith(u8, r, "mark\t")) saw_mark = true;
    }
    try testing.expect(saw_null);
    try testing.expect(saw_empty);
    try testing.expect(saw_mark);
}

// ---------------------------------------------------------------------------
// C-D4 — the generated embed table
// ---------------------------------------------------------------------------

test "xfixtures v2: the embed table, the manifest and the distributed blobs agree" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadSample(&ctx);
    defer sample.deinit(a);

    var from_manifest: std.ArrayListUnmanaged([]const u8) = .empty;
    defer from_manifest.deinit(a);
    for (sample.files.items) |f| try from_manifest.append(a, f.blob);

    var from_table: std.ArrayListUnmanaged([]const u8) = .empty;
    defer from_table.deinit(a);
    for (embedded_v2.blobs) |b| try from_table.append(a, b.name);

    try xfix.checkBlobSets(&ctx, from_manifest.items, from_table.items, &distributed.gz);
}

// The validator itself must be able to fail — C-D4 asks for exactly this.
//
// One-way coverage is tautological when the table and the manifest come off the
// same list, so the invariant is set equality; and a set-equality check that
// nobody has ever seen reject anything is a set-equality check nobody has
// measured. These triples delete, duplicate and add an entry.
test "xfixtures v2: the three-way blob check rejects every way the sets can differ" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    const full = [_][]const u8{ "a.gz", "b.gz", "c.gz" };
    const short = [_][]const u8{ "a.gz", "b.gz" };
    const dup = [_][]const u8{ "a.gz", "b.gz", "b.gz" };
    const extra = [_][]const u8{ "a.gz", "b.gz", "c.gz", "d.gz" };
    const unsafe = [_][]const u8{ "a.gz", "b.gz", "../c.gz" };
    const empty = [_][]const u8{};

    try xfix.checkBlobSets(&ctx, &full, &full, &full);

    const cases = [_]struct {
        what: []const u8,
        m: []const []const u8,
        t: []const []const u8,
        d: []const []const u8,
    }{
        .{ .what = "an entry missing from the generated table", .m = &full, .t = &short, .d = &full },
        .{ .what = "an entry missing from the manifest", .m = &short, .t = &full, .d = &full },
        .{ .what = "a blob distributed that nothing embeds", .m = &full, .t = &full, .d = &extra },
        .{ .what = "a blob embedded that is not distributed", .m = &extra, .t = &extra, .d = &full },
        .{ .what = "a duplicated table entry", .m = &short, .t = &dup, .d = &short },
        .{ .what = "an unsafe name on disk", .m = &full, .t = &full, .d = &unsafe },
        .{ .what = "an empty distributed set", .m = &full, .t = &full, .d = &empty },
        .{ .what = "an empty manifest set", .m = &empty, .t = &full, .d = &full },
    };
    for (cases) |c| {
        try xfix.expectRefused(&ctx, c.what, xfix.checkBlobSets, .{ &ctx, c.m, c.t, c.d });
    }
}

// Nothing in the distributed v2 root may be unexplained.
//
// The three tables plus one blob per `file` row, and nothing else. A stray
// `.gz` that no manifest row names is either a fixture the suite silently never
// runs or a leftover from a half-finished sync; both are the kind of thing only
// ever noticed by a check that enumerates. `build.zig` supplies the enumeration
// because `@embedFile` cannot walk a directory.
test "xfixtures v2: the distributed root has nothing unexplained" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadSample(&ctx);
    defer sample.deinit(a);

    var want: std.ArrayListUnmanaged([]const u8) = .empty;
    defer want.deinit(a);
    try want.appendSlice(a, &.{ "MANIFEST.tsv", "GOLDEN-DECODE.tsv", "GOLDEN-BODY.tsv" });
    for (sample.files.items) |f| try want.append(a, f.blob);

    for (distributed.all) |name| {
        var known = false;
        for (want.items) |w| {
            if (std.mem.eql(u8, w, name)) known = true;
        }
        if (!known) {
            std.debug.print("[xfixtures] data-v2/{s} is explained by no manifest row\n", .{name});
            return error.XFixtures;
        }
    }
    for (want.items) |w| {
        var present = false;
        for (distributed.all) |name| {
            if (std.mem.eql(u8, w, name)) present = true;
        }
        if (!present) {
            std.debug.print("[xfixtures] data-v2/{s} is named but not distributed\n", .{w});
            return error.XFixtures;
        }
    }
}

// ---------------------------------------------------------------------------
// the dispatch itself
// ---------------------------------------------------------------------------

fn parseOk(ctx: *xfix.Ctx, text: []const u8) !void {
    var loaded = try xfix.parse(ctx, text);
    loaded.deinit(ctx.alloc);
}

fn refuse(ctx: *xfix.Ctx, what: []const u8, text: []const u8) !void {
    try xfix.expectRefused(ctx, what, parseOk, .{ ctx, text });
}

// The version line is a HARD dispatch, and the reason is the arity collision.
//
// `expect <fid> <engine> <verdict> <opener> <placeAs> <openArg>` (v1) and
// `expect <fid> <engine> <mode> <verdict> <opener> <openArg>` (v2) are both
// seven fields. Guessing the schema from a row's shape would read `accept` as a
// mode and `wal3` as a verdict without a single arity check firing, so the
// version line decides and an unknown version is refused rather than assumed to
// be the newest.
test "xfixtures: the two schemas are told apart by their version line only" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    const v1 = "version\t1\nfixture\tf\tdirect\tjava\tc\nfile\tf\tx.db\t1\taa\tbb\n" ++
        "expect\tf\tzig\taccept\tdirect\tx.db\tx.db\n";
    const v2 = "version\t2\nfixture\tf\twal3-namespace\tjava\tc\nfile\tf\tx\t1\taa\tbb\n" ++
        "expect\tf\tzig\tro\taccept\twal3\tx\n";

    var l1 = try xfix.parse(&ctx, v1);
    defer l1.deinit(a);
    try testing.expectEqual(@as(u32, 1), l1.version());
    var l2 = try xfix.parse(&ctx, v2);
    defer l2.deinit(a);
    try testing.expectEqual(@as(u32, 2), l2.version());

    // The v1 rows, read as v2, are not merely different — the third column is a
    // verdict where v2 wants a mode, so the vocabulary check catches it. That is
    // the collision made visible rather than assumed away.
    const v1_as_v2 = "version\t2\nfixture\tf\tdirect\tjava\tc\nfile\tf\tx.db\t1\taa\tbb\n" ++
        "expect\tf\tzig\taccept\tdirect\tx.db\tx.db\n";
    try refuse(&ctx, "v1 expect rows under a v2 version line", v1_as_v2);
    try refuse(&ctx, "an unknown schema version", "version\t3\n");
    try refuse(&ctx, "a manifest with no version line", "fixture\tf\tdirect\tjava\tc\n");
    try refuse(&ctx, "a version line with a trailing field", "version\t2\tx\n");
}

const V2_HEAD = "version\t2\nfixture\tf\twal3-namespace\tjava\tc\n";
const V2_FILE = "file\tf\tx.wal.0000000000000001\t36\taa\tbb\n";

// Rows the reader must refuse rather than skip.
//
// A reader that ignores what it does not recognise turns every future schema
// addition into a silent no-op: the row is in the manifest, the suite is green,
// and nothing ran.
test "xfixtures: unrecognised and malformed rows are refused" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    try refuse(&ctx, "an unknown row type", V2_HEAD ++ V2_FILE ++ "sparkle\tf\tx\n");
    try refuse(&ctx, "a short file row", V2_HEAD ++ "file\tf\tx\t36\taa\n");
    try refuse(&ctx, "a file row with an empty field", V2_HEAD ++ "file\tf\tx\t36\t\tbb\n");
    try refuse(&ctx, "a non-canonical integer", V2_HEAD ++ "file\tf\tx\t036\taa\tbb\n");
    try refuse(&ctx, "a relName that escapes the cell directory", V2_HEAD ++ "file\tf\t../x\t36\taa\tbb\n");
    try refuse(&ctx, "an unknown engine", V2_HEAD ++ V2_FILE ++ "expect\tf\tgo\tro\taccept\twal3\tx\n");
    try refuse(&ctx, "an unknown mode", V2_HEAD ++ V2_FILE ++ "expect\tf\tzig\trwx\taccept\twal3\tx\n");
    try refuse(&ctx, "an unknown verdict on a java row", V2_HEAD ++ V2_FILE ++ "expect\tf\tjava\tro\tmaybe\twal3\tx\n");
    try refuse(&ctx, "a duplicate expect row", V2_HEAD ++ V2_FILE ++
        "expect\tf\tzig\tro\taccept\twal3\tx\nexpect\tf\tzig\tro\taccept\twal3\tx\n");
    try refuse(&ctx, "a duplicate post row", V2_HEAD ++ V2_FILE ++
        "post\tf\tzig\tro\tx.lock\tunchanged\npost\tf\tzig\tro\tx.lock\tdeleted\n");
    try refuse(&ctx, "an unknown post disposition", V2_HEAD ++ V2_FILE ++ "post\tf\tzig\tro\tx.lock\tvanished\n");
    try refuse(&ctx, "a sized post disposition missing its sha", V2_HEAD ++ V2_FILE ++ "post\tf\tzig\tro\tx.lock\tcreated:0\n");
    try refuse(&ctx, "a duplicate recid within one fixture", V2_HEAD ++ V2_FILE ++
        "recid\tf\ta\t1\tlive\t1\t1\nrecid\tf\tb\t1\tlive\t1\t1\n");
    try refuse(&ctx, "an unbounded recidrange", V2_HEAD ++ V2_FILE ++ "recidrange\tf\tr\t1\t99999999\tlive\t1\t1\n");
    try refuse(&ctx, "a v2 manifest with no file rows", V2_HEAD);

    // Vocabularies contract §2 makes load-bearing. The C3r review found kind,
    // generatorEngine and opener stored unchecked — and `opener` in particular was
    // only ever validated by the cell executor, AFTER it had filtered to its own
    // engine's rows, so a bad opener on another engine's row reached nothing. The
    // cases below are therefore addressed to OTHER engines on purpose: executor
    // filtering must not be able to masquerade as parser validation.
    try refuse(&ctx, "an unknown opener on a java row", V2_HEAD ++ V2_FILE ++ "expect\tf\tjava\tro\taccept\twal9\tx\n");
    try refuse(&ctx, "an unknown opener on a rust row", V2_HEAD ++ V2_FILE ++ "expect\tf\trust\trw\taccept\tdirekt\tx\n");
    try refuse(&ctx, "an unknown fixture kind", "version\t2\nfixture\tf\twal3-namespaces\tjava\tc\n" ++ V2_FILE);
    try refuse(&ctx, "an unknown generatorEngine", "version\t2\nfixture\tf\twal3-namespace\tgo\tc\n" ++ V2_FILE);

    // `port-wal` and `java-wal-namespace` are RETAINED tokens: no v2 fixture uses
    // them, and §2 says retiring a family is not a reason for a version-dispatch
    // parser to reject the token. So they must still parse.
    inline for (.{ "direct", "reject", "wal3-namespace", "port-wal", "java-wal-namespace" }) |kind| {
        try parseOk(&ctx, "version\t2\nfixture\tf\t" ++ kind ++ "\tjava\tc\n" ++ V2_FILE);
    }

    // §2 amendment 3: `generatorEngine = derived` and a `derived` row imply each
    // other, exactly once.
    try refuse(&ctx, "a derived fixture with no derived row", "version\t2\nfixture\tf\treject\tderived\tc\n" ++ V2_FILE);
    try refuse(&ctx, "a derived row on a fixture an engine wrote", V2_HEAD ++ V2_FILE ++ "derived\tf\tsrc\t1\trecipe\n");
}

// A fixture id a row REFERS to must be DECLARED, and vice versa.
//
// Without this the exact-cell-set rule has a coordinated escape: delete a
// `fixture` row together with this engine's `expect` rows for it, and the
// executor sees a consistently smaller world — the expected set shrinks by
// exactly the cell that stopped running. The `file` and `recid` rows stay
// behind, the golden comparisons still decode them, and the resource inventory
// is unchanged. Found by the C3r review.
test "xfixtures: every referenced fixture must be declared and every declared one used" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    try parseOk(&ctx, V2_HEAD ++ V2_FILE);
    try refuse(&ctx, "a file row naming a fixture with no fixture row", V2_HEAD ++ V2_FILE ++ "file\tg\tx.wal.0000000000000002\t36\tcc\tdd\n");
    try refuse(&ctx, "an expect row naming a fixture with no fixture row", V2_HEAD ++ V2_FILE ++ "expect\tg\tzig\tro\taccept\twal3\tx\n");
    try refuse(&ctx, "a post row naming a fixture with no fixture row", V2_HEAD ++ V2_FILE ++ "post\tg\tzig\tro\tx.lock\tunchanged\n");
    try refuse(&ctx, "a recid row naming a fixture with no fixture row", V2_HEAD ++ V2_FILE ++ "recid\tg\tr1\t1\tlive\t1\t8\n");
    try refuse(&ctx, "a declared fixture no row refers to", V2_HEAD ++ V2_FILE ++ "fixture\tg\twal3-namespace\tjava\tc\n");

    // The same rule guards the v1 tree, where the live manifest satisfies it.
    const v1 = "version\t1\nfixture\tf\tdirect\tjava\tc\nfile\tf\tx.db\t1\taa\tbb\n";
    try parseOk(&ctx, v1);
    try refuse(&ctx, "a v1 recid row naming a fixture with no fixture row", v1 ++ "recid\tg\tr1\t1\tlive\t1\t8\n");
}

// The v1 grammar's own vocabularies, which are NOT the v2 ones.
//
// v1's opener set is `{direct, wal}` where v2's is `{direct, wal3}`, and v1's
// kind set is v2's minus `wal3-namespace`. Sharing one reader across two
// grammars makes it easy to validate against the wrong set — or against no set
// at all — and the live v1 tree cannot notice, because every value in it is
// correct.
test "xfixtures: the v1 grammar has its own vocabularies" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    const head = "version\t1\nfixture\tf\tport-wal\tjava\tc\n";
    const file = "file\tf\tx.wal\t1\taa\tbb\n";
    inline for (.{ "direct", "wal" }) |opener| {
        try parseOk(&ctx, head ++ file ++ "expect\tf\tzig\taccept\t" ++ opener ++ "\tx.wal\tx.wal\n");
    }
    // `wal3` is the V2 opener token and must NOT be accepted under v1.
    try refuse(&ctx, "the v2 opener token on a v1 row", head ++ file ++ "expect\tf\tzig\taccept\twal3\tx.wal\tx.wal\n");
    try refuse(&ctx, "an unknown v1 opener on a java row", head ++ file ++ "expect\tf\tjava\taccept\twalrus\tx.wal\tx.wal\n");
    try refuse(&ctx, "an unknown v1 verdict", head ++ file ++ "expect\tf\tzig\tmaybe\tdirect\tx.wal\tx.wal\n");
    // `wal3-namespace` is the kind v2 ADDED; a v1 manifest must not carry it.
    try refuse(&ctx, "the v2-only fixture kind on a v1 row", "version\t1\nfixture\tf\twal3-namespace\tjava\tc\nfile\tf\tx\t1\taa\tbb\n");
    try refuse(&ctx, "an unknown v1 generatorEngine", "version\t1\nfixture\tf\tdirect\tgo\tc\nfile\tf\tx\t1\taa\tbb\n");
}

// A `bytes` row is refused BY NAME, not skipped.
//
// `bytes` describes a derived fixture built by `walfmt.py` from another
// fixture's image, and C4 is the slice that introduces both the deriver and the
// fixtures. Until then the honest thing for a reader to do is stop: a `bytes`
// row silently ignored is a fixture the manifest says exists and that nothing
// ever opens.
test "xfixtures: a bytes row is refused until C4 can execute it" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    // The row must be GRAMMATICALLY VALID, or the test proves only that a
    // malformed row is refused — which the arity and vocabulary rules already do,
    // and which is not what the name claims.
    try refuse(&ctx, "a v2 `bytes` row", V2_HEAD ++ V2_FILE ++
        "bytes\tf\tzig\tro\tx.wal.0000000000000001\t0\taa\n");
}

// ---------------------------------------------------------------------------
// the D6 post-state rule, exercised directly
// ---------------------------------------------------------------------------

const PostCase = struct {
    what: []const u8,
    inputs: []const xfix.InputFile,
    after: []const xfix.InputFile,
    posts: []const []const u8,
    ok: bool,
    make_dir: bool = false,
};

// Both sides of the post-state rule, on inputs the sample cannot supply.
//
// The sample's `rw` and `ro` cells leave every segment untouched and create one
// `x.lock`, so the corpus is CONSTANT in everything the rule's second side
// checks: removing "an unnamed input must still be there byte for byte" and "a
// file that is neither an input nor named must not exist" leaves the whole
// suite green. That is lesson (g) again, and the answer is the same: an input
// built to vary. These directories are built by hand.
test "xfixtures: the post-state rule fails in both directions" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const abc = [_]xfix.InputFile{.{ .rel = "seg", .bytes = "abc" }};
    const abd = [_]xfix.InputFile{.{ .rel = "seg", .bytes = "abd" }};
    const q = [_]xfix.InputFile{.{ .rel = "seg", .bytes = "q" }};
    const abc_lock = [_]xfix.InputFile{ .{ .rel = "seg", .bytes = "abc" }, .{ .rel = "x.lock", .bytes = "" } };
    const abc_lockz = [_]xfix.InputFile{ .{ .rel = "seg", .bytes = "abc" }, .{ .rel = "x.lock", .bytes = "z" } };
    const abc_new = [_]xfix.InputFile{ .{ .rel = "seg", .bytes = "abc" }, .{ .rel = "new", .bytes = "q" } };
    const surprise = [_]xfix.InputFile{ .{ .rel = "seg", .bytes = "abc" }, .{ .rel = "surprise", .bytes = "x" } };
    const none = [_]xfix.InputFile{};

    // `E` is the empty-string sha and `S` the sha of "q"; expanded below so the
    // rows stay readable.
    const cases = [_]PostCase{
        .{ .what = "an untouched input named by nothing", .inputs = &abc, .after = &abc, .posts = &.{}, .ok = true },
        .{ .what = "an unnamed input rewritten behind the rule's back", .inputs = &abc, .after = &abd, .posts = &.{}, .ok = false },
        .{ .what = "an unnamed input deleted behind the rule's back", .inputs = &abc, .after = &none, .posts = &.{}, .ok = false },
        .{ .what = "a file that is neither an input nor named", .inputs = &abc, .after = &surprise, .posts = &.{}, .ok = false },
        .{ .what = "a lock file the post rows do declare", .inputs = &abc, .after = &abc_lock, .posts = &.{"x.lock\tcreated:0:E"}, .ok = true },
        .{ .what = "a `created` file whose sha does not match", .inputs = &abc, .after = &abc_lockz, .posts = &.{"x.lock\tcreated:0:E"}, .ok = false },
        .{ .what = "a `deleted` file that is still there", .inputs = &abc, .after = &abc, .posts = &.{"seg\tdeleted"}, .ok = false },
        .{ .what = "a `deleted` file that really is gone", .inputs = &abc, .after = &none, .posts = &.{"seg\tdeleted"}, .ok = true },
        .{ .what = "an `unchanged` file that changed", .inputs = &abc, .after = &abd, .posts = &.{"seg\tunchanged"}, .ok = false },
        .{ .what = "`modified` naming a file that was never an input", .inputs = &abc, .after = &abc_new, .posts = &.{"new\tmodified:1:S"}, .ok = false },
        // §2.1's split has TWO sides: a post row is an explicit override of an
        // input, or an explicit NEW file. The three below are the ones the C3r
        // review found missing, and each was green under the old rule.
        .{ .what = "`created` naming a file that WAS an input", .inputs = &q, .after = &q, .posts = &.{"seg\tcreated:1:S"}, .ok = false },
        .{ .what = "`deleted` naming a file that was never an input", .inputs = &abc, .after = &abc, .posts = &.{"ghost\tdeleted"}, .ok = false },
        .{ .what = "a `deleted` file replaced by a directory of the same name", .inputs = &abc, .after = &none, .posts = &.{"seg\tdeleted"}, .ok = false, .make_dir = true },
    };

    const sha_q = xfix.sha256Hex("q");

    for (cases, 0..) |c, i| {
        var name_buf: [32]u8 = undefined;
        const cell_name = try std.fmt.bufPrint(&name_buf, "post-{d}", .{i});
        var dir = try tmp.dir.makeOpenPath(cell_name, .{ .iterate = true });
        defer dir.close();
        for (c.after) |f| try dir.writeFile(.{ .sub_path = f.rel, .data = f.bytes });
        if (c.make_dir) try dir.makeDir("seg");

        // The post rows are written as manifest text and parsed by the REAL
        // reader, so the disposition grammar under test is the shipped one.
        var text: std.ArrayListUnmanaged(u8) = .empty;
        defer text.deinit(a);
        try text.appendSlice(a, V2_HEAD ++ "file\tf\tseg\t3\taa\tbb\n");
        for (c.posts) |row| {
            try text.appendSlice(a, "post\tf\tzig\tro\t");
            for (row) |ch| {
                switch (ch) {
                    'E' => try text.appendSlice(a, xfix.EMPTY_SHA),
                    'S' => try text.appendSlice(a, &sha_q),
                    else => try text.append(a, ch),
                }
            }
            try text.append(a, '\n');
        }

        var loaded = try xfix.parse(&ctx, text.items);
        defer loaded.deinit(a);
        var posts: std.ArrayListUnmanaged(xfix.V2Post) = .empty;
        defer posts.deinit(a);
        for (loaded.v2.posts.items) |p| try posts.append(a, p);

        if (c.ok) {
            try xfix.assertPostState(&ctx, dir, c.inputs, posts.items, c.what);
        } else {
            try xfix.expectRefused(&ctx, c.what, xfix.assertPostState, .{ &ctx, dir, c.inputs, posts.items, c.what });
        }
    }
    try testing.expectEqual(@as(usize, 13), cases.len);
}

test {
    testing.refAllDecls(@This());
}
