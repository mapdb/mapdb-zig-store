//! Cross-port conformance harness — schema **v2 only** (Stage C slice **C7z**).
//!
//! `src/xfixtures/data-v2/` is the shared static schema-v2 sample
//! (`todo/store-cross/sample-v2/`, byte for byte). Schema v1, its skip list, and
//! the dual dispatch retired at C7z after the corpus cutover (C6) was green.
//! The frozen corpus runs in `corpus_test.zig`.
//!
//! What runs here:
//!
//! - **v2 `rw` and `ro` cells** — both here. Decision C-D3 costs this port
//!   nothing: `WalOptions.read_only` is `pub` and this suite is in-package, so
//!   neither mode needs new public surface (rust had to move its `ro` executor
//!   into the crate to say the same thing).
//! - **the two §11.2 comparisons** — framing against `GOLDEN-DECODE.tsv`,
//!   decoded bodies against `GOLDEN-BODY.tsv`, which the frozen Java reader
//!   authored.
//! - **C-D4** — the generated `embedded_v2.zig` table, graded by three-way
//!   set equality against the embedded names and the on-disk directory listing.
//!
//! The schema-v1 tree and `retired_v1_accepts` skip list are gone (contract §9).

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

/// Two well-formed sha256 columns for the hand-written manifests below.
///
/// They used to be `aa` and `bb`, which the frozen java reader refuses and this
/// reader accepted — so every case named for a LATER rule was resting on a
/// manifest that is not grammatically valid at all, and would have started
/// measuring the hash rule the moment it was added. Lesson (h), one layer above
/// where it was found. The C3z review named it.
const SHAS = "\t" ++ "a" ** 64 ++ "\t" ++ "b" ** 64;
const SHAS2 = "\t" ++ "c" ** 64 ++ "\t" ++ "d" ** 64;

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

// The golden-shape rule, on texts the distributed files cannot supply.
//
// Both golden files are a leading comment block and then rows, so the rule never
// fires on them and deleting it would be invisible — the same shape as every
// other survivor this slice found. These are hand-written.
test "xfixtures v2: the golden-shape rule rejects text the row comparison would drop" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    try xfix.assertGoldenShape(&ctx, "ok", "# header\n# more\nsec\ta\tb\nsec\tc\td\n");
    try xfix.assertGoldenShape(&ctx, "ok, no trailing newline", "# header\nsec\ta\tb");

    const cases = [_]struct { text: []const u8, what: []const u8 }{
        .{ .text = "# header\nsec\ta\n# a later comment\nsec\tb\n", .what = "a comment after the first data row" },
        .{ .text = "# header\nsec\ta\n\nsec\tb\n", .what = "a blank line between data rows" },
        .{ .text = "# header\n# only comments\n", .what = "a golden file with no data rows" },
        .{ .text = "", .what = "an empty golden file" },
    };
    for (cases) |c| {
        try xfix.expectRefused(&ctx, c.what, xfix.assertGoldenShape, .{ &ctx, c.what, c.text });
    }
}

// The write-gate probe fires in BOTH directions.
//
// The probe is what makes the manifest's `mode` column observable, and its two
// branches are the rule. Pointing it at a handle opened the other way is the
// only input that reaches them: on the real cells both branches pass, so making
// either one vacuous was invisible until this test existed.
test "xfixtures v2: the write-gate probe fires in both directions" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadSample(&ctx);
    defer sample.deinit(a);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const fixture = sample.files.items[0].fixture;
    for ([_]bool{ true, false }, 0..) |read_only, i| {
        var name_buf: [32]u8 = undefined;
        var dir = try tmp.dir.makeOpenPath(try std.fmt.bufPrint(&name_buf, "gate-{d}", .{i}), .{ .iterate = true });
        defer dir.close();
        for (sample.files.items) |f| {
            if (!std.mem.eql(u8, f.fixture, fixture)) continue;
            try dir.writeFile(.{ .sub_path = f.rel, .data = f.bytes });
        }
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const base = try std.fs.path.join(a, &.{ try dir.realpath(".", &path_buf), "x" });
        defer a.free(base);

        var s2 = try StoreWAL.openCfg(a, base, .{ .read_only = read_only });
        defer s2.deinit();
        // The handle satisfies the branch that matches how it was opened, and the
        // WITNESS it returns names the branch it took — the executor's `ro_probed`
        // bookkeeping is derived from that value, so a probe that skipped its
        // assertions and returned the right tag is refused here.
        try testing.expectEqual(
            if (read_only) xfix.WriteGate.ro_refused else xfix.WriteGate.rw_rolled_back,
            try xfix.assertWriteGate(&ctx, &s2, if (read_only) "ro" else "rw", "the matching mode"),
        );
        // ...and must fail the other one, FOR THE STATED REASON. A bare "it
        // refused" is not enough here: a read-only handle graded as `rw` also
        // fails the `rollback` that follows the probe, so a probe that swallowed
        // the preallocate error would still be refused — by the wrong rule.
        // Measured: that mutant survived until the message was checked.
        const what = if (read_only) "a read-only handle graded as rw" else "a read-write handle graded as ro";
        const saying = if (read_only) "refused a preallocate" else "preallocated recid";
        try xfix.expectRefusedSaying(&ctx, what, saying, xfix.assertWriteGate, .{ &ctx, &s2, if (read_only) "rw" else "ro", what });
        try s2.close();
    }
}

// The loader's REFUSAL paths, under `testing.allocator`.
//
// A green suite that only ever loads successfully is not memory evidence. The
// C3z review reproduced a segfault here: `loaded.v2` was copied into
// `sample.manifest` with an `errdefer` still live on each, so every refusal
// after that line ran both destructors over the same array lists. Nothing asked
// this function to refuse, so nothing saw it. These do, and the leak detector
// grades the result.
test "xfixtures v2: the loader refuses cleanly once it owns the manifest" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    // (a) a manifest whose blobs are in no embed table.
    try xfix.expectRefused(&ctx, "a manifest with no embedded blobs", xfix.loadSampleV2, .{ &ctx, v2_manifest_tsv, @as([]const xfix.Blob, &.{}) });

    // (b) the right blob NAME carrying the wrong bytes: the gz hash refuses, and
    // that refusal is one step further in, past the table lookup.
    var wrong: [embedded_v2.blobs.len]xfix.Blob = undefined;
    for (embedded_v2.blobs, 0..) |b, i| wrong[i] = .{ .name = b.name, .gz = "not a gzip stream" };
    try xfix.expectRefused(&ctx, "a blob whose gz hash does not match", xfix.loadSampleV2, .{ &ctx, v2_manifest_tsv, @as([]const xfix.Blob, &wrong) });

    // (c) a schema-v1 manifest handed to the loader — refused at the version
    // gate (C7z), before any ownership transfer.
    const v1_text = "version\t1\nfixture\tf\tdirect\tjava\tc\nfile\tf\tx.db\t1" ++ SHAS ++ "\n";
    try xfix.expectRefused(&ctx, "a schema-v1 manifest in the v2 loader", xfix.loadSampleV2, .{ &ctx, v1_text, @as([]const xfix.Blob, &embedded_v2.blobs) });
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

    try xfix.assertGoldenShape(&ctx, "GOLDEN-DECODE.tsv", golden_decode_tsv);
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

// EVERY bundle's recids are cross-checked, not just some of them.
//
// `renderBody` calls the one-way rule twice — once per bundle boundary and once
// for the last bundle — and on a corpus where every bundle satisfies the rule,
// dropping either call leaves the suite green. Measured, not assumed: both
// mutants survived round 2. So each case below doctors ONE bundle's manifest
// with a recid its log never mentions, and the two cases pick a bundle that is
// not last and the bundle that is.
test "xfixtures v2: every bundle's manifest recids are cross-checked" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadSample(&ctx);
    defer sample.deinit(a);

    // dump order is (fixtureId, relName): java-cleaned, java-tail, zig-tail.
    const cases = [_]struct { row: []const u8, what: []const u8 }{
        .{
            .row = "recid\twal3-java-cleaned\tghost\t9999\tlive\t1\t8\n",
            .what = "a phantom recid on a bundle that is not the last",
        },
        .{
            .row = "recid\twal3-zig-tail\tghost\t9999\tlive\t1\t8\n",
            .what = "a phantom recid on the last bundle",
        },
    };
    for (cases) |c| {
        const text = try std.mem.concat(a, u8, &.{ v2_manifest_tsv, c.row });
        defer a.free(text);
        var loaded = try xfix.parse(&ctx, text);
        defer loaded.deinit(a);

        var files: std.ArrayListUnmanaged(xfix.RawFile) = .empty;
        defer files.deinit(a);
        try files.appendSlice(a, sample.files.items);
        const doctored = xfix.SampleV2{ .manifest = loaded.v2, .files = files };

        var rows: xfix.Strings = .{};
        defer rows.deinit(a);
        try xfix.expectRefused(&ctx, c.what, xfix.renderBody, .{ &ctx, &doctored, &rows });
    }
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

    // Rows and the leading block are compared separately, so a comment hiding
    // AFTER the first data row would be seen by neither. Java compares whole
    // text; this is the equivalent, without a second unreadable diff.
    try xfix.assertGoldenShape(&ctx, "GOLDEN-BODY.tsv", golden_body_tsv);
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

/// [`refuse`], plus the demand that the refusal NAMES the rule that fired.
///
/// A bare "the parser refused" cannot tell two rules apart, and several of the
/// grammar's rules refuse each other's inputs: an empty key is also a key whose
/// first character is not `[a-z]`, and a pair with two `=` also has a value
/// carrying a character outside the pinned class. The C5z campaign measured the
/// consequence — with only `refuse`, deleting either of those two rules left the
/// whole suite green, because its neighbour refused the same input. This is
/// lesson (h) in the parser battery, and the same fix the corpus cases already
/// use.
fn refuseSaying(ctx: *xfix.Ctx, what: []const u8, saying: []const u8, text: []const u8) !void {
    try xfix.expectRefusedSaying(ctx, what, saying, parseOk, .{ ctx, text });
}

// Schema version 1 is retired; schema version 2 is the only accepted form (C7z).
//
// The historical reason the version line is a hard gate: v1 and v2 `expect` rows
// were both seven fields with different columns. A reader that keyed on arity
// would put `mode` where `verdict` belongs.
test "xfixtures: the reader accepts only schema v2" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    const v2 = "version\t2\nfixture\tf\twal3-namespace\tjava\tc\nfile\tf\tx\t1" ++ SHAS ++ "\n" ++
        "expect\tf\tzig\tro\taccept\twal3\tx\n";
    var l2 = try xfix.parse(&ctx, v2);
    defer l2.deinit(a);
    try testing.expectEqual(@as(u32, 2), l2.version());
    try testing.expectEqualStrings("ro", l2.v2.expects.items[0].mode);
    try testing.expectEqualStrings("accept", l2.v2.expects.items[0].verdict);

    try refuse(&ctx, "retired schema version 1", "version\t1\nfixture\tf\tdirect\tjava\tc\nfile\tf\tx.db\t1" ++ SHAS ++ "\n" ++
        "expect\tf\tzig\taccept\tdirect\tx.db\tx.db\n");
    // A v1-shaped expect under a v2 version line is still refused (vocabulary).
    try refuse(&ctx, "v1 expect rows under a v2 version line", "version\t2\nfixture\tf\tdirect\tjava\tc\nfile\tf\tx.db\t1" ++ SHAS ++ "\n" ++
        "expect\tf\tzig\taccept\tdirect\tx.db\tx.db\n");
    try refuse(&ctx, "an unknown schema version", "version\t3\n");
    try refuse(&ctx, "a manifest with no version line", "fixture\tf\tdirect\tjava\tc\n");
    try refuse(&ctx, "a version line with a trailing field", "version\t2\tx\n");
}

const V2_HEAD = "version\t2\nfixture\tf\twal3-namespace\tjava\tc\n";
const V2_FILE = "file\tf\tx.wal.0000000000000001\t36" ++ SHAS ++ "\n";

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
    try refuse(&ctx, "a non-canonical integer", V2_HEAD ++ "file\tf\tx\t036" ++ SHAS ++ "\n");
    try refuse(&ctx, "a relName that escapes the cell directory", V2_HEAD ++ "file\tf\t../x\t36" ++ SHAS ++ "\n");
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

    // The two hash columns, which the frozen java reader validates and this one
    // did not until the C3z review.
    try refuse(&ctx, "a rawSha that is not 64 hex digits", V2_HEAD ++ "file\tf\tx\t36\taa" ++ "\t" ++ "b" ** 64 ++ "\n");
    try refuse(&ctx, "a gzSha that is not 64 hex digits", V2_HEAD ++ "file\tf\tx\t36\t" ++ "a" ** 64 ++ "\tbb\n");
    try refuse(&ctx, "an uppercase sha", V2_HEAD ++ "file\tf\tx\t36\t" ++ "A" ** 64 ++ "\t" ++ "b" ** 64 ++ "\n");

    // A `derived` row NAMES another fixture, and that fixture must exist —
    // `manifest_v2.py`'s `fixture_unknown_ref`. The referential-integrity rule
    // exempted the one row type whose purpose is to point at a fixture.
    try refuse(&ctx, "a derived row whose source fixture does not exist", "version\t2\nfixture\tf\treject\tderived\tc\n" ++ V2_FILE ++ "derived\tf\tghost\t1\trecipe\n");

    // `edit` rows: a fixture reference like every other row's first column, plus
    // the canonical scalar forms.
    try refuse(&ctx, "an edit row naming a fixture with no fixture row", V2_HEAD ++ V2_FILE ++ "edit\tghost\tx\t3\t53\t35\n");
    try refuse(&ctx, "an edit row with a non-canonical offset", V2_HEAD ++ V2_FILE ++ "edit\tf\tx\t03\t53\t35\n");
    try refuse(&ctx, "an edit row whose before-bytes are not whole hex bytes", V2_HEAD ++ V2_FILE ++ "edit\tf\tx\t3\t5\t35\n");
    try refuse(&ctx, "an edit row whose after-bytes are not hex", V2_HEAD ++ V2_FILE ++ "edit\tf\tx\t3\t53\tzz\n");

    // A recidrange at the very top of the recid domain. `from == to ==
    // maxInt(u64)` passes the span check, and with `r <= to` as the loop
    // condition the counter then overflows — a trap in Debug, a wrap through
    // most of the u64 domain in ReleaseFast, and in neither case a refusal. It
    // is a LEGAL one-row range, so the fix is a terminal break and this case
    // asserts it PARSES: a rule that refused it would be inventing a limit the
    // grammar does not state.
    try parseOk(&ctx, V2_HEAD ++ V2_FILE ++ "recidrange\tf\tr\t18446744073709551615\t18446744073709551615\tlive\t1\t8\n");
    // The payload id is an INDEPENDENT addition and can overflow on a range that
    // is otherwise unremarkable. That one really is a refusal.
    try refuse(&ctx, "a recidrange whose payload ids overflow", V2_HEAD ++ V2_FILE ++ "recidrange\tf\tr\t1\t2\tlive\t18446744073709551615\t8\n");

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
    try refuse(&ctx, "a file row naming a fixture with no fixture row", V2_HEAD ++ V2_FILE ++ "file\tg\tx.wal.0000000000000002\t36" ++ SHAS2 ++ "\n");
    try refuse(&ctx, "an expect row naming a fixture with no fixture row", V2_HEAD ++ V2_FILE ++ "expect\tg\tzig\tro\taccept\twal3\tx\n");
    try refuse(&ctx, "a post row naming a fixture with no fixture row", V2_HEAD ++ V2_FILE ++ "post\tg\tzig\tro\tx.lock\tunchanged\n");
    try refuse(&ctx, "a recid row naming a fixture with no fixture row", V2_HEAD ++ V2_FILE ++ "recid\tg\tr1\t1\tlive\t1\t8\n");
    try refuse(&ctx, "a declared fixture no row refers to", V2_HEAD ++ V2_FILE ++ "fixture\tg\twal3-namespace\tjava\tc\n");
}

// The four C5 row types PARSE, and every rule the grammar states about them can
// fire.
//
// The `bytes` row used to be refused by name here — C3's landmine, because the
// deriver and the fixtures it describes did not exist yet. C5s built both, so a
// reader that still refused it would refuse the corpus, and slice C5z is where
// this engine stops refusing and starts accounting.
//
// Each positive case is paired with the negative that proves the corresponding
// rule can fail. A grammar rule with no malformed input is a rule nothing has
// shown to be there.
test "xfixtures: the C5 oracle rows parse and are checked" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };

    const ACT = "action\tf\tzig\tro\tcommit_one_record\top=put,payload_id=1,payload_len=2,recid_label=Q,serializer=raw\n";

    // The four row types, well formed, in one manifest that must PARSE.
    try parseOk(&ctx, V2_HEAD ++ V2_FILE ++ "applies\tf\tzig\tro\n" ++ ACT ++
        "bytes\tf\tzig\tro\tx.wal.0000000000000001\t0\taabb\n" ++
        "reopen\tf\tzig\tro\tS2\n");

    try refuse(&ctx, "a short applies row", V2_HEAD ++ V2_FILE ++ "applies\tf\tzig\n");
    try refuse(&ctx, "an applies row for an unknown engine", V2_HEAD ++ V2_FILE ++ "applies\tf\tgo\tro\n");
    try refuse(&ctx, "a duplicate applies row", V2_HEAD ++ V2_FILE ++ "applies\tf\tzig\tro\napplies\tf\tzig\tro\n");
    try refuse(&ctx, "a duplicate action row for one cell and verb", V2_HEAD ++ V2_FILE ++ ACT ++ ACT);
    // ONE NEGATIVE PER SITE, not per rule. Round 2 of review measured four of
    // these sites deletable with the whole suite green, because each rule had a
    // single negative that reached only its FIRST site — "one case per METHOD is
    // not one case per BRANCH" (C5r's recurring shape) inside the parser this
    // time. And this is the authority `runAction` was restructured to lean on,
    // so an unmeasured half here is an unmeasured foundation under that repair:
    // the DISTINCT half below is the exact guarantee that let `runAction`'s own
    // repeated-key check be deleted.
    try refuseSaying(&ctx, "an action argument with no `=` at all", "is not one k=v pair", V2_HEAD ++ V2_FILE ++
        "action\tf\tzig\tro\tcommit_one_record\top\n");
    try refuseSaying(&ctx, "an action argument whose key is empty", "has an empty key", V2_HEAD ++ V2_FILE ++
        "action\tf\tzig\tro\tcommit_one_record\t=put\n");
    try refuseSaying(&ctx, "an action argument with two `=`", "is not one k=v pair", V2_HEAD ++ V2_FILE ++
        "action\tf\tzig\tro\tcommit_one_record\top=a=b\n");
    // `0p`, not `Op`: `O` is refused by the character-class LOOP as well, so it
    // measured the loop and left the first-character rule deletable green —
    // measured. `0` is IN [a-z0-9_], so only the first-character rule refuses it.
    try refuseSaying(&ctx, "an action argument key whose FIRST character is not [a-z]", "is not [a-z][a-z0-9_]*", V2_HEAD ++ V2_FILE ++
        "action\tf\tzig\tro\tcommit_one_record\t0p=put\n");
    try refuseSaying(&ctx, "an action argument key whose LATER character is not [a-z0-9_]", "is not [a-z][a-z0-9_]*", V2_HEAD ++ V2_FILE ++
        "action\tf\tzig\tro\tcommit_one_record\toP=put\n");
    try refuseSaying(&ctx, "action argument keys out of order", "must be sorted and distinct", V2_HEAD ++ V2_FILE ++
        "action\tf\tzig\tro\tcommit_one_record\tserializer=raw,op=put\n");
    try refuseSaying(&ctx, "action argument keys REPEATED", "must be sorted and distinct", V2_HEAD ++ V2_FILE ++
        "action\tf\tzig\tro\tcommit_one_record\top=a,op=b\n");
    try refuseSaying(&ctx, "an action argument value that is EMPTY", "must be nonempty", V2_HEAD ++ V2_FILE ++
        "action\tf\tzig\tro\tcommit_one_record\top=\n");
    try refuseSaying(&ctx, "an action argument value outside the pinned character class", "must be nonempty", V2_HEAD ++ V2_FILE ++
        "action\tf\tzig\tro\tcommit_one_record\top=p t\n");
    try refuse(&ctx, "a duplicate reopen row", V2_HEAD ++ V2_FILE ++
        "reopen\tf\tzig\tro\tS2\nreopen\tf\tzig\tro\tS2\n");
    try refuse(&ctx, "a bytes row with an odd-length hex blob", V2_HEAD ++ V2_FILE ++
        "bytes\tf\tzig\tro\tx.wal.0000000000000001\t0\taab\n");
    try refuse(&ctx, "a bytes row with an uppercase hex blob", V2_HEAD ++ V2_FILE ++
        "bytes\tf\tzig\tro\tx.wal.0000000000000001\t0\tAA\n");
    try refuse(&ctx, "a duplicate bytes row for one cell, file and offset", V2_HEAD ++ V2_FILE ++
        "bytes\tf\tzig\tro\tx.wal.0000000000000001\t0\taa\n" ++
        "bytes\tf\tzig\tro\tx.wal.0000000000000001\t0\tbb\n");
    // The fixture reference is a reference like any other row's: a row addressed
    // to a fixture nothing declares must be refused, in all four types.
    try refuse(&ctx, "an applies row naming an undeclared fixture", V2_HEAD ++ V2_FILE ++ "applies\tghost\tzig\tro\n");
    try refuse(&ctx, "an action row naming an undeclared fixture", V2_HEAD ++ V2_FILE ++
        "action\tghost\tzig\tro\tcommit_one_record\top=put\n");
    try refuse(&ctx, "a reopen row naming an undeclared fixture", V2_HEAD ++ V2_FILE ++ "reopen\tghost\tzig\tro\tS2\n");
    try refuse(&ctx, "a bytes row naming an undeclared fixture", V2_HEAD ++ V2_FILE ++
        "bytes\tghost\tzig\tro\tx.wal.0000000000000001\t0\taa\n");
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
    const ab = [_]xfix.InputFile{.{ .rel = "seg", .bytes = "ab" }};
    const xy = [_]xfix.InputFile{.{ .rel = "seg", .bytes = "xy" }};
    const abcd = [_]xfix.InputFile{.{ .rel = "seg", .bytes = "abcd" }};
    const abc_lock = [_]xfix.InputFile{ .{ .rel = "seg", .bytes = "abc" }, .{ .rel = "x.lock", .bytes = "" } };
    const abc_lockz = [_]xfix.InputFile{ .{ .rel = "seg", .bytes = "abc" }, .{ .rel = "x.lock", .bytes = "z" } };
    const abc_lockq = [_]xfix.InputFile{ .{ .rel = "seg", .bytes = "abc" }, .{ .rel = "x.lock", .bytes = "q" } };
    const abc_new = [_]xfix.InputFile{ .{ .rel = "seg", .bytes = "abc" }, .{ .rel = "new", .bytes = "q" } };
    const surprise = [_]xfix.InputFile{ .{ .rel = "seg", .bytes = "abc" }, .{ .rel = "surprise", .bytes = "x" } };
    const none = [_]xfix.InputFile{};

    // `E` is the empty-string sha, `S` the sha of "q", `A` of "ab", `X` of "xy"
    // and `D` of "abcd"; expanded below so the rows stay readable.
    const cases = [_]PostCase{
        .{ .what = "an untouched input named by nothing", .inputs = &abc, .after = &abc, .posts = &.{}, .ok = true },
        .{ .what = "an unnamed input rewritten behind the rule's back", .inputs = &abc, .after = &abd, .posts = &.{}, .ok = false },
        .{ .what = "an unnamed input deleted behind the rule's back", .inputs = &abc, .after = &none, .posts = &.{}, .ok = false },
        .{ .what = "a file that is neither an input nor named", .inputs = &abc, .after = &surprise, .posts = &.{}, .ok = false },
        .{ .what = "a lock file the post rows do declare", .inputs = &abc, .after = &abc_lock, .posts = &.{"x.lock\tcreated:0:E"}, .ok = true },
        .{ .what = "a `created` file whose length does not match", .inputs = &abc, .after = &abc_lockz, .posts = &.{"x.lock\tcreated:0:E"}, .ok = false },
        .{ .what = "a `created` file whose length is right and whose sha is not", .inputs = &abc, .after = &abc_lockq, .posts = &.{"x.lock\tcreated:1:E"}, .ok = false },
        .{ .what = "a `deleted` file that is still there", .inputs = &abc, .after = &abc, .posts = &.{"seg\tdeleted"}, .ok = false },
        .{ .what = "a `deleted` file that really is gone", .inputs = &abc, .after = &none, .posts = &.{"seg\tdeleted"}, .ok = true },
        .{ .what = "an `unchanged` file that changed", .inputs = &abc, .after = &abd, .posts = &.{"seg\tunchanged"}, .ok = false },
        .{ .what = "an `unchanged` file that really is unchanged", .inputs = &abc, .after = &abc, .posts = &.{"seg\tunchanged"}, .ok = true },
        .{ .what = "`modified` naming a file that was never an input", .inputs = &abc, .after = &abc_new, .posts = &.{"new\tmodified:1:S"}, .ok = false },
        // §2.1's split has TWO sides: a post row is an explicit override of an
        // input, or an explicit NEW file. The three below are the ones the C3r
        // review found missing, and each was green under the old rule.
        .{ .what = "`created` naming a file that WAS an input", .inputs = &q, .after = &q, .posts = &.{"seg\tcreated:1:S"}, .ok = false },
        .{ .what = "`deleted` naming a file that was never an input", .inputs = &abc, .after = &abc, .posts = &.{"ghost\tdeleted"}, .ok = false },
        // Presence is decided by the CAPTURE, which enumerates the directory and
        // refuses any entry that is not a regular file. That is where a file
        // replaced by a directory of the same name is refused now: `deleted`
        // passing on something very much still there in another shape was the C3r
        // finding, and moving presence from a stat-by-name to an enumeration
        // keeps it while removing the errno-swallowing hazard the C3z review
        // found one level down — nothing is ever stat'd by a name the kernel did
        // not just hand back.
        .{ .what = "a `deleted` file replaced by a directory of the same name", .inputs = &abc, .after = &none, .posts = &.{"seg\tdeleted"}, .ok = false, .make_dir = true },
        // The two quadrants C5r's round-5 review found had no input. Equality
        // alone cannot establish that an `unchanged` row names an input file
        // (`null == null`), and every `created` case varied the input side and
        // never post-file PRESENCE.
        .{ .what = "an `unchanged` row naming a file absent before and after", .inputs = &abc, .after = &abc, .posts = &.{"ghost\tunchanged"}, .ok = false },
        // …and the same rule's OTHER half, isolated. The case above trips the
        // "gone after the cell" check as well, so it measures whichever runs
        // first: the campaign proved it by deleting the was-an-input check with
        // the whole gate green. This one names a file that is PRESENT after and
        // whose content is empty, so a defective executor substituting `""` for
        // the missing input compares equal and accepts.
        .{ .what = "an `unchanged` row naming a file that was never an input", .inputs = &abc, .after = &abc_lock, .posts = &.{"x.lock\tunchanged"}, .ok = false },
        // The length check, isolated from the hash that subsumes it. A wrong
        // length always implies a wrong hash, so "length does not match" above
        // measures the HASH; this row's hash is right and only its length is
        // wrong. Measured: without it, deleting the length check is green.
        .{ .what = "an `unchanged` file that is gone after the cell", .inputs = &abc, .after = &none, .posts = &.{"seg\tunchanged"}, .ok = false },
        .{ .what = "a `created` file whose sha is right and whose length is not", .inputs = &abc, .after = &abc_lock, .posts = &.{"x.lock\tcreated:5:E"}, .ok = false },
        .{ .what = "a `created` file that is missing after the cell", .inputs = &abc, .after = &abc, .posts = &.{"x.lock\tcreated:0:E"}, .ok = false },
        // The verb RELATIONS (C5r round 3, and `NEXT.md` rev 26 item 8). Grading
        // the length and hash alone leaves both verbs as decoration: a file that
        // GREW satisfied `truncated` and an unchanged file satisfied `modified`.
        // Each half of each collapsed conjunction gets its own input, because the
        // collapse buys freedom from masking and not coverage (round 4).
        .{ .what = "a `truncated` file that is a proper prefix", .inputs = &abc, .after = &ab, .posts = &.{"seg\ttruncated:2:A"}, .ok = true },
        .{ .what = "a `truncated` file that grew", .inputs = &abc, .after = &abcd, .posts = &.{"seg\ttruncated:4:D"}, .ok = false },
        .{ .what = "a `truncated` file that shrank but is not a PREFIX of the input", .inputs = &abc, .after = &xy, .posts = &.{"seg\ttruncated:2:X"}, .ok = false },
        // LAST of the three negatives, deliberately: it is the only one the
        // one-token `<` -> `<=` mutant lets through, so the whole-relation
        // mutant reports "that grew" and the strictness mutant reports this.
        .{ .what = "a `truncated` file whose bytes are exactly the input", .inputs = &q, .after = &q, .posts = &.{"seg\ttruncated:1:S"}, .ok = false },
        .{ .what = "a `modified` file whose bytes really changed", .inputs = &abc, .after = &xy, .posts = &.{"seg\tmodified:2:X"}, .ok = true },
        .{ .what = "a `modified` file whose bytes are unchanged", .inputs = &q, .after = &q, .posts = &.{"seg\tmodified:1:S"}, .ok = false },
        .{ .what = "a `modified` row describing what is really a truncation", .inputs = &abc, .after = &ab, .posts = &.{"seg\tmodified:2:A"}, .ok = false },
    };

    const sha_q = xfix.sha256Hex("q");
    const sha_ab = xfix.sha256Hex("ab");
    const sha_xy = xfix.sha256Hex("xy");
    const sha_abcd = xfix.sha256Hex("abcd");

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
        try text.appendSlice(a, V2_HEAD ++ "file\tf\tseg\t3" ++ SHAS ++ "\n");
        for (c.posts) |row| {
            try text.appendSlice(a, "post\tf\tzig\tro\t");
            for (row) |ch| {
                switch (ch) {
                    'E' => try text.appendSlice(a, xfix.EMPTY_SHA),
                    'S' => try text.appendSlice(a, &sha_q),
                    'A' => try text.appendSlice(a, &sha_ab),
                    'X' => try text.appendSlice(a, &sha_xy),
                    'D' => try text.appendSlice(a, &sha_abcd),
                    else => try text.append(a, ch),
                }
            }
            try text.append(a, '\n');
        }

        var loaded = try xfix.parse(&ctx, text.items);
        defer loaded.deinit(a);
        var posts: std.ArrayListUnmanaged(*const xfix.V2Post) = .empty;
        defer posts.deinit(a);
        for (loaded.v2.posts.items) |*p| try posts.append(a, p);

        if (c.ok) {
            try gradePosts(&ctx, dir, c, posts.items);
            // …and every row it graded was ACCOUNTED for. Without this the
            // `owed.consume` call inside the rule can be deleted with the whole
            // battery green, because nothing here would ever read the books.
        } else {
            try xfix.expectRefused(&ctx, c.what, gradePosts, .{ &ctx, dir, c, posts.items });
        }
    }
    try testing.expectEqual(@as(usize, 27), cases.len);
}

/// One battery case, through the CAPTURE and the ACCOUNTANT rather than around
/// them — the same two pieces the executor puts in front of the rule.
fn gradePosts(ctx: *xfix.Ctx, dir: std.fs.Dir, c: PostCase, posts: []const *const xfix.V2Post) !void {
    var after = try xfix.capture(ctx, dir, c.what);
    defer after.deinit(ctx.alloc);
    var owed = xfix.Consumption.init(c.what);
    defer owed.deinit(ctx.alloc);
    for (posts) |p| try owed.owe(ctx, "post {s}", .{p.rel}, p);
    try xfix.assertPostState(ctx, c.inputs, &after, posts, c.what, &owed);
    try owed.requireAllConsumed(ctx);
}

test {
    testing.refAllDecls(@This());
}
