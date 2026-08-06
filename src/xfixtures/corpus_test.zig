//! The schema-v2 **preflight corpus** against this engine — Stage C, slice
//! **C5z**.
//!
//! `src/xfixtures/data-v2-corpus/` is a byte-identical copy of the `root`-marked
//! files of `todo/store-cross/preflight-v2/` — twelve files: `MANIFEST.tsv` and
//! one blob per `file` row, and nothing else (C5 plan §4c) — plus, beside it,
//! the `zig`-marked `embedded_v2_corpus.zig`, which is this engine's generated
//! embed table and part of its distribution. It is the `v2-oracle` profile: it
//! carries `applies`, `action`, `bytes` and `reopen` rows. The static
//! `data-v2/` sample stays `v2-core` and is untouched by C5; `conformance_test`
//! still owns it, through the same executor.
//!
//! # What this engine executes, and what it accounts for
//!
//! **The corpus addresses no `action`, `bytes` or `reopen` row to zig**, and
//! that is a property of the format rather than an oversight: `Cell.actions`,
//! `Cell.byte_assertions` and `Cell.reopen` exist on exactly one cell and are
//! keyed `("java", "rw")`. Revision 3 of the C5 plan claimed all three engines
//! execute them and both round-3 reviewers found the claim had an empty input
//! column for two engines. Manufacturing a port-addressed assertion in the
//! corpus to fix that would be fixture theatre.
//!
//! So plan §5.3 item 2 splits the flip: zig **accepts and accounts**, and its
//! execution paths get their inputs from SYNTHETIC manifests here — where a row
//! addressed to zig can be written by hand — run through the production path
//! over the corpus's real bytes. `theActionRowIsExecuted`, `theBytesRowIsGraded`
//! and `theReopenRowIsGraded` are those inputs. An addressed row no handler
//! consumed is a failure, not a no-op: that accounting is the only thing that
//! makes "executes" distinguishable from "parses and drops".
//!
//! # What C5z measured rather than inherited
//!
//! Plan §3.11's amendment made `DIRECT_OPENER_LOCKS` this slice's first
//! obligation, because for java both of §3.11's premises turned out false. For
//! zig they both hold, and the measurement is in the corpus run itself:
//!
//! - `StoreDirect.openFile` refuses the bare v3 segment (`DataCorruption`, bad
//!   magic) and leaves the cell directory holding `{x}` — it takes **no**
//!   `<base>.lock`. That is why `reject-wal3-segment-at-direct` carries no post
//!   row at all and why plan §5.3 item 5's second relaxation is needed here.
//! - `StoreWAL.openCfg` on the same path refuses it as D1 — a regular file at
//!   the WAL base path — but takes the lock BEFORE the check and leaves
//!   `{x, x.lock}`.
//!
//! So both openers reject and the VERDICT discriminates nothing; the stray lock
//! does, against the two-sided file-set rule. That is
//! `aDirectCellSentToTheWalOpenerGoesRed`, and it is a substitution rather than
//! a deletion: restoring an `opener == wal3` refusal would prove only parser
//! branching.
//!
//! **The reject cells' FAMILIES were measured too** (plan §3.12): the two
//! derived reject images refuse with `DataCorruption` and
//! `div-wal3-lsn-exhausted` refuses with `StoreFull` in both modes, which is
//! what contract §10.1 pins for this engine. The v2 `expect` row has no column
//! for a family, so the reject arm can only assert that the open failed. That is
//! recorded at the site as an open hole, and `assertFamily` implements **both**
//! families this engine produces so the day C5t emits `reopen` rows for the
//! reject cells there is nothing left to write.
//!
//! # The mutation campaign
//!
//! A set of NAMED cases in `todo/store-wal3/campaigns/mut_z.py` +
//! `mutants_z.sh`, with the run that produced this slice's result beside them in
//! `campaign_z.log`. Each case mutates one named site — deleting, replacing or
//! moving it — and the suite must then go red for the reason that case names.
//! The runner exits non-zero if any case survives, mis-kills or fails to apply,
//! so the count and the result are read from a run rather than asserted here.
//!
//! **It is a named campaign, not an exhaustive sweep.** What is true is
//! narrower: every check the campaign names has a red that names it. Most checks
//! are green when deleted unless something supplies an input, so they are closed
//! with DOCTORED manifests routed through the PRODUCTION path — never by calling
//! the check directly, which proves the method and leaves its call unobserved.
//! Where a check's red is unreachable from any conforming corpus it gets a
//! direct firing probe instead (`theReopenFamilyPredicateDiscriminates`).
//!
//! # What the campaign measured and could NOT kill
//!
//! Named, because a campaign that reports only its kills is a campaign whose
//! coverage claim nothing checks — and **MEASURED, because a disclosure is a
//! claim like any other.** C5r's review filed an inaccurate one twice: once for
//! an undisclosed survivor and once for a disclosure that counted six where the
//! runner held seven. So each entry below has a mutant of its own in
//! `mut_z.py`, and `campaigns/disclose_z.sh` is the runner that grades them —
//! with the opposite convention to `mutants_z.sh`, because here a SURVIVOR
//! confirms the claim and a KILL means this list is wrong. It reported
//! `disclosure: 6 confirmed, 0 refuted, 0 unmeasured`.
//!
//! - `leaf_rocount`, `leaf_roprobed`, `leaf_rootset`, `leaf_distseal` — the
//!   `ro_probed` count and membership comparisons, the corpus-root file-set
//!   comparison and the distribution-seal comparison. Each is the last statement
//!   in its group: they are what give the probe call, the root inventory and the
//!   copy their reds, and nothing observes THEM. This is the leaf problem — a
//!   statement no other statement depends on is invisible to deletion — pushed
//!   DOWN by collecting outcomes and comparing once per group, not removed.
//! - `leaf_v2core` — the `v2-core` profile assertion in `runV2Cells`. The static
//!   sample carries no oracle row, so no input reaches it; it exists for the day
//!   one appears.
//! - `leaf_capture_isfile` — `capture`'s "not a regular file" refusal. Not a
//!   leaf but SUBSUMED: deleting it leaves the read failing on the same input
//!   with a worse message, so what it buys is the diagnosis, not the refusal.
//!
//! **One check is killed only by a WEAKER signal**, and the runner names it:
//! `bytesrange`, whose deletion makes the slice go out of bounds, so the red is
//! the language's and not the rule's. No conforming manifest reaches that check
//! with the slice still in range. `grep -c '^# WEAKER SIGNAL' mutants_z.sh` is
//! the count and the `^#` anchor is load-bearing — unanchored it counts the
//! runner's own header, which is the mistake C5r's round 3 caught.
//!
//! **Two interlocks are recorded rather than closed.** `runV2CorpusCells` checks
//! `applies ⊆ ran` and not the converse, because `ran` is built from `expect`
//! rows and the `expect`-has-an-`applies` loop already forbids the other
//! direction; the two guard each other one way only. And `assertBytesRows`
//! renders at most 32 asserted bytes, refusing a longer row loudly rather than
//! truncating it — a bound, stated at the site, not a silent cap.
//!
//! # What the campaign cost, and what it was worth
//!
//! Round 1 returned **48 killed, 13 not killed**, and eleven of the thirteen
//! were defects in the CAMPAIGN rather than in the suite: three mutants that did
//! not COMPILE (Zig makes a deletion that orphans a binding an error, and both
//! runners now refuse to score one as a kill), and eight expectations of mine
//! that named the wrong red. **Two were real survivors** — checks deletable with
//! the whole gate green — and both were masked by a neighbour: `unchanged`'s
//! "this names an input" refusal, whose case also tripped the "gone after the
//! cell" check, and the post-state LENGTH check, which a whole-file hash
//! subsumes. Each now has an input that reaches it alone.
//!
//! Round 1 also found **four places where two mutants shared one red**.
//! `expectRefused` returns at the first case a mutant lets through, so the ORDER
//! of the negatives decides what each mutant can prove — and two mutants with
//! one red between them are proof for neither site. The truncation negatives and
//! the eleven action cases are ordered deliberately for that reason, and the
//! `applies`/`expect` cases name the row type each one dropped.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const xfix = @import("xfix.zig");
const embedded_corpus = @import("embedded_v2_corpus.zig");
const store_mod = @import("../store/mod.zig");
const StoreWAL = store_mod.StoreWAL;

/// What `build.zig` reads off `src/xfixtures/data-v2-corpus/` at configure time.
/// The one set neither the manifest nor the generated table can influence.
const distributed = @import("xfix_distributed_corpus");

const corpus_manifest_tsv: []const u8 = @embedFile("data-v2-corpus/MANIFEST.tsv");
/// This engine's own generated embed table, hashed as the `zig`-marked member of
/// its distribution. `@embedFile` on a `.zig` file is exactly the trick that lets
/// the seal cover the table that the seal's other members are reached through.
const corpus_embed_table_src: []const u8 = @embedFile("embedded_v2_corpus.zig");

/// `freeze_v2.PREFLIGHT_DIST_SEALS["zig"]`.
///
/// The per-engine seal over only the marks this engine carries — `root` and
/// `zig`, per `freeze_v2.DIST_MARKS`. No engine can recompute `PREFLIGHT_SEAL`,
/// because the `todo`-marked post-state blob is not distributed and its hash is
/// in that preimage. Pinning it here is what makes "the three hand-copied roots
/// have not drifted" a CI fact rather than a review note.
const DIST_SEAL = "f2ef720435ffb67fb222d3297fc0c5ab59f218c55619283ac5a4714444c96cd8";

fn loadCorpus(ctx: *xfix.Ctx) !xfix.SampleV2 {
    return xfix.loadSampleV2(ctx, corpus_manifest_tsv, &embedded_corpus.blobs);
}

fn loadDoctored(ctx: *xfix.Ctx, text: []const u8) !xfix.SampleV2 {
    return xfix.loadSampleV2(ctx, text, &embedded_corpus.blobs);
}

// ---------------------------------------------------------------------------
// the corpus itself
// ---------------------------------------------------------------------------

test "xfixtures corpus: the zig cells conform in both modes" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadCorpus(&ctx);
    defer sample.deinit(a);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    for (xfix.MODES) |mode| try xfix.runV2CorpusCells(&ctx, &sample, mode, tmp.dir, .by_manifest);
}

// §3.11's mutant, as a SUBSTITUTION rather than a deletion.
//
// Routing the `direct` row through the WAL opener must turn the suite red. A
// deletion that merely restores an `opener == wal3` refusal proves only that
// the parser branches on the column.
test "xfixtures corpus: a direct cell sent to the wal opener goes red" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadCorpus(&ctx);
    defer sample.deinit(a);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // The red must be the FILE-SET rule, not "a wal3 cell has no post rows":
    // the misrouted open leaves a stray `x.lock` in a cell whose post rows do
    // not name one. If the cardinality guard keyed on the DISPATCHED opener it
    // would fire first and this case would report a red it did not produce.
    try xfix.expectRefusedSaying(
        &ctx,
        "the direct cell dispatched to the wal3 opener",
        "x.lock is neither an input nor named by a post row",
        xfix.runV2CorpusCells,
        .{ &ctx, &sample, "rw", tmp.dir, xfix.Dispatch.always_wal3 },
    );
}

// ---------------------------------------------------------------------------
// the three oracle rows this engine accepts, given inputs by hand
// ---------------------------------------------------------------------------

const CLEANED_RW = "wal3-java-cleaned\tzig\trw";
const ACTION_ROW = "action\t" ++ CLEANED_RW ++ "\tcommit_one_record\top=put,payload_id=161,payload_len=64,recid_label=Q,serializer=raw\n";

/// The post state one `commit_one_record` leaves on the cleaned bundle's tail
/// segment — MEASURED for this engine, not copied from rust's.
///
/// D6 permits two writers to frame the same commit differently, so a number
/// taken from another port would be an accident this suite pinned. These are
/// this engine's, read off a run.
const ACTION_POST_LEN: usize = 279;
const ACTION_POST_SHA = "b3286aee528406b137f8df56fd435e647617cb1ea9ff6e6ea403e16400a4ee4b";
/// A byte range inside that post state, and a wrong value for it.
const ACTION_BYTES_OFFSET: usize = 187;
const ACTION_BYTES_HEX = "000000000000000b";
const ACTION_BYTES_WRONG = "000000000000000c";

/// Rows the doctored `action` cell needs so the CELL still conforms: the tail
/// segment's new disposition, and no recid oracle.
///
/// The recid rows go because the commit reuses recid 5 — E is deleted in §5.2's
/// workload, so its slot is free and `put` allocates it — and the reader
/// contract would then refuse a record the manifest calls deleted. That is a
/// fact about the corpus, measured in C4 when java refused the same thing.
fn actionManifest(a: Allocator, extra: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(a);
    var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "recid\twal3-java-cleaned")) continue;
        try out.appendSlice(a, line);
        try out.append(a, '\n');
    }
    try out.appendSlice(a, ACTION_ROW);
    try out.appendSlice(a, "post\t" ++ CLEANED_RW ++ "\tx.wal.0000000000000004\tmodified:");
    try out.writer(a).print("{d}:{s}\n", .{ ACTION_POST_LEN, ACTION_POST_SHA });
    try out.appendSlice(a, extra);
    return out.toOwnedSlice(a);
}

test "xfixtures corpus: the action row is executed" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    const text = try actionManifest(a, "");
    defer a.free(text);
    var sample = try loadDoctored(&ctx, text);
    defer sample.deinit(a);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // Through the PRODUCTION path: the claim is that the executor runs the row,
    // not that `runAction` works when called.
    try xfix.runV2CorpusCells(&ctx, &sample, "rw", tmp.dir, .by_manifest);
}

// Eleven refusal SITES, eleven inputs.
//
// C5r needed to be told twice that one case per METHOD is not one case per
// BRANCH: the five per-key reads and the two integer parses are separate sites,
// and one mutation of a shared helper is proof for none of them.
//
// Every case carries the same post rows as the positive one, so a DELETED
// refusal lets the action run and the cell PASSES — which makes each red name
// its own branch instead of landing on the unnamed-input rule. Without that,
// C5r measured, a deleted refusal is still killed but for the wrong reason.
test "xfixtures corpus: the action row's refusals each have an input" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const cases = [_]struct { what: []const u8, args: []const u8, verb: []const u8 = "commit_one_record" }{
        .{ .what = "an unknown verb", .args = "op=put,payload_id=161,payload_len=64,recid_label=Q,serializer=raw", .verb = "rewrite_the_log" },
        .{ .what = "an unknown argument key", .args = "colour=red,op=put,payload_id=161,payload_len=64,recid_label=Q,serializer=raw" },
        // The five per-key READS come first, then the two VALUE checks. A
        // mutant that replaces one read with a constant also satisfies that
        // key's value check, so with the value cases first the two mutants
        // would report one red between them — which is proof for neither site.
        .{ .what = "no op argument", .args = "payload_id=161,payload_len=64,recid_label=Q,serializer=raw" },
        .{ .what = "no recid_label argument", .args = "op=put,payload_id=161,payload_len=64,serializer=raw" },
        .{ .what = "no payload_id argument", .args = "op=put,payload_len=64,recid_label=Q,serializer=raw" },
        .{ .what = "no payload_len argument", .args = "op=put,payload_id=161,recid_label=Q,serializer=raw" },
        .{ .what = "no serializer argument", .args = "op=put,payload_id=161,payload_len=64,recid_label=Q" },
        .{ .what = "an unimplemented op", .args = "op=append,payload_id=161,payload_len=64,recid_label=Q,serializer=raw" },
        .{ .what = "an unimplemented serializer", .args = "op=put,payload_id=161,payload_len=64,recid_label=Q,serializer=java" },
        .{ .what = "a payload_id that is not an integer", .args = "op=put,payload_id=x,payload_len=64,recid_label=Q,serializer=raw" },
        .{ .what = "a payload_len that is not an integer", .args = "op=put,payload_id=161,payload_len=x,recid_label=Q,serializer=raw" },
    };

    for (cases, 0..) |c, i| {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(a);
        var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "recid\twal3-java-cleaned")) continue;
            try out.appendSlice(a, line);
            try out.append(a, '\n');
        }
        try out.writer(a).print("action\t" ++ CLEANED_RW ++ "\t{s}\t{s}\n", .{ c.verb, c.args });
        try out.writer(a).print("post\t" ++ CLEANED_RW ++ "\tx.wal.0000000000000004\tmodified:{d}:{s}\n", .{ ACTION_POST_LEN, ACTION_POST_SHA });

        var sample = try loadDoctored(&ctx, out.items);
        defer sample.deinit(a);
        var name_buf: [32]u8 = undefined;
        var dir = try tmp.dir.makeOpenPath(try std.fmt.bufPrint(&name_buf, "act-{d}", .{i}), .{ .iterate = true });
        defer dir.close();
        try xfix.expectRefused(&ctx, c.what, xfix.runV2CorpusCells, .{ &ctx, &sample, "rw", dir, xfix.Dispatch.by_manifest });
    }
    try testing.expectEqual(@as(usize, 11), cases.len);
}

test "xfixtures corpus: the bytes row is graded" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const BYTES = std.fmt.comptimePrint(
        "bytes\t" ++ CLEANED_RW ++ "\tx.wal.0000000000000004\t{d}\t{s}\n",
        .{ ACTION_BYTES_OFFSET, ACTION_BYTES_HEX },
    );
    const WRONG = std.fmt.comptimePrint(
        "bytes\t" ++ CLEANED_RW ++ "\tx.wal.0000000000000004\t{d}\t{s}\n",
        .{ ACTION_BYTES_OFFSET, ACTION_BYTES_WRONG },
    );
    // Past the end of the POST state, which is the direction that proves the row
    // is read against the captured bytes and not against the input: the input
    // segment is 186 bytes and this offset is inside the post state only.
    // A file the cell directory does not hold at all: the row is addressed, owed
    // and unreachable, which is a failure and never a skip.
    const ABSENT_FILE = std.fmt.comptimePrint(
        "bytes\t" ++ CLEANED_RW ++ "\tx.wal.0000000000000009\t{d}\t{s}\n",
        .{ ACTION_BYTES_OFFSET, ACTION_BYTES_HEX },
    );
    const OUT_OF_RANGE = std.fmt.comptimePrint(
        "bytes\t" ++ CLEANED_RW ++ "\tx.wal.0000000000000004\t{d}\t{s}\n",
        .{ ACTION_POST_LEN + 8, ACTION_BYTES_HEX },
    );

    {
        const text = try actionManifest(a, BYTES);
        defer a.free(text);
        var sample = try loadDoctored(&ctx, text);
        defer sample.deinit(a);
        var dir = try tmp.dir.makeOpenPath("ok", .{ .iterate = true });
        defer dir.close();
        try xfix.runV2CorpusCells(&ctx, &sample, "rw", dir, .by_manifest);
    }
    // Each negative names the rule it must trip, not merely "it refused": three
    // rules stand between a `bytes` row and its comparison, and a bare refusal
    // cannot tell them apart (lesson h).
    const bad = [_]struct { row: []const u8, saying: []const u8 }{
        .{ .row = WRONG, .saying = "the asserted bytes are" },
        .{ .row = OUT_OF_RANGE, .saying = "the range ends at" },
        .{ .row = ABSENT_FILE, .saying = "names a file the cell directory does not hold" },
    };
    for (bad, 0..) |c, i| {
        const text = try actionManifest(a, c.row);
        defer a.free(text);
        var sample = try loadDoctored(&ctx, text);
        defer sample.deinit(a);
        var name_buf: [32]u8 = undefined;
        var dir = try tmp.dir.makeOpenPath(try std.fmt.bufPrint(&name_buf, "bad-{d}", .{i}), .{ .iterate = true });
        defer dir.close();
        try xfix.expectRefusedSaying(&ctx, "a bytes row that does not hold", c.saying, xfix.runV2CorpusCells, .{ &ctx, &sample, "rw", dir, xfix.Dispatch.by_manifest });
    }
}

// A `reopen` row, on the one cell whose store really is permanently unopenable.
//
// `div-wal3-lsn-exhausted` refuses in both modes with `StoreFull`, so a reopen
// of it refuses the same way its open did — which is exactly the shape C5t will
// emit for every reject cell to close plan §3.12's transport hole.
test "xfixtures corpus: the reopen row is graded" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const cases = [_]struct { what: []const u8, family: []const u8, ok: bool }{
        .{ .what = "the family the reopen really produces", .family = "StoreFull", .ok = true },
        .{ .what = "a family the reopen does not produce", .family = "S2", .ok = false },
        .{ .what = "a family this engine has no predicate for", .family = "R4", .ok = false },
    };
    for (cases, 0..) |c, i| {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(a);
        try out.appendSlice(a, corpus_manifest_tsv);
        try out.writer(a).print("reopen\tdiv-wal3-lsn-exhausted\tzig\trw\t{s}\n", .{c.family});

        var sample = try loadDoctored(&ctx, out.items);
        defer sample.deinit(a);
        var name_buf: [32]u8 = undefined;
        var dir = try tmp.dir.makeOpenPath(try std.fmt.bufPrint(&name_buf, "reopen-{d}", .{i}), .{ .iterate = true });
        defer dir.close();
        if (c.ok) {
            try xfix.runV2CorpusCells(&ctx, &sample, "rw", dir, .by_manifest);
        } else {
            try xfix.expectRefused(&ctx, c.what, xfix.runV2CorpusCells, .{ &ctx, &sample, "rw", dir, xfix.Dispatch.by_manifest });
        }
    }
}

// A `reject` cell whose store OPENS must fail.
//
// No conforming corpus supplies that input — every reject cell really does
// refuse — so without a doctored one the reject arm's whole claim can be deleted
// with the gate green. Re-labelling the cleaned bundle's accept cell as `reject`
// is the smallest input that reaches it.
test "xfixtures corpus: a reject cell whose store opens is refused" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(a);
    var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "expect\t" ++ CLEANED_RW ++ "\taccept\twal3\tx")) {
            try out.appendSlice(a, "expect\t" ++ CLEANED_RW ++ "\treject\twal3\tx\n");
            continue;
        }
        try out.appendSlice(a, line);
        try out.append(a, '\n');
    }
    try testing.expect(std.mem.indexOf(u8, out.items, "\treject\twal3\tx") != null);

    var sample = try loadDoctored(&ctx, out.items);
    defer sample.deinit(a);
    try xfix.expectRefusedSaying(
        &ctx,
        "a reject cell whose store opened",
        "expected a refusal, but the store opened",
        xfix.runV2CorpusCells,
        .{ &ctx, &sample, "rw", tmp.dir, xfix.Dispatch.by_manifest },
    );
}

// A `reopen` row on a store that opens again must fail.
//
// The corpus's only reopenable-and-refusing cell is `div-wal3-lsn-exhausted`, so
// the positive path never exercises "it opened again". The cleaned bundle does
// open again, and a reopen row on it is the input that makes that branch
// falsifiable.
test "xfixtures corpus: a reopen row on a store that opens again is refused" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(a);
    try out.appendSlice(a, corpus_manifest_tsv);
    try out.appendSlice(a, "reopen\t" ++ CLEANED_RW ++ "\tStoreFull\n");

    var sample = try loadDoctored(&ctx, out.items);
    defer sample.deinit(a);
    try xfix.expectRefusedSaying(
        &ctx,
        "a reopen row on a store that opens again",
        "the store opened again",
        xfix.runV2CorpusCells,
        .{ &ctx, &sample, "rw", tmp.dir, xfix.Dispatch.by_manifest },
    );
}

// The family predicate, fired DIRECTLY — the one place in this file where that
// is the honest thing to do.
//
// No conforming corpus can hand `assertFamily` a refusal that carries the S2
// reason on a non-corruption error, or a corruption verdict carrying a
// different reason, so the two halves of the S2 conjunction have no input from
// any manifest. They are given one here. **This is the round-4 lesson applied
// before a reviewer has to find it**: collapsing the two halves into one
// statement removes the masking and buys no coverage, so each half owes an
// input of its own.
test "xfixtures corpus: the reopen family predicate discriminates" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    const recover = @import("../store/wal_recover.zig");

    const s2_real = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = recover.H_LSN_BACK } };
    const s2_wrong_variant = xfix.Refusal{ .err = error.StoreFull, .diag = .{ .reason = recover.H_LSN_BACK } };
    const s2_wrong_reason = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = recover.R_CHAIN } };
    const full = xfix.Refusal{ .err = error.StoreFull, .diag = .{} };

    try xfix.assertFamily(&ctx, "S2 positive", "S2", s2_real);
    try xfix.assertFamily(&ctx, "StoreFull positive", "StoreFull", full);

    // Each half of the collapsed S2 conjunction, alone.
    try xfix.expectRefused(&ctx, "an operational failure wearing the S2 reason", xfix.assertFamily, .{ &ctx, "w", "S2", s2_wrong_variant });
    try xfix.expectRefused(&ctx, "a corruption verdict carrying a different reason", xfix.assertFamily, .{ &ctx, "w", "S2", s2_wrong_reason });
    // …and the two families really are told apart, in both directions.
    try xfix.expectRefused(&ctx, "StoreFull graded as S2", xfix.assertFamily, .{ &ctx, "w", "S2", full });
    try xfix.expectRefused(&ctx, "an S2 corruption graded as StoreFull", xfix.assertFamily, .{ &ctx, "w", "StoreFull", s2_real });
    try xfix.expectRefused(&ctx, "a family with no predicate", xfix.assertFamily, .{ &ctx, "w", "R4", s2_real });
}

// ---------------------------------------------------------------------------
// consumption, in both halves
// ---------------------------------------------------------------------------

// The per-cell half: an oracle row addressed to a cell that RUNS, which no arm
// can execute.
//
// A `bytes` row on a REJECT cell is the cleanest instance — the cell never
// opens, so nothing captures a store's output, and yet the row is addressed and
// owed.
test "xfixtures corpus: an oracle row no arm can run fails the cell" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(a);
    try out.appendSlice(a, corpus_manifest_tsv);
    try out.appendSlice(a, "action\tdiv-wal3-lsn-exhausted\tzig\trw\tcommit_one_record\top=put,payload_id=1,payload_len=2,recid_label=Q,serializer=raw\n");

    var sample = try loadDoctored(&ctx, out.items);
    defer sample.deinit(a);
    try xfix.expectRefusedSaying(
        &ctx,
        "an action row on a reject cell",
        "no handler consumed: action commit_one_record",
        xfix.runV2CorpusCells,
        .{ &ctx, &sample, "rw", tmp.dir, xfix.Dispatch.by_manifest },
    );
}

// The suite-wide half: a row addressed to a cell this engine never runs at all.
//
// Per-cell consumption cannot see this — the accountant is built from the rows
// addressed to the cell BEING RUN, so a row addressed to a `(fixture, mode)`
// with no `expect` row is owed by nobody and graded by nobody. Both C5j
// reviewers proved it independently.
test "xfixtures corpus: an oracle row addressed to an absent cell fails the suite" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // One case per addressed ROW TYPE. `post` is the fourth, and it is the one
    // C5j's round 2 found droppable in silence on both sides of the fence.
    const rows = [_][]const u8{
        "action\treject-wal3-segment-at-direct\tzig\tro\tcommit_one_record\top=put,payload_id=1,payload_len=2,recid_label=Q,serializer=raw\n",
        "bytes\treject-wal3-segment-at-direct\tzig\tro\tx\t0\taa\n",
        "reopen\treject-wal3-segment-at-direct\tzig\tro\tS2\n",
        "post\treject-wal3-segment-at-direct\tzig\tro\tx\tunchanged\n",
    };
    for (rows, 0..) |row, i| {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(a);
        try out.appendSlice(a, corpus_manifest_tsv);
        try out.appendSlice(a, row);

        var sample = try loadDoctored(&ctx, out.items);
        defer sample.deinit(a);
        var name_buf: [32]u8 = undefined;
        var dir = try tmp.dir.makeOpenPath(try std.fmt.bufPrint(&name_buf, "orphan-{d}", .{i}), .{ .iterate = true });
        defer dir.close();
        // `reject-wal3-segment-at-direct` has a `rw` cell and no `ro` one, so a
        // row addressed to its `ro` cell addresses a cell that does not exist.
        try xfix.expectRefusedSaying(
            &ctx,
            "an oracle row addressed to a cell this engine never runs",
            "whose cell this engine never ran",
            xfix.runV2CorpusCells,
            .{ &ctx, &sample, "ro", dir, xfix.Dispatch.by_manifest },
        );
    }
}

test "xfixtures corpus: an unconsumed post row is a failure" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var ctx2 = xfix.Ctx{ .alloc = a };
    _ = &ctx2;

    var owed = xfix.Consumption.init("probe");
    defer owed.deinit(a);
    const row: xfix.V2Post = .{ .fixture = "f", .engine = "zig", .mode = "rw", .rel = "x", .verb = "unchanged" };
    const other: xfix.V2Post = .{ .fixture = "f", .engine = "zig", .mode = "rw", .rel = "y", .verb = "unchanged" };
    try owed.owe(&ctx, "post {s}", .{row.rel}, &row);
    try xfix.expectRefused(&ctx, "a debt nobody paid", xfix.Consumption.requireAllConsumed, .{ &owed, &ctx });
    // The ADDRESS is part of the identity, not just the key: a handler that
    // grades a different object still balances the books without it.
    try xfix.expectRefused(&ctx, "the right key with the wrong row", xfix.Consumption.consume, .{ &owed, &ctx, "post {s}", .{row.rel}, &other });
    try xfix.expectRefused(&ctx, "a key nobody owed", xfix.Consumption.consume, .{ &owed, &ctx, "post {s}", .{other.rel}, &other });
    try owed.consume(&ctx, "post {s}", .{row.rel}, &row);
    try xfix.expectRefused(&ctx, "the same debt paid twice", xfix.Consumption.consume, .{ &owed, &ctx, "post {s}", .{row.rel}, &row });
    try owed.requireAllConsumed(&ctx);
}

// ---------------------------------------------------------------------------
// the guards that make a green cell mean something
// ---------------------------------------------------------------------------

test "xfixtures corpus: a file no post row names fails the cell" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(a);
    var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        // Drop the `x.lock` row the cleaned rw cell needs, and nothing else: the
        // lock is still created, and now nothing names it.
        if (std.mem.eql(u8, line, "post\t" ++ CLEANED_RW ++ "\tx.lock\tcreated:0:" ++ xfix.EMPTY_SHA)) continue;
        try out.appendSlice(a, line);
        try out.append(a, '\n');
    }
    // …and put a DIFFERENT post row back, so the cell still has one. Without it
    // the post-cardinality guard fires first and this case would measure that
    // instead of the rule it is named for — lesson (h), an input that trips
    // several checks measures the first one only.
    try out.appendSlice(a, "post\t" ++ CLEANED_RW ++ "\tx.wal.0000000000000004\tunchanged\n");

    var sample = try loadDoctored(&ctx, out.items);
    defer sample.deinit(a);
    try xfix.expectRefusedSaying(
        &ctx,
        "a lock file no post row names",
        "x.lock is neither an input nor named by a post row",
        xfix.runV2CorpusCells,
        .{ &ctx, &sample, "rw", tmp.dir, xfix.Dispatch.by_manifest },
    );
}

// The reader contract really runs, and really can fail.
//
// Without a doctored input the recid oracle is satisfied by construction on
// every corpus cell, so deleting the call is invisible. One wrong length in one
// `recid` row is the smallest input that reaches it.
test "xfixtures corpus: the reader contract is not vacuous" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(a);
    var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "recid\twal3-java-cleaned\tA\t1\tlive\t116\t120")) {
            try out.appendSlice(a, "recid\twal3-java-cleaned\tA\t1\tlive\t116\t121\n");
            continue;
        }
        try out.appendSlice(a, line);
        try out.append(a, '\n');
    }
    try testing.expect(std.mem.indexOf(u8, out.items, "116\t121") != null);

    var sample = try loadDoctored(&ctx, out.items);
    defer sample.deinit(a);
    try xfix.expectRefused(&ctx, "a recid row that lies about a length", xfix.runV2CorpusCells, .{ &ctx, &sample, "rw", tmp.dir, xfix.Dispatch.by_manifest });
}

// An accept cell must assert SOMETHING — the C3j guard as a disjunction.
//
// C5j's first draft deleted it for the sealed root and offered the distribution
// seal instead. The seal proves copy fidelity; the guard proves assertion
// adequacy, and artifact identity cannot buy a semantic property. Stripping the
// recid rows from the `rw` accept cell leaves it asserting nothing but the
// universal `x.lock` post row.
test "xfixtures corpus: an accept cell that asserts nothing is refused" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(a);
    var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "recid\twal3-java-cleaned")) continue;
        try out.appendSlice(a, line);
        try out.append(a, '\n');
    }

    var sample = try loadDoctored(&ctx, out.items);
    defer sample.deinit(a);
    // `rw` only: in `ro` the read-only write refusal is the executable claim, so
    // the disjunction admits that cell and this rule must NOT fire there.
    try xfix.expectRefusedSaying(
        &ctx,
        "an accept cell with no oracle at all",
        "asserts nothing about the store it opened",
        xfix.runV2CorpusCells,
        .{ &ctx, &sample, "rw", tmp.dir, xfix.Dispatch.by_manifest },
    );
    var dir2 = try tmp.dir.makeOpenPath("ro", .{ .iterate = true });
    defer dir2.close();
    try xfix.runV2CorpusCells(&ctx, &sample, "ro", dir2, .by_manifest);
}

// Plan §5.3 item 5's second relaxation is a guard CONDITIONED on the opener,
// not a blanket exemption.
//
// The direct cell legitimately carries no post row — this engine's
// `StoreDirect` takes no lock, measured — but a `wal3` cell that carries none
// asserts nothing about a directory it just opened and locked.
test "xfixtures corpus: a wal3 cell with no post rows is refused" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(a);
    var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        // The d1 reject cell's post row goes, and its `x.lock` INPUT is added, so
        // the file-set rule is satisfied and the guard is the only rule left to
        // fire. Without that input the stray lock trips the file-set rule first
        // and this case would measure that instead (lesson h).
        if (std.mem.eql(u8, line, "post\treject-wal3-d1-barebase\tzig\trw\tx.lock\tcreated:0:" ++ xfix.EMPTY_SHA)) continue;
        try out.appendSlice(a, line);
        try out.append(a, '\n');
    }

    var sample = try loadDoctored(&ctx, out.items);
    defer sample.deinit(a);
    try xfix.expectRefusedSaying(
        &ctx,
        "a wal3 cell stripped of its post rows",
        "asserts nothing about the directory it just opened",
        xfix.runV2CorpusCells,
        .{ &ctx, &sample, "rw", tmp.dir, xfix.Dispatch.by_manifest },
    );
}

// `applies` and `expect` are two row types emitted from one catalogue, so they
// move together — and an engine has no catalogue, which makes their
// disagreement the only inconsistency an engine can detect.
test "xfixtures corpus: applies and expect must be the same set" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Each case names the rule its own drop must trip. A shared message would
    // let the two loops' mutants report one red between them, which is proof
    // for neither — measured, `applies_noexpect` reported the other loop's.
    const drops = [_]struct { line: []const u8, saying: []const u8 }{
        .{ .line = "applies\twal3-java-cleaned\tzig\trw", .saying = "has no `applies` row" },
        .{ .line = "expect\twal3-java-cleaned\tzig\trw\taccept\twal3\tx", .saying = "has no `expect` row" },
    };
    for (drops, 0..) |drop, i| {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(a);
        var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.eql(u8, line, drop.line)) continue;
            try out.appendSlice(a, line);
            try out.append(a, '\n');
        }
        try testing.expect(out.items.len < corpus_manifest_tsv.len);

        var sample = try loadDoctored(&ctx, out.items);
        defer sample.deinit(a);
        var name_buf: [32]u8 = undefined;
        var dir = try tmp.dir.makeOpenPath(try std.fmt.bufPrint(&name_buf, "applies-{d}", .{i}), .{ .iterate = true });
        defer dir.close();
        try xfix.expectRefusedSaying(
            &ctx,
            "applies and expect disagreeing",
            drop.saying,
            xfix.runV2CorpusCells,
            .{ &ctx, &sample, "rw", dir, xfix.Dispatch.by_manifest },
        );
    }
}

// ---------------------------------------------------------------------------
// the root itself
// ---------------------------------------------------------------------------

test "xfixtures corpus: the embed table, the manifest and the distributed blobs agree" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadCorpus(&ctx);
    defer sample.deinit(a);

    var from_manifest: std.ArrayListUnmanaged([]const u8) = .empty;
    defer from_manifest.deinit(a);
    for (sample.files.items) |f| try from_manifest.append(a, f.blob);

    var from_table: std.ArrayListUnmanaged([]const u8) = .empty;
    defer from_table.deinit(a);
    for (embedded_corpus.blobs) |b| try from_table.append(a, b.name);

    try xfix.checkBlobSets(&ctx, from_manifest.items, from_table.items, &distributed.gz);
}

// Nothing in the corpus root may be unexplained (C5 plan §4c).
//
// The corpus is `MANIFEST.tsv` plus one blob per `file` row, and NOTHING else —
// no golden tables, because the corpus carries neither and neither can be
// produced for it. A stray file is either a fixture the suite silently never
// runs or a leftover from a half-finished copy.
test "xfixtures corpus: the corpus root has nothing unexplained" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadCorpus(&ctx);
    defer sample.deinit(a);

    var want: std.ArrayListUnmanaged([]const u8) = .empty;
    defer want.deinit(a);
    try want.append(a, "MANIFEST.tsv");
    for (sample.files.items) |f| try want.append(a, f.blob);

    for (distributed.all) |name| {
        var known = false;
        for (want.items) |w| {
            if (std.mem.eql(u8, w, name)) known = true;
        }
        if (!known) {
            std.debug.print("[xfixtures] data-v2-corpus/{s} is explained by no manifest row\n", .{name});
            return error.XFixtures;
        }
    }
    for (want.items) |w| {
        var present = false;
        for (distributed.all) |name| {
            if (std.mem.eql(u8, w, name)) present = true;
        }
        if (!present) {
            std.debug.print("[xfixtures] data-v2-corpus/{s} is named but not distributed\n", .{w});
            return error.XFixtures;
        }
    }
}

// The copy is byte-identical to todo's sealed tree, checked in CI rather than
// in a review note.
//
// Three hand-copied roots that drift are how the static sample survives today
// only by luck. The preimage is `freeze_v2.dist_preimage`'s, transcribed: the
// domain line, the engine line, then one sorted `file` row per distributed
// member with its size, sha256 and MARK. This engine's distribution is
// `("root", "zig")` — the twelve files of the corpus root, plus the generated
// embed table beside it, which is why that table is hashed here as well.
test "xfixtures corpus: the corpus root matches todo's sealed tree" {
    const a = testing.allocator;

    const Row = struct { path: []const u8, bytes: []const u8, mark: []const u8 };
    var rows: std.ArrayListUnmanaged(Row) = .empty;
    defer rows.deinit(a);
    try rows.append(a, .{ .path = "MANIFEST.tsv", .bytes = corpus_manifest_tsv, .mark = "root" });
    for (embedded_corpus.blobs) |b| try rows.append(a, .{ .path = b.name, .bytes = b.gz, .mark = "root" });
    try rows.append(a, .{ .path = "embedded_v2_corpus.zig", .bytes = corpus_embed_table_src, .mark = "zig" });

    std.mem.sort(Row, rows.items, {}, struct {
        fn lt(_: void, x: Row, y: Row) bool {
            return std.mem.lessThan(u8, x.path, y.path);
        }
    }.lt);

    var pre: std.ArrayListUnmanaged(u8) = .empty;
    defer pre.deinit(a);
    try pre.appendSlice(a, "mapdb-xfixtures-dist\tv1\nengine\tzig\n");
    for (rows.items) |r| {
        const sha = xfix.sha256Hex(r.bytes);
        try pre.writer(a).print("file\t{s}\t{d}\t{s}\t{s}\n", .{ r.path, r.bytes.len, &sha, r.mark });
    }
    const seal = xfix.sha256Hex(pre.items);
    try testing.expectEqualStrings(DIST_SEAL, &seal);
}
