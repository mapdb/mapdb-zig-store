//! The schema-v2 **frozen corpus** against this engine — Stage C, slice
//! **C6z**.
//!
//! `src/xfixtures/data-v2-corpus/` is a byte-identical copy of the `root`-marked
//! files of `todo/store-cross/corpus-v2/` — eighty-nine files: `MANIFEST.tsv`
//! and one blob per `file` row, and nothing else (C5 plan §4c) — plus, beside
//! it, the `zig`-marked `embedded_v2_corpus.zig`, which is this engine's
//! generated embed table and part of its distribution. It is the `v2-oracle`
//! profile: it carries `applies`, `action`, `bytes` and `reopen` rows. The
//! static `data-v2/` sample stays `v2-core` and is untouched by C6;
//! `conformance_test` still owns it, through the same executor. The dual
//! reader (v1 sample + v2 sample + this corpus root) is what keeps the cutover
//! a data commit.
//!
//! # What this engine executes, and what it accounts for
//!
//! **The corpus addresses no `action` or `bytes` row to zig**, and that is a
//! property of the format rather than an oversight: `Cell.actions` and
//! `Cell.byte_assertions` exist on exactly one cell and are keyed
//! `("java", "rw")`. Revision 3 of the C5 plan claimed all three engines
//! execute them and both round-3 reviewers found the claim had an empty input
//! column for two engines. Manufacturing a port-addressed assertion in the
//! corpus to fix that would be fixture theatre.
//!
//! **`reopen` IS addressed to zig, and C5t is what changed that** (plan §3.12).
//! Every eligible reject arm now carries one, derived in `catalogue.py` from the
//! error family already pinned there. THIS ROOT — the full frozen corpus after
//! C6, with C8f f2/f3 sealing every reject arm's `family` row and the expanded
//! `REOPEN_FAMILIES` set (18 names; zig reopen 42, family 43) — so this engine
//! grades WHICH failure a reject cell produced on first open, and that the
//! refusal is STABLE on reopen. Until C5t the reject arm could only assert that
//! the open failed, and a store that refused Q8 because a bug made it refuse
//! everything passed. Pre-f2 inject bridges are gone: the sealed MANIFEST is
//! the only source of family rows.
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
//! what contract §10.1 pins for this engine. **C5t transports them.** The v2
//! `expect` row still has no family column; the derived `reopen` rows carry it
//! instead, and `assertFamily` grew the three families those rows name.
//!
//! C5z left a CONSTRAINT for that work — the D1 refusal happens inside
//! `WalSegmentSet.openWithIo`, before `wr.recover` runs, so its `Diag` is empty
//! and no `diag.reason` predicate can be written for it. It turned out to be the
//! DISCRIMINATOR: a refusal from the segment-set opener has no reason precisely
//! because recovery never ran, and every refusal recovery produces notes one
//! immediately before returning. `D1` and `DataCorruption` are exact complements
//! on that test, and `direct-magic` is separated from both by the opener, which
//! is why `assertFamily` takes one.
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
//! `disclosure: 7 confirmed, 0 refuted, 0 unmeasured`.
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
//! - `leaf_keybound` — `Consumption.consume`'s key-length bound, added by round
//!   2. Subsumed the same way: a `relName` long enough to overflow the 256-byte
//!   key buffer fails placement or the missing-file rules first. It is an
//!   invariant of the accountant rather than of the manifest, so it is disclosed
//!   with a mutant rather than deleted.
//!
//! **This paragraph was itself wrong for two commits**, and that is worth
//! leaving on the record: round 2 added the seventh entry to the runner and this
//! doc went on saying six and naming six. An inaccurate disclosure is a claim
//! like any other — the defect C5r's review filed twice and this whole mechanism
//! exists to prevent — and the way it recurred here is the way it always does:
//! the runner and its description are two places, and only one of them was
//! edited. The count is `grep -c '^case_ ' disclose_z.sh`; do not trust this
//! sentence over that command.
//!
//! **One check is killed only by a WEAKER signal**, and the runner names it:
//! `bytesrange`, whose deletion makes the slice go out of bounds, so the red is
//! the language's and not the rule's. No conforming manifest reaches that check
//! with the slice still in range. `grep -c '^# WEAKER SIGNAL' mutants_z.sh` is
//! the count and the `^#` anchor is load-bearing — unanchored it counts the
//! runner's own header, which is the mistake C5r's round 3 caught.
//!
//! `assertBytesRows` renders at most 32 asserted bytes, refusing a longer row
//! loudly rather than truncating it — a bound, stated at the site, not a silent
//! cap.
//!
//! # What round 1 of review found, and why this section is shorter than it was
//!
//! The brief asked the reviewer one question this list could not answer about
//! itself: **is it COMPLETE?** The measured answer was no — seven production
//! checks were deletable with the whole fixture suite green and appeared on
//! neither the campaign nor this list. That is C5r round 1's finding (an
//! undisclosed survivor) at the level of the mechanism built to prevent it: a
//! disclosure list can be honest about every entry it contains and still be
//! short. **Measuring the entries is not the same as measuring the set.**
//!
//! Three of them sat under `runAction`'s "every refusal below is its own SITE
//! with its own input" — re-checks of the argument GRAMMAR the parser had
//! already refused, which made that sentence false two screens from where it was
//! written. The repair was to make the sentence true: the grammar has one
//! authority and `runAction` now checks only what the parser deliberately does
//! not.
//!
//! Two more were guards the parser already supplies — a third cardinality
//! comparison in `runV2CorpusCells` (the two loops above it force the sets equal
//! in both directions, so it could never fire, and the paragraph that used to be
//! here presented it as the LIVE half of an interlock) and a duplicate-fixture
//! check in `runCells`. Both are gone: C2j's rule is that a check no input can
//! reach is deleted rather than decorated, because leaving it in claims a guard
//! that is not there.
//!
//! Two got INPUTS instead, because they are real. `refusalOf`'s "the direct
//! opener has no read-only mode" is REACHABLE from a doctored manifest, and
//! without it an `ro` cell addressed to the direct opener would be opened
//! read-write and graded as though its mode meant something. `Consumption.owe`'s
//! duplicate-key guard is an invariant of the accountant rather than of the
//! manifest, so it keeps the only input it can have — a direct one, stated as
//! such.
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

/// `freeze_v2.CORPUS_DIST_SEALS["zig"]`.
///
/// The per-engine seal over only the marks this engine carries — `root` and
/// `zig`, per `freeze_v2.DIST_MARKS`. No engine can recompute `CORPUS_SEAL`,
/// because the `todo`-marked post-state blob is not distributed and its hash is
/// in that preimage. Pinning the corpus digest in this repository (C6) is the
/// trust upgrade over C5t's disposable staged worktree: four repositories must
/// move together. Regenerate with
/// `python3 todo/store-cross/freeze_v2.py --corpus --dist-seals`.
const DIST_SEAL = "cbafad196a6a9480271ddb525e2208860ed7fd7016bc6658ac2e98ec63201ec9";

fn loadCorpus(ctx: *xfix.Ctx) !xfix.SampleV2 {
    return xfix.loadSampleV2(ctx, corpus_manifest_tsv, &embedded_corpus.blobs);
}

fn loadDoctored(ctx: *xfix.Ctx, text: []const u8) !xfix.SampleV2 {
    return xfix.loadSampleV2(ctx, text, &embedded_corpus.blobs);
}

// ---------------------------------------------------------------------------
// the corpus itself
// ---------------------------------------------------------------------------

// C8f f3: the sealed MANIFEST carries the full family bijection. Pure load is
// the green path — first-open family grade + reopen stability, no inject bridge.
test "xfixtures corpus: the zig cells conform in both modes" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try loadCorpus(&ctx);
    defer sample.deinit(a);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    for (xfix.MODES) |mode| try xfix.runV2CorpusCells(&ctx, &sample, mode, tmp.dir, .by_manifest);
}

// Fail-closed raw-manifest doctor: a missing family key still reds (plan §4.2).
test "xfixtures corpus: a MANIFEST missing a family row is refused" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(a);
    var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        // Strip every family row so the first reject arm fails closed.
        if (std.mem.startsWith(u8, line, "family\t")) continue;
        try out.appendSlice(a, line);
        try out.append(a, '\n');
    }
    try testing.expect(out.items.len < corpus_manifest_tsv.len);
    var sample = try loadDoctored(&ctx, out.items);
    defer sample.deinit(a);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try xfix.expectRefusedSaying(
        &ctx,
        "a reject arm with no family row in the doctored MANIFEST",
        "reject arm has no family row",
        xfix.runV2CorpusCells,
        .{ &ctx, &sample, "rw", tmp.dir, xfix.Dispatch.by_manifest },
    );
}

// §3.11's mutant, as a SUBSTITUTION rather than a deletion.
//
// Routing the `direct` row through the WAL opener must turn the suite red. A
// deletion that merely restores an `opener == wal3` refusal proves only that
// the parser branches on the column.
test "xfixtures corpus: a direct cell sent to the wal opener goes red" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    // Sealed MANIFEST already carries every reject arm's family row (C8f f2/f3);
    // pure load so the red names the file-set rule, not a missing family key.
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
// C8f f1: first-open is graded by the `family` row; reopen is stability only.
test "xfixtures corpus: the reopen row is graded" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // H99 is outside the catalogue vocabulary — every real family now has a
    // predicate (C8f f0), so the no-predicate red needs a token none of them is.
    const cases = [_]struct { what: []const u8, family: []const u8, ok: bool }{
        .{ .what = "the family the reopen really produces", .family = "StoreFull", .ok = true },
        .{ .what = "a family the reopen does not produce", .family = "S2", .ok = false },
        .{ .what = "a family this engine has no predicate for", .family = "H99", .ok = false },
    };
    // The row is REPLACED, not appended. C5t made the positive case real — the
    // checked-in corpus now carries this exact line, derived from the family
    // pinned in `catalogue.py` — and a second copy is a duplicate the parser
    // refuses, which would grade the two negatives for the wrong reason.
    // First-open `family` stays correct (StoreFull) so only the reopen grade
    // moves under the doctored name.
    const pfx = "reopen\tdiv-wal3-lsn-exhausted\tzig\trw\t";
    for (cases, 0..) |c, i| {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(a);
        var dropped = false;
        var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, pfx)) {
                dropped = true;
                continue;
            }
            try out.appendSlice(a, line);
            try out.append(a, '\n');
        }
        try testing.expect(dropped);
        try out.writer(a).print("{s}{s}\n", .{ pfx, c.family });

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

// On a REJECT cell the family is graded on the cell's OWN refusal via the
// `family` row (C8f f1), not via the reopen.
//
// codex round 1 finding 2: C5t's first draft graded the family only on the
// reopen, which is a WRITABLE open whatever the cell's mode was. Every `mode=ro`
// row was therefore graded by a retry in the other mode, and a store that
// refuses read-only for one reason and writable for another passed.
//
// THE CORPUS ALONE CANNOT SHOW THE FIX. Both opens of a conforming store refuse
// the same way, so deleting the first grading leaves the reopen's — same family,
// same predicate, gate green. What separates them is WHERE the red comes from:
// this doctored family reds at `family[..]` if the cell's own refusal was graded
// and at `reopen[..]` if only the second open was. Asserting the prefix is what
// makes the deletion visible.
test "xfixtures corpus: a reject arm's own refusal is graded" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Doctor the FIRST-OPEN family row on the sealed MANIFEST (not reopen).
    // Reopen stays D1 so a missing first-open grade would red at reopen[H99]
    // only if we had put H99 there — asserting the family[H99] prefix proves
    // assertFirstOpenFamily ran.
    const pfx = "family\treject-wal3-d1-barebase\tzig\trw\t";
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(a);
    var dropped = false;
    var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, pfx)) {
            dropped = true;
            continue;
        }
        try out.appendSlice(a, line);
        try out.append(a, '\n');
    }
    try testing.expect(dropped);
    try out.writer(a).print("{s}H99\n", .{pfx});

    var sample = try loadDoctored(&ctx, out.items);
    defer sample.deinit(a);
    var dir = try tmp.dir.makeOpenPath("first-refusal", .{ .iterate = true });
    defer dir.close();
    try xfix.expectRefusedSaying(
        &ctx,
        "a reject arm whose own refusal is graded by nothing",
        "family[H99]: error family H99 has no predicate in this engine",
        xfix.runV2CorpusCells,
        .{ &ctx, &sample, "rw", dir, xfix.Dispatch.by_manifest },
    );
}

// The `family` row itself is graded on first open — wrong name / unknown name /
// correct name. Parallel to the reopen battery; first-open is the family row.
test "xfixtures corpus: the family row is graded" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const cases = [_]struct { what: []const u8, family: []const u8, ok: bool }{
        .{ .what = "the family the first open really produces", .family = "StoreFull", .ok = true },
        .{ .what = "a family the first open does not produce", .family = "S2", .ok = false },
        .{ .what = "a family this engine has no predicate for", .family = "H99", .ok = false },
    };
    const pfx = "family\tdiv-wal3-lsn-exhausted\tzig\trw\t";
    for (cases, 0..) |c, i| {
        // Replace the sealed family name for this arm; other family rows stay.
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(a);
        var dropped = false;
        var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, pfx)) {
                dropped = true;
                continue;
            }
            try out.appendSlice(a, line);
            try out.append(a, '\n');
        }
        try testing.expect(dropped);
        try out.writer(a).print("{s}{s}\n", .{ pfx, c.family });

        var sample = try loadDoctored(&ctx, out.items);
        defer sample.deinit(a);
        var name_buf: [32]u8 = undefined;
        var dir = try tmp.dir.makeOpenPath(try std.fmt.bufPrint(&name_buf, "family-{d}", .{i}), .{ .iterate = true });
        defer dir.close();
        if (c.ok) {
            try xfix.runV2CorpusCells(&ctx, &sample, "rw", dir, .by_manifest);
        } else {
            try xfix.expectRefused(&ctx, c.what, xfix.runV2CorpusCells, .{ &ctx, &sample, "rw", dir, xfix.Dispatch.by_manifest });
        }
    }
}

// The `direct` opener has no read-only mode, and a manifest CAN ask for one.
//
// The C5z review found this refusal reachable and inputless — the same shape as
// C5r's round-1 blocking finding. `reject-wal3-segment-at-direct` has a `rw`
// cell and no `ro` one, but nothing in the grammar stops a manifest from
// addressing an `ro` cell through the `direct` opener, and with the refusal gone
// that cell would be opened READ-WRITE and graded as though its mode meant
// something — which is the C3z "selecting a flag is not coverage" defect, one
// opener over.
test "xfixtures corpus: a direct cell addressed to the ro mode is refused" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(a);
    try out.appendSlice(a, corpus_manifest_tsv);
    try out.appendSlice(a, "applies\treject-wal3-segment-at-direct\tzig\tro\n");
    try out.appendSlice(a, "expect\treject-wal3-segment-at-direct\tzig\tro\treject\tdirect\tx\n");
    // New reject arm (direct/ro) needs a family row so the red names the mode
    // refusal, not a missing first-open key.
    try out.appendSlice(a, "family\treject-wal3-segment-at-direct\tzig\tro\tdirect-magic\n");

    var sample = try loadDoctored(&ctx, out.items);
    defer sample.deinit(a);
    try xfix.expectRefusedSaying(
        &ctx,
        "a direct cell addressed to the ro mode",
        "the direct opener has no read-only mode here",
        xfix.runV2CorpusCells,
        .{ &ctx, &sample, "ro", tmp.dir, xfix.Dispatch.by_manifest },
    );
}

// Five corpus PRECONDITIONS and bounds, each with the input round 2 of review
// measured it did not have.
//
// Round 1 found the disclosure list short by seven and the repair enumerated the
// EXECUTOR; round 2 found eleven more, because the slice's touched surface is
// also the parser, the corpus preconditions and the bounds. Measuring the
// entries is not the same as measuring the set, and measuring the executor is
// not the same as measuring the slice. These are the reachable half of round 2's
// finding 3, each routed through the production path.
test "xfixtures corpus: the preconditions and bounds each refuse" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const Case = struct {
        what: []const u8,
        saying: []const u8,
        mode: []const u8,
        drop: []const u8 = "",
        drop2: []const u8 = "",
        drop_contains: []const u8 = "",
        drop_ro: bool = false,
        // Every zig/ro cell whose verdict is ACCEPT — found by reading the
        // manifest, not by naming one. Naming one is what the preflight root
        // allowed and the frozen corpus does not: see the case that uses this.
        drop_ro_accept: bool = false,
        add: []const u8 = "",
    };
    const cases = [_]Case{
        // An `accept` cell through the DIRECT opener. `V2_OPENERS` and `VERDICTS`
        // are vocabulary-checked independently, so nothing in the grammar stops
        // this — and without the refusal the cell is opened through the WAL
        // opener and fully graded, which is dispatch-by-manifest ignored for the
        // accept arm: C3z's "selecting a flag is not coverage", one verdict over.
        .{
            .what = "an accept cell through the direct opener",
            .saying = "an accept cell through a non-wal3 opener",
            .mode = "ro",
            .add = "applies\treject-wal3-segment-at-direct\tzig\tro\nexpect\treject-wal3-segment-at-direct\tzig\tro\taccept\tdirect\tx\n",
        },
        // A fixture whose only rows are `applies`+`expect`: the parser requires
        // that SOME row refer to each fixture and that the manifest have file
        // rows, not that every fixture have one.
        .{
            .what = "a fixture with no file rows",
            .saying = "fixture has no file rows",
            .mode = "ro",
            .add = "fixture\tghost\treject\tjava\tc\napplies\tghost\tzig\tro\nexpect\tghost\tzig\tro\treject\twal3\tx\n",
        },
        // An accept cell over an image this engine refuses.
        .{
            .what = "an accept cell whose store refuses to open",
            .saying = "accept cell failed to open",
            .mode = "ro",
            .drop = "expect\treject-wal3-d1-barebase\tzig\tro\treject\twal3\tx",
            .add = "expect\treject-wal3-d1-barebase\tzig\tro\taccept\twal3\tx\n",
        },
        // `applies` rows in one mode only, run in the other. EVERY zig/ro row
        // goes, not one: dropping a single `applies` row leaves its `expect`
        // orphaned and the applies/expect comparison fires first, so the case
        // would measure that instead (lesson h, caught by running it).
        .{
            .what = "a mode the corpus declares no applies rows for",
            .saying = "declares no zig applies rows for mode",
            .mode = "ro",
            .drop_ro = true,
        },
        // Every zig/ro ACCEPT cell gone, leaving only reject cells: the
        // read-only write probe then has no input at all, which is the thing
        // this precondition exists to refuse. Its two NEIGHBOURS
        // (`leaf_rocount`, `leaf_roprobed`) are on the measured disclosure list
        // and it was on neither.
        .{
            .what = "a corpus with no ro accept cell",
            .saying = "has no zig ro accept cell",
            .mode = "ro",
            // EVERY row of EVERY such cell, and both halves of that matter.
            //
            // Every ROW of a cell, not two of its three: leaving its `post` row
            // behind makes the suite-wide addressing rule fire first, and the
            // case measures that instead (lesson h, caught by running it — for
            // the third time in this slice, which is why every one of these
            // cases asserts the MESSAGE and not merely "it refused").
            //
            // Every such CELL, found by reading the manifest. This case named
            // `wal3-java-cleaned` outright, which was the preflight root's only
            // zig/ro accept cell — so against the thirty-fixture corpus it
            // dropped one of several, left the precondition satisfied, and the
            // probe got an acceptance where it wanted a refusal. **The staged
            // run found it, and only the staged run could have**: a doctoring
            // written against a four-fixture root under-doctors a thirty-fixture
            // one, and the case passed for four slices meaning something
            // narrower than it said.
            .drop_ro_accept = true,
        },
        // A `bytes` row longer than this reader renders. The bound is REACHABLE —
        // `hexBytes` permits any whole number of bytes — and the module doc
        // describes it, so a described mechanism with no red is the C2j B-finding
        // shape this slice corrected twice in comments and left here in code.
        .{
            .what = "a bytes row longer than this reader renders",
            .saying = "assertion longer than this reader renders",
            .mode = "rw",
            .add = "bytes\twal3-java-cleaned\tzig\trw\tx.wal.0000000000000004\t0\t" ++ ("ab" ** 40) ++ "\n",
        },
    };

    for (cases, 0..) |c, i| {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(a);
        // Which fixtures have a zig/ro ACCEPT cell — read off the manifest, so
        // the doctoring scales with the corpus instead of naming what one root
        // happened to hold.
        var ro_accept: std.ArrayListUnmanaged([]const u8) = .empty;
        defer ro_accept.deinit(a);
        if (c.drop_ro_accept) {
            var scan = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
            while (scan.next()) |line| {
                if (!std.mem.startsWith(u8, line, "expect\t")) continue;
                if (std.mem.indexOf(u8, line, "\tzig\tro\taccept\t") == null) continue;
                var f = std.mem.splitScalar(u8, line, '\t');
                _ = f.next();
                if (f.next()) |fix| try ro_accept.append(a, fix);
            }
            try testing.expect(ro_accept.items.len > 0);
        }
        var it = std.mem.splitScalar(u8, corpus_manifest_tsv, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            if (c.drop.len != 0 and std.mem.eql(u8, line, c.drop)) continue;
            if (c.drop2.len != 0 and std.mem.eql(u8, line, c.drop2)) continue;
            if (c.drop_contains.len != 0 and std.mem.indexOf(u8, line, c.drop_contains) != null) continue;
            if (c.drop_ro and (std.mem.startsWith(u8, line, "applies\t") or std.mem.startsWith(u8, line, "expect\t")) and
                std.mem.indexOf(u8, line, "\tzig\tro") != null) continue;
            if (c.drop_ro_accept) {
                var dropped = false;
                for (ro_accept.items) |fix| {
                    // `<fixture>\tzig\tro` catches `applies`, `expect`, `post`,
                    // `reopen`, `family`, `bytes` and `action` alike — every row
                    // type that addresses a cell puts those three fields adjacent.
                    var key_buf: [128]u8 = undefined;
                    const key = try std.fmt.bufPrint(&key_buf, "{s}\tzig\tro", .{fix});
                    if (std.mem.indexOf(u8, line, key) != null) dropped = true;
                }
                if (dropped) continue;
            }
            try out.appendSlice(a, line);
            try out.append(a, '\n');
        }
        if (c.drop.len != 0 or c.drop_ro or c.drop_contains.len != 0 or c.drop_ro_accept)
            try testing.expect(out.items.len < corpus_manifest_tsv.len);
        try out.appendSlice(a, c.add);

        var sample = try loadDoctored(&ctx, out.items);
        defer sample.deinit(a);
        var name_buf: [32]u8 = undefined;
        var dir = try tmp.dir.makeOpenPath(try std.fmt.bufPrint(&name_buf, "pre-{d}", .{i}), .{ .iterate = true });
        defer dir.close();
        try xfix.expectRefusedSaying(&ctx, c.what, c.saying, xfix.runV2CorpusCells, .{ &ctx, &sample, c.mode, dir, xfix.Dispatch.by_manifest });
    }
    try testing.expectEqual(@as(usize, 6), cases.len);
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
    // Sealed family rows cover the real reject arms so we reach the doctored
    // accept-turned-reject cell; that cell itself has no family row and fails
    // at "store opened" before the first-open family lookup.

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

    // All reasons SPELLED OUT (lesson j) — pins, not store constants.
    const s2_real = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "section LSN does not follow the previous one" } };
    const s2_wrong_variant = xfix.Refusal{ .err = error.StoreFull, .diag = .{ .reason = "section LSN does not follow the previous one" } };
    const s2_wrong_reason = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "segment does not begin where its predecessor ended: sections between them are gone" } };
    const full = xfix.Refusal{ .err = error.StoreFull, .diag = .{} };

    const direct_magic = xfix.Refusal{ .err = error.DataCorruption, .direct = .{ .reason = "not a MapDB StoreDirect file (bad magic)" } };
    const direct_short = xfix.Refusal{ .err = error.DataCorruption, .direct = .{ .reason = "store file smaller than the header page" } };
    const d1_base = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "regular file at the WAL base path (the v3 opener takes a base, not a log file): no migration to v3 — open it with the release that wrote it and copy the data across, or move it aside" } };
    const d1_ckpt = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "v1 checkpoint temp present at <base>.ckpt, possibly the only recoverable copy after a v1 crash: no migration to v3 — open it with the release that wrote it and copy the data across, or move it aside" } };
    const n6 = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "v1 single-file WAL present at <base>.wal: no migration to v3 — open it with the release that wrote it and copy the data across, or move it aside" } };
    // Unrefined corruption (entry-level) and undiagnosed recovery exits.
    const corrupt = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "entry references the reserved recid 0" } };
    const undiagnosed = xfix.Refusal{ .err = error.DataCorruption, .diag = .{} };

    // C8f f0 representative samples for the thirteen L15 families.
    const h5 = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "unsupported WAL format version" } };
    const h6 = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "unknown segment flags" } };
    const h7 = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "header sequence does not match its name" } };
    const h9 = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "header firstLsn is not a valid LSN" } };
    const k4 = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "clean mark authorizes removing its own segment" } };
    const s8 = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "clean mark attests a non-positive cleanedThroughSeq" } };
    const s9 = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "section LSNs must be consecutive" } };
    const s4 = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "section body CRC mismatch in a non-final segment" } };
    const r4_floor = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "the retained log does not begin where the mark attests: sections below it are gone" } };
    const r4_chain = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "segment does not begin where its predecessor ended: sections between them are gone" } };
    const r4_self = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "segment's first section is not the LSN its header states: its leading sections are gone" } };
    const r6 = xfix.Refusal{ .err = error.DataCorruption, .diag = .{ .reason = "replay skipped append(s) whose base image is absent and which no later entry superseded" } };

    // Column order for accepts strings below.
    const Sample = struct { name: []const u8, opener: []const u8, r: xfix.Refusal };
    const samples = [_]Sample{
        .{ .name = "direct-magic", .opener = "direct", .r = direct_magic }, // 0
        .{ .name = "direct-short", .opener = "direct", .r = direct_short }, // 1
        .{ .name = "d1-base", .opener = "wal3", .r = d1_base }, // 2
        .{ .name = "d1-ckpt", .opener = "wal3", .r = d1_ckpt }, // 3
        .{ .name = "n6", .opener = "wal3", .r = n6 }, // 4
        .{ .name = "corrupt", .opener = "wal3", .r = corrupt }, // 5
        .{ .name = "undiagnosed", .opener = "wal3", .r = undiagnosed }, // 6
        .{ .name = "s2", .opener = "wal3", .r = s2_real }, // 7
        .{ .name = "full", .opener = "wal3", .r = full }, // 8
        .{ .name = "h5", .opener = "wal3", .r = h5 }, // 9
        .{ .name = "h6", .opener = "wal3", .r = h6 }, // 10
        .{ .name = "h7", .opener = "wal3", .r = h7 }, // 11
        .{ .name = "h9", .opener = "wal3", .r = h9 }, // 12
        .{ .name = "k4", .opener = "wal3", .r = k4 }, // 13
        .{ .name = "s8", .opener = "wal3", .r = s8 }, // 14
        .{ .name = "s9", .opener = "wal3", .r = s9 }, // 15
        .{ .name = "s4", .opener = "wal3", .r = s4 }, // 16
        .{ .name = "r4-floor", .opener = "wal3", .r = r4_floor }, // 17
        .{ .name = "r4-chain", .opener = "wal3", .r = r4_chain }, // 18
        .{ .name = "r4-self", .opener = "wal3", .r = r4_self }, // 19
        .{ .name = "r6", .opener = "wal3", .r = r6 }, // 20
    };
    // 21 columns. DataCorruption accepts corrupt + undiagnosed only among the
    // refined-unclaimed samples; N6 is now refined (C8f f0).
    const Row = struct { family: []const u8, accepts: []const u8 };
    const rows = [_]Row{
        .{ .family = "direct-magic", .accepts = "ynnnnnnnnnnnnnnnnnnnn" },
        .{ .family = "D1", .accepts = "nnyynnnnnnnnnnnnnnnnn" },
        .{ .family = "N6", .accepts = "nnnnynnnnnnnnnnnnnnnn" },
        // DataCorruption: corrupt(5)+undiagnosed(6) only; N6(4) and S2(7) excluded.
        .{ .family = "DataCorruption", .accepts = "nnnnnyynnnnnnnnnnnnnn" },
        .{ .family = "S2", .accepts = "nnnnnnnynnnnnnnnnnnnn" },
        .{ .family = "StoreFull", .accepts = "nnnnnnnnynnnnnnnnnnnn" },
        .{ .family = "H5", .accepts = "nnnnnnnnnynnnnnnnnnnn" },
        .{ .family = "H6", .accepts = "nnnnnnnnnnynnnnnnnnnn" },
        .{ .family = "H7", .accepts = "nnnnnnnnnnnynnnnnnnnn" },
        .{ .family = "H9", .accepts = "nnnnnnnnnnnnynnnnnnnn" },
        .{ .family = "K4", .accepts = "nnnnnnnnnnnnnynnnnnnn" },
        .{ .family = "S8/K-bounds", .accepts = "nnnnnnnnnnnnnnynnnnnn" },
        .{ .family = "S9", .accepts = "nnnnnnnnnnnnnnnynnnnn" },
        .{ .family = "S4/mid-log", .accepts = "nnnnnnnnnnnnnnnnynnnn" },
        .{ .family = "R4-floor", .accepts = "nnnnnnnnnnnnnnnnnynnn" },
        .{ .family = "R4-chain", .accepts = "nnnnnnnnnnnnnnnnnnynn" },
        .{ .family = "R4-self", .accepts = "nnnnnnnnnnnnnnnnnnnyn" },
        .{ .family = "R6-audit", .accepts = "nnnnnnnnnnnnnnnnnnnny" },
    };
    for (rows) |row| {
        try testing.expectEqual(samples.len, row.accepts.len);
        for (samples, row.accepts) |s, want| {
            var buf: [128]u8 = undefined;
            const what = try std.fmt.bufPrint(&buf, "{s} graded as {s}", .{ s.name, row.family });
            if (want == 'y')
                try xfix.assertFamily(&ctx, what, s.opener, row.family, s.r)
            else
                try xfix.expectRefused(&ctx, what, xfix.assertFamily, .{ &ctx, "w", s.opener, row.family, s.r });
        }
    }

    // Each half of the collapsed S2 conjunction, alone.
    try xfix.expectRefused(&ctx, "an operational failure wearing the S2 reason", xfix.assertFamily, .{ &ctx, "w", "wal3", "S2", s2_wrong_variant });
    try xfix.expectRefused(&ctx, "a corruption verdict carrying a different reason", xfix.assertFamily, .{ &ctx, "w", "wal3", "S2", s2_wrong_reason });
    try xfix.expectRefused(&ctx, "a family with no predicate", xfix.assertFamily, .{ &ctx, "w", "wal3", "H99", s2_real });

    // S8 / S4 extra disjuncts.
    try xfix.assertFamily(&ctx, "S8 logStart", "wal3", "S8/K-bounds", .{ .err = error.DataCorruption, .diag = .{ .reason = "clean mark attests a logStartLsn that is not at or below its own LSN" } });
    try xfix.assertFamily(&ctx, "S4 mid-log active", "wal3", "S4/mid-log", .{ .err = error.DataCorruption, .diag = .{ .reason = "mid-log corruption: section body CRC mismatch but valid sections follow" } });
    try xfix.expectRefused(&ctx, "K4 as S8", xfix.assertFamily, .{ &ctx, "w", "wal3", "S8/K-bounds", k4 });
}

// ---------------------------------------------------------------------------
// consumption, in both halves
// ---------------------------------------------------------------------------

// The per-cell half: an oracle row addressed to a cell that RUNS, which no arm
// can execute.
//
// An `action` row on a REJECT cell is the instance, and the row TYPE matters:
// only `runAccept` consumes an action, and a reject cell never reaches it. A
// `bytes` row would not do — `assertBytesRows` runs for reject cells too,
// against the capture, so a bytes row there is consumable. The C5z review caught
// this comment naming the wrong row type for the right test.
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

    // One case per addressed ROW TYPE. `family` is C8f f1's addition; `post` is
    // the one C5j's round 2 found droppable in silence on both sides of the fence.
    const rows = [_][]const u8{
        "action\treject-wal3-segment-at-direct\tzig\tro\tcommit_one_record\top=put,payload_id=1,payload_len=2,recid_label=Q,serializer=raw\n",
        "bytes\treject-wal3-segment-at-direct\tzig\tro\tx\t0\taa\n",
        "reopen\treject-wal3-segment-at-direct\tzig\tro\tS2\n",
        "family\treject-wal3-segment-at-direct\tzig\tro\tS2\n",
        "post\treject-wal3-segment-at-direct\tzig\tro\tx\tunchanged\n",
    };
    for (rows, 0..) |row, i| {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(a);
        try out.appendSlice(a, corpus_manifest_tsv);
        // Sealed zig/ro family rows let the suite reach the orphan check rather
        // than failing closed on a missing first-open key.
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
    // Two rows under one key would make the books balance while a handler graded
    // the wrong object. The parser dedups every addressed row type on exactly the
    // fields these keys render, so no production caller can collide — the C5z
    // review measured the guard as unkillable from the suite. It is kept because
    // it is an invariant of the ACCOUNTANT rather than of the manifest, and it is
    // given the only input it can have: a direct one, stated as such.
    try xfix.expectRefused(&ctx, "two rows under one key", xfix.Consumption.owe, .{ &owed, &ctx, "post {s}", .{row.rel}, &other });
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

    // The MUTATION-CLAIM arm, which no cell in this root exercises: the staged
    // corpus's torn-tail fixtures carry a `post ... truncated` row and nothing
    // else, and until the staged run they were graded by a guard that refused
    // them. The same stripped manifest with the universal lock row relabelled
    // `modified` — the guard must let the cell through, and the red must then
    // come from the POST check, which refuses `modified` on a file that was
    // never an input. Asserting WHICH red fires is the whole case: delete the
    // arm and the guard reds first with "asserts nothing".
    const lock = "post\twal3-java-cleaned\tzig\trw\tx.lock\tcreated:";
    var out2: std.ArrayListUnmanaged(u8) = .empty;
    defer out2.deinit(a);
    var relabelled = false;
    var it2 = std.mem.splitScalar(u8, out.items, '\n');
    while (it2.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, lock)) {
            relabelled = true;
            try out2.writer(a).print("post\twal3-java-cleaned\tzig\trw\tx.lock\tmodified:{s}\n", .{line[lock.len..]});
            continue;
        }
        try out2.appendSlice(a, line);
        try out2.append(a, '\n');
    }
    try testing.expect(relabelled);

    var sample2 = try loadDoctored(&ctx, out2.items);
    defer sample2.deinit(a);
    var dir3 = try tmp.dir.makeOpenPath("mutclaim", .{ .iterate = true });
    defer dir3.close();
    try xfix.expectRefusedSaying(
        &ctx,
        "an accept cell whose only oracle is a mutation claim",
        "which was never an input — only `created` may name a",
        xfix.runV2CorpusCells,
        .{ &ctx, &sample2, "rw", dir3, xfix.Dispatch.by_manifest },
    );
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
        // The d1 reject cell's only post row goes, so the cell has none. What
        // makes the GUARD fire rather than the file-set rule is the ORDER: the
        // guard runs before `assertPostState` (plan §5.3 item 5's amendment).
        // The first draft of this comment claimed an `x.lock` INPUT was added —
        // it is not, and could not be: `x.lock` is a `post created` row, never a
        // `file` row. The C5z review caught the comment describing a mechanism
        // the code does not have.
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
// `("root", "zig")` — the eighty-nine files of the frozen corpus root, plus
// the generated embed table beside it, which is why that table is hashed here
// as well.
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
