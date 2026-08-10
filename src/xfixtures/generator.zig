//! Cross-port conformance fixture GENERATOR — the two live modes.
//!
//! ```
//! zig build fixtures -- --golden <dir>              # one port-authored v3 namespace
//! zig build fixtures -- --wal3 <dir> [--force] [--commit <hash>]   # the C2z accept bundle
//! ```
//!
//! These fixtures pin the CURRENT state of an UNSTABLE on-disk format for
//! divergence detection between the java/rust/zig store engines. Cross-engine
//! openability is an implementation fact, not a supported feature; any format
//! change regenerates the fixtures as part of that change.
//!
//! **What used to be here.** Stage 1's `D` workload and Stage 2's `W` WAL
//! workloads wrote the schema-v1 tree (`direct-v1-zig.db`, `wal-v1-zig-*.wal`,
//! `fragment.tsv`) with a self-check suite around them: churn-recid
//! contiguity, a local index-slot decoder for the E→G extent-reuse assertion,
//! WAL section-tag scans, and two-run determinism. Contract §9 retired that
//! tree at C7z and `10c3933` deleted its entry point (`mainStageC`) — and with
//! it the `_ = &mainStageC` anti-rot anchor, so ~450 lines stopped being
//! REFERENCED and, this being zig, stopped being semantically analysed at all.
//! r1 finding 6 measured the result. They are gone rather than parked: the
//! schema-v1 tree they wrote is gone too, so there is nothing left for them to
//! be correct about, and this commit's parent still has them if a v1 image
//! ever has to be reproduced.

const std = @import("std");
const Allocator = std.mem.Allocator;
const mapdb = @import("mapdb_zig_store");
const DbError = mapdb.DbError;
const DataInput2 = mapdb.DataInput2;
const DataOutput2 = mapdb.DataOutput2;
/// Stage C slice C2z: the WAL v3 accept-bundle generator (`--wal3 <dir>`).
const wal3 = mapdb.xfixtures_wal3;

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

// ---------------------------------------------------------------- utilities

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.process.fatal(fmt, args);
}

/// `--golden <dir>`: write ONE port-authored WAL v3 namespace and stop.
///
/// Not the Stage C accept-bundle generator — that is `--wal3`, and the two
/// share nothing but this entry point. This is C0b's single deliverable from
/// plan C-D2 / fable finding 7: the byte-pinned reader sample is Java-written,
/// so without a port-written bundle beside it the first time any engine reads
/// port-authored GROUPING is C5's full staged run. D6 explicitly permits
/// writers to group entries differently, so that is a real reader bug class
/// surfacing at the pipeline's most expensive point instead of its cheapest.
///
/// The workload mirrors `Wal3GoldenWriter.workload` in mapdb-java-store — same
/// operations, same payload ids, same lengths, same 4096-byte segment size — so
/// a diff between the two bundles is a diff in ENGINE behaviour and nothing
/// else. Their bytes are NOT expected to match.
fn mainGolden(alloc: Allocator, out_dir: []const u8) !void {
    const BASE: u64 = 141; // zig tail base (contract §5)

    // REFUSE a non-empty target before touching anything. The C0b review found
    // this mode would happily open an EXISTING namespace in place and append,
    // update and delete records in it — the same class of damage the schema-v1
    // staleness refusal existed to prevent, reintroduced by a mode that ran
    // before it. There is deliberately no `--force`: this writes one fixture,
    // so "point it somewhere fresh" costs nothing and removes the failure mode
    // rather than gating it behind a flag someone will pass reflexively.
    std.fs.cwd().makePath(out_dir) catch |e|
        fatal("cannot create output dir `{s}`: {s}", .{ out_dir, @errorName(e) });
    {
        var dir = std.fs.cwd().openDir(out_dir, .{ .iterate = true }) catch |e|
            fatal("cannot open output dir `{s}`: {s}", .{ out_dir, @errorName(e) });
        defer dir.close();
        var it = dir.iterate();
        if (try it.next()) |first|
            fatal("--golden needs an EMPTY directory; `{s}` already contains `{s}`. " ++
                "Opening a populated namespace would mutate it in place.", .{ out_dir, first.name });
    }

    const base_path = try std.fs.path.join(alloc, &.{ out_dir, "x" });
    defer alloc.free(base_path);

    var s = mapdb.StoreWAL.openSegmentBytes(alloc, base_path, 4096) catch |e|
        fatal("cannot open `{s}`: {s}", .{ base_path, @errorName(e) });
    // On the error path both teardown steps must run, exactly once each: the
    // explicit `close()` at the end is part of the fixture (it seals the
    // segment), and `close()` is a documented no-op on an already-closed store,
    // so a failing explicit close cannot be retried into a double free here.
    errdefer {
        s.close() catch {};
        s.deinit();
    }

    const p1 = try payloadAlloc(alloc, BASE, 200);
    defer alloc.free(p1);
    const p2 = try payloadAlloc(alloc, BASE + 1, 900);
    defer alloc.free(p2);
    const a = try s.put([]const u8, alloc, p1, R);
    const b = try s.put([]const u8, alloc, p2, R);
    _ = try s.preallocate();
    try s.commit();

    var i: u64 = 0;
    while (i < 6) : (i += 1) {
        const p = try payloadAlloc(alloc, BASE + 10 + i, 700);
        defer alloc.free(p);
        _ = try s.put([]const u8, alloc, p, R);
    }
    try s.commit();

    const p3 = try payloadAlloc(alloc, BASE + 2, 120);
    defer alloc.free(p3);
    try s.update([]const u8, alloc, a, p3, R);
    try s.delete(b);
    try s.commit();

    const p4 = try payloadAlloc(alloc, BASE + 3, 64);
    defer alloc.free(p4);
    _ = try s.put([]const u8, alloc, p4, R);
    try s.commit();

    // the smallest bodies the engine can produce (see the java writer's note)
    _ = try s.preallocate();
    try s.commit();
    _ = try s.put([]const u8, alloc, "", R);
    try s.commit();

    // commits 7 and 8: a NULL-content record. `lenPlus == 0` is null and
    // `lenPlus == 1` is the zero-length record written just above, and a reader
    // that decodes `lenPlus` into a length collapses the two. C3s added this to
    // both writers because the corpus contained no `lenPlus == 0` entry at all,
    // which made the C3 body comparison unable to fail on that row. Kept in
    // lockstep with `Wal3GoldenWriter.workload` — a divergence here is a
    // divergence in the sample, not in the engines.
    const p5 = try payloadAlloc(alloc, BASE + 4, 32);
    defer alloc.free(p5);
    const nul = try s.put([]const u8, alloc, p5, R);
    try s.commit();
    try s.update([]const u8, alloc, nul, null, R);
    try s.commit();

    try s.close();
    s.deinit(); // close() and deinit() are separate steps (store_wal_test.zig:242)
    std.debug.print("wrote a zig-authored v3 namespace under {s}\n", .{out_dir});
}

pub fn main() !void {
    // The two live modes are dispatched here; anything else lands on the C7z
    // retirement refusal at the bottom. Each mode owns its own output
    // directory and its own non-empty-target rule.
    {
        var gpa: std.heap.DebugAllocator(.{}) = .init;
        defer _ = gpa.deinit();
        const alloc = gpa.allocator();
        const args = try std.process.argsAlloc(alloc);
        defer std.process.argsFree(alloc, args);
        // EXACT shape: `--golden <dir>` and nothing else. Scanning for
        // `--golden` anywhere let `--out protected --golden protected` silently
        // ignore `--out` and run against the directory the (now retired)
        // schema-v1 staleness refusal was protecting (C0b review finding 5).
        // The v1 outputs are gone; the exact-shape rule stays, because the
        // failure it prevents is "a flag scan silently discards the argument
        // that named the target", which is not about v1.
        if (args.len >= 2 and std.mem.eql(u8, args[1], "--golden")) {
            if (args.len != 3)
                fatal("usage: --golden <dir>   (exactly one argument, no other flags)", .{});
            try mainGolden(alloc, args[2]);
            return;
        }
        // `--wal3 <dir> [--force]`: the Stage C (C2z) accept-bundle generator.
        // Like `--golden` it writes into its own directory. EXACT shape, for
        // the reason `--golden` is: scanning for the flag anywhere let
        // `--out protected --wal3 protected` silently ignore `--out` (C0b
        // review finding 5).
        if (args.len >= 2 and std.mem.eql(u8, args[1], "--wal3")) {
            if (args.len < 3) fatal("usage: --wal3 <dir> [--force] [--commit <hash>]", .{});
            var force = false;
            var commit: []const u8 = "unknown";
            var i: usize = 3;
            while (i < args.len) : (i += 1) {
                if (std.mem.eql(u8, args[i], "--force")) {
                    force = true;
                } else if (std.mem.eql(u8, args[i], "--commit")) {
                    i += 1;
                    if (i >= args.len) fatal("--commit needs a hash argument", .{});
                    commit = args[i];
                } else {
                    fatal("usage: --wal3 <dir> [--force] [--commit <hash>]", .{});
                }
            }
            var arena_state = std.heap.ArenaAllocator.init(alloc);
            defer arena_state.deinit();
            var g: wal3.Grade = .{};
            wal3.generate(arena_state.allocator(), args[2], force, commit, &g) catch |e| {
                if (g.row) |row|
                    fatal("§5.3/§5.3.1 refusal [{s}]: {s}", .{ @tagName(row), g.message() });
                fatal("--wal3 failed: {s}", .{@errorName(e)});
            };
            std.debug.print("wrote {s}/ and {s}/ plus fragment.tsv and layout.tsv under {s}\n", .{ wal3.TAIL_ID, wal3.CLEANED_ID, args[2] });
            return;
        }
        for (args[1..]) |a| {
            if (std.mem.eql(u8, a, "--wal3"))
                fatal("--wal3 must be the FIRST argument: `--wal3 <dir> [--force]`", .{});
        }
        for (args[1..]) |a| {
            if (std.mem.eql(u8, a, "--golden"))
                fatal("--golden must be the FIRST argument and the only mode: " ++
                    "`--golden <dir>`", .{});
        }
    }

    // Schema-v1 fixture generation retired at C7z (contract §9). The live
    // modes are `--golden <dir>` and `--wal3 <dir>` only.
    fatal("the schema-v1 fixture generator is retired (Stage C, C7z): " ++
        "use `--golden <dir>` or `--wal3 <dir>`; see src/xfixtures/generator.zig header", .{});
}
