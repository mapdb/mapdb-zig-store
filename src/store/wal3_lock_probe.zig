//! Cross-process WAL lock probe for Stage C C8x (`wal3-c8-plan.md` §3).
//!
//! Built as `zig build lock-probe` (dedicated target, not the fixture generator).
//! Speaks the env protocol; CLI flags accepted as equivalent.

const std = @import("std");
const testing = std.testing;
const mapdb = @import("mapdb_zig_store");
const StoreWAL = mapdb.store.StoreWAL;
const Diag = mapdb.store.wal_recover.Diag;
const DbError = mapdb.errors.DbError;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try parseArgs(alloc);

    if (std.mem.eql(u8, args.cmd, "hold")) {
        try hold(alloc, args);
    } else if (std.mem.eql(u8, args.cmd, "open")) {
        try openCmd(alloc, args);
    } else {
        std.debug.print("cmd must be hold|open\n", .{});
        std.process.exit(2);
    }
}

const Args = struct {
    cmd: []const u8,
    base: []const u8,
    mode: []const u8,
    ready: ?[]const u8,
    release: ?[]const u8,
};

fn parseArgs(alloc: std.mem.Allocator) !Args {
    var a = Args{
        .cmd = "",
        .base = "",
        .mode = "",
        .ready = null,
        .release = null,
    };
    if (std.posix.getenv("MAPDB_LOCK_PROBE_CMD")) |v| a.cmd = v;
    if (std.posix.getenv("MAPDB_LOCK_PROBE_BASE")) |v| a.base = v;
    if (std.posix.getenv("MAPDB_LOCK_PROBE_MODE")) |v| a.mode = v;
    if (std.posix.getenv("MAPDB_LOCK_PROBE_READY")) |v| a.ready = v;
    if (std.posix.getenv("MAPDB_LOCK_PROBE_RELEASE")) |v| a.release = v;

    var it = try std.process.argsWithAllocator(alloc);
    defer it.deinit();
    _ = it.next(); // argv0
    while (it.next()) |f| {
        if (std.mem.eql(u8, f, "hold") or std.mem.eql(u8, f, "open")) {
            a.cmd = f;
        } else if (std.mem.eql(u8, f, "--base")) {
            a.base = it.next() orelse {
                failUsage();
            };
        } else if (std.mem.eql(u8, f, "--mode")) {
            a.mode = it.next() orelse {
                failUsage();
            };
        } else if (std.mem.eql(u8, f, "--ready-file")) {
            a.ready = it.next() orelse {
                failUsage();
            };
        } else if (std.mem.eql(u8, f, "--release-file")) {
            a.release = it.next() orelse {
                failUsage();
            };
        } else {
            std.debug.print("unknown arg: {s}\n", .{f});
            std.process.exit(2);
        }
    }
    if (a.cmd.len == 0 or a.base.len == 0 or a.mode.len == 0) failUsage();
    if (!std.mem.eql(u8, a.mode, "rw") and !std.mem.eql(u8, a.mode, "ro")) failUsage();
    return a;
}

fn failUsage() noreturn {
    std.debug.print("usage: hold|open --base PATH --mode rw|ro [--ready-file P --release-file P]\n", .{});
    std.process.exit(2);
}

fn openStore(alloc: std.mem.Allocator, base: []const u8, mode: []const u8, diag: ?*Diag) DbError!StoreWAL {
    const read_only = std.mem.eql(u8, mode, "ro");
    return StoreWAL.openCfg(alloc, base, .{ .read_only = read_only, .diag = diag });
}

/// The terminal line for an open that failed for a reason other than lock
/// contention: `OTHER:<class>:<msg>` (`wal3-c8-plan.md` §3.3).
///
/// `<class>` is the zig error name. `<msg>` is the ENGINE's explanation, which
/// the first draft did not have and substituted the class for a second time —
/// a line that told a reader nothing the class had not already said. `DbError`
/// carries no payload, so the explanation travels in the typed `Diag` side
/// channel instead, and `openCfg` fills it on a refused open. The class-as-
/// message fallback stays for the case where the diag is genuinely empty: a
/// refusal from below the recovery layer has no note, and there the error name
/// really is all there is.
///
/// ONE line, and the caller's line only: `lock_matrix.py` takes the whole
/// stripped line as the verdict and prefix-matches `OTHER:`, so an embedded
/// newline would forge a second verdict. Today's `Diag` reasons are static and
/// newline-free; that is a property of the current reason set, not a rule
/// anything enforces, so it is enforced here.
fn otherLine(buf: []u8, e: anyerror, diag: *const Diag) []const u8 {
    const class = @errorName(e);
    const raw = if (diag.reason.len != 0) diag.reason else class;
    const frame = "OTHER::\n".len;
    // Truncate the MESSAGE rather than let a long reason turn a legal verdict
    // into a `bufPrint` error and a nonzero exit, which `lock_matrix.py` reads
    // as the probe itself crashing.
    const room = if (buf.len > frame + class.len) buf.len - frame - class.len else 0;
    const msg = raw[0..@min(raw.len, room)];
    const line = std.fmt.bufPrint(buf, "OTHER:{s}:{s}\n", .{ class, msg }) catch
        return "OTHER:probe:the verdict line does not fit\n";
    for (line[0 .. line.len - 1]) |*c| {
        if (c.* == '\n' or c.* == '\r') c.* = ' ';
    }
    return line;
}

fn hold(alloc: std.mem.Allocator, a: Args) !void {
    const ready = a.ready orelse {
        std.debug.print("hold requires ready-file\n", .{});
        std.process.exit(2);
    };
    const release = a.release orelse {
        std.debug.print("hold requires release-file\n", .{});
        std.process.exit(2);
    };
    if (std.fs.cwd().access(ready, .{})) |_| {
        std.debug.print("ready must be initially absent\n", .{});
        std.process.exit(2);
    } else |_| {}
    if (std.fs.cwd().access(release, .{})) |_| {
        std.debug.print("release must be initially absent\n", .{});
        std.process.exit(2);
    } else |_| {}

    var diag: Diag = .{};
    var store = openStore(alloc, a.base, a.mode, &diag) catch |e| {
        std.debug.print("hold open failed: {s} ({s})\n", .{ @errorName(e), diag.reason });
        std.process.exit(3);
    };
    defer store.deinit();

    {
        const f = try std.fs.cwd().createFile(ready, .{});
        defer f.close();
        try f.writeAll("ready\n");
    }
    const out = std.fs.File.stdout();
    try out.writeAll("HOLD_READY\n");

    const deadline_ns = std.time.nanoTimestamp() + 30 * std.time.ns_per_min;
    while (true) {
        if (std.fs.cwd().access(release, .{})) |_| break else |_| {}
        if (std.time.nanoTimestamp() > deadline_ns) {
            std.debug.print("release never appeared\n", .{});
            std.process.exit(3);
        }
        std.Thread.sleep(20 * std.time.ns_per_ms);
    }
}

fn openCmd(alloc: std.mem.Allocator, a: Args) !void {
    const out = std.fs.File.stdout();
    var diag: Diag = .{};
    var store = openStore(alloc, a.base, a.mode, &diag) catch |e| {
        if (e == error.Locked) {
            try out.writeAll("REFUSED\n");
            return;
        }
        var buf: [512]u8 = undefined;
        try out.writeAll(otherLine(&buf, e, &diag));
        return;
    };
    store.deinit();
    try out.writeAll("OK\n");
}

// ---------------------------------------------------------------------------
// tests
//
// This file is an EXECUTABLE, not part of the library module, so nothing in
// `src/root.zig` reaches these. They run because `build.zig` compiles the probe
// module as a test binary in the `test` step — added with this test, since the
// gate did not previously compile this file at all and a probe the gate never
// analyses is the same rot as a function nothing calls.
// ---------------------------------------------------------------------------

test "lock probe: OTHER carries the engine's own message, not the class twice" {
    var buf: [512]u8 = undefined;

    // With a diag: class then the engine's reason.
    {
        var d: Diag = .{};
        d.note("bad append base delta", 3, 128, 7, 2);
        try testing.expectEqualStrings(
            "OTHER:DataCorruption:bad append base delta\n",
            otherLine(&buf, error.DataCorruption, &d),
        );
    }
    // Empty diag: the error name is genuinely all there is, so it stands in.
    {
        const d: Diag = .{};
        try testing.expectEqualStrings(
            "OTHER:AccessDenied:AccessDenied\n",
            otherLine(&buf, error.AccessDenied, &d),
        );
    }
}

test "lock probe: the OTHER verdict is one line and fits its buffer" {
    // A reason with an embedded newline would otherwise put a SECOND line on
    // stdout, and `lock_matrix.py` reads every recognised line as a verdict —
    // "two verdicts" is one of its own self-test failures.
    {
        var buf: [512]u8 = undefined;
        var d: Diag = .{};
        d.note("first line\nOK\r", 0, 0, 0, 0);
        try testing.expectEqualStrings(
            "OTHER:DataCorruption:first line OK \n",
            otherLine(&buf, error.DataCorruption, &d),
        );
    }
    // A reason longer than the buffer truncates the MESSAGE and keeps the
    // grammar; it must not become a `bufPrint` error and a nonzero exit, which
    // `lock_matrix.py` reads as the probe crashing rather than as a verdict.
    {
        var buf: [32]u8 = undefined;
        var d: Diag = .{};
        d.note("x" ** 200, 0, 0, 0, 0);
        const line = otherLine(&buf, error.DataCorruption, &d);
        try testing.expect(line.len <= buf.len);
        try testing.expect(std.mem.startsWith(u8, line, "OTHER:DataCorruption:xxx"));
        try testing.expectEqual(@as(u8, '\n'), line[line.len - 1]);
    }
    // And a buffer that cannot even hold the frame yields a legal line rather
    // than a crash.
    {
        var buf: [4]u8 = undefined;
        const d: Diag = .{};
        try testing.expectEqualStrings(
            "OTHER:probe:the verdict line does not fit\n",
            otherLine(&buf, error.DataCorruption, &d),
        );
    }
}
