//! Cross-process WAL lock probe for Stage C C8x (`wal3-c8-plan.md` §3).
//!
//! Built as `zig build lock-probe` (dedicated target, not the fixture generator).
//! Speaks the env protocol; CLI flags accepted as equivalent.

const std = @import("std");
const mapdb = @import("mapdb_zig_store");
const StoreWAL = mapdb.store.StoreWAL;
const DbError = mapdb.errors.DbError;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
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

fn openStore(alloc: std.mem.Allocator, base: []const u8, mode: []const u8) DbError!StoreWAL {
    const read_only = std.mem.eql(u8, mode, "ro");
    return StoreWAL.openCfg(alloc, base, .{ .read_only = read_only });
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

    var store = openStore(alloc, a.base, a.mode) catch |e| {
        std.debug.print("hold open failed: {s}\n", .{@errorName(e)});
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
    var store = openStore(alloc, a.base, a.mode) catch |e| {
        if (e == error.Locked) {
            try out.writeAll("REFUSED\n");
            return;
        }
        var buf: [128]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, "OTHER:{s}:{s}\n", .{ @errorName(e), @errorName(e) });
        try out.writeAll(line);
        return;
    };
    store.deinit();
    try out.writeAll("OK\n");
}
