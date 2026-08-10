//! StoreDirect cross-port harness (Stage C, **C7z** residual).
//!
//! Contract §9 retires the WAL schema-v1 tree and its skip lists; it does
//! **not** retire the StoreDirect accept images (`direct-v1-*`) or the shared
//! malformed-StoreDirect reject images. Those lived under the same schema-v1
//! root and would have vanished with it, so C7 keeps them as a dedicated
//! schema-v2 root (`data-direct/`) without reintroducing dual dispatch.

const std = @import("std");
const testing = std.testing;
const xfix = @import("xfix.zig");
const store_mod = @import("../store/mod.zig");
const StoreDirect = store_mod.StoreDirect;

const ENGINE = "zig";

const direct_manifest_tsv: []const u8 = @embedFile("data-direct/MANIFEST.tsv");
const direct_blobs = [_]xfix.Blob{
    .{ .name = "direct-v1-java.direct-v1-java.db.gz", .gz = @embedFile("data-direct/direct-v1-java.direct-v1-java.db.gz") },
    .{ .name = "direct-v1-rust.direct-v1-rust.db.gz", .gz = @embedFile("data-direct/direct-v1-rust.direct-v1-rust.db.gz") },
    .{ .name = "direct-v1-zig.direct-v1-zig.db.gz", .gz = @embedFile("data-direct/direct-v1-zig.direct-v1-zig.db.gz") },
    .{ .name = "reject-mdb5-sd1.reject-mdb5-sd1.db.gz", .gz = @embedFile("data-direct/reject-mdb5-sd1.reject-mdb5-sd1.db.gz") },
    .{ .name = "reject-sd1-badfeatures.reject-sd1-badfeatures.db.gz", .gz = @embedFile("data-direct/reject-sd1-badfeatures.reject-sd1-badfeatures.db.gz") },
    .{ .name = "reject-sd1-badchecksum.reject-sd1-badchecksum.db.gz", .gz = @embedFile("data-direct/reject-sd1-badchecksum.reject-sd1-badchecksum.db.gz") },
    .{ .name = "reject-sd1-short.reject-sd1-short.db.gz", .gz = @embedFile("data-direct/reject-sd1-short.reject-sd1-short.db.gz") },
};

test "xfixtures direct: StoreDirect cross-port cells (engine=zig)" {
    const a = testing.allocator;
    var ctx = xfix.Ctx{ .alloc = a };
    var sample = try xfix.loadSampleV2(&ctx, direct_manifest_tsv, &direct_blobs);
    defer sample.deinit(a);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var accepts: usize = 0;
    var rejects: usize = 0;

    for (sample.manifest.expects.items, 0..) |e, idx| {
        if (!std.mem.eql(u8, e.engine, ENGINE)) continue;
        try testing.expectEqualStrings("direct", e.opener);
        try testing.expectEqualStrings("rw", e.mode);

        var name_buf: [64]u8 = undefined;
        const cell_name = try std.fmt.bufPrint(&name_buf, "direct-{d}", .{idx});
        var cell_dir = try tmp.dir.makeOpenPath(cell_name, .{ .iterate = true });
        defer cell_dir.close();

        for (sample.manifest.files.items) |f| {
            if (!std.mem.eql(u8, f.fixture, e.fixture)) continue;
            const bytes = sample.bytesOf(f.fixture, f.rel) orelse return error.MissingBytes;
            try cell_dir.writeFile(.{ .sub_path = f.rel, .data = bytes });
        }

        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const cell_abs = try cell_dir.realpath(".", &path_buf);
        const target = try std.fs.path.join(a, &.{ cell_abs, e.open_arg });
        defer a.free(target);
        const before = try std.fs.cwd().readFileAlloc(a, target, 16 * 1024 * 1024);
        defer a.free(before);

        var cell_buf: [192]u8 = undefined;
        const cell = try std.fmt.bufPrint(&cell_buf, "direct cell {d}: fixture={s} verdict={s}", .{
            idx, e.fixture, e.verdict,
        });

        if (std.mem.eql(u8, e.verdict, "accept")) {
            var s = StoreDirect.openFile(a, target, true) catch |err| {
                std.debug.print("[xfixtures-direct] {s}: open failed: {s}\n", .{ cell, @errorName(err) });
                return error.XFixtures;
            };
            defer s.deinit();
            try xfix.assertReaderContract(&ctx, &s, sample.manifest.recids.items, e.fixture, cell);
            try s.close();
            accepts += 1;
        } else if (std.mem.eql(u8, e.verdict, "reject")) {
            if (StoreDirect.openFile(a, target, true)) |*opened| {
                var s = opened.*;
                s.deinit();
                std.debug.print("[xfixtures-direct] {s}: open unexpectedly succeeded\n", .{cell});
                return error.XFixtures;
            } else |err| try testing.expectEqual(error.DataCorruption, err);
            rejects += 1;
        } else return error.UnknownVerdict;

        const after = try std.fs.cwd().readFileAlloc(a, target, 16 * 1024 * 1024);
        defer a.free(after);
        try testing.expectEqualSlices(u8, before, after);

        // ...AND NOTHING NEW IN THE CELL DIRECTORY. Byte-identity of the image
        // is only half the post-state rule: an opener that wrote a companion
        // file — a journal, a temp, a checkpoint — passes the first half and
        // leaves evidence only a directory listing can see. The retired
        // schema-v1 executor carried this check; `17db512`'s rewrite of the
        // StoreDirect root as `data-direct/` dropped it, so from C7z until now
        // this root asserted nothing about a directory it had just opened
        // (r1 finding 7, "direct residual roots have no nothing-unexplained
        // test").
        //
        // `.lock` is excepted because a lock sidecar is an OPENER's business,
        // not a store mutation. `.ckpt` is deliberately NOT excepted, exactly
        // as in the v1 original: a clean close must leave no checkpoint temp
        // behind. Everything else is an input the manifest named, so the
        // allowed set is derived from the `file` rows rather than listed.
        var it = cell_dir.iterate();
        while (try it.next()) |entry| {
            if (std.mem.endsWith(u8, entry.name, ".lock")) continue;
            var an_input = false;
            for (sample.manifest.files.items) |f| {
                if (!std.mem.eql(u8, f.fixture, e.fixture)) continue;
                if (std.mem.eql(u8, f.rel, entry.name)) an_input = true;
            }
            if (an_input) continue;
            std.debug.print("[xfixtures-direct] {s}: unexpected new file `{s}`\n", .{ cell, entry.name });
            return error.XFixtures;
        }
    }

    try testing.expectEqual(@as(usize, 3), accepts);
    try testing.expectEqual(@as(usize, 4), rejects);
}
