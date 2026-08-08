const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("mapdb_zig_store", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // C-D4's third set. `src/xfixtures/data-v2/embedded.zig` is GENERATED from
    // MANIFEST.tsv, so "the table covers every manifest row" compares a script's
    // output with its own input and cannot fail. The adopted invariant is set
    // equality across three INDEPENDENTLY derived sets, and this is the one
    // neither the manifest nor the generator can influence: the `*.gz` basenames
    // actually present in the distributed directory, read off the filesystem
    // here and handed to the suite as a generated module. A blob shipped but
    // embedded by nobody has no other way of being noticed — `@embedFile` makes
    // the opposite direction a compile error and says nothing about this one.
    mod.addImport("xfix_distributed", b.createModule(.{
        .root_source_file = b.addWriteFiles().add(
            "xfix_distributed.zig",
            distributedGzListing(b, "src/xfixtures/data-v2"),
        ),
    }));

    // The same third set for the schema-v2 PREFLIGHT CORPUS root (slice C5z).
    // A second root needs a second listing, not a widened first one: the two
    // roots have different profiles (`v2-core` and `v2-oracle`) and different
    // embed tables, and one merged set would let a blob distributed under one
    // root be explained by the other root's manifest.
    mod.addImport("xfix_distributed_corpus", b.createModule(.{
        .root_source_file = b.addWriteFiles().add(
            "xfix_distributed_corpus.zig",
            distributedGzListing(b, "src/xfixtures/data-v2-corpus"),
        ),
    }));

    // Test-name filters, so a mutation campaign can run the xfixtures suites
    // alone instead of all 575 tests for each of its mutants. The GATE never
    // passes it: `ci/check.sh` runs `zig build test` with no filter, and a
    // filtered run is a development convenience that cannot become the gate by
    // accident.
    const test_filters = b.option([]const []const u8, "test-filter", "Run only tests whose name contains one of these") orelse &.{};
    const unit_tests = b.addTest(.{ .root_module = mod, .filters = test_filters });
    const run_unit = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_unit.step);

    // Cross-port conformance fixture generator (Stage 1 D workload + Stage 2
    // W WAL workloads). Dedicated run step — never fires during
    // `zig build test`. The output directory is passed as RUN ARGS (not a -D
    // build option):
    //
    //   zig build fixtures -- --out <dir> [--force] [--commit <hash>]
    //
    // Refuses a nonempty output dir unless --force; writes
    // `direct-v1-zig.db` + `wal-v1-zig-tail.wal` + `wal-v1-zig-ckpt.wal` +
    // `fragment.tsv`. See src/xfixtures/generator.zig.
    const fixtures_exe = b.addExecutable(.{
        .name = "xfixtures-gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/xfixtures/generator.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "mapdb_zig_store", .module = mod }},
        }),
    });
    const run_fixtures = b.addRunArtifact(fixtures_exe);
    if (b.args) |args| run_fixtures.addArgs(args);
    const fixtures_step = b.step("fixtures", "Write the cross-port conformance fixtures (-- --out <dir> [--force])");
    fixtures_step.dependOn(&run_fixtures.step);

    // The WAL sync probe: a fixed writer scenario the gate runs under strace to
    // count the REAL fsync/fdatasync calls (see src/store/wal_sync_probe.zig).
    // Built and installed by its own step; never fires during `zig build test`.
    const probe_exe = b.addExecutable(.{
        .name = "wal-sync-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/store/wal_sync_probe.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "mapdb_zig_store", .module = mod }},
        }),
    });
    const probe_step = b.step("sync-probe", "Build the WAL sync probe (run it under strace; see ci/check.sh)");
    probe_step.dependOn(&b.addInstallArtifact(probe_exe, .{}).step);

    // C8x cross-engine lock matrix probe (hold/open CLI). Dedicated target so
    // the fixture generator is not overloaded; never part of `zig build test`.
    const lock_probe_exe = b.addExecutable(.{
        .name = "wal3-lock-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/store/wal3_lock_probe.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "mapdb_zig_store", .module = mod }},
        }),
    });
    const lock_probe_step = b.step("lock-probe", "Build the C8x WAL lock matrix probe");
    lock_probe_step.dependOn(&b.addInstallArtifact(lock_probe_exe, .{}).step);
}

/// The `*.gz` basenames in `rel_dir`, sorted, as a zig source file.
///
/// Read at BUILD time off the real directory: this set exists to disagree with
/// the manifest and with the generated embed table, so deriving it from either
/// of them would defeat its only purpose. A missing directory is a hard build
/// error rather than an empty list, because an empty list would make the set
/// equality that consumes it pass vacuously the moment the sync step broke.
fn distributedGzListing(b: *std.Build, rel_dir: []const u8) []const u8 {
    var dir = b.build_root.handle.openDir(rel_dir, .{ .iterate = true }) catch |e|
        std.debug.panic("build: cannot open {s}: {s}", .{ rel_dir, @errorName(e) });
    defer dir.close();

    var gz: std.ArrayListUnmanaged([]const u8) = .empty;
    var all: std.ArrayListUnmanaged([]const u8) = .empty;
    var it = dir.iterate();
    while (it.next() catch |e|
        std.debug.panic("build: cannot list {s}: {s}", .{ rel_dir, @errorName(e) })) |entry|
    {
        if (entry.kind != .file)
            std.debug.panic("build: {s}/{s} is not a regular file", .{ rel_dir, entry.name });
        if (std.mem.indexOfAny(u8, entry.name, "\"\\\n") != null)
            std.debug.panic("build: unquotable fixture name {s}", .{entry.name});
        const name = b.dupe(entry.name);
        all.append(b.allocator, name) catch @panic("OOM");
        if (std.mem.endsWith(u8, entry.name, ".gz")) gz.append(b.allocator, name) catch @panic("OOM");
    }
    // Directory order is filesystem order; sorting makes the generated source
    // reproducible so an unrelated rebuild is not a cache miss.
    const byName = struct {
        fn lt(_: void, a: []const u8, c: []const u8) bool {
            return std.mem.lessThan(u8, a, c);
        }
    }.lt;
    std.mem.sort([]const u8, gz.items, {}, byName);
    std.mem.sort([]const u8, all.items, {}, byName);

    var src: std.ArrayListUnmanaged(u8) = .empty;
    src.appendSlice(b.allocator,
        \\//! GENERATED by build.zig: what is ACTUALLY distributed in
        \\//! src/xfixtures/data-v2, read off the filesystem at build time.
        \\//!
        \\//! `gz` feeds C-D4's three-way set equality; `all` feeds the resource
        \\//! inventory, which is the check that nothing in the fixture root is
        \\//! unexplained. Neither can be derived from the manifest or from the
        \\//! generated embed table without becoming a comparison with itself.
        \\
        \\pub const gz = [_][]const u8{
        \\
    ) catch @panic("OOM");
    for (gz.items) |n|
        src.appendSlice(b.allocator, b.fmt("    \"{s}\",\n", .{n})) catch @panic("OOM");
    src.appendSlice(b.allocator, "};\n\npub const all = [_][]const u8{\n") catch @panic("OOM");
    for (all.items) |n|
        src.appendSlice(b.allocator, b.fmt("    \"{s}\",\n", .{n})) catch @panic("OOM");
    src.appendSlice(b.allocator, "};\n") catch @panic("OOM");
    return src.items;
}
