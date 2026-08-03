const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("mapdb_zig_store", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit_tests = b.addTest(.{ .root_module = mod });
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
}
