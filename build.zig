const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const urview = b.addStaticLibrary(.{
        .name = "urview",
        .root_source_file = .{ .path = "Urview.zig" },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(urview);
    const urlink = b.addStaticLibrary(.{
        .name = "urlink",
        .root_source_file = .{ .path = "Urlink.zig" },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(urlink);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const urview_tests = b.addTest(.{
        .root_source_file = .{ .path = "Urview.zig" },
        .target = target,
        .optimize = optimize,
    });
    const run_urview_tests = b.addRunArtifact(urview_tests);
    const urlink_tests = b.addTest(.{
        .root_source_file = .{ .path = "Urlink.zig" },
        .target = target,
        .optimize = optimize,
    });
    const run_urlink_tests = b.addRunArtifact(urlink_tests);

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build test`
    // This will evaluate the `test` step rather than the default, which is "install".
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_urview_tests.step);
    test_step.dependOn(&run_urlink_tests.step);

    const parse_fuzzer = b.addExecutable(.{
        .name = "fuzz-parse",
        .root_source_file = .{ .path = "fuzz-parse.zig" },
        .optimize = std.builtin.OptimizeMode.ReleaseSafe,
    });
    b.installArtifact(parse_fuzzer);
    const url_fuzzer = b.addExecutable(.{
        .name = "fuzz-url",
        .root_source_file = .{ .path = "fuzz-url.zig" },
        .optimize = std.builtin.OptimizeMode.ReleaseSafe,
    });
    b.installArtifact(url_fuzzer);
    const urn_fuzzer = b.addExecutable(.{
        .name = "fuzz-urn",
        .root_source_file = .{ .path = "fuzz-urn.zig" },
        .optimize = std.builtin.OptimizeMode.ReleaseSafe,
    });
    b.installArtifact(urn_fuzzer);

    const bench = b.addExecutable(.{
        .name = "bench",
        .root_source_file = .{ .path = "bench.zig" },
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    });
    b.installArtifact(bench);
}
