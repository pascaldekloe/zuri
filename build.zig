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

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const run_urview_tests = b.addRunArtifact(b.addTest(.{
        .root_source_file = .{ .path = "Urview.zig" },
        .target = target,
        .optimize = std.builtin.OptimizeMode.Debug,
    }));
    const run_urlink_tests = b.addRunArtifact(b.addTest(.{
        .root_source_file = .{ .path = "Urlink.zig" },
        .target = target,
        .optimize = std.builtin.OptimizeMode.Debug,
    }));
    const run_urname_tests = b.addRunArtifact(b.addTest(.{
        .root_source_file = .{ .path = "Urname.zig" },
        .target = target,
        .optimize = std.builtin.OptimizeMode.Debug,
    }));

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build test`
    // This will evaluate the `test` step rather than the default, which is "install".
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_urview_tests.step);
    test_step.dependOn(&run_urlink_tests.step);
    test_step.dependOn(&run_urname_tests.step);

    // fuzzer commands
    const fuzzers = [_]*std.Build.Step.Compile{
        b.addExecutable(.{
            .name = "fuzz-url",
            .root_source_file = .{ .path = "fuzz-url.zig" },
            .target = target,
            .optimize = std.builtin.OptimizeMode.ReleaseSafe,
        }),
        b.addExecutable(.{
            .name = "fuzz-urn",
            .root_source_file = .{ .path = "fuzz-urn.zig" },
            .target = target,
            .optimize = std.builtin.OptimizeMode.ReleaseSafe,
        }),
        b.addExecutable(.{
            .name = "fuzz-urview",
            .root_source_file = .{ .path = "fuzz-urview.zig" },
            .target = target,
            .optimize = std.builtin.OptimizeMode.ReleaseSafe,
        }),
    };
    for (fuzzers) |exe| {
        b.installArtifact(exe);

        // include quick-check
        const samples = [_][]const u8{ "sample/bloat", "sample/empty", "sample/semantic", "sample/tricky" };
        for (samples) |path| {
            var run = b.addRunArtifact(exe);
            run.setStdIn(.{ .lazy_path = .{ .path = path } });
            run.expectExitCode(0);
            run.setName(std.fmt.allocPrint(b.allocator, "{s} {s}", .{ exe.name, path }) catch @panic("OOM"));
            test_step.dependOn(&run.step);
        }
    }

    // benchmark command
    b.installArtifact(b.addExecutable(.{
        .name = "bench",
        .root_source_file = .{ .path = "bench.zig" },
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    }));

    // C library
    const zuri = b.addStaticLibrary(.{
        .name = "zuri",
        .root_source_file = .{ .path = "zuri.zig" },
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    });
    b.installArtifact(zuri);
    // cross-compile for packaging
    b.installArtifact(b.addStaticLibrary(.{
        .name = "linux-amd64",
        .root_source_file = .{ .path = "zuri.zig" },
        .target = std.zig.CrossTarget.parse(.{
            .arch_os_abi = "x86_64-linux",
            .cpu_features = "baseline",
        }) catch @panic("x86_64-linux baseline"),
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    }));
    b.installArtifact(b.addStaticLibrary(.{
        .name = "linux-arm64",
        .root_source_file = .{ .path = "zuri.zig" },
        .target = std.zig.CrossTarget.parse(.{
            .arch_os_abi = "aarch64-linux",
            .cpu_features = "baseline",
        }) catch @panic("aarch64-linux baseline"),
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    }));
}
