const std = @import("std");
const mem = std.mem;
const Timer = std.time.Timer;

const urlink = @import("./urlink.zig");
const urview = @import("./urview.zig");

const stderr = std.io.getStdErr().writer();
const stdout = std.io.getStdOut().writer();
const report = stdout;

const bench_count = 500_000; // number of iterations

pub fn main() !void {
    var sample_buf: [128]u8 = undefined;
    const bench_url = loadSampleUrl(&sample_buf);

    var bench_host: []const u8 = "";
    var bench_segs: [3][]const u8 = .{ "", "", "" };
    {
        const view = try urview.parse(bench_url);
        bench_host = view.raw_host;
        var path = std.mem.splitScalar(u8, view.raw_path[1..], '/');
        if (path.next()) |s| {
            bench_segs[0] = s;
        }
        if (path.next()) |s| {
            bench_segs[1] = s;
        }
        if (path.next()) |s| {
            bench_segs[2] = s;
        }
    }

    // fast allocator to minimize benchmark influence
    var buf: [1024]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fix.allocator();

    var timer = try Timer.start();
    {
        try report.print("benchmark newUrl with host {s} and path {s}\n", .{ bench_host, bench_segs });

        const start = timer.lap();

        var n: usize = bench_count;
        while (n != 0) : (n -= 1) {
            var s = try urlink.newUrl("http", null, bench_host, null, &bench_segs, allocator);
            mem.doNotOptimizeAway(s);
            allocator.free(s);
        }

        const end = timer.read();
        try report.print("URL construction took {d} ns on average, including free\n", .{@divTrunc(end - start, bench_count)});
    }

    timer.reset();
    {
        var bench_addr: [16]u8 = undefined;
        @memcpy(&bench_addr, bench_url[0..16]);
        try report.print("benchmark newIp6Url with address {d} and path {s}\n", .{ bench_addr, bench_segs });

        const start = timer.lap();

        var n: usize = bench_count;
        while (n != 0) : (n -= 1) {
            var s = try urlink.newIp6Url("http", null, bench_addr, null, &bench_segs, allocator);
            mem.doNotOptimizeAway(s);
            allocator.free(s);
        }

        const end = timer.read();
        try report.print("IPv6 URL construction took {d} ns on average, including free\n", .{@divTrunc(end - start, bench_count)});
    }

    timer.reset();
    {
        // arbitrary content with one escape (of "#")
        var spec = bench_url[20..];
        try report.print("benchmark newUrn with namespace specific part {s}\n", .{spec});

        const start = timer.lap();

        var n: usize = bench_count;
        while (n != 0) : (n -= 1) {
            var s = try urlink.newUrn("bench", spec, "", allocator);
            mem.doNotOptimizeAway(s);
            allocator.free(s);
        }

        const end = timer.read();
        try report.print("URN construction took {d} ns on average, including free\n", .{@divTrunc(end - start, bench_count)});
    }

    timer.reset();
    {
        try report.print("benchmark parse with {s}\n", .{bench_url});

        const start = timer.lap();

        var n: usize = bench_count;
        while (n != 0) : (n -= 1) {
            const view = try urview.parse(bench_url);
            mem.doNotOptimizeAway(&view);
        }

        const end = timer.read();
        try report.print("parse took {d} ns on average\n", .{@divTrunc(end - start, bench_count)});
    }
}

// Load test data from filesystem to prevent the compiler from getting clever.
fn loadSampleUrl(sample_buf: *[128]u8) []const u8 {
    var path_buf: [1024]u8 = undefined;
    var wd = std.os.getcwd(&path_buf) catch |err| {
        stderr.print("working directory unavailable: {}", .{err}) catch {};
        std.os.exit(255);
    };

    const loc = "/sample/semantic";
    @memcpy(path_buf[wd.len..].ptr, loc);
    var path = path_buf[0 .. wd.len + loc.len];
    var file = std.fs.openFileAbsolute(path, .{}) catch |err| {
        stderr.print("path {s} unavailable: {}", .{ path, err }) catch {};
        std.os.exit(255);
    };
    defer file.close();

    var n = file.readAll(sample_buf) catch |err| {
        stderr.print("path {s} data unavailable: {}", .{ path, err }) catch {};
        std.os.exit(255);
    };
    return sample_buf[0..n];
}
