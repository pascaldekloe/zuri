const std = @import("std");
const mem = std.mem;
const Timer = std.time.Timer;

const Urlink = @import("./Urlink.zig");
const Urname = @import("./Urname.zig");
const Urview = @import("./Urview.zig");

const stderr = std.io.getStdErr().writer();
const stdout = std.io.getStdOut().writer();
const report = stdout;

const allocator = std.heap.page_allocator;

const bench_count = 50_000_000; // number of iterations

pub fn main() !void {
    const sample_url = try loadSampleUrl();
    defer allocator.free(sample_url);
    const sample = try Urview.parse(sample_url);

    // TODO(pascaldekloe): Need an API for path segment extraction.
    var sample_segs: [3][]const u8 = .{ "", "", "" };
    {
        if (!sample.hasPath()) {
            try stderr.print("path absent in sample {s}\n", .{sample_url});
            std.os.exit(1);
        }
        var path = std.mem.splitScalar(u8, sample.rawPath()[1..], '/');
        if (path.next()) |s| sample_segs[0] = s;
        if (path.next()) |s| sample_segs[1] = s;
        if (path.next()) |s| sample_segs[2] = s;
    }

    const arbitrary_point = sample.rawHost().len;

    // fast allocator to minimize benchmark influence
    var buf: [1024]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    const bench_allocator = fix.allocator();

    var timer = try Timer.start();
    {
        const start = timer.lap();

        var n: usize = bench_count;
        while (n != 0) : (n -= 1) {
            const ur: Urlink = .{ .host = sample.rawHost(), .segments = sample_segs[0..] };
            const url = try ur.newUrl("http", bench_allocator);
            std.mem.doNotOptimizeAway(url);
            if (n == arbitrary_point) try report.print("benchmark newUrl does {s}.\n", .{url});
            bench_allocator.free(url);
        }

        try reportAverageNs("URL construction", timer.read() - start);
    }

    timer.reset();
    {
        // test content from arbitrary data
        var bench_addr: [16]u8 = undefined;
        @memcpy(&bench_addr, sample_url[0..16]);

        const start = timer.lap();

        var n: usize = bench_count;
        while (n != 0) : (n -= 1) {
            const ur: Urlink = .{ .segments = sample_segs[0..] };
            const url = try ur.newIp6Url("http", bench_addr, bench_allocator);
            mem.doNotOptimizeAway(url);
            if (n == arbitrary_point) try report.print("benchmark newIp6Url does {s}.\n", .{url});
            bench_allocator.free(url);
        }

        try reportAverageNs("IPv6 URL construction", timer.read() - start);
    }

    timer.reset();
    {
        // test content with three escapes
        const bench_spec = sample_url[20..];

        const start = timer.lap();

        var n: usize = bench_count;
        while (n != 0) : (n -= 1) {
            const urn = try Urname.newUrn("bench", bench_spec, "", bench_allocator);
            mem.doNotOptimizeAway(urn);
            if (n == arbitrary_point) try report.print("benchmark newUrn does {s}.\n", .{urn});
            bench_allocator.free(urn);
        }

        try reportAverageNs("URN construction", timer.read() - start);
    }

    timer.reset();
    {
        const start = timer.lap();

        var n: usize = bench_count;
        while (n != 0) : (n -= 1) {
            const ur = try Urview.parse(sample_url);
            if (n == arbitrary_point) try report.print("benchmark parse does {s}{s}{s}{s}{s}.\n", .{ ur.rawScheme(), ur.rawAuthority(), ur.rawPath(), ur.rawQuery(), ur.rawFragment() });
            mem.doNotOptimizeAway(&ur);
        }

        try reportAverageNs("parse", timer.read() - start);
    }
}

fn reportAverageNs(label: []const u8, duration_ns: u64) !void {
    const avg = @as(f64, @floatFromInt(duration_ns)) / @as(f64, @floatFromInt(bench_count));
    try report.print("{s} took {d:.1} ns on average\n", .{ label, avg });
}

// Load test data from filesystem to prevent the compiler from getting clever.
fn loadSampleUrl() ![:0]const u8 {
    var path_buf: [1024]u8 = undefined;
    const wd = std.os.getcwd(&path_buf) catch |err| {
        stderr.print("working directory unavailable: {}", .{err}) catch {};
        std.os.exit(255);
    };

    const loc = "/sample/semantic";
    @memcpy(path_buf[wd.len..].ptr, loc);
    const path = path_buf[0 .. wd.len + loc.len];
    var file = std.fs.openFileAbsolute(path, .{}) catch |err| {
        stderr.print("path {s} unavailable: {}", .{ path, err }) catch {};
        std.os.exit(255);
    };
    defer file.close();

    var sample_buf: [128]u8 = undefined;
    var n = file.readAll(&sample_buf) catch |err| {
        stderr.print("path {s} data unavailable: {}", .{ path, err }) catch {};
        std.os.exit(255);
    };
    return allocator.dupeZ(u8, sample_buf[0..n]);
}
