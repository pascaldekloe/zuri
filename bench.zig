const std = @import("std");
const mem = std.mem;
const Timer = std.time.Timer;
const zuri = @import("./zuri.zig");

const report = std.io.getStdOut().writer();

pub fn main() !void {
    var buf: [1024]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fix.allocator();

    const bench_count = 500_000; // number of iterations

    // create random arguments to prevent the compiler from getting clever
    var prng = std.rand.DefaultPrng.init(32);
    const rand = prng.random();

    var timer = try Timer.start();
    {
        var host: [17]u8 = undefined;
        @memcpy(&host, "www.some-host.com");
        rand.shuffle(u8, &host);

        var seg1 = try allocator.dupe(u8, "path");
        var seg2 = try allocator.dupe(u8, "to a");
        var seg3 = try allocator.dupe(u8, "long-name");
        var path = [_][]u8{ seg1, seg2, seg3 };
        rand.shuffle(u8, seg1);
        rand.shuffle(u8, seg2);
        rand.shuffle(u8, seg3);
        rand.shuffle([]u8, &path);

        const start = timer.lap();

        var n: usize = bench_count;
        while (n != 0) : (n -= 1) {
            var s = try zuri.newURL("imap", null, &host, null, &path, allocator);
            mem.doNotOptimizeAway(s);
            allocator.free(s);
        }

        const end = timer.read();
        try report.print("URL construction with host and {d}-segment path took {d} on average, including free\n", .{ path.len, @divTrunc(end - start, bench_count) });
    }

    {
        const sample = "http://www.example.com/path/to%20a/long-name";

        timer.reset();
        const start = timer.lap();

        var n: usize = bench_count;
        while (n != 0) : (n -= 1) {
            var parts = try zuri.parse(sample);
            mem.doNotOptimizeAway(&parts);
        }

        const end = timer.read();
        try report.print("parse {s} took {d} ns on average\n", .{ sample, @divTrunc(end - start, bench_count) });
    }
}
