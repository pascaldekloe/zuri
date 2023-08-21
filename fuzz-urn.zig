const std = @import("std");
const os = std.os;

const zuri = @import("./zuri.zig");

const size_max = 1024; // upper boundary in bytes

pub fn main() !void {
    // fetch fuzzing input up to size_max
    var readb: [size_max]u8 = undefined;
    const stdin = std.io.getStdIn();
    const readn = try stdin.readAll(&readb);
    const fuzz_in = readb[0..readn];

    defer if (fuzzFail) os.exit(1);

    var buf: [size_max]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    const s = zuri.newUrn("test", fuzz_in, "Ol", fix.allocator()) catch |err| {
        if (err == std.mem.Allocator.Error.OutOfMemory and fuzz_in.len < buf.len / 3)
            fail("error {} for {d}-byte input with {d}-byte buffer", .{ err, fuzz_in.len, buf.len });
        return;
    };

    const p = zuri.parse(s) catch |err| {
        fail("produced invalid URI {s}: {}", .{ s, err });
        return;
    };
    if (!p.hasPath(fuzz_in))
        fail("fuzz input does not match path in {s}", .{s});
}

var fuzzFail = false;

fn fail(comptime format: []const u8, args: anytype) void {
    fuzzFail = true;
    std.log.err(format, args);
}
