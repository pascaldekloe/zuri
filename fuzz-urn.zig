const std = @import("std");
const os = std.os;

const urview = @import("./urview.zig");
const urlink = @import("./urlink.zig");

pub fn main() !void {
    // fetch fuzz input
    const stdin = std.io.getStdIn();
    // sync size with afl-fuzz(1) -G argument
    var readb: [64]u8 = undefined;
    const readn = try stdin.readAll(&readb);
    const fuzz_in: []const u8 = readb[0..readn];

    var buf: [256]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    const urn = urlink.newUrn("test", fuzz_in, "Ol", fix.allocator()) catch {
        std.log.err("out of memory on {d} bytes of input with {d} bytes of space", .{ fuzz_in.len, buf.len });
        std.os.exit(137);
    };

    const view = urview.parse(urn) catch |err| {
        std.log.err("invalid URN result {s}: {}", .{ urn, err });
        std.os.exit(1);
    };
    if (!view.hasPath(fuzz_in)) {
        std.log.err("fuzz input does not match path of {s}", .{urn});
        std.os.exit(1);
    }
}
