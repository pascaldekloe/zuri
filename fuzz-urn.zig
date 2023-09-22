const std = @import("std");
const os = std.os;

const Urview = @import("./Urview.zig");
const Urname = @import("./Urname.zig");

pub fn main() !void {
    // fetch fuzz input
    const stdin = std.io.getStdIn();
    // sync size with afl-fuzz(1) -G argument
    var readb: [64]u8 = undefined;
    const readn = try stdin.readAll(&readb);
    const fuzz_in: []const u8 = readb[0..readn];

    var buf: [4 * readb.len + "urn:test:".len + "test:".len + 1]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    var allocator = fix.allocator();
    const urn = Urname.newUrn("test", fuzz_in, "Ol", allocator) catch {
        std.log.err("out of memory on {d} bytes of input with {d} bytes of space", .{ fuzz_in.len, buf.len });
        std.os.exit(137);
    };

    if (urn.len == 0) {
        if (fuzz_in.len != 0) {
            std.log.err("got zero string", .{});
            std.os.exit(1);
        }
        return;
    }

    const ur = Urview.parse(urn) catch |err| {
        std.log.err("invalid URN result {s}: {}", .{ urn, err });
        std.os.exit(1);
    };

    const want = std.mem.concat(allocator, u8, &.{ "test:", fuzz_in }) catch {
        std.log.err("out of memory on {d} bytes of input with {d} bytes of space", .{ fuzz_in.len, buf.len });
        std.os.exit(137);
    };
    if (!ur.equalsPath(want)) {
        std.log.err("fuzz input does not match path {s}", .{want});
        std.os.exit(1);
    }
}
