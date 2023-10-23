const Urview = @import("./Urview.zig");
const Urname = @import("./Urname.zig");

const std = @import("std");
const heap = std.heap;
const io = std.io;
const log = std.log;
const mem = std.mem;
const os = std.os;

pub fn main() !void {
    // fetch fuzz input
    const stdin = io.getStdIn();
    // sync size with afl-fuzz(1) -G argument
    var read_buffer: [64]u8 = undefined;
    const read_count = try stdin.readAll(&read_buffer);
    const fuzz_in: []const u8 = read_buffer[0..read_count];

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const urn = Urname.newUrn("test", fuzz_in, "Ol", allocator) catch |err|
        fatal("URN construction error.{}", .{err});

    if (urn.len == 0) {
        if (fuzz_in.len != 0)
            fatal("new URN got zero string from non-zero input", .{});

        return;
    }

    const ur = Urview.parse(urn) catch |err|
        fatal("invalid URN result {s}: error.{}", .{ urn, err });

    if (mem.concat(allocator, u8, &.{ "test:", fuzz_in })) |want| {
        defer allocator.free(want);
        if (!ur.equalsPath(want))
            fatal("fuzz render {s} path mismatch", .{urn});
    } else |err| {
        fatal("compare string error.{}", .{err});
    }

    allocator.free(urn);
    if (gpa.detectLeaks())
        fatal("fuzzer leaks memory", .{});
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    log.err(format, args);
    os.exit(1);
}
