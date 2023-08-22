const std = @import("std");
const zuri = @import("./zuri.zig");

pub fn main() !void {
    // fetch fuzzing input
    const stdin = std.io.getStdIn();
    // sync size with afl-fuzz(1) -G argument
    var readb: [64]u8 = undefined;
    const readn = try stdin.readAll(&readb);
    var in: []const u8 = readb[0..readn];

    var buf: [1024]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fix.allocator();

    // construct parameters from input
    var params: []zuri.QueryParam = &.{};
    var fragment: ?[]const u8 = null;
    if (in.len != 0) {
        var param_count = in[0] & 3;
        var with_fragment = in[0] & 0xf0 == 0;
        in = in[1..];

        params = try allocator.alloc(zuri.QueryParam, param_count);
        if (params.len > 0) in = loadParam(&params[0], in);
        if (params.len > 1) in = loadParam(&params[1], in);
        if (params.len > 2) in = loadParam(&params[2], in);

        if (with_fragment) fragment = in;
    }

    const got = zuri.addParamsAndOrFragment("http://example.com/foo", params, fragment, allocator) catch {
        std.log.err("ran out of memory on {d} bytes of input with {d} bytes of space", .{ readn, buf.len });
        std.os.exit(137);
    };

    _ = zuri.parse(got) catch |err| {
        std.log.err("produced malformed URI {s}: {}", .{ got, err });
        std.os.exit(1);
    };
}

fn loadParam(p: *zuri.QueryParam, fuzz_data: []const u8) []const u8 {
    var in = fuzz_data;

    if (in.len == 0) return "";
    var kn = @as(usize, in[0] >> 2) & 7;
    var vn = @as(usize, in[0] >> 5) & 7;
    in = in[1..];

    if (kn > in.len) kn = in.len;
    p.key = in[0..kn];
    in = in[kn..];

    if (vn > 6) {
        p.value = null;
    } else {
        if (vn > in.len) vn = in.len;
        p.value = in[0..vn];
        in = in[vn..];
    }
    return in;
}
