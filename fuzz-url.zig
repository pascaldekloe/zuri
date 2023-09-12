const std = @import("std");
const mem = std.mem;

const Urview = @import("./Urview.zig");
const Urlink = @import("./Urlink.zig");

pub fn main() !void {
    // fetch fuzz input
    const stdin = std.io.getStdIn();
    // sync size with afl-fuzz(1) -G argument
    var readb: [256]u8 = undefined;
    const readn = try stdin.readAll(&readb);
    var in: []const u8 = readb[0..readn];

    var buf: [readb.len * 4]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fix.allocator();

    // construct components from fuzz data in
    var ur = Urlink{};
    in = load(&ur.host, in);
    if (in.len > 3 and in[0] & 7 == 0) {
        ur.port = mem.readPackedIntNative(u16, in, 1);
        in = in[3..];
    }
    in = loadOptional(&ur.userinfo, in);
    in = loadOptional(&ur.fragment, in);

    if (in.len != 0) {
        const seg_count = in[0] & 15;
        const param_count = in[0] >> 4;
        in = in[1..];

        if (seg_count < 9) {
            var segs = try allocator.alloc([]const u8, seg_count);
            for (0..segs.len) |i| {
                // init malloc
                segs[i] = "";

                in = load(&segs[i], in);
            }
            ur.segments = segs;
        }

        if (param_count < 9) {
            var params = try allocator.alloc(Urlink.Param, param_count);
            for (0..params.len) |i| {
                // init malloc
                params[i].key = "";
                params[i].value = null;

                in = load(&params[i].key, in);
                in = loadOptional(&params[i].value, in);
            }
            ur.params = params;
        }
    }

    // build from components
    const url = ur.newUrl("example", allocator) catch {
        std.log.err("out of memory on {d} bytes of input with {d} bytes of space", .{ readn, buf.len });
        std.os.exit(137);
    };

    // validate result
    const view = Urview.parse(url) catch |err| {
        std.log.err("invalid URL result {s}: {}", .{ url, err });
        std.os.exit(1);
    };
    // validate lossless per component

    if ((view.raw_userinfo.len == 0) != (ur.userinfo == null)) {
        std.log.err("fuzz with userinfo {} became {} in URL {s}", .{
            ur.userinfo != null,
            view.raw_userinfo.len != 0,
            url,
        });
        std.os.exit(1);
    }
    if (ur.userinfo) |want| {
        const got = try view.userinfo(allocator);
        if (!mem.eql(u8, got, want)) {
            std.log.err("userinfo {s} became {s} in URL {s}", .{ want, got, url });
            std.os.exit(1);
        }
    }

    const h = try view.host(allocator);
    if (!mem.eql(u8, h, ur.host)) {
        std.log.err("host {s} became {s} in URL {s}", .{ ur.host, h, url });
        std.os.exit(1);
    }

    if ((view.raw_port.len == 0) != (ur.port == null)) {
        std.log.err("fuzz with port {} became {} in URL {s}", .{
            ur.port != null,
            view.raw_port.len != 0,
            url,
        });
        std.os.exit(1);
    }
    if (ur.port) |n| {
        if (view.port() != n) {
            std.log.err("fuzz with port {d} became {s} in URL {s}", .{ n, view.raw_port, url });
            std.os.exit(1);
        }
    }

    if (view.raw_path.len != ur.segments.len) {
        std.log.err("fuzz with path {s} became {s} in URL {s}", .{ ur.segments, view.raw_path, url });
        std.os.exit(1);
    }
    if (view.raw_path.len != 0) {
        const p = try view.path(allocator);
        if (p.len == 0 or !mem.eql(u8, p[1..], try mem.join(allocator, "/", ur.segments))) {
            std.log.err("fuzz with path {s} became {s} in URL {s}", .{ ur.segments, view.raw_path, url });
            std.os.exit(1);
        }
    }

    if (view.raw_query.len != ur.params.len) {
        std.log.err("fuzz with parameters {} became {} in URL {s}", .{
            ur.params.len != 0,
            view.raw_query.len != 0,
            url,
        });
        std.os.exit(1);
    }
    // TODO(pascaldekloe): query paramater parser

    if ((view.raw_fragment.len == 0) != (ur.fragment == null)) {
        std.log.err("fuzz with fragment {} became {} in URL {s}", .{
            ur.fragment != null,
            view.raw_fragment.len != 0,
            url,
        });
        std.os.exit(1);
    }
    if (ur.fragment) |want| {
        const got = try view.fragment(allocator);
        if (!mem.eql(u8, got, want)) {
            std.log.err("fragment {s} became {s} in URL {s}", .{ want, got, url });
            std.os.exit(1);
        }
    }
}

/// Load a string from fuzz_data sometimes, and return the fuzz_data remainder.
fn load(to: *[]const u8, fuzz_data: []const u8) []const u8 {
    // skip on EOF
    if (fuzz_data.len == 0) return "";
    var in = fuzz_data[1..];

    var size = @as(usize, fuzz_data[0]);
    // empty string 1 out of 4 times
    if (size > 31) size = 0;
    if (size > in.len) size = in.len;
    to.* = in[0..size];
    return in[size..];
}

/// Load a string from fuzz_data sometimes, and return the fuzz_data remainder.
fn loadOptional(to: *?[]const u8, fuzz_data: []const u8) []const u8 {
    // skip on EOF
    if (fuzz_data.len == 0) return "";
    // skip 7 out of 8 times
    if (fuzz_data[0] & 7 != 0) return fuzz_data[1..];
    var in = fuzz_data[1..];

    var size = @as(usize, fuzz_data[0] >> 3);
    // empty string half the time
    if (size > 16) size = 0;
    if (size > in.len) size = in.len;
    to.* = in[0..size];
    return in[size..];
}