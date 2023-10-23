const Urview = @import("./Urview.zig");
const Urlink = @import("./Urlink.zig");

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
    var read_buf: [256]u8 = undefined;
    const read_count = try stdin.readAll(&read_buf);
    var fuzz_in: []const u8 = read_buf[0..read_count];

    // construct components from fuzz data in
    var ur = Urlink{};
    fuzz_in = sliceSome(&ur.host, fuzz_in);
    if (fuzz_in.len > 3 and fuzz_in[0] & 7 == 0) {
        ur.port = mem.readPackedIntNative(u16, fuzz_in, 1);
        fuzz_in = fuzz_in[3..];
    }
    fuzz_in = sliceSomeOptional(&ur.userinfo, fuzz_in);
    fuzz_in = sliceSomeOptional(&ur.query, fuzz_in);
    fuzz_in = sliceSomeOptional(&ur.fragment, fuzz_in);

    var seg_array = [3][]const u8{ "", "", "" };
    var param_array = [3]Urlink.Param{ .{ .key = "a" }, .{ .key = "b" }, .{ .key = "c" } };
    if (fuzz_in.len != 0) {
        const seg_count = fuzz_in[0] & 15;
        const param_count = fuzz_in[0] >> 4;
        fuzz_in = fuzz_in[1..];

        if (seg_count < seg_array.len) {
            for (0..seg_count) |i| {
                fuzz_in = sliceSome(&seg_array[i], fuzz_in);
            }
            ur.segments = seg_array[0..seg_count];
        }

        if (param_count < param_array.len) {
            for (0..param_count) |i| {
                fuzz_in = sliceSome(&param_array[i].key, fuzz_in);
                fuzz_in = sliceSomeOptional(&param_array[i].value, fuzz_in);
            }
            ur.params = param_array[0..param_count];
        }
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // build from components
    const url = ur.newUrl("example", allocator) catch |err|
        fatal("URL construction error.{}", .{err});

    // validate result
    const view = Urview.parse(url) catch |err| {
        fatal("invalid URL result {s}: {}", .{ url, err });
    };

    // validate lossless per component
    if (ur.userinfo) |want| {
        if (!view.hasUserinfo())
            fatal("fuzz userinfo {s} lost in {s}", .{ want, url });
        if (view.userinfo(allocator)) |got| {
            defer allocator.free(got);
            if (!mem.eql(u8, got, want)) {
                fatal("userinfo {s} became {s} in URL {s}", .{
                    want, got, url,
                });
            }
        } else |err| fatal("userinfo resolve error.{}", .{err});
    } else if (view.hasUserinfo())
        fatal("fuzz without userinfo became URL {s}", .{url});

    if (view.host(allocator)) |h| {
        defer allocator.free(h);
        if (!mem.eql(u8, h, ur.host)) {
            fatal("host {s} became {s} in URL {s}", .{
                ur.host, h, url,
            });
        }
    } else |err| fatal("host resolve error.{}", .{err});

    if (ur.port) |want| {
        if (view.portAsU16()) |got| {
            if (got != want) {
                fatal("fuzz with port {d} became {d} in URL {s}", .{
                    want, got, url,
                });
            }
        } else fatal("fuzz with port {d} became URL {s}", .{ want, url });
    } else if (view.hasPort())
        fatal("fuzz without port became URL {s}", .{url});

    if (ur.segments.len != 0) {
        const want = mem.join(allocator, "/", ur.segments) catch |err|
            fatal("path match error.{}", .{err});
        defer allocator.free(want);

        if (view.path(allocator)) |got| {
            defer allocator.free(got);
            if (got.len == 0 or got[0] != '/' or !mem.eql(u8, got[1..], want)) {
                fatal("fuzz with path {s} became {s} in URL {s}", .{
                    ur.segments, view.rawPath(), url,
                });
            }
        } else |err| fatal("path resolve error.{}", .{err});
    } else if (view.hasPath())
        fatal("fuzz without path segments became URL {s}", .{url});

    if (ur.params.len == 0) {
        if ((ur.query != null) != view.hasQuery())
            fatal("fuzz with query {?s} became URL {s}", .{ ur.query, url });
    } else if (ur.query != null) {
        if (!view.hasQuery())
            fatal("fuzz with query and parameters got lost in URL {s}", .{url});
    } else { // fuzz with params and no query
        if (!view.hasQuery()) {
            fatal("fuzz with {d} parameter got lost in URL {s}", .{
                ur.params.len, url,
            });
        }

        // parse
        var params = view.params(allocator) catch |err|
            fatal("parameter resolve error.{}", .{err});
        defer { // free memory
            for (params) |p| {
                allocator.free(p.key);
                if (p.value) |s| allocator.free(s);
            }
            allocator.free(params);
        }

        // compare
        if (params.len != ur.params.len) {
            fatal("fuzz with {d} parameters became {d} parameters in URL {s}", .{
                ur.params.len, params.len, url,
            });
        }
        for (params, ur.params, 1..) |got, want, param_count| {
            if (!mem.eql(u8, got.key, want.key) or (got.value == null) != (want.value == null) or got.value != null and !mem.eql(u8, got.value.?, want.value.?)) {
                fatal("fuzz parameter {d} in URL production {s} doesn't match fuzz input {s}={?s}", .{
                    param_count, url, want.key, want.value,
                });
            }
        }
    }

    if (ur.fragment) |want| {
        if (!view.hasFragment())
            fatal("fuzz with fragment {s} became URL {s}", .{ want, url });
        if (view.fragment(allocator)) |got| {
            defer allocator.free(got);
            if (!mem.eql(u8, got, want)) {
                fatal("fragment {s} became {s} in URL {s}", .{
                    want, got, url,
                });
            }
        } else |err| fatal("fragment resolve error.{}", .{err});
    } else if (view.hasFragment())
        fatal("fuzz withouth fragment became URL {s}", .{url});

    allocator.free(url);
    if (gpa.detectLeaks())
        fatal("fuzzer leaks memory", .{});
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    log.err(format, args);
    os.exit(1);
}

/// Slice a string from fuzz_data sometimes, and return the remainder.
fn sliceSome(to: *[]const u8, fuzz_data: []const u8) []const u8 {
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

/// Slice a string from fuzz_data sometimes, and return the remainder.
fn sliceSomeOptional(to: *?[]const u8, fuzz_data: []const u8) []const u8 {
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
