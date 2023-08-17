const std = @import("std");
const zuri = @import("./zuri.zig");

const size_max = 1024; // upper boundary in bytes

pub fn main() !void {
    // fetch fuzzing input up to size_max
    var readb: [size_max]u8 = undefined;
    const stdin = std.io.getStdIn();
    var readn = try stdin.readAll(&readb);
    var fuzz_in = readb[0..readn];

    var parts = try zuri.parse(fuzz_in);

    try verifyConstraints(parts, fuzz_in);
    try verifyEscapeMatch(parts);
    std.mem.doNotOptimizeAway(parts.port());
}

var buf: [size_max]u8 = undefined;

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectStringEndsWith = std.testing.expectStringEndsWith;
const expectStringStartsWith = std.testing.expectStringStartsWith;

fn expectFmt(want: []const u8, comptime template: []const u8, args: anytype) !void {
    const got = try std.fmt.bufPrint(&buf, template, args);
    return expectEqual(want, got);
}

// VerifyConstraints checks the claims in field comments from Parts.
fn verifyConstraints(parts: zuri.Parts, fuzz_in: []const u8) !void {
    // lossless mapping
    try expectFmt(fuzz_in, "{s}{s}{s}{s}{s}", .{ parts.raw_scheme, parts.raw_authority, parts.raw_path, parts.raw_query, parts.raw_fragment });

    // scheme is the only required part
    try expectStringEndsWith(parts.raw_scheme, ":");

    if (parts.raw_authority.len != 0) {
        try expectFmt(parts.raw_authority, "//{s}{s}{s}", .{ parts.raw_userinfo, parts.raw_host, parts.raw_port });
        if (parts.raw_userinfo.len != 0) try expectStringEndsWith(parts.raw_userinfo, "@");
        if (parts.raw_port.len != 0) try expectStringStartsWith(parts.raw_port, ":");
    } else {
        const empty: []const u8 = "";
        try expectEqual(empty, parts.raw_userinfo);
        try expectEqual(empty, parts.raw_host);
        try expectEqual(empty, parts.raw_port);
    }

    if (parts.raw_path.len != 0 and parts.raw_authority.len != 0) try expectStringStartsWith(parts.raw_path, "/");
    if (parts.raw_query.len != 0) try expectStringStartsWith(parts.raw_query, "?");
    if (parts.raw_fragment.len != 0) try expectStringStartsWith(parts.raw_fragment, "#");
}

fn verifyEscapeMatch(parts: zuri.Parts) !void {
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fix.allocator();

    var s = try parts.scheme(allocator);
    try expect(std.ascii.eqlIgnoreCase(parts.raw_scheme[0 .. parts.raw_scheme.len - 1], s));
    allocator.free(s);

    var u = try parts.user(allocator);
    try expect(parts.hasUser(u));
    allocator.free(u);

    var h = try parts.host(allocator);
    try expect(parts.hasHost(h));
    allocator.free(h);

    var p = try parts.path(allocator);
    try expect(parts.hasPath(p));
    allocator.free(p);

    var q = try parts.query(allocator);
    try expect(parts.hasQuery(q));
    allocator.free(q);

    var f = try parts.fragment(allocator);
    try expect(parts.hasFragment(f));
    allocator.free(f);
}
