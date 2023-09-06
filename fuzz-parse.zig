const std = @import("std");
const ascii = std.ascii;
const os = std.os;
const mem = std.mem;

const Urview = @import("./Urview.zig");

pub fn main() !void {
    // fetch fuzz input
    const stdin = std.io.getStdIn();
    // sync size with afl-fuzz(1) -G argument
    var readb: [64]u8 = undefined;
    const readn = try stdin.readAll(&readb);
    const fuzz_in: []const u8 = readb[0..readn];

    const ur = Urview.parse(fuzz_in) catch return;

    defer if (fuzzFail) os.exit(1);

    verifyConstraints(ur, fuzz_in);
    if (!fuzzFail) verifyEscapeMatch(ur);
    mem.doNotOptimizeAway(ur.port());
}

var fuzzFail = false;

fn fail(comptime format: []const u8, args: anytype) void {
    fuzzFail = true;
    std.log.err(format, args);
}

var buf: [1024]u8 = undefined;

// VerifyConstraints checks the claims in field comments from Parts.
fn verifyConstraints(ur: Urview, fuzz_in: []const u8) void {
    // lossless mapping
    {
        const components = .{ ur.raw_scheme, ur.raw_authority, ur.raw_path, ur.raw_query, ur.raw_fragment };
        const rejoin = std.fmt.bufPrint(&buf, "{s}{s}{s}{s}{s}", components) catch "<fmt out of space>";
        if (!mem.eql(u8, rejoin, fuzz_in))
            fail("raw components concatenated {s} does not equal original input {s}", .{ rejoin, fuzz_in });
    }

    // scheme is the only required component
    if (!mem.endsWith(u8, ur.raw_scheme, ":"))
        fail("raw scheme {s} does not end with a colon character", .{ur.raw_scheme});

    if (ur.raw_authority.len != 0) {
        if (!mem.startsWith(u8, ur.raw_authority, "//"))
            fail("raw authority {s} does not start with two slashes", .{ur.raw_authority});

        // subcomponents
        if (ur.raw_userinfo.len != 0 and !mem.endsWith(u8, ur.raw_userinfo, "@"))
            fail("raw userinfo {s} does not end with an at character", .{ur.raw_userinfo});
        if (ur.raw_port.len != 0 and !mem.startsWith(u8, ur.raw_port, ":"))
            fail("raw port {s} does not start with a colon character", .{ur.raw_port});

        const auth_components = .{ ur.raw_userinfo, ur.raw_host, ur.raw_port };
        const reformat = std.fmt.bufPrint(&buf, "//{s}{s}{s}", auth_components) catch "<fmt out of space>";
        if (!mem.eql(u8, reformat, ur.raw_authority))
            fail("raw authority components reformatted {s} do not equal raw authority {s}", .{ reformat, ur.raw_authority });
    } else {
        if (ur.raw_userinfo.len != 0)
            fail("raw userinfo {s} not zero with zero raw authority", .{ur.raw_userinfo});
        if (ur.raw_host.len != 0)
            fail("raw host {s} not zero with zero raw authority", .{ur.raw_host});
        if (ur.raw_port.len != 0)
            fail("raw port {s} not zero with zero raw authority", .{ur.raw_port});
    }

    if (ur.raw_path.len != 0 and ur.raw_authority.len != 0 and !mem.startsWith(u8, ur.raw_path, "/"))
        fail("raw path {s} with authority presence does not start with slash character", .{ur.raw_path});
    if (ur.raw_query.len != 0 and !mem.startsWith(u8, ur.raw_query, "?"))
        fail("raw query {s} does not start with questionmark character", .{ur.raw_query});
    if (ur.raw_fragment.len != 0 and !mem.startsWith(u8, ur.raw_fragment, "#"))
        fail("raw fragment {s} does not start with hash character", .{ur.raw_fragment});
}

// VerifyEscapeMatch requires a verifyConstraints pass.
fn verifyEscapeMatch(ur: Urview) void {
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fix.allocator();

    var s = ur.scheme(allocator) catch "<scheme escape took too much memory>";
    if (!ascii.eqlIgnoreCase(ur.raw_scheme[0 .. ur.raw_scheme.len - 1], s))
        fail("escaped scheme {s} does not equal raw scheme {s} in lower-case excluding colon", .{ s, ur.raw_scheme });
    allocator.free(s);

    var u = ur.userinfo(allocator) catch "<userinfo escape took too much memory>";
    if (ur.hasUserinfo(u) != (ur.raw_userinfo.len != 0))
        fail("escaped user {s} is not matched by raw userinfo {s}", .{ u, ur.raw_userinfo });
    allocator.free(u);

    var h = ur.host(allocator) catch "<host escape took too much memory>";
    if (ur.hasHost(h) != (ur.raw_authority.len != 0))
        fail("escaped host {s} is not matched by raw {s}, authority {s}", .{ h, ur.raw_host, ur.raw_authority });
    allocator.free(h);

    var p = ur.path(allocator) catch "<path escape took too much memory>";
    if (!ur.hasPath(p))
        fail("escaped path {s} is not matched by raw {s}", .{ p, ur.raw_path });
    allocator.free(p);

    var q = ur.query(allocator) catch "<query escape took too much memory>";
    if (ur.hasQuery(q) != (ur.raw_query.len != 0))
        fail("escaped query {s} is not matched by raw {s}", .{ q, ur.raw_query });
    allocator.free(q);

    var f = ur.fragment(allocator) catch "<fragment escape took too much memory>";
    if (ur.hasFragment(f) != (ur.raw_fragment.len != 0))
        fail("escaped fragment {s} is not matched by raw {s}", .{ f, ur.raw_fragment });
    allocator.free(f);
}
