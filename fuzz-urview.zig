const std = @import("std");
const ascii = std.ascii;
const os = std.os;
const mem = std.mem;

const Urview = @import("./Urview.zig");

var buf: [1024]u8 = undefined;
var fix = std.heap.FixedBufferAllocator.init(&buf);
const allocator = fix.allocator();

pub fn main() !void {
    // fetch fuzz input
    const stdin = std.io.getStdIn();
    // sync size with afl-fuzz(1) -G argument
    var readb: [64:0]u8 = undefined;
    const readn = try stdin.readAll(&readb);
    if (readn < readb.len) readb[readn] = 0;

    const ur = Urview.parse(&readb) catch return;

    defer if (fuzzFail) os.exit(1);

    try verifyConstraints(ur, readb[0..readn]);
    if (!fuzzFail) try verifyEscapeMatch(ur);
    mem.doNotOptimizeAway(ur.internationalDomainName(allocator));
    mem.doNotOptimizeAway(ur.ip6Address());
    mem.doNotOptimizeAway(ur.portAsU16());

    allocator.free(try ur.pathNorm("", allocator));
    allocator.free(try ur.pathNorm("👯", allocator));
}

var fuzzFail = false;

fn fail(comptime format: []const u8, args: anytype) void {
    fuzzFail = true;
    std.log.err(format, args);
}

// VerifyConstraints checks the claims in field comments from Parts.
fn verifyConstraints(ur: Urview, fuzz_in: []const u8) !void {
    const raw_scheme = ur.rawScheme();
    const raw_authority = ur.rawAuthority();
    const raw_userinfo = ur.rawUserinfo();
    const raw_host = ur.rawHost();
    const raw_port = ur.rawPort();
    const raw_path = ur.rawPath();
    const raw_query = ur.rawQuery();
    const raw_fragment = ur.rawFragment();

    // lossless mapping
    {
        const rejoin = try std.fmt.allocPrint(allocator, "{s}{s}{s}{s}{s}", .{ raw_scheme, raw_authority, raw_path, raw_query, raw_fragment });
        defer allocator.free(rejoin);
        if (!mem.eql(u8, rejoin, fuzz_in))
            fail("raw components concatenated {s} do not equal original input {s}", .{ rejoin, fuzz_in });
    }

    // scheme is the only required component
    if (!mem.endsWith(u8, raw_scheme, ":"))
        fail("raw scheme {s} does not end with a colon character", .{raw_scheme});

    if (raw_authority.len != 0) {
        if (!mem.startsWith(u8, raw_authority, "//"))
            fail("raw authority {s} does not start with two slashes", .{raw_authority});

        // subcomponents
        if (raw_userinfo.len != 0 and !mem.endsWith(u8, raw_userinfo, "@"))
            fail("raw userinfo {s} does not end with an at character", .{raw_userinfo});
        if (raw_port.len != 0 and !mem.startsWith(u8, raw_port, ":"))
            fail("raw port {s} does not start with a colon character", .{raw_port});

        const auth_components = .{ raw_userinfo, raw_host, raw_port };
        const reformat = try std.fmt.allocPrint(allocator, "//{s}{s}{s}", auth_components);
        defer allocator.free(reformat);
        if (!mem.eql(u8, reformat, raw_authority))
            fail("raw authority components reformatted {s} do not equal raw authority {s}", .{ reformat, raw_authority });
    } else {
        if (raw_userinfo.len != 0)
            fail("raw userinfo {s} not zero with zero raw authority", .{raw_userinfo});
        if (raw_host.len != 0)
            fail("raw host {s} not zero with zero raw authority", .{raw_host});
        if (raw_port.len != 0)
            fail("raw port {s} not zero with zero raw authority", .{raw_port});
    }

    if (raw_path.len != 0 and raw_authority.len != 0 and !mem.startsWith(u8, raw_path, "/"))
        fail("raw path {s} with authority presence does not start with slash character", .{raw_path});
    if (raw_query.len != 0 and !mem.startsWith(u8, raw_query, "?"))
        fail("raw query {s} does not start with questionmark character", .{raw_query});
    if (raw_fragment.len != 0 and !mem.startsWith(u8, raw_fragment, "#"))
        fail("raw fragment {s} does not start with hash character", .{raw_fragment});
}

// VerifyEscapeMatch requires a verifyConstraints pass.
fn verifyEscapeMatch(ur: Urview) !void {
    var s = try ur.scheme(allocator);
    if (!ascii.eqlIgnoreCase(s, mem.trimRight(u8, ur.rawScheme(), ":")))
        fail("escaped scheme {s} does not equal raw scheme {s} in lower-case excluding colon", .{ s, ur.rawScheme() });
    allocator.free(s);

    var u = try ur.userinfo(allocator);
    if (ur.equalsUserinfo(u) != ur.hasUserinfo())
        fail("escaped user {s} is not matched by raw userinfo {s}", .{ u, ur.rawUserinfo() });
    allocator.free(u);

    var h = try ur.host(allocator);
    if (ur.equalsHost(h) != ur.hasAuthority())
        fail("escaped host {s} is not matched by raw {s}, authority {s}", .{ h, ur.rawHost(), ur.rawAuthority() });
    allocator.free(h);

    var p = try ur.path(allocator);
    if (!ur.equalsPath(p))
        fail("escaped path {s} is not matched by raw {s}", .{ p, ur.rawPath() });
    allocator.free(p);

    var q = try ur.query(allocator);
    if (ur.equalsQuery(q) != ur.hasQuery())
        fail("escaped query {s} is not matched by raw {s}", .{ q, ur.rawQuery() });
    allocator.free(q);

    var f = try ur.fragment(allocator);
    if (ur.equalsFragment(f) != ur.hasFragment())
        fail("escaped fragment {s} is not matched by raw {s}", .{ f, ur.rawFragment() });
    allocator.free(f);
}
