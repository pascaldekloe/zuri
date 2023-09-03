const std = @import("std");
const ascii = std.ascii;
const os = std.os;
const mem = std.mem;

const zuri = @import("./zuri.zig");

pub fn main() !void {
    // fetch fuzz input
    const stdin = std.io.getStdIn();
    // sync size with afl-fuzz(1) -G argument
    var readb: [64]u8 = undefined;
    const readn = try stdin.readAll(&readb);
    const fuzz_in: []const u8 = readb[0..readn];

    const view = zuri.parse(fuzz_in) catch return;

    defer if (fuzzFail) os.exit(1);

    verifyConstraints(view, fuzz_in);
    if (!fuzzFail) verifyEscapeMatch(view);
    mem.doNotOptimizeAway(view.port());
}

var fuzzFail = false;

fn fail(comptime format: []const u8, args: anytype) void {
    fuzzFail = true;
    std.log.err(format, args);
}

var buf: [1024]u8 = undefined;

// VerifyConstraints checks the claims in field comments from Parts.
fn verifyConstraints(view: zuri.View, fuzz_in: []const u8) void {
    // lossless mapping
    {
        const components = .{ view.raw_scheme, view.raw_authority, view.raw_path, view.raw_query, view.raw_fragment };
        const rejoin = std.fmt.bufPrint(&buf, "{s}{s}{s}{s}{s}", components) catch "<fmt out of space>";
        if (!mem.eql(u8, rejoin, fuzz_in))
            fail("raw components concatenated {s} does not equal original input {s}", .{ rejoin, fuzz_in });
    }

    // scheme is the only required component
    if (!mem.endsWith(u8, view.raw_scheme, ":"))
        fail("raw scheme {s} does not end with a colon character", .{view.raw_scheme});

    if (view.raw_authority.len != 0) {
        if (!mem.startsWith(u8, view.raw_authority, "//"))
            fail("raw authority {s} does not start with two slashes", .{view.raw_authority});

        // subcomponents
        if (view.raw_userinfo.len != 0 and !mem.endsWith(u8, view.raw_userinfo, "@"))
            fail("raw userinfo {s} does not end with an at character", .{view.raw_userinfo});
        if (view.raw_port.len != 0 and !mem.startsWith(u8, view.raw_port, ":"))
            fail("raw port {s} does not start with a colon character", .{view.raw_port});

        const auth_components = .{ view.raw_userinfo, view.raw_host, view.raw_port };
        const reformat = std.fmt.bufPrint(&buf, "//{s}{s}{s}", auth_components) catch "<fmt out of space>";
        if (!mem.eql(u8, reformat, view.raw_authority))
            fail("raw authority components reformatted {s} do not equal raw authority {s}", .{ reformat, view.raw_authority });
    } else {
        if (view.raw_userinfo.len != 0)
            fail("raw userinfo {s} not zero with zero raw authority", .{view.raw_userinfo});
        if (view.raw_host.len != 0)
            fail("raw host {s} not zero with zero raw authority", .{view.raw_host});
        if (view.raw_port.len != 0)
            fail("raw port {s} not zero with zero raw authority", .{view.raw_port});
    }

    if (view.raw_path.len != 0 and view.raw_authority.len != 0 and !mem.startsWith(u8, view.raw_path, "/"))
        fail("raw path {s} with authority presence does not start with slash character", .{view.raw_path});
    if (view.raw_query.len != 0 and !mem.startsWith(u8, view.raw_query, "?"))
        fail("raw query {s} does not start with questionmark character", .{view.raw_query});
    if (view.raw_fragment.len != 0 and !mem.startsWith(u8, view.raw_fragment, "#"))
        fail("raw fragment {s} does not start with hash character", .{view.raw_fragment});
}

// VerifyEscapeMatch requires a verifyConstraints pass.
fn verifyEscapeMatch(view: zuri.View) void {
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fix.allocator();

    var s = view.scheme(allocator) catch "<scheme escape took too much memory>";
    if (!ascii.eqlIgnoreCase(view.raw_scheme[0 .. view.raw_scheme.len - 1], s))
        fail("escaped scheme {s} does not equal raw scheme {s} in lower-case excluding colon", .{ s, view.raw_scheme });
    allocator.free(s);

    var u = view.userinfo(allocator) catch "<userinfo escape took too much memory>";
    if (view.hasUserinfo(u) != (view.raw_userinfo.len != 0))
        fail("escaped user {s} is not matched by raw userinfo {s}", .{ u, view.raw_userinfo });
    allocator.free(u);

    var h = view.host(allocator) catch "<host escape took too much memory>";
    if (view.hasHost(h) != (view.raw_authority.len != 0))
        fail("escaped host {s} is not matched by raw {s}, authority {s}", .{ h, view.raw_host, view.raw_authority });
    allocator.free(h);

    var p = view.path(allocator) catch "<path escape took too much memory>";
    if (!view.hasPath(p))
        fail("escaped path {s} is not matched by raw {s}", .{ p, view.raw_path });
    allocator.free(p);

    var q = view.query(allocator) catch "<query escape took too much memory>";
    if (view.hasQuery(q) != (view.raw_query.len != 0))
        fail("escaped query {s} is not matched by raw {s}", .{ q, view.raw_query });
    allocator.free(q);

    var f = view.fragment(allocator) catch "<fragment escape took too much memory>";
    if (view.hasFragment(f) != (view.raw_fragment.len != 0))
        fail("escaped fragment {s} is not matched by raw {s}", .{ f, view.raw_fragment });
    allocator.free(f);
}
