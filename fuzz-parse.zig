const std = @import("std");
const ascii = std.ascii;
const os = std.os;
const mem = std.mem;

const zuri = @import("./zuri.zig");

const size_max = 1024; // upper boundary in bytes

pub fn main() !void {
    // fetch fuzzing input up to size_max
    var readb: [size_max]u8 = undefined;
    const stdin = std.io.getStdIn();
    const readn = try stdin.readAll(&readb);
    const fuzz_in = readb[0..readn];

    const parts = zuri.parse(fuzz_in) catch return;

    defer if (fuzzFail) os.exit(1);

    verifyConstraints(parts, fuzz_in);
    if (!fuzzFail) verifyEscapeMatch(parts);
    mem.doNotOptimizeAway(parts.port());
}

var fuzzFail = false;

fn fail(comptime format: []const u8, args: anytype) void {
    fuzzFail = true;
    std.log.err(format, args);
}

var buf: [size_max]u8 = undefined;

// VerifyConstraints checks the claims in field comments from Parts.
fn verifyConstraints(parts: zuri.Parts, fuzz_in: []const u8) void {
    // lossless mapping
    {
        const URI_parts = .{ parts.raw_scheme, parts.raw_authority, parts.raw_path, parts.raw_query, parts.raw_fragment };
        const rejoin = std.fmt.bufPrint(&buf, "{s}{s}{s}{s}{s}", URI_parts) catch "<fmt out of space>";
        if (!mem.eql(u8, rejoin, fuzz_in))
            fail("raw parts concatenated {s} does not equal original input {s}", .{ rejoin, fuzz_in });
    }

    // scheme is the only required part
    if (!mem.endsWith(u8, parts.raw_scheme, ":"))
        fail("raw scheme {s} does not end with a colon character", .{parts.raw_scheme});

    if (parts.raw_authority.len != 0) {
        if (!mem.startsWith(u8, parts.raw_authority, "//"))
            fail("raw authority {s} does not start with two slashes", .{parts.raw_authority});

        // subcomponents
        if (parts.raw_userinfo.len != 0 and !mem.endsWith(u8, parts.raw_userinfo, "@"))
            fail("raw userinfo {s} does not end with an at character", .{parts.raw_userinfo});
        if (parts.raw_port.len != 0 and !mem.startsWith(u8, parts.raw_port, ":"))
            fail("raw port {s} does not start with a colon character", .{parts.raw_port});

        const auth_parts = .{ parts.raw_userinfo, parts.raw_host, parts.raw_port };
        const reformat = std.fmt.bufPrint(&buf, "//{s}{s}{s}", auth_parts) catch "<fmt out of space>";
        if (!mem.eql(u8, reformat, parts.raw_authority))
            fail("raw authority parts reformatted {s} do not equal raw authority {s}", .{ reformat, parts.raw_authority });
    } else {
        if (parts.raw_userinfo.len != 0)
            fail("raw userinfo {s} not zero with zero raw authority", .{parts.raw_userinfo});
        if (parts.raw_host.len != 0)
            fail("raw host {s} not zero with zero raw authority", .{parts.raw_host});
        if (parts.raw_port.len != 0)
            fail("raw port {s} not zero with zero raw authority", .{parts.raw_port});
    }

    if (parts.raw_path.len != 0 and parts.raw_authority.len != 0 and !mem.startsWith(u8, parts.raw_path, "/"))
        fail("raw path {s} with authority presence does not start with slash character", .{parts.raw_path});
    if (parts.raw_query.len != 0 and !mem.startsWith(u8, parts.raw_query, "?"))
        fail("raw query {s} does not start with questionmark character", .{parts.raw_query});
    if (parts.raw_fragment.len != 0 and !mem.startsWith(u8, parts.raw_fragment, "#"))
        fail("raw fragment {s} does not start with hash character", .{parts.raw_fragment});
}

// VerifyEscapeMatch requires a verifyConstraints pass.
fn verifyEscapeMatch(parts: zuri.Parts) void {
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    const allocator = fix.allocator();

    var s = parts.scheme(allocator) catch "<scheme escape took too much memory>";
    if (!ascii.eqlIgnoreCase(parts.raw_scheme[0 .. parts.raw_scheme.len - 1], s))
        fail("escaped scheme {s} does not equal raw scheme {s} in lower-case excluding colon", .{ s, parts.raw_scheme });
    allocator.free(s);

    var u = parts.user(allocator) catch "<user escape took too much memory>";
    if (parts.hasUser(u) != (parts.raw_userinfo.len != 0))
        fail("escaped user {s} is not matched by raw userinfo {s}", .{ u, parts.raw_userinfo });
    allocator.free(u);

    var h = parts.host(allocator) catch "<host escape took too much memory>";
    if (parts.hasHost(h) != (parts.raw_authority.len != 0))
        fail("escaped host {s} is not matched by raw {s}, authority {s}", .{ h, parts.raw_host, parts.raw_authority });
    allocator.free(h);

    var p = parts.path(allocator) catch "<path escape took too much memory>";
    if (parts.hasPath(p) != (parts.raw_path.len != 0))
        fail("escaped path {s} is not matched by raw {s}", .{ p, parts.raw_path });
    allocator.free(p);

    var q = parts.query(allocator) catch "<query escape took too much memory>";
    if (parts.hasQuery(q) != (parts.raw_query.len != 0))
        fail("escaped query {s} is not matched by raw {s}", .{ q, parts.raw_query });
    allocator.free(q);

    var f = parts.fragment(allocator) catch "<fragment escape took too much memory>";
    if (parts.hasFragment(f) != (parts.raw_fragment.len != 0))
        fail("escaped fragment {s} is not matched by raw {s}", .{ f, parts.raw_fragment });
    allocator.free(f);
}
