const Urview = @import("./Urview.zig");

const std = @import("std");
const ascii = std.ascii;
const heap = std.heap;
const io = std.io;
const log = std.log;
const mem = std.mem;
const Allocator = mem.Allocator;
const os = std.os;

pub fn main() !void {
    defer if (fuzzFail) os.exit(1);

    // fetch fuzz input
    const stdin = io.getStdIn();
    // sync size with afl-fuzz(1) -G argument
    var read_buf: [64:0]u8 = undefined;
    const read_count = try stdin.readAll(&read_buf);
    if (read_count < read_buf.len) read_buf[read_count] = 0;

    const ur = Urview.parse(&read_buf) catch return;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    verifyConstraints(ur, read_buf[0..read_count], allocator);
    verifyEscapeMatch(ur, allocator);
    verifyResolves(ur, allocator);

    if (gpa.detectLeaks())
        fail("fuzzer leaks memory", .{});
}

var fuzzFail = false;

fn fail(comptime format: []const u8, args: anytype) void {
    fuzzFail = true;
    log.err(format, args);
}

// VerifyConstraints checks the claims in field comments from Parts.
fn verifyConstraints(ur: Urview, fuzz_in: []const u8, allocator: Allocator) void {
    const raw_scheme = ur.rawScheme();
    const raw_authority = ur.rawAuthority();
    const raw_userinfo = ur.rawUserinfo();
    const raw_host = ur.rawHost();
    const raw_port = ur.rawPort();
    const raw_path = ur.rawPath();
    const raw_query = ur.rawQuery();
    const raw_fragment = ur.rawFragment();

    // lossless mapping
    if (mem.concat(allocator, u8, &.{
        raw_scheme, raw_authority, raw_path, raw_query, raw_fragment,
    })) |want| {
        defer allocator.free(want);
        if (!mem.eql(u8, want, fuzz_in)) {
            fail("raw components joined in {s} do not equal fuzz input {s}", .{ want, fuzz_in });
        }
    } else |err| {
        log.err("raw URI parts join error.{}", .{err});
        os.exit(137);
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

        if (mem.concat(allocator, u8, &.{ "//", raw_userinfo, raw_host, raw_port })) |want| {
            defer allocator.free(want);
            if (!mem.eql(u8, want, raw_authority)) {
                fail("raw authority components joined in {s} don't equal raw authority {s}", .{
                    want, raw_authority,
                });
            }
        } else |err| {
            log.err("raw authority parts join error.{}", .{err});
            os.exit(137);
        }
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

fn verifyEscapeMatch(ur: Urview, allocator: Allocator) void {
    if (fuzzFail) return;

    if (ur.scheme(allocator)) |s| {
        defer allocator.free(s);
        if (!ascii.eqlIgnoreCase(s, mem.trimRight(u8, ur.rawScheme(), ":"))) {
            fail("escaped scheme {s} does not equal raw scheme {s} in lower-case excluding colon", .{
                s, ur.rawScheme(),
            });
        }
    } else |err| fail("scheme resolve error.{}", .{err});

    if (ur.userinfo(allocator)) |u| {
        defer allocator.free(u);
        if (ur.equalsUserinfo(u) != ur.hasUserinfo()) {
            fail("escaped user {s} is not matched by raw userinfo {s}", .{
                u, ur.rawUserinfo(),
            });
        }
    } else |err| fail("userinfo resolve error.{}", .{err});

    if (ur.host(allocator)) |h| {
        defer allocator.free(h);
        if (ur.equalsHost(h) != ur.hasAuthority()) {
            fail("escaped host {s} is not matched by raw {s}, authority {s}", .{
                h, ur.rawHost(), ur.rawAuthority(),
            });
        }
    } else |err| fail("host resolve error.{}", .{err});

    if (ur.path(allocator)) |p| {
        defer allocator.free(p);
        if (!ur.equalsPath(p)) {
            fail("escaped path {s} is not matched by raw {s}", .{
                p, ur.rawPath(),
            });
        }
    } else |err| fail("path resolve error.{}", .{err});

    if (ur.query(allocator)) |q| {
        defer allocator.free(q);
        if (ur.equalsQuery(q) != ur.hasQuery()) {
            fail("escaped query {s} is not matched by raw {s}", .{
                q, ur.rawQuery(),
            });
        }
    } else |err| fail("query resolve error.{}", .{err});

    if (ur.fragment(allocator)) |f| {
        defer allocator.free(f);
        if (ur.equalsFragment(f) != ur.hasFragment()) {
            fail("escaped fragment {s} is not matched by raw {s}", .{ f, ur.rawFragment() });
        }
    } else |err| fail("fragment resolve error.{}", .{err});
}

fn verifyResolves(ur: Urview, allocator: Allocator) void {
    if (fuzzFail) return;

    mem.doNotOptimizeAway(ur.ip6Address());
    if (ur.internationalDomainName(allocator)) |s| {
        allocator.free(s);
    } else |err| fail("international domain-name resolve error.{}", .{err});

    mem.doNotOptimizeAway(ur.portAsU16());

    if (ur.pathNorm("", allocator)) |s| {
        allocator.free(s);
    } else |err| fail("path normalization error.{}", .{err});
    if (ur.pathNorm("👯", allocator)) |s| {
        allocator.free(s);
    } else |err| fail("path normalization with Unicode replacement error.{}", .{err});

    var read_buf: [8]u8 = undefined;
    mem.doNotOptimizeAway(ur.readParam(&read_buf, "x"));
    mem.doNotOptimizeAway(ur.readWebParam(&read_buf, "yz"));

    if (ur.params(allocator)) |params| {
        for (params) |p| {
            allocator.free(p.key);
            if (p.value) |s| allocator.free(s);
        }
        allocator.free(params);
    } else |err| fail("parameter parse error.{}", .{err});
    if (ur.webParams(allocator)) |params| {
        for (params) |p| {
            allocator.free(p.key);
            if (p.value) |s| allocator.free(s);
        }
        allocator.free(params);
    } else |err| fail("web-parameter parse replacement error.{}", .{err});
}
