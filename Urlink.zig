//! Strict writings of URLs.

const std = @import("std");
const Allocator = std.mem.Allocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;

const expect = std.testing.expect;
const expectEqualStrings = std.testing.expectEqualStrings;

/// Urlink contains components for URL construction.
const Urlink = @This();

userinfo: ?[]const u8 = null,

/// Host is either a registered name or an IPv4 address. Use newIp6Url for IPv6
/// addresses.
host: []const u8 = "",

/// The default port number for the respective protocol should be omitted, i.e.,
/// specify non-standard values only.
port: ?u16 = null,

/// Relative paths are prefixed with a leading slash when any of userinfo, host
/// or port is present.
path: ?[]const u8 = null,

/// Segments append to the path component each with a leading slash character
/// ("/") in order of appearance. Use an empty empty string at the end for a
/// trailing slash.
segments: []const []const u8 = &.{},

query: ?[]const u8 = null,

/// Parameters append to the query component in order of appearance.
params: []const Param = &.{},

fragment: ?[]const u8 = null,

/// NewUrl returns a valid URL/URI. Caller owns the returned memory.
pub fn newUrl(ur: *const Urlink, comptime scheme: []const u8, m: Allocator) error{OutOfMemory}![:0]u8 {
    schemeCheck(scheme); // compile-time validation

    // buffer decimal port number
    var port_decimals: [5]u8 = undefined; // range ":0"–":65535"
    var port_offset: usize = undefined;
    if (ur.port) |portv| {
        var v: usize = @intCast(portv);
        // write backwards
        port_offset = port_decimals.len;
        while (true) {
            const decimal: u8 = @intCast(@mod(v, 10));
            port_offset -= 1;
            port_decimals[port_offset] = '0' + decimal;
            v /= 10;
            if (v == 0) break;
        }
    }

    // count output bytes
    var size = scheme.len + 3;
    if (ur.port) |_| size += 1 + port_decimals.len - port_offset;
    if (ur.userinfo) |u| size += userinfoSize(u);
    for (ur.host) |c| size += reg_name_char_sizes[c];
    size += ur.pathSize();
    if (ur.query) |s| size += queryOrFragmentSize(s);
    size += ur.params.len; // "?" or "&"
    for (ur.params) |param| size += param.size();
    if (ur.fragment) |s| size += queryOrFragmentSize(s);

    // output + write pointer
    var b = try m.allocSentinel(u8, size, 0);
    var p = b.ptr;
    inline for (scheme ++ "://") |c| {
        p[0] = c;
        p += 1;
    }

    if (ur.userinfo) |u| writeUserinfo(&p, u);
    for (ur.host) |c| {
        if (reg_name_char_sizes[c] & 2 == 0) {
            p[0] = c;
            p += 1;
        } else percentEncode(&p, c);
    }
    if (ur.port) |_| {
        p[0] = ':';
        p += 1;
        var s = port_decimals[port_offset..];
        @memcpy(p, s);
        p += s.len;
    }
    ur.writePath(&p);
    if (ur.query) |s| writeQueryOrFragment(&p, '?', s);
    for (ur.params, 0..) |param, i| {
        p[0] = if (i == 0 and ur.query == null) '?' else '&';
        p += 1;
        param.write(&p);
    }
    if (ur.fragment) |s| writeQueryOrFragment(&p, '#', s);
    return b;
}

test "URL Construction" {
    // allocate URIs without free to get readable errors (on single line)
    var buffer: [1024]u8 = undefined;
    var fix = FixedBufferAllocator.init(&buffer);
    const allocator = fix.allocator();

    // “Internationalized Resource Identifiers” RFC 3987, subsection 3.2.1
    try expectEqualStrings("http://xn--99zt52a.example.org/%E2%80%AE", try (&Urlink{ .host = "xn--99zt52a.example.org", .segments = &.{"\u{202E}"} }).newUrl("http", allocator));

    // “IMAP URL Scheme” RFC 2192, section 10
    try expectEqualStrings("imap://michael@minbari.org/users.*;type=list", try (&Urlink{ .userinfo = "michael", .host = "minbari.org", .path = "users.*;type=list" }).newUrl("imap", allocator));
    try expectEqualStrings("imap://psicorp.org/~peter/%E6%97%A5%E6%9C%AC%E8%AA%9E/%E5%8F%B0%E5%8C%97", try (&Urlink{ .host = "psicorp.org", .segments = &.{ "~peter", "日本語", "台北" } }).newUrl("imap", allocator));

    // “POP URL Scheme” RFC 2384, section 7
    try expectEqualStrings("pop://rg;AUTH=+APOP@mail.eudora.com:8110", try (&Urlink{ .userinfo = "rg;AUTH=+APOP", .host = "mail.eudora.com", .port = 8110 }).newUrl("pop", allocator));

    // port zero is sometimes used in configruation to match any free port
    try expectEqualStrings("wss://syncd%40cluster2@ferep%3Atun0:0", try (&Urlink{ .userinfo = "syncd@cluster2", .host = "ferep:tun0", .port = 0 }).newUrl("wss", allocator));

    try expectEqualStrings("redis://user:pass@127.0.0.1:6379/0?foo=bar&baz", try (&Urlink{ .userinfo = "user:pass", .host = "127.0.0.1", .port = 6379, .segments = &.{"0"}, .params = &.{ .{ .key = "foo", .value = "bar" }, .{ .key = "baz" } } }).newUrl("redis", allocator));

    try expectEqualStrings("http://?%20&%20=%20#%20", try (&Urlink{ .params = &.{ .{ .key = " " }, .{ .key = " ", .value = " " } }, .fragment = " " }).newUrl("http", allocator));
    try expectEqualStrings("http://?+=+&+#+", try (&Urlink{ .params = &.{ .{ .key = "+", .value = "+" }, .{ .key = "+" } }, .fragment = "+" }).newUrl("http", allocator));
}

/// NewIp6Url is like newUrl, yet it formats addr as an IPv6 address instead of
/// using the host field.
pub fn newIp6Url(ur: *const Urlink, comptime scheme: []const u8, addr: [16]u8, m: Allocator) error{OutOfMemory}![:0]u8 {
    schemeCheck(scheme); // compile-time validation

    const host_port_max = "[0000:0000:0000:0000:0000:0000:0000:0000]:65535".len;
    var buf: [host_port_max]u8 = undefined;
    var host_port = formatIp6AndPortIn(&buf, addr, ur.port);

    // count output bytes
    var size = scheme.len + 3;
    if (ur.userinfo) |u| size += userinfoSize(u);
    size += host_port.len;
    size += ur.pathSize();
    if (ur.query) |s| size += queryOrFragmentSize(s);
    size += ur.params.len; // "?" or "&"
    for (ur.params) |param| size += param.size();
    if (ur.fragment) |s| size += queryOrFragmentSize(s);

    // output + write pointer
    var b = try m.allocSentinel(u8, size, 0);
    var p = b.ptr;
    inline for (scheme ++ "://") |c| {
        p[0] = c;
        p += 1;
    }
    if (ur.userinfo) |u| writeUserinfo(&p, u);
    @memcpy(p, host_port);
    p += host_port.len;
    ur.writePath(&p);
    if (ur.query) |s| writeQueryOrFragment(&p, '?', s);
    for (ur.params, 0..) |param, i| {
        p[0] = if (i == 0) '?' else '&';
        p += 1;
        param.write(&p);
    }
    if (ur.fragment) |s| writeQueryOrFragment(&p, '#', s);
    return b;
}

test "IPv6 URL Construction" {
    // allocate URIs without free to get readable errors (on single line)
    var buffer: [1024]u8 = undefined;
    var fix = FixedBufferAllocator.init(&buffer);
    const allocator = fix.allocator();

    try expectEqualStrings("ftp://[::0]/%F0%9F%91%BE", try (&Urlink{ .segments = &.{"👾"} }).newIp6Url("ftp", .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, allocator));
    try expectEqualStrings("ssh://[::2]/%F0%9F%91%BB", try (&Urlink{ .segments = &.{"👻"} }).newIp6Url("ssh", .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }, allocator));
    try expectEqualStrings("echo://[102:3400::]:7", try (&Urlink{ .port = 7 }).newIp6Url("echo", .{ 1, 2, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, allocator));
    try expectEqualStrings("telnet://:guest@[1001::f607:809]", try (&Urlink{ .userinfo = ":guest" }).newIp6Url("telnet", .{ 16, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf6, 7, 8, 9 }, allocator));
}

/// FormatIp6AndPortIn encodes the address with an optional port number
/// using buf.
fn formatIp6AndPortIn(buf: *[47]u8, addr: [16]u8, port: ?u16) []u8 {
    // write backwards into buf
    var offset = buf.len;

    // optional port number
    if (port) |portv| {
        var v: usize = @intCast(portv);
        while (true) {
            offset -= 1;
            var decimal: u8 = @intCast(@mod(v, 10));
            buf[offset] = '0' + decimal;
            v /= 10;
            if (v == 0) break;
        }

        offset -= 1;
        buf[offset] = ':';
    }

    // IPv6 address
    offset -= 1;
    buf[offset] = ']';

    var zero_pair_count: usize = 0;
    var zero_pair_offset: usize = 0;
    ip6ZeroRange(addr, &zero_pair_count, &zero_pair_offset);
    if (zero_pair_count == 0) {
        // print all 8 octet-pairs
        var i = addr.len;
        while (true) {
            i -= 2;
            writeOctetPairBackwards(buf, &offset, addr[i], addr[i + 1]);
            if (i == 0) break;
            offset -= 1;
            buf[offset] = ':';
        }
    } else if (zero_pair_offset == 0) { // gap left
        // "::0" for all-zero case
        if (zero_pair_count > 7)
            zero_pair_count = 7;

        var pairn = 8 - zero_pair_count;
        var i = addr.len;
        for (0..pairn) |_| {
            i -= 2;
            writeOctetPairBackwards(buf, &offset, addr[i], addr[i + 1]);
            offset -= 1;
            buf[offset] = ':';
        }
        offset -= 1;
        buf[offset] = ':';
    } else { // gap right or middle
        if (zero_pair_offset + zero_pair_count > 7) { // gap right
            offset -= 1;
            buf[offset] = ':';
        } else { // gap middle
            var pairn = 8 - (zero_pair_offset + zero_pair_count);
            var i = addr.len;
            for (0..pairn) |_| {
                i -= 2;
                writeOctetPairBackwards(buf, &offset, addr[i], addr[i + 1]);
                offset -= 1;
                buf[offset] = ':';
            }
        }

        // left remainder
        var i = zero_pair_offset << 1;
        while (i != 0) {
            i -= 2;
            offset -= 1;
            buf[offset] = ':';
            writeOctetPairBackwards(buf, &offset, addr[i], addr[i + 1]);
        }
    }

    offset -= 1;
    buf[offset] = '[';
    return buf[offset..];
}

/// Ip6ZeroRange finds the longest sequence of octet-pairs with a zero value.
fn ip6ZeroRange(addr: [16]u8, countp: *usize, offsetp: *usize) void {
    var pair_count: usize = 0;
    var pair_offset: usize = 0;

    for (0..8) |pair_index| {
        if (addr[pair_index << 1] == 0 and addr[(pair_index << 1) + 1] == 0) {
            if (pair_count == 0) pair_offset = pair_index; // start sequence
            pair_count += 1;
        } else if (pair_count != 0) { // terminate sequence
            if (pair_count > countp.*) {
                countp.* = pair_count;
                offsetp.* = pair_offset;
            }
            pair_count = 0;
        }
    }
    if (pair_count > countp.*) {
        countp.* = pair_count;
        offsetp.* = pair_offset;
    }
}

test "IPv6 Zero Pairs" {
    const Golden = struct {
        addr: [16]u8,
        count: usize,
        offset: usize,
    };
    const tests = [_]Golden{
        // no zeroes
        .{ .addr = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, .count = 0, .offset = 0 },
        // all zeroes
        .{ .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .count = 8, .offset = 0 },
        // leading zeroes
        .{ .addr = .{ 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 }, .count = 2, .offset = 0 },
        .{ .addr = .{ 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 }, .count = 2, .offset = 0 },
        // tailing zeroes
        .{ .addr = .{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 128, 0, 0, 0, 0 }, .count = 2, .offset = 6 },
        .{ .addr = .{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 128, 0, 0, 0, 0, 0 }, .count = 2, .offset = 6 },

        // bigger sequence first
        .{ .addr = .{ 1, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 128 }, .count = 3, .offset = 1 },
        // bigger sequence second
        .{ .addr = .{ 128, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 128 }, .count = 3, .offset = 4 },
    };

    for (tests) |golden| {
        var count: usize = 0;
        var offset: usize = 0;
        ip6ZeroRange(golden.addr, &count, &offset);
        if (golden.count != count or golden.offset != offset) {
            std.debug.print("got {d}@{d} for address {d}, want {d}@{d}", .{ count, offset, golden.addr, golden.count, golden.offset });
            try expect(false);
        }
    }
}

/// “… producers and normalizers should use lowercase for registered names and
/// hexadecimal addresses for the sake of uniformity …”
// — RFC 3986, subsection 3.2.2
const lower_hex_digits = "0123456789abcdef";

/// WriteOctetPairBackwards encodes 16 bits in hexadecimal with any and all
/// leading zeroes omitted. Dst is written backwards, starting at pos minus one.
inline fn writeOctetPairBackwards(dst: *[47]u8, pos: *usize, o1: u8, o2: u8) void {
    pos.* -= 1;
    dst[pos.*] = lower_hex_digits[o2 & 0xf];
    if (o1 != 0 or o2 & 0xf0 != 0) {
        pos.* -= 1;
        dst[pos.*] = lower_hex_digits[o2 >> 4];
    }
    if (o1 != 0) {
        pos.* -= 1;
        dst[pos.*] = lower_hex_digits[o1 & 0xf];
        if (o1 & 0xf0 != 0) {
            pos.* -= 1;
            dst[pos.*] = lower_hex_digits[o1 >> 4];
        }
    }
}

fn schemeCheck(comptime scheme: []const u8) void {
    if (scheme.len == 0) @compileError("empty URI scheme");

    inline for (scheme, 0..) |c, i| switch (c) {
        // “… should only produce lowercase scheme names for consistency.”
        // — RFC 3986, subsection 3.1
        'A'...'Z' => @compileError("URI scheme with upper-case (production prohibited)"),
        'a'...'z' => continue,
        '0'...'9', '+', '-', '.' => if (i == 0) @compileError("URI scheme needs alphabet letter first"),
        else => @compileError("URI scheme with illegal character"),
    };
}

inline fn userinfoSize(s: []const u8) usize {
    var size: usize = 1; // "@"
    for (s) |c| size += userinfo_char_sizes[c];
    return size;
}

inline fn writeUserinfo(p: *[*]u8, s: []const u8) void {
    for (s) |c| {
        if (userinfo_char_sizes[c] & 2 == 0) {
            p.*[0] = c;
            p.* += 1;
        } else percentEncode(p, c);
    }

    p.*[0] = '@';
    p.* += 1;
}

inline fn pathSize(ur: *const Urlink) usize {
    var size: usize = 0;
    if (ur.path) |s| {
        if ((s.len == 0 or s[0] != '/') and (ur.userinfo != null or ur.host.len != 0 or ur.port != null)) size += 1;
        for (s) |c| size += path_char_sizes[c];
    }
    for (ur.segments) |seg| {
        size += 1; // "/"
        for (seg) |c| size += segment_char_sizes[c];
    }
    return size;
}

inline fn writePath(ur: *const Urlink, p: *[*]u8) void {
    if (ur.path) |s| {
        if ((s.len == 0 or s[0] != '/') and (ur.userinfo != null or ur.host.len != 0 or ur.port != null)) {
            p.*[0] = '/';
            p.* += 1;
        }
        for (s) |c| if (path_char_sizes[c] & 2 == 0) {
            p.*[0] = c;
            p.* += 1;
        } else percentEncode(p, c);
    }

    for (ur.segments) |seg| {
        p.*[0] = '/';
        p.* += 1;
        for (seg) |c| {
            if (segment_char_sizes[c] & 2 == 0) {
                p.*[0] = c;
                p.* += 1;
            } else percentEncode(p, c);
        }
    }
}

fn queryOrFragmentSize(s: []const u8) usize {
    var size: usize = 1; // "?" or "#"
    for (s) |c| size += query_or_fragment_char_sizes[c];
    return size;
}

fn writeQueryOrFragment(p: *[*]u8, comptime header: u8, s: []const u8) void {
    p.*[0] = header;
    p.* += 1;
    for (s) |c| {
        if (query_or_fragment_char_sizes[c] & 2 == 0) {
            p.*[0] = c;
            p.* += 1;
        } else percentEncode(p, c);
    }
}

/// Param represents a common format for the query component.
///
///     key ?( "=" value ) *( "&" key ?( "=" value ))
///
/// There are no constraints on the byte content. Key and value may or may not
/// be a valid UTF-8 string.
pub const Param = struct {
    // Key can be either a value label, or a tag on its own.
    key: []const u8,

    /// The equal character ("=") is omitted for null values.
    value: ?[]const u8 = null,

    fn size(param: Param) usize {
        var n: usize = 0;
        for (param.key) |c| n += param_char_sizes[c];
        if (param.value) |s| {
            n += 1; // "="
            for (s) |c| n += param_char_sizes[c];
        }
        return n;
    }

    fn write(param: Param, p: *[*]u8) void {
        writeParamValue(p, param.key);
        if (param.value) |s| {
            p.*[0] = '=';
            p.* += 1;
            writeParamValue(p, s);
        }
    }
};

inline fn writeParamValue(p: *[*]u8, s: []const u8) void {
    for (s) |c| {
        if (param_char_sizes[c] & 2 == 0) {
            p.*[0] = c;
            p.* += 1;
        } else percentEncode(p, c);
    }
}

const hex_digits = "0123456789ABCDEF";

inline fn percentEncode(p: *[*]u8, o: u8) void {
    p.*[0] = '%';
    p.*[1] = hex_digits[o >> 4];
    p.*[2] = hex_digits[o & 15];
    p.* += 3;
}

const userinfo_char_sizes: [256]u2 = buildUserinfoCharSizes();

fn buildUserinfoCharSizes() [256]u2 {
    var sizes: [256]u2 = undefined;
    // match userinfo from RFC 3986, subsection 3.2.1
    for (0..256) |c| sizes[c] = switch (c) {
        // unreserved
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => 1,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => 1,
        // userinfo
        ':' => 1,
        else => 3,
    };
    return sizes;
}

const reg_name_char_sizes: [256]u2 = buildRegNameCharSizes();

fn buildRegNameCharSizes() [256]u2 {
    var sizes: [256]u2 = undefined;
    // match reg-name from RFC 3986, subsection 3.2.2
    for (0..256) |c| sizes[c] = switch (c) {
        // unreserved
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => 1,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => 1,
        else => 3,
    };
    return sizes;
}

const path_char_sizes: [256]u2 = buildPathCharSizes();

fn buildPathCharSizes() [256]u2 {
    var sizes: [256]u2 = buildSegmentCharSizes();
    sizes['/'] = 1;
    return sizes;
}

const segment_char_sizes: [256]u2 = buildSegmentCharSizes();

fn buildSegmentCharSizes() [256]u2 {
    var sizes: [256]u2 = undefined;
    // match segment from RFC 3986, subsection 3.3
    for (0..256) |c| sizes[c] = switch (c) {
        // unreserved
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => 1,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => 1,
        // pchar
        ':', '@' => 1,
        else => 3,
    };
    return sizes;
}

const query_or_fragment_char_sizes: [256]u2 = buildQueryOrFragmentCharSizes();

fn buildQueryOrFragmentCharSizes() [256]u2 {
    var sizes: [256]u2 = undefined;
    // match query from RFC 3986, subsection 3.4
    // match fragment from RFC 3986, subsection 3.5
    for (0..256) |c| sizes[c] = switch (c) {
        // unreserved
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => 1,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => 1,
        // pchar
        ':', '@' => 1,
        // query ∪ fragment
        '/', '?' => 1,
        else => 3,
    };
    return sizes;
}

const param_char_sizes: [256]u2 = buildParamCharSizes();

fn buildParamCharSizes() [256]u2 {
    var sizes: [256]u2 = undefined;
    for (0..256) |c| sizes[c] = switch (c) {
        // unreserved
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => 1,
        // sub-delims − "=" − "+"
        '!', '$', '\'', '(', ')', '*', '+', ',', ';' => 1,
        // query
        ':', '@', '/', '?' => 1,
        else => 3,
    };
    return sizes;
}
