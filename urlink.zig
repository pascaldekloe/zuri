//! Strict formatting of URIs.

const std = @import("std");
const Allocator = std.mem.Allocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;

const expect = std.testing.expect;
const expectEqualStrings = std.testing.expectEqualStrings;

/// NewUrl returns a valid URL/URI.
pub fn newUrl(comptime scheme: []const u8, userinfo: ?[]const u8, hostname: []const u8, port: ?u16, path_segs: []const []const u8, m: Allocator) error{OutOfMemory}![]u8 {
    schemeCheck(scheme); // compile-time validation

    // buffer decimal port number
    var port_decimals: [5]u8 = undefined; // range ":0"–":65535"
    var port_offset: usize = undefined;
    if (port) |portv| {
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
    if (port) |_| size += 1 + port_decimals.len - port_offset;
    if (userinfo) |u| size += userinfoSize(u);
    for (hostname) |c| size += reg_name_char_sizes[c];
    size += pathSegsSize(path_segs);

    // output + write pointer
    var b = try m.alloc(u8, size);
    var p = b.ptr;
    inline for (scheme) |c| {
        p[0] = c;
        p += 1;
    }
    inline for ("://") |c| {
        p[0] = c;
        p += 1;
    }

    if (userinfo) |u| writeUserinfo(&p, u);
    for (hostname) |c| {
        if (reg_name_char_sizes[c] & 2 == 0) {
            p[0] = c;
            p += 1;
        } else percentEncode(&p, c);
    }
    if (port) |_| {
        p[0] = ':';
        p += 1;
        var s = port_decimals[port_offset..];
        @memcpy(p, s);
        p += s.len;
    }
    writePathSegs(&p, path_segs);
    return b;
}

test "URL Construction" {
    // allocate URIs without free to get readable errors (on single line)
    var buffer: [1024]u8 = undefined;
    var fix = FixedBufferAllocator.init(&buffer);
    const allocator = fix.allocator();

    // “Internationalized Resource Identifiers” RFC 3987, subsection 3.2.1
    try expectEqualStrings("http://xn--99zt52a.example.org/%E2%80%AE", try newUrl("http", null, "xn--99zt52a.example.org", null, &.{"\u{202E}"}, allocator));

    // “IMAP URL Scheme” RFC 2192, section 10
    try expectEqualStrings("imap://michael@minbari.org/users.*;type=list", try newUrl("imap", "michael", "minbari.org", null, &.{"users.*;type=list"}, allocator));
    try expectEqualStrings("imap://psicorp.org/~peter/%E6%97%A5%E6%9C%AC%E8%AA%9E/%E5%8F%B0%E5%8C%97", try newUrl("imap", null, "psicorp.org", null, &.{ "~peter", "日本語", "台北" }, allocator));

    // “POP URL Scheme” RFC 2384, section 7
    try expectEqualStrings("pop://rg;AUTH=+APOP@mail.eudora.com:8110", try newUrl("pop", "rg;AUTH=+APOP", "mail.eudora.com", 8110, &.{}, allocator));

    // port zero is sometimes used in configruation to match any free port
    try expectEqualStrings("wss://syncd%40cluster2@ferep%3Atun0:0", try newUrl("wss", "syncd@cluster2", "ferep:tun0", 0, &.{}, allocator));
}

pub fn newIp6Url(comptime scheme: []const u8, userinfo: ?[]const u8, addr: [16]u8, port: ?u16, path_segs: []const []const u8, m: Allocator) error{OutOfMemory}![]u8 {
    schemeCheck(scheme); // compile-time validation

    const host_port_max = "[0000:0000:0000:0000:0000:0000:0000:0000]:65535".len;
    var buf: [host_port_max]u8 = undefined;
    var host_port = formatIp6AndPortIn(&buf, addr, port);

    // count output bytes
    var size = scheme.len + 3;
    if (userinfo) |u| size += userinfoSize(u);
    size += host_port.len;
    size += pathSegsSize(path_segs);

    // output + write pointer
    var b = try m.alloc(u8, size);
    var p = b.ptr;
    inline for (scheme) |c| {
        p[0] = c;
        p += 1;
    }
    inline for ("://") |c| {
        p[0] = c;
        p += 1;
    }
    if (userinfo) |u| writeUserinfo(&p, u);
    @memcpy(p, host_port);
    p += host_port.len;
    writePathSegs(&p, path_segs);
    return b;
}

test "IPv6 URL Construction" {
    // allocate URIs without free to get readable errors (on single line)
    var buffer: [1024]u8 = undefined;
    var fix = FixedBufferAllocator.init(&buffer);
    const allocator = fix.allocator();

    try expectEqualStrings("ftp://[::0]/%F0%9F%91%BE", try newIp6Url("ftp", null, .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, null, &.{"👾"}, allocator));
    try expectEqualStrings("ssh://[::2]/%F0%9F%91%BB", try newIp6Url("ssh", null, .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }, null, &.{"👻"}, allocator));
    try expectEqualStrings("echo://[102:3400::]:7", try newIp6Url("echo", null, .{ 1, 2, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 7, &.{}, allocator));
    try expectEqualStrings("telnet://:guest@[1001::F607:809]", try newIp6Url("telnet", ":guest", .{ 16, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf6, 7, 8, 9 }, null, &.{}, allocator));
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

/// WriteOctetPairBackwards encodes 16 bits in hexadecimal with any and all
/// leading zeroes omitted. Dst is written backwards, starting at pos minus one.
inline fn writeOctetPairBackwards(dst: *[47]u8, pos: *usize, o1: u8, o2: u8) void {
    pos.* -= 1;
    dst[pos.*] = hex_table[o2 & 0xf];
    if (o1 != 0 or o2 & 0xf0 != 0) {
        pos.* -= 1;
        dst[pos.*] = hex_table[o2 >> 4];
    }
    if (o1 != 0) {
        pos.* -= 1;
        dst[pos.*] = hex_table[o1 & 0xf];
        if (o1 & 0xf0 != 0) {
            pos.* -= 1;
            dst[pos.*] = hex_table[o1 >> 4];
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

fn userinfoSize(s: []const u8) usize {
    var size: usize = 1; // "@"
    for (s) |c| size += userinfo_char_sizes[c];
    return size;
}

fn writeUserinfo(p: *[*]u8, s: []const u8) void {
    for (s) |c| {
        if (userinfo_char_sizes[c] & 2 == 0) {
            p.*[0] = c;
            p.* += 1;
        } else percentEncode(p, c);
    }

    p.*[0] = '@';
    p.* += 1;
}

fn pathSegsSize(segs: []const []const u8) usize {
    var size: usize = 0;
    for (segs) |seg| {
        size += 1; // "/"
        for (seg) |c| size += segment_char_sizes[c];
    }
    return size;
}

fn writePathSegs(p: *[*]u8, segs: []const []const u8) void {
    for (segs) |seg| {
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

/// NewUrn returns either a valid URN/URI or the empty string when specifics is
/// empty. An upper-case scheme "URN:" is used if and only if namespace contains
/// upper-case letters and if it contains no lower-case letters. The escape_set
/// opts in percent-encoding for octets in the specifics string which would
/// otherwise get included as is, namely 'A'–'Z', 'a'–'z', '0'–'9', '(', ')',
/// '+', ',', '-', '.', ':', '=', '@', ';', '$', '_', '!', '*', and '\''.
pub fn newUrn(comptime namespace: []const u8, specifics: []const u8, comptime escape_set: []const u8, m: Allocator) error{OutOfMemory}![]u8 {
    // compile-time validation
    const prefix = comptime urnPrefixFromNamespaceCheck(namespace);
    // match NSS from RFC 2141, subsection 2.2
    inline for (escape_set) |c| switch (c) {
        // <trans>
        'A'...'Z', 'a'...'z', '0'...'9' => {},
        // <other>
        '(', ')', '+', ',', '-', '.', ':', '=', '@', ';', '$', '_', '!', '*', '\'' => {},
        else => @compileError("URN escape set with redundant escape characer"),
    };

    if (specifics.len == 0) return "";

    var size: usize = prefix.len;
    for (specifics) |c| {
        size += inline for (escape_set) |o| {
            if (o == c) break 3;
        } else nss_char_sizes[c];
    }

    // output string + write pointer
    var b = try m.alloc(u8, size);
    inline for (prefix, 0..) |c, i| b[i] = c;
    var p = b.ptr + prefix.len;

    // match NSS from RFC 2141, subsection 2.2 with a jump table
    for (specifics) |c| {
        inline for (escape_set) |o| {
            if (o == c) {
                percentEncode(&p, o);
                break;
            }
        } else {
            if (nss_char_sizes[c] & 2 == 0) {
                p[0] = c;
                p += 1;
            } else percentEncode(&p, c);
        }
    }

    return b;
}

test "URN Construction" {
    // allocate URIs without free to get readable errors (on single line)
    var buffer: [4096]u8 = undefined;
    var fix = FixedBufferAllocator.init(&buffer);
    const allocator = fix.allocator();

    try expectEqualStrings("urn:Example:0", try newUrn("Example", "0", "Ol", allocator));
    try expectEqualStrings("URN:EXAMPLE:z", try newUrn("EXAMPLE", "z", "Ol", allocator));

    try expectEqualStrings("urn:oid:1:3:6:1:4:1:28114", try newUrn("oid", "1:3:6:1:4:1:28114", "", allocator));

    // “A URN Namespace for Public Identifiers” RFC 3151, section 3
    try expectEqualStrings("urn:publicid:3%2B3=6", try newUrn("publicid", "3+3=6", "+:;'", allocator));
}

fn urnPrefixFromNamespaceCheck(comptime namespace: []const u8) []const u8 {
    // letter-casing counts
    var uppern: usize = 0;
    var lowern: usize = 0;

    inline for (namespace, 0..) |c, i| switch (c) {
        'A'...'Z' => uppern += 1,
        'a'...'z' => lowern += 1,
        '0'...'9' => continue,
        '-' => {
            if (i == 0)
                @compileError("URN namespace identifier with hyphen prefix");
        },
        else => @compileError("URN namespace identifier with illegal character"),
    };

    if (namespace.len < 2)
        @compileError("URN namespace identifier with less than 2 characters");
    if (namespace.len > 32)
        @compileError("URN namespace identifier exceeds 32 characters");

    return if (lowern == 0 and uppern != 0) "URN:" ++ namespace ++ ":" else "urn:" ++ namespace ++ ":";
}

pub const QueryParam = struct {
    key: []const u8,
    value: ?[]const u8 = null,
};

/// AddParamsAndOrFragment returns a new URI with the query parameters and/or a
/// fragment appended to the input URI. Caller owns the result.
///
/// When params is not empty, then a query component is added conform the
/// defacto application/x-www-form-urlencoded standard. Note that spaces are
/// replaced by a plus ("+") character. The equals ("=") character is omitted
/// when a value is null.
pub fn addParamsAndOrFragment(uri: []const u8, params: []const QueryParam, fragment: ?[]const u8, m: Allocator) error{OutOfMemory}![]u8 {
    var size: usize = uri.len;
    for (params) |param| size += paramSize(param);
    if (fragment) |s| size += fragmentSize(s);
    var b = try m.alloc(u8, size);
    @memcpy(b.ptr, uri);

    // write pointer
    var p = b.ptr + uri.len;
    for (params, 0..) |param, i| {
        p[0] = if (i == 0) '?' else '&';
        p += 1;
        writeParamValue(&p, param.key);
        if (param.value) |s| {
            p[0] = '=';
            p += 1;
            writeParamValue(&p, s);
        }
    }
    if (fragment) |s| writeFragment(&p, s);
    return b;
}

test "Params and/or Fragment" {
    // allocate URIs without free to get readable errors (on single line)
    var buffer: [4096]u8 = undefined;
    var fix = FixedBufferAllocator.init(&buffer);
    const allocator = fix.allocator();

    try expectEqualStrings("arbitrary", try addParamsAndOrFragment("arbitrary", &.{}, null, allocator));
    try expectEqualStrings("arbitrary?foo", try addParamsAndOrFragment("arbitrary", &.{.{ .key = "foo" }}, null, allocator));
    try expectEqualStrings("arbitrary?foo=bar", try addParamsAndOrFragment("arbitrary", &.{.{ .key = "foo", .value = "bar" }}, null, allocator));
    try expectEqualStrings("arbitrary?%26%3D=%3D%26&%E2%98%A0%EF%B8%8F", try addParamsAndOrFragment("arbitrary", &.{ .{ .key = "&=", .value = "=&" }, .{ .key = "☠️" } }, null, allocator));

    try expectEqualStrings("arbitrary#", try addParamsAndOrFragment("arbitrary", &.{}, "", allocator));
    try expectEqualStrings("arbitrary#toc", try addParamsAndOrFragment("arbitrary", &.{}, "toc", allocator));

    // '+' = ' ' 🤡
    try expectEqualStrings("arbitrary?+&+=+#%20", try addParamsAndOrFragment("arbitrary", &.{ .{ .key = " " }, .{ .key = " ", .value = " " } }, " ", allocator));
    try expectEqualStrings("arbitrary?%2B=%2B&%2B#+", try addParamsAndOrFragment("arbitrary", &.{ .{ .key = "+", .value = "+" }, .{ .key = "+" } }, "+", allocator));
}

fn paramSize(p: QueryParam) usize {
    var n: usize = 1; // '?' or '&'
    for (p.key) |c| n += param_char_sizes[c];
    if (p.value) |s| {
        n += 1; // "="
        for (s) |c| n += param_char_sizes[c];
    }
    return n;
}

fn writeParamValue(p: *[*]u8, s: []const u8) void {
    for (s) |c| {
        if (c == ' ') {
            p.*[0] = '+';
            p.* += 1;
        } else if (param_char_sizes[c] & 2 == 0) {
            p.*[0] = c;
            p.* += 1;
        } else percentEncode(p, c);
    }
}

fn fragmentSize(s: []const u8) usize {
    var size: usize = 1; // "#"
    for (s) |c| size += fragment_char_sizes[c];
    return size;
}

fn writeFragment(p: *[*]u8, s: []const u8) void {
    p.*[0] = '#';
    p.* += 1;
    for (s) |c| {
        if (fragment_char_sizes[c] & 2 == 0) {
            p.*[0] = c;
            p.* += 1;
        } else percentEncode(p, c);
    }
}

const hex_table = "0123456789ABCDEF";

inline fn percentEncode(p: *[*]u8, o: u8) void {
    p.*[0] = '%';
    p.*[1] = hex_table[o >> 4];
    p.*[2] = hex_table[o & 15];
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

const fragment_char_sizes: [256]u2 = buildFragmentCharSizes();

fn buildFragmentCharSizes() [256]u2 {
    var sizes: [256]u2 = undefined;
    // match fragment from RFC 3986, subsection 3.5
    for (0..256) |c| sizes[c] = switch (c) {
        // unreserved
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => 1,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => 1,
        // pchar
        ':', '@' => 1,
        // query
        '/', '?' => 1,
        else => 3,
    };
    return sizes;
}

/// namespace-specific string table without reserved
const nss_char_sizes: [256]u2 = buildNssCharSizes();

fn buildNssCharSizes() [256]u2 {
    var sizes: [256]u2 = undefined;
    // match nss from RFC 2141, subsection 2.2, excluding reserved
    for (0..256) |c| sizes[c] = switch (c) {
        // upper
        'A'...'Z' => 1,
        // lower
        'a'...'z' => 1,
        // number
        '0'...'9' => 1,
        // other
        '(', ')', '+', ',', '-', '.', ':', '=', '@', ';', '$', '_', '!', '*', '\'' => 1,
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
        // sub-delims − "=&+"
        '!', '$', '\'', '(', ')', '*', ',', ';' => 1,
        // query
        ':', '@', '/', '?' => 1,
        // space is mapped to +
        ' ' => 1,
        else => 3,
    };
    return sizes;
}
