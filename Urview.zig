//! Strict readings of URIs.

const std = @import("std");

const assert = std.debug.assert;

const parseInt = std.fmt.parseInt;

const Allocator = std.mem.Allocator;
const copyBackwards = std.mem.copyBackwards;
const indexOf = std.mem.indexOf;
const indexOfScalar = std.mem.indexOfScalar;
const lastIndexOfScalar = std.mem.lastIndexOfScalar;

const utf8CodepointSequenceLength = std.unicode.utf8CodepointSequenceLength;
const utf8Encode = std.unicode.utf8Encode;

const test_allocator = std.testing.allocator;
const expect = std.testing.expect;
const expectFmt = std.testing.expectFmt;
const expectEqual = std.testing.expectEqual;
const expectEqualStrings = std.testing.expectEqualStrings;
const expectStringEndsWith = std.testing.expectStringEndsWith;
const expectStringStartsWith = std.testing.expectStringStartsWith;

/// Urview provides read-only access to URI components. Input passed to parse
/// always equals the concatenation of its rawScheme, rawAuthority, rawPath,
/// rawQuery and rawFragment readings.
const Urview = @This();

// input reference + octet count
uri_ptr: [*:0]const u8,
uri_len: u16 = undefined,

// The seven offsets plus the overall (URI) size fits nicely into 16 bits.
// The userinfo offset could be calculated by comparing the authority and path
// offsets at the expense of an exectuion branche.

// Offsets are set (to non-zero) regardless of the component's presence.
authority_offset: u16 = undefined,
userinfo_offset: u16 = undefined,
host_offset: u16 = undefined,
port_offset: u16 = undefined,
path_offset: u16 = undefined,
query_offset: u16 = undefined,
fragment_offset: u16 = undefined,

/// The raw scheme component ends with ":".
pub fn rawScheme(ur: Urview) []const u8 {
    return ur.uri_ptr[0..ur.authority_offset];
}

/// The raw authority component starts with "//" when present.
pub fn rawAuthority(ur: Urview) []const u8 {
    return ur.uri_ptr[ur.authority_offset..ur.path_offset];
}

/// The authority component is optional.
pub fn hasAuthority(ur: Urview) bool {
    return ur.authority_offset < ur.path_offset;
}

/// The raw userinfo subcomponent ends with "@" when present.
pub fn rawUserinfo(ur: Urview) []const u8 {
    return ur.uri_ptr[ur.userinfo_offset..ur.host_offset];
}

/// The userinfo component is optional.
pub fn hasUserinfo(ur: Urview) bool {
    return ur.userinfo_offset < ur.host_offset;
}

/// The host subcomponent can be a registered name, or an IP address.
pub fn rawHost(ur: Urview) []const u8 {
    return ur.uri_ptr[ur.host_offset..ur.port_offset];
}

/// The host component is optional, even with an authority present.
pub fn hasHost(ur: Urview) bool {
    return ur.host_offset < ur.port_offset;
}

/// The host component can be an IPv6 address in square brackets ("[" and "]").
pub fn hasIp6Address(ur: Urview) bool {
    return ur.port_offset - ur.host_offset > 2 and ur.uri_ptr[ur.host_offset] == '[' and ur.uri_ptr[ur.host_offset + 1] != 'v';
}

/// The raw IPv6 zone identifier starts with "%25" when present.
pub fn rawIp6Zone(ur: Urview) []const u8 {
    if (ur.hasIp6Address()) {
        const raw = ur.rawHost();
        if (indexOf(u8, raw, "%25")) |i| return raw[i .. raw.len - 1];
    }
    return "";
}

/// The raw port subcomponent starts with ":" when present.
pub fn rawPort(ur: Urview) []const u8 {
    return ur.uri_ptr[ur.port_offset..ur.path_offset];
}

/// The port component is optional.
pub fn hasPort(ur: Urview) bool {
    return ur.port_offset < ur.path_offset;
}

/// The raw path compoment, if any, starts with "/" when the authority component
/// is present.
pub fn rawPath(ur: Urview) []const u8 {
    return ur.uri_ptr[ur.path_offset..ur.query_offset];
}

/// The path component is optional.
pub fn hasPath(ur: Urview) bool {
    return ur.path_offset < ur.query_offset;
}

/// The raw query compoment starts with "?" when present.
pub fn rawQuery(ur: Urview) []const u8 {
    return ur.uri_ptr[ur.query_offset..ur.fragment_offset];
}

/// The query component is optional.
pub fn hasQuery(ur: Urview) bool {
    return ur.query_offset < ur.fragment_offset;
}

/// The raw fragment component starts with "#" when present.
pub fn rawFragment(ur: Urview) []const u8 {
    return ur.uri_ptr[ur.fragment_offset..ur.uri_len];
}

/// The fragment component is optional.
pub fn hasFragment(ur: Urview) bool {
    return ur.fragment_offset < ur.uri_len;
}

/// Scheme returns the component in lower-case. Caller owns the retured memory.
pub fn scheme(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8 {
    const raw = ur.uri_ptr[0 .. ur.authority_offset - 1];
    var b = try m.allocSentinel(u8, raw.len, 0);
    for (raw, 0..) |c, i| {
        b[i] = if (c < 'A' or c > 'Z') c else c + ('a' - 'A');
    }
    return b;
}

/// EqualsScheme returns whether the component normalized to lower-case equals
/// match.
pub fn equalsScheme(ur: Urview, comptime match: []const u8) bool {
    // compile-time validation of match
    inline for (match) |c| switch (c) {
        'a'...'z', '0'...'9', '+', '-', '.' => continue,
        'A'...'Z' => @compileError("upper-case in scheme (never matches)"),
        else => @compileError("illegal character in scheme (never matches)"),
    };
    if (match.len == 0 or match[0] < 'a' or match[0] > 'z')
        @compileError("scheme without letter start (never matches)");

    if (match.len != ur.authority_offset - 1) return false;
    inline for (match, 0..) |c, i| {
        var r = ur.uri_ptr[i];
        if (r != c and (c < 'a' or c > 'z' or c - ('a' - 'A') != r))
            return false;
    }
    return true;
}

/// Userinfo returns the component with any and all percent-encodings resolved.
/// None of the applicable standards put any constraints on the byte content.
/// The return may or may not be a valid UTF-8 string. Caller owns the returned
/// memory.
pub fn userinfo(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8 {
    const offset = ur.userinfo_offset;
    const end = ur.host_offset - 1; // trim '@'
    if (offset >= end) return m.allocSentinel(u8, 0, 0);
    return resolvePercentEncodings(ur.uri_ptr[offset..end], m);
}

/// EqualsUserinfo returns whether the component with any and all percent-
/// encodings resolved equals match. Absent components don't equal any match.
pub fn equalsUserinfo(ur: Urview, match: []const u8) bool {
    const offset = ur.userinfo_offset;
    const end = ur.host_offset - 1; // trim '@'
    if (offset > end) return false;
    return equalsString(ur.uri_ptr[offset..end], match);
}

/// Host returns the component with any and all percent-encodings resolved in
/// lower-case. None of the applicable standards put any constraints on the byte
/// content. The return may or may not be a valid UTF-8 string. Caller owns the
/// returned memory.
pub fn host(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8 {
    if (ur.host_offset >= ur.port_offset) return m.allocSentinel(u8, 0, 0);
    return resolvePercentEncodingsToLower(ur.uri_ptr[ur.host_offset..ur.port_offset], m);
}

/// EqualsHost returns whether the component with any and all percent-encodings
/// resolved equals match. Absent components don't equal any match.
pub fn equalsHost(ur: Urview, match: []const u8) bool {
    if (ur.authority_offset >= ur.path_offset) return false;
    return equalsString(ur.rawHost(), match);
}

/// DomainName returns the host component if and only if it is a valid domain
/// name in the DNS. A trailing dot is permitted (to indicate an absolute domain
/// name), yet the empty string and a single dot are not.
///
/// The top-level domain is NOT verified against the official IANA registration.
/// See <https://data.iana.org/TLD/tlds-alpha-by-domain.txt> for the full list.
pub fn domainName(ur: Urview) []const u8 {
    const raw = ur.rawHost();

    // “To simplify implementations, the total number of octets that represent a
    // domain name (i.e., the sum of all label octets and label lengths) is
    // limited to 255.”
    // — RFC 1034
    //
    // “URI producing applications must not use percent-encoding in host unless
    // it is used to represent a UTF-8 character sequence.”
    // — RFC 3986
    if (raw.len == 0 or raw.len > 253 and (raw[253] != '.' or raw.len != 254))
        return "";

    var i: usize = 0;
    while (i < raw.len) {
        // “Each node has a label, which is zero to 63 octets in length.”
        // — RFC 1034
        const label_limit = 63;
        const label_offset = i;

        switch (raw[i]) {
            'A'...'Z', 'a'...'z' => {},
            else => return "",
        }
        i += 1;

        while (i < raw.len and raw[i] != '.') : (i += 1) switch (raw[i]) {
            'A'...'Z', 'a'...'z', '0'...'9', '-' => {},
            else => return "",
        };
        // i is at EOF or a dot

        if (raw[i - 1] == '-' or i - label_offset > label_limit)
            return "";
        i += 1;
    }

    return raw;
}

test "Domain Names" {
    try expectEqualStrings("www.example.com", (try parse("http://www.example.com")).domainName());
    try expectEqualStrings("www.example.com.", (try parse("http://www.example.com./")).domainName());
    try expectEqualStrings("xn--mller-kva.ch", (try parse("http://xn--mller-kva.ch")).domainName());

    try expectEqualStrings("", (try parse("example://")).domainName());
    try expectEqualStrings("", (try parse("example://.")).domainName());
    try expectEqualStrings("", (try parse("example://.com")).domainName());
    try expectEqualStrings("", (try parse("example://.example.com")).domainName());
    try expectEqualStrings("com", (try parse("example://com")).domainName());
    try expectEqualStrings("com.", (try parse("example://com.")).domainName());
    try expectEqualStrings("c.c4.c-4", (try parse("example://c.c4.c-4")).domainName());

    try expectEqualStrings("", (try parse("example://3.example.com")).domainName());
    try expectEqualStrings("", (try parse("example://xn-.com")).domainName());
    try expectEqualStrings("", (try parse("example://xn--.com")).domainName());

    // label exceeds 63 characters
    try expectEqualStrings("", (try parse("http://www.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com")).domainName());
    // domain exceeds 253 characters
    try expectEqualStrings("", (try parse("http://ww.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.example.com")).domainName());
    try expectEqualStrings("", (try parse("http://ww.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.example.com.")).domainName());
    // 254 characters permitted with leading dot
    try expectEqualStrings("w.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.example.com.", (try parse("http://w.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.www.example.com.")).domainName());
}

/// IDN provides characters beyond the DNS range. The function maps to UTF-8,
/// including null terminator, with the empty string for absence or non-DNS host
/// components. Caller owns the returned memory.
pub fn internationalDomainName(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8 {
    const raw = ur.domainName();
    if (raw.len == 0) return m.dupeZ(u8, "");

    // Collect as Unicode codepoints in a heap buffer first.
    // Punycode produces at most one codepoint per input octet.
    var buf: [254]u21 = undefined;
    var bufn: usize = 0;

    var offset: usize = 0;
    while (true) {
        // read label
        var end = raw.len;
        if (indexOfScalar(u8, raw[offset..], '.')) |i|
            end = offset + i;
        const raw_label = raw[offset..end];

        // try as punycode
        const codepoint_count = readPunycodeLabel(buf[bufn..], raw_label);
        if (codepoint_count != 0) {
            // got an IDN label
            bufn += codepoint_count;
        } else {
            // copy non-IDN label as is
            for (raw_label) |c| {
                buf[bufn] = c;
                bufn += 1;
            }
        }

        if (end >= raw.len) break;
        buf[bufn] = '.';
        bufn += 1;
        offset = end + 1;
        if (offset >= raw.len) break;
    }

    var utf8_size: usize = 0;
    for (buf[0..bufn]) |c| utf8_size += utf8CodepointSequenceLength(c) catch unreachable;
    var utf8 = try m.allocSentinel(u8, utf8_size, 0);
    var write_index: usize = 0;
    for (buf[0..bufn]) |c| write_index += utf8Encode(c, utf8[write_index..]) catch unreachable;
    assert(write_index == utf8.len);
    return utf8;
}

test "IDN" {
    var buf: [2048]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    try expectEqualStrings("台灣", try (try parse("http://xn--kpry57d")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("台灣", try (try parse("http://XN--KPRY57D")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("台灣", try (try parse("http://xN--kPrY57d")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("台灣", try (try parse("http://Xn--KpRy57D")).internationalDomainName(fix.allocator()));

    try expectEqualStrings("müller.ch", try (try parse("http://xn--mller-kva.ch")).internationalDomainName(fix.allocator()));

    try expectEqualStrings("🔥👯♀✨", try (try parse("example://xn--e5h45at481i1ua")).internationalDomainName(fix.allocator()));

    // “Sample strings” from RFC 3492, subsection 7.1
    try expectEqualStrings("ليهمابتكلموشعربي؟", try (try parse("example://xn--egbpdaj6bu4bxfgehfvwxn")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("他们为什么不说中文", try (try parse("example://xn--ihqwcrb4cv8a8dqg056pqjye")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("他們爲什麽不說中文", try (try parse("example://xn--ihqwctvzc91f659drss3x8bo0yb")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("Pročprostěnemluvíčesky", try (try parse("example://xn--Proprostnemluvesky-uyb24dma41a")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("למההםפשוטלאמדבריםעברית", try (try parse("example://xn--4dbcagdahymbxekheh6e0a7fei0b")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("यहलोगहिन्दीक्योंनहींबोलसकतेहैं", try (try parse("example://xn--i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("なぜみんな日本語を話してくれないのか", try (try parse("example://xn--n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa")).internationalDomainName(fix.allocator()));
    // H exceeds size-limit of node
    try expectEqualStrings("", try (try parse("example://xn--989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a0dt30a5jpsd879ccm6fea98c")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("почемужеонинеговорятпорусски", try (try parse("example://xn--b1abfaaepdrnnbgefbaDotcwatmq2g4l")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("PorquénopuedensimplementehablarenEspañol", try (try parse("example://xn--PorqunopuedensimplementehablarenEspaol-fmd56a")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("TạisaohọkhôngthểchỉnóitiếngViệt", try (try parse("example://xn--TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("3年B組金八先生", try (try parse("example://xn--3B-ww4c5e180e575a65lsy2b")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("安室奈美恵-with-SUPER-MONKEYS", try (try parse("example://xn---with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("Hello-Another-Way-それぞれの場所", try (try parse("example://xn--Hello-Another-Way--fc4qua05auwb3674vfr0b")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("ひとつ屋根の下2", try (try parse("example://xn--2-u9tlzr9756bt3uc0v")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("MajiでKoiする5秒前", try (try parse("example://xn--MajiKoi5-783gue6qz075azm5e")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("パフィーdeルンバ", try (try parse("example://xn--de-jg4avhby1noc0d")).internationalDomainName(fix.allocator()));
    try expectEqualStrings("そのスピードで", try (try parse("example://xn--d9juau41awczczp")).internationalDomainName(fix.allocator()));
}

/// ReadPunycode parses raw in full, and it returns the number of codepoints
/// set in buf, with zero for invalid punycode encounters.
fn readPunycodeLabel(buf: []u21, raw: []const u8) usize {
    var bufn: usize = 0; // read count in octets (to return)

    // “The ACE prefix for IDNA is "xn--" or any capitalization thereof.”
    // “(ACE stands for ASCII Compatible Encoding)”
    // — RFC 3490, section 5.
    const ace_prefix = "xn--";

    if (raw.len < 4 or raw[0] != 'x' and raw[0] != 'X' or raw[1] != 'n' and raw[1] != 'N' or raw[2] != '-' or raw[3] != '-')
        return 0;
    var rawi: usize = ace_prefix.len;

    const segregation_split = lastIndexOfScalar(u8, raw, '-').?;
    if (segregation_split > ace_prefix.len) {
        for (ace_prefix.len..segregation_split) |i| {
            buf[bufn] = raw[i];
            bufn += 1;
        }
        rawi = segregation_split + 1;
    }
    assert(rawi < raw.len); // labels can't end in '-'

    const base = 36; // case-insensitive alphanumeric

    // “Decoding procedure” from RFC 3492, subsection 6.2
    var codepoint: usize = 128; // called n in spec
    var i: usize = 0; // write index is not sequential
    var bias: usize = 72;

    parse_codepoint: while (true) {
        const old_i: usize = i;

        var digit = @as(usize, base36_table[raw[rawi]]);
        rawi += 1;
        if (digit >= base) break :parse_codepoint;

        i += digit; // won't overflow as i gets truncated to modulo readn

        var weight: usize = 1; // called w in spec, a.k.a. the scale factor
        var base_step: usize = base + base; // called k in spec

        const t_min = 1;
        const t_max = 26;
        var t: usize = if (base <= bias) t_min else @min(base - bias, t_max);
        while (digit >= t) : (base_step += base) {
            // update weight, inbetween × 10 and × 35
            weight *= base - t;

            // read digit
            if (rawi >= raw.len) break :parse_codepoint;
            digit = @as(usize, base36_table[raw[rawi]]);
            rawi += 1;
            if (digit >= base) break :parse_codepoint;

            // update i
            i += digit * weight;
            // Failfast on i ÷ bufn ≥ U+10ffff prevents codepoint overflow
            // below and it also elminates the overflow checks on weight.
            if (i > 254 * 0x10ffff) break :parse_codepoint;

            // update t, range 1–26
            t = if (base_step <= bias) t_min else @min(base_step - bias, t_max);
        }

        bufn += 1; // grow with one codepoint

        // set bias conform “Bias adaptation” from RFC 3492, subsection 3.4
        var delta = i - old_i;
        // “Delta is scaled in order to avoid overflow in the next step”
        delta /= if (old_i == 0) 700 else 2;
        // “Delta is increased to compensate for the fact that the next delta
        // will be inserting into a longer string”
        delta += delta / bufn;
        bias = 0; // omit k from spec
        // “Delta is repeatedly divided until it falls within a threshold, to
        // predict the minimum number of digits needed to represent the next
        // delta”
        while (delta > ((base - t_min) * t_max) / 2) {
            delta /= base - t_min;
            bias += base;
        }
        bias += (base * delta) / (delta + 38);

        // define the new codepoint
        codepoint += i / bufn;
        // check range and not surrogate
        if (codepoint > 0x10ffff or codepoint >= 0xd800 and codepoint <= 0xdfff)
            break :parse_codepoint;

        // insert new codepoint at i(ndex)
        i %= bufn;
        copyBackwards(u21, buf[i + 1 ..], buf[i .. bufn - 1]);
        buf[i] = @intCast(codepoint); // range checked above
        i += 1;

        if (rawi >= raw.len) return bufn;
    }

    return 0; // failed
}

const base36_table = buildBase36Table();

fn buildBase36Table() [256]u6 {
    var table: [256]u6 = undefined;
    for (0..256) |c| table[c] = switch (c) {
        '0'...'9' => c - '0' + 26,
        'A'...'Z' => c - 'A',
        'a'...'z' => c - 'a',
        else => 63,
    };
    return table;
}

/// Ip6Zone returns the IPv6 zone idententifier from the host component with any
/// and all percent-encodings resolved. None of the applicable standandards put
/// any constraints on the byte content. The return may or may not be a valid
/// UTF-8 string. Caller owns the returned memory.
pub fn ip6Zone(ur: Urview, m: Allocator) error{OutOfMemory}![]const u8 {
    const raw = ur.rawIp6Zone();
    if (raw.len == 0) return "";
    return resolvePercentEncodings(raw[3..], m);
}

/// EqualsIp6Zone returns the IPv6 zone idententifier from the host component
/// with any and all percent-encodings resolved equals match. Absent components
/// don't equal any match.
pub fn equalsIp6Zone(ur: Urview, match: []const u8) bool {
    const raw = ur.rawIp6Zone();
    return raw.len != 0 and equalsString(raw[3..], match);
}

test "IPv6 Zone Identifier" {
    var buf: [32]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    try expectEqualStrings("en1", try (try parse("http://[fe80::a%25en1]")).ip6Zone(fix.allocator()));
    try expectEqualStrings("🏯", try (try parse("http://[::1%25%F0%9F%8F%AF]")).ip6Zone(fix.allocator()));
    try expect((try parse("http://[fe80::a%25en1]")).equalsIp6Zone("en1"));
    try expect((try parse("http://[::1%25%F0%9F%8F%AF]")).equalsIp6Zone("🏯"));
}

/// TCP and UDP use 16-bit port numbers (range 0–65535). The return is null when
/// the URI defines no port, or when the value is out of bounds, or when leading
/// zeroes bring the total number of decimals beyond five positions.
pub fn portAsU16(ur: Urview) ?u16 {
    // decimal value table (prevents multiplication)
    const decis: [10]u16 = .{ 0, 10, 20, 30, 40, 50, 60, 70, 80, 90 };
    const hectas: [10]u16 = .{ 0, 100, 200, 300, 400, 500, 600, 700, 800, 900 };
    const kilos: [10]u16 = .{ 0, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000 };
    const leads: [7]u16 = .{ 0, 10000, 20000, 30000, 40000, 50000, 60000 };

    const offset = @as(usize, ur.port_offset); // includes ":" if any
    const end = @as(usize, ur.path_offset);
    // parse values ":0"–":65535" exclusively; "" and ":" underflow usize
    return switch (end -% offset -% 2) {
        0 => @as(u16, ur.uri_ptr[end - 1] - '0'),
        1 => @as(u16, ur.uri_ptr[end - 1] - '0') + decis[ur.uri_ptr[end - 2] - '0'],
        2 => @as(u16, ur.uri_ptr[end - 1] - '0') + decis[ur.uri_ptr[end - 2] - '0'] + hectas[ur.uri_ptr[end - 3] - '0'],
        3 => @as(u16, ur.uri_ptr[end - 1] - '0') + decis[ur.uri_ptr[end - 2] - '0'] + hectas[ur.uri_ptr[end - 3] - '0'] + kilos[ur.uri_ptr[end - 4] - '0'],
        4 => max_digits: {
            const port = @as(u16, ur.uri_ptr[end - 1] - '0') + decis[ur.uri_ptr[end - 2] - '0'] + hectas[ur.uri_ptr[end - 3] - '0'] + kilos[ur.uri_ptr[end - 4] - '0'];
            const msd = @as(u16, ur.uri_ptr[end - 5] - '0');
            if (msd > 6 or (msd == 6 and port > 5535)) break :max_digits null;
            break :max_digits leads[msd] + port;
        },
        else => null,
    };
}

test "16-Bit Port Numbers" {
    try expectEqual(@as(?u16, null), (try parse("example://")).portAsU16());
    try expectEqual(@as(?u16, null), (try parse("example://:")).portAsU16());
    try expectEqual(@as(?u16, 0), (try parse("example://:0")).portAsU16());
    try expectEqual(@as(?u16, 1), (try parse("example://:1")).portAsU16());
    try expectEqual(@as(?u16, 12), (try parse("example://:12")).portAsU16());
    try expectEqual(@as(?u16, 123), (try parse("example://:123")).portAsU16());
    try expectEqual(@as(?u16, 1234), (try parse("example://:1234")).portAsU16());
    try expectEqual(@as(?u16, 12345), (try parse("example://:12345")).portAsU16());
    try expectEqual(@as(?u16, 65535), (try parse("example://:65535")).portAsU16());
    try expectEqual(@as(?u16, null), (try parse("example://:65536")).portAsU16());
    try expectEqual(@as(?u16, null), (try parse("example://:99999")).portAsU16());
    try expectEqual(@as(?u16, null), (try parse("example://:100000")).portAsU16());
}

/// Path returns the component with any and all percent-encodings resolved. None
/// of the applicable standards put any constraints on the byte content. The
/// return may or may not be a valid UTF-8 string. Caller owns the returned
/// memory.
pub fn path(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8 {
    const raw = ur.rawPath();
    if (raw.len == 0) return m.allocSentinel(u8, 0, 0);
    return resolvePercentEncodings(raw, m);
}

/// EqualsPath returns whether the component with any and all percent-encodings
/// resolved equals match.
pub fn equalsPath(ur: Urview, match: []const u8) bool {
    return equalsString(ur.rawPath(), match);
}

/// PathNorm returns the component with any and all percent-encodings resolved,
/// normalized conform the “Normalization and Comparison” rules of RFC 3986.
/// None of the applicable standards put any constraints on the byte content.
/// The return may or may not be a valid UTF-8 string. Caller owns the returned
/// memory.
///
/// Any and all percent-encoded slashes ("%2F") are written as encodedSlashOut.
/// Valid options include:
///
///  • Plain "/" undoes any percent-encoding of slashes
///  • Unicode Fullwidth Solidus U+FF0F ("／")
///  • Unicode Object Replacement Charactacter U+FFFC can be “used as
///    placeholder in text for an otherwise unspecified object”
///  • Empty "" simply drops percent-encoded slashes
///
pub fn pathNorm(ur: *const Urview, comptime encodedSlashOut: []const u8, m: Allocator) error{OutOfMemory}![:0]u8 {
    const raw = ur.rawPath();
    // normalization not possible with just one character
    if (raw.len < 2) return m.dupeZ(u8, raw);

    // first count output octets for memory allocation
    var size: usize = 0;

    // count sequential dot occurences to act upon "." and ".." segments
    var dot_count: usize = 0; // current streak in segment
    var seg_skipn: usize = 0; // pending dot-dot appliances

    // read path backwards because dot-dot applies to the previous
    var i = raw.len;

    // stop at first character in raw path
    scan_segment: while (i != 0) {
        i -= 1;
        switch (raw[i]) {
            '.' => {
                dot_count += 1;
                continue :scan_segment; // dot streak
            },

            'E', 'e' => {
                // percent-encoded dot possible
                if (i > 1 and raw[i - 1] == '2' and raw[i - 2] == '%') {
                    dot_count += 1;
                    i -= 2;
                    continue :scan_segment; // dot streak
                }
            },

            '/' => {
                // apply segment
                switch (dot_count) {
                    0, 1 => {}, // empty segment and single-dot discard
                    2 => seg_skipn += 1, // enqueue
                    else => size += dot_count + 1, // dots with slash
                }
                dot_count = 0; // reset for next
                continue :scan_segment;
            },

            else => {},
        }
        // segment not empty, not dot and not dot-dot

        // apply any pending dot-dots
        if (seg_skipn != 0) {
            seg_skipn -= 1;

            while (i != 0 and raw[i] != '/') i -= 1;
            dot_count = 0; // reset for next
            continue :scan_segment;
        }

        // count path separator on segment continuation
        if (size != 0) size += 1;

        // count any dots read
        size += dot_count;
        dot_count = 0; // reset

        // count segment remainder
        while (raw[i] != '/') {
            if (i < 2 or raw[i - 2] != '%') {
                size += 1;

                if (i == 0) break :scan_segment;
                i -= 1;
                continue;
            }

            // resolve percent-encoding
            const v = (hex_table[raw[i - 1]] << 4) | hex_table[raw[i]];
            size += if (v == '/') encodedSlashOut.len else 1;

            if (i < 3) break :scan_segment;
            i -= 3; // pass percent-encoding
        }
    }
    // pending dot-streak possible
    switch (dot_count) {
        0, 1 => {}, // discard empty segment or single dot
        2 => seg_skipn += 1, // enqueue dot-dot
        else => size += dot_count, // segment with three or more dots
    }

    if (raw[0] == '/') {
        // keep path absolute
        size += "/".len;
        // any dot-dots beyond root dropped
    } else if (seg_skipn != 0) {
        if (size != 0) size += "/".len;
        while (true) {
            size += "..".len;
            seg_skipn -= 1;
            if (seg_skipn == 0) break;
            size += "/".len;
        }
    } else if (size == 0) {
        // relative path deducted to zero
        size = ".".len;
    }

    // output string & write pointer
    var out = try m.allocSentinel(u8, size, 0);
    var p = out.ptr + size;

    // reset for second/final pass
    dot_count = 0;
    seg_skipn = 0;
    i = raw.len;

    // write segments (backwards) with lazy path separation
    map_segment: while (i != 0) {
        i -= 1;
        switch (raw[i]) {
            '.' => {
                dot_count += 1;
                continue :map_segment; // next
            },

            'E', 'e' => {
                // percent-encoded dot possible;
                if (i > 1 and raw[i - 1] == '2' and raw[i - 2] == '%') {
                    i -= 2;
                    dot_count += 1;
                    continue :map_segment; // next
                }
            },

            '/' => {
                // apply segment
                switch (dot_count) {
                    0, 1 => {
                        // discard empty segment or single dot
                        dot_count = 0;
                        continue :map_segment;
                    },
                    2 => {
                        // enqueue dot-dot
                        seg_skipn += 1;
                        dot_count = 0;
                        continue :map_segment;
                    },

                    else => {},
                }
            },

            else => {},
        }
        // segment not empty, not dot and not dot-dot

        // apply any pending dot-dots
        if (seg_skipn != 0) {
            seg_skipn -= 1;
            while (i != 0 and raw[i] != '/') i -= 1;
            dot_count = 0; // reset for next
            continue :map_segment;
        }

        // write path separator on segment continuation
        if (p != out.ptr + out.len) {
            p -= 1;
            p[0] = '/';
        }

        // write any dots read
        for (0..dot_count) |_| {
            p -= 1;
            p[0] = '.';
        }
        dot_count = 0; // reset

        // write segment remainder
        while (raw[i] != '/') {
            if (i < 2 or raw[i - 2] != '%') {
                // copy c
                p -= 1;
                p[0] = raw[i];

                if (i == 0) break :map_segment;
                i -= 1;
                continue;
            }

            // resolve percent-encoding
            const v = (hex_table[raw[i - 1]] << 4) | hex_table[raw[i]];
            if (v == '/') {
                p -= encodedSlashOut.len;
                @memcpy(p, encodedSlashOut);
            } else {
                p -= 1;
                p[0] = v;
            }

            if (i < 3) break :map_segment;
            i -= 3; // pass percent-encoding
        }
    }

    switch (dot_count) {
        0, 1 => {}, // discard empty segment or single dot
        2 => seg_skipn += 1, // enqueue dot-dot
        else => {
            // write path separator
            if (p != out.ptr + out.len) {
                p -= 1;
                p[0] = '/';
            }
            for (0..dot_count) |_| {
                p -= 1;
                p[0] = '.';
            }
        },
    }

    if (raw[0] == '/') {
        // keep path absolute
        p -= 1;
        p[0] = '/';
        // any dot-dots beyond root dropped
    } else if (seg_skipn != 0) {
        if (p != out.ptr + out.len) {
            p -= 1;
            p[0] = '/';
        }
        while (true) {
            p -= 2;
            p[0] = '.';
            p[1] = '.';
            seg_skipn -= 1;
            if (seg_skipn == 0) break;
            p -= 1;
            p[0] = '/';
        }
    } else if (p == out.ptr + out.len) {
        // relative path deducted to zero
        p -= 1;
        p[0] = '.';
    }

    return out;
}

test "Path Normalization" {
    const golden = struct {
        path: []const u8,
        want: []const u8,
    };
    const tests = [_]golden{
        .{ .path = "foo", .want = "foo" },
        .{ .path = "/foo", .want = "/foo" },
        .{ .path = "foo/bar", .want = "foo/bar" },
        .{ .path = "/foo/bar", .want = "/foo/bar" },
        .{ .path = "%62%61%7A", .want = "baz" },
        .{ .path = "/%62%61%7a", .want = "/baz" },

        // leading dots
        .{ .path = "./r", .want = "r" },
        .{ .path = "/./a", .want = "/a" },
        .{ .path = "././r", .want = "r" },
        .{ .path = "/././a", .want = "/a" },

        .{ .path = "../r", .want = "../r" },
        .{ .path = "/../a", .want = "/a" },
        .{ .path = "../../r", .want = "../../r" },
        .{ .path = "/../../a", .want = "/a" },

        .{ .path = ".././r", .want = "../r" },
        .{ .path = "/.././a", .want = "/a" },
        .{ .path = "./../r", .want = "../r" },
        .{ .path = "/./../a", .want = "/a" },

        // trailing dots
        .{ .path = "r/.", .want = "r" },
        .{ .path = "/a/.", .want = "/a" },
        .{ .path = "r/./.", .want = "r" },
        .{ .path = "/a/./.", .want = "/a" },

        .{ .path = "r/..", .want = "." },
        .{ .path = "/a/..", .want = "/" },
        .{ .path = "r/../..", .want = ".." },
        .{ .path = "/a/../..", .want = "/" },

        .{ .path = "r/../.", .want = "." },
        .{ .path = "/a/../.", .want = "/" },
        .{ .path = "r/./..", .want = "." },
        .{ .path = "/a/./..", .want = "/" },

        // inner dots
        .{ .path = "r/./e", .want = "r/e" },
        .{ .path = "/a/./e", .want = "/a/e" },
        .{ .path = "r/././e", .want = "r/e" },
        .{ .path = "/a/././e", .want = "/a/e" },

        .{ .path = "r/../e", .want = "e" },
        .{ .path = "/a/../e", .want = "/e" },
        .{ .path = "r/../../e", .want = "../e" },
        .{ .path = "/a/../../e", .want = "/e" },

        .{ .path = "r/.././e", .want = "e" },
        .{ .path = "/a/.././e", .want = "/e" },
        .{ .path = "r/./../e", .want = "e" },
        .{ .path = "/a/./../e", .want = "/e" },

        .{ .path = "r/../.././e", .want = "../e" },
        .{ .path = "/a/../.././e", .want = "/e" },
        .{ .path = "r/.././../e", .want = "../e" },
        .{ .path = "/a/.././../e", .want = "/e" },
        .{ .path = "r/./../../e", .want = "../e" },
        .{ .path = "/a/./../../e", .want = "/e" },

        // trailing percent-encoded dots
        .{ .path = "r/e/%2E%2e", .want = "r" },
        .{ .path = "/a/e/%2e%2E", .want = "/a" },
        .{ .path = "r/e/.%2E/%2e.", .want = "." },
        .{ .path = "/a/e/.%2e/%2E.", .want = "/" },
        // leading percent-encoded dots
        .{ .path = "%2E/%2E%2E", .want = ".." },
        .{ .path = "%2E%2e/%2E/%2E%2E", .want = "../.." },
        // deduct percent-encoded alphabeticals
        .{ .path = "%72/%65/%2E%2e", .want = "r" },
        .{ .path = "/%61/%65/%2e%2E", .want = "/a" },
        .{ .path = "%72/%65/.%2E/%2e.", .want = "." },
        .{ .path = "/%61/%65/.%2e/%2E.", .want = "/" },

        // percent-encoded slashes & dots
        .{ .path = "%2F%2E", .want = "💀." },
        .{ .path = "%2f%2e", .want = "💀." },
        .{ .path = "%2E%2F", .want = ".💀" },
        .{ .path = "%2e%2f", .want = ".💀" },
        .{ .path = "%2F%2e%2E", .want = "💀.." },
        .{ .path = "%2f%2E%2e", .want = "💀.." },
        .{ .path = "%2e%2E%2F", .want = "..💀" },
        .{ .path = "%2E%2e%2f", .want = "..💀" },
    };

    var failn: usize = 0;
    inline for (tests) |t| {
        const ur = try parse("file:" ++ t.path);
        try expectEqualStrings(t.path, ur.rawPath());
        const got = ur.pathNorm("💀", std.testing.allocator) catch "<out of memory>";
        defer std.testing.allocator.free(got);
        expectEqualStrings(t.want, got) catch {
            std.debug.print("pathNorm({s}) got {s}, want {s}\n", .{ t.path, got, t.want });
            failn += 1;
        };
    }
    try expectEqual(@as(usize, 0), failn);
}

test "Percent-Encoded Slash Trim" {
    // 🤢 “<file> URI with UNC Path” — RFC 8089, appendix E.3.2
    const ur = try Urview.parse("file://///host.example.com/I%2FO/");
    try expectEqualStrings("///host.example.com/I%2FO/", ur.rawPath());

    // replace "%2F" with zero string
    const got = try ur.pathNorm("", std.testing.allocator);
    defer std.testing.allocator.free(got);
    try expectEqualStrings("/host.example.com/IO", got);
}

/// Query returns the component with any and all percent-encodings resolved.
/// None of the applicable standards put any constraints on the byte content.
/// The return may or may not be a valid UTF-8 string. Caller owns the retured
/// memory.
pub fn query(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8 {
    const offset = ur.query_offset + 1; // trim '?'
    const end = ur.fragment_offset;
    if (offset >= end) return m.allocSentinel(u8, 0, 0);
    return resolvePercentEncodings(ur.uri_ptr[offset..end], m);
}

/// EqualsQuery returns whether the component with any and all percent-encodings
/// resolved equals match. Absent components don't equal any match.
pub fn equalsQuery(ur: Urview, match: []const u8) bool {
    const offset = ur.query_offset + 1; // trim '?'
    const end = ur.fragment_offset;
    if (offset > end) return false;
    return equalsString(ur.uri_ptr[offset..end], match);
}

/// Fragment returns the component with any and all percent-encodings resolved.
/// None of the applicable standards put any constraints on the byte content.
/// The return may or may not be a valid UTF-8 string. Caller owns the returned
/// memory.
pub fn fragment(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8 {
    const offset = ur.fragment_offset + 1; // trim '#'
    const end = ur.uri_len;
    if (offset >= end) return m.allocSentinel(u8, 0, 0);
    return resolvePercentEncodings(ur.uri_ptr[offset..end], m);
}

/// EqualsFragment returns whether the component with any and all percent-
/// encodings resolved equals match. Absent components don't equal any match.
pub fn equalsFragment(ur: Urview, match: []const u8) bool {
    const offset = ur.fragment_offset + 1; // trim '#'
    const end = ur.uri_len;
    if (offset > end) return false;
    return equalsString(ur.uri_ptr[offset..end], match);
}

/// Parse errors signal syntax violation.
pub const ParseError = error{
    /// A scheme prefix is the only required component of a URI. NoScheme
    /// implies not-a-URI.
    NoScheme,

    /// The IPv6 address syntax is well defined. Note that zone identifiers are
    /// permitted since RFC 6874. IPv4 addresses have no validation options. Any
    /// invalid IPv4 address matches the free-form syntax of registered names.
    AddressViolation,

    /// Any bracket range "[" and "]" must span the entire host component. The
    /// authority may contain at most one at character ("@"). The authority may
    /// contain at most one colon character (":") outside userinfo ("…@").
    MalformedAuthority,

    /// The authority components may contain: "A"–"Z", "a"–"z", "0"–"9", "-",
    /// ".", "_", "~", "!", "$", "&", "'", "(", ")", "*", "+", ",", ";" and "=".
    /// All other characters need percent-encoding. Misplaced "@", "[", "]" or
    /// ":" characters cause MalformedAuthority.
    IllegalAuthorityCharacter,

    /// The port must consist of decimals exclusively.
    IllegalPortCharacter,

    /// The path component may contain: "A"–"Z", "a"–"z", "0"–"9", "-", ".",
    /// "_", "~", "!", "$", "&", "'", "(", ")", "*", "+", ",", ";", "=", ":",
    /// "@" and "/". All other characters need percent-encoding.
    IllegalPathCharacter,

    /// The query component may contain: "A"–"Z", "a"–"z", "0"–"9", "-", ".",
    /// "_", "~", "!", "$", "&", "'", "(", ")", "*", "+", ",", ";", "=", ":",
    /// "@", "/" and "?". All other characters need percent-encoding.
    IllegalQueryCharacter,

    /// The fragment component may contain: "A"–"Z", "a"–"z", "0"–"9", "-", ".",
    /// "_", "~", "!", "$", "&", "'", "(", ")", "*", "+", ",", ";", "=", ":",
    /// "@", "/" and "?". All other characters need percent-encoding.
    IllegalFragmentCharacter,

    /// Every percent character ("%") must be followed by two hex digits.
    BrokenPercentEncoding,

    /// Input of 64 KiB or more is denied.
    StringTooBig,
};

/// Parse returns a projection of s if and only if s is a valid URI.
pub fn parse(p: [*:0]const u8) ParseError!Urview {
    var i: usize = 0;

    // match scheme from RFC 3986, subsection 3.1
    match_scheme: while (true) : (i += 1) switch (p[i]) {
        // ALPHA from RFC 2234, subsection 6.1
        'A'...'Z', 'a'...'z' => continue,
        // DIGIT from RFC 2234, subsection 6.1
        '0'...'9', '+', '-', '.' => if (i == 0) break :match_scheme,
        ':' => {
            if (i == 0) break :match_scheme;
            var ur = Urview{ .uri_ptr = p };
            try sinceScheme(&ur, i + 1);
            return ur;
        },
        else => break :match_scheme,
    };
    return ParseError.NoScheme;
}

test "Examples" {
    const samples = [_][:0]const u8{
        // “Uniform Resource Identifier (URI): Generic Syntax” RFC 3986, subsection 1.1.2
        "ftp://ftp.is.co.za/rfc/rfc1808.txt",
        "http://www.ietf.org/rfc/rfc2396.txt",
        "ldap://[2001:db8::7]/c=GB?objectClass?one",
        "mailto:John.Doe@example.com",
        "news:comp.infosystems.www.servers.unix",
        "tel:+1-816-555-1212",
        "telnet://192.0.2.16:80/",
        "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",

        // “Internationalized Resource Identifiers” RFC 3987, subsection 3.2.1
        "http://xn--99zt52a.example.org/%E2%80%AE",

        // “IPv6 Zone IDs in URIs” RFC 6874, section 2
        "http://[fe80::a%25en1]",

        // “Uniform Resource Locators (URL)” RFC 1738, subsection 3.1
        "ftp://@host.com/",
        "ftp://foo:@host.com/",
        // “Uniform Resource Locators (URL)” RFC 1738, subsection 3.2.2
        "ftp://myname@host.dom/%2Fetc/motd",
        "ftp://myname@host.dom//etc/motd",
        // “Uniform Resource Locators (URL)” RFC 1738, subsection 3.10
        "file://vms.host.edu/disk$user/my/notes/note12345.txt",
        // “Uniform Resource Locators (URL)” RFC 1738, appendix
        "ftp://info.cern.ch/pub/www/doc;type=d",
        "http://ds.internic.net/instructions/overview.html#WARNING",

        // “URNs" RFC 8141, subsection 3.2
        "urn:example:a123,z456",
        "URN:example:a123,z456",
        "urn:EXAMPLE:a123,z456",
        "urn:example:a123,z456?+abc",
        "urn:example:a123,z456?=xyz",
        "urn:example:a123,z456#789",
        "urn:example:a123,z456/foo",

        // “A URN Namespace for Public Identifiers” RFC 3151, section 3
        "urn:publicid:ISO%2FIEC+10179%3A1996:DTD+DSSSL+Architecture:EN",
        "urn:publicid:ISO+8879%3A1986:ENTITIES+Added+Latin+1:EN",
        "urn:publicid:-:OASIS:DTD+DocBook+XML+V4.1.2:EN",
        "urn:publicid:%2B:IDN+example.org:DTD+XML+Bookmarks+1.0:EN:XML",

        // “The "file" URI Scheme” RFC 8089, appendix B
        "file:///path/to/file",
        "file:/path/to/file",
        "file://host.example.com/path/to/file",
        // RFC 8089, appendix E.2, “DOS and Windows Drive Letters”
        "file:c:/path/to/file",
        // RFC 8089, appendix E.2.1, “Relative Resolution”
        "file:///c:/path/to/file.txt",
        "file:///c:/foo.txt",
        // RFC 8089, appendix E.3.2, “<file> URI with UNC Path”
        "file:////host.example.com/path/to/file",
        "file://///host.example.com/path/to/file",

        // “IMAP URL Scheme” RFC 5092, section 6
        "imap://psicorp.example.org/~peter/%E6%97%A5%E6%9C%AC%E8%AA%9E/%E5%8F%B0%E5%8C%97",
        "imap://;AUTH=*@minbari.example.org/gray%20council?SUBJECT%20shadows",

        // “The "data" URL scheme” RFC 2397, section 4
        "data:,A%20brief%20note",
        "data:text/plain;charset=iso-8859-7,%be%d3%be",

        // “The mailto URL scheme” RFC 2368, section 2
        "mailto:addr1%2C%20addr2",
        "mailto:?to=addr1%2C%20addr2",
        "mailto:addr1?to=addr2",

        // “SIP: Session Initiation Protocol” RFC 2543, section 2
        "sip:j.doe@big.com;maddr=239.255.255.1;ttl=15",
        "sip:+1-212-555-1212:1234@gateway.com;user=phone",

        // “Decentralized Identifiers (DIDs) v1.0” W3C Recommendation, example 2
        "did:example:123456/path", // path starts at example:1…—not /p…
        // “Decentralized Identifiers (DIDs) v1.0” W3C Recommendation, example 3
        "did:example:123?service=agent&relativeRef=/credentials#degree",
        // “Decentralized Identifiers (DIDs) v1.0” W3C Recommendation, example 7
        "did:example:123?versionTime=2021-05-10T17:00:00Z",

        // “MySQL Connector/J 8.1 Developer Guide”, section 6.2 “Connection URL Syntax”
        "jdbc:mysql://myhost1:1111,myhost2:2222/db",
    };

    for (samples) |s| {
        const ur = parse(s) catch |err| {
            std.debug.print("got error {} for {s}\n", .{ err, s });
            return err;
        };

        const raw_scheme = ur.rawScheme();
        const raw_authority = ur.rawAuthority();
        const raw_userinfo = ur.rawUserinfo();
        const raw_host = ur.rawHost();
        const raw_port = ur.rawPort();
        const raw_path = ur.rawPath();
        const raw_query = ur.rawQuery();
        const raw_fragment = ur.rawFragment();

        // ensure lossless mapping
        try expectFmt(s, "{s}{s}{s}{s}{s}", .{ raw_scheme, raw_authority, raw_path, raw_query, raw_fragment });

        // verify constraints from the field comments
        try expectStringEndsWith(raw_scheme, ":");
        if (raw_authority.len != 0) {
            try expectFmt(raw_authority, "//{s}{s}{s}", .{ raw_userinfo, raw_host, raw_port });
            if (raw_userinfo.len != 0) try expectStringEndsWith(raw_userinfo, "@");
            if (raw_port.len != 0) try expectStringStartsWith(raw_port, ":");
        } else {
            try expectEqualStrings("", raw_userinfo);
            try expectEqualStrings("", raw_host);
            try expectEqualStrings("", raw_port);
        }
        if (raw_path.len != 0 and raw_authority.len != 0) try expectStringStartsWith(raw_path, "/");
        if (raw_query.len != 0) try expectStringStartsWith(raw_query, "?");
        if (raw_fragment.len != 0) try expectStringStartsWith(raw_fragment, "#");
    }
}

test "Upper-Case URN" {
    // sample from “Using ISBNs as URNs” RFC 3187, subsection 3.2
    const ur = try parse("URN:ISBN:0-395-36341-1");

    try expect(ur.equalsScheme("urn"));

    const s = try ur.scheme(test_allocator);
    defer test_allocator.free(s);
    try expectEqualStrings("urn", s);

    try expect(ur.equalsPath("ISBN:0-395-36341-1"));
    try expect(!ur.equalsPath("isbn:0-395-36341-1"));

    const p = try ur.path(test_allocator);
    defer test_allocator.free(p);
    try expectEqualStrings("ISBN:0-395-36341-1", p);
}

test "Tricky" {
    const v = try parse("bang://AD2%5cBill%40live.com@?C:%5cProgram+Files%5C*.EXE");

    const u = try v.userinfo(test_allocator);
    defer test_allocator.free(u);
    try expectEqualStrings("AD2\\Bill@live.com", u);

    const q = try v.query(test_allocator);
    defer test_allocator.free(q);
    try expectEqualStrings("C:\\Program+Files\\*.EXE", q);
}

test "Bloat" {
    const ur = try parse("x-odbc://admin:fe:main@[0::192.168.57.2]:05432/cms?SELECT%20*%20FROM%20users;#80%E2%80%93160");

    try expectEqualStrings("x-odbc:", ur.rawScheme());
    try expectEqualStrings("//admin:fe:main@[0::192.168.57.2]:05432", ur.rawAuthority());
    try expectEqualStrings("admin:fe:main@", ur.rawUserinfo());
    try expectEqualStrings("[0::192.168.57.2]", ur.rawHost());
    try expectEqualStrings(":05432", ur.rawPort());
    try expectEqualStrings("/cms", ur.rawPath());
    try expectEqualStrings("?SELECT%20*%20FROM%20users;", ur.rawQuery());
    try expectEqualStrings("#80%E2%80%93160", ur.rawFragment());

    try expect(ur.equalsScheme("x-odbc"));
    try expect(ur.equalsUserinfo("admin:fe:main"));
    try expect(!ur.equalsUserinfo("admin:fe:main@"));
    try expect(ur.equalsHost("[0::192.168.57.2]"));
    try expect(!ur.equalsHost("0::192.168.57.2"));
    try expect(!ur.equalsHost("192.168.57.2"));
    try expectEqual(@as(?u16, 5432), ur.portAsU16());
    try expect(ur.equalsPath("/cms"));
    try expect(!ur.equalsPath("cms"));
    try expect(ur.equalsFragment("80–160"));
    try expect(!ur.equalsFragment("80%E2%80%93160"));
    try expect(!ur.equalsFragment("#80%E2%80%93160"));

    const q = try ur.query(test_allocator);
    defer test_allocator.free(q);
    try expectEqualStrings("SELECT * FROM users;", q);

    const f = try ur.fragment(test_allocator);
    defer test_allocator.free(f);
    try expectEqualStrings("80–160", f);
}

test "Absent" {
    const ur = try parse("X11:");

    try expect(ur.equalsScheme("x11"));
    try expect(!ur.equalsScheme("ssh"));
    try expect(!ur.equalsUserinfo(""));
    try expect(!ur.equalsHost(""));
    try expectEqual(@as(?u16, null), ur.portAsU16());
    try expect(ur.equalsPath(""));
    try expect(!ur.equalsFragment(""));

    const s = try ur.scheme(test_allocator);
    defer test_allocator.free(s);
    try expectEqualStrings("x11", s);

    var buf: [5]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    try expectEqualStrings("", try ur.userinfo(fix.allocator()));
    try expectEqualStrings("", try ur.host(fix.allocator()));
    try expectEqual(@as(?u16, null), ur.portAsU16());
    try expectEqualStrings("", try ur.path(fix.allocator()));
    try expectEqualStrings("", try ur.query(fix.allocator()));
    try expectEqualStrings("", try ur.fragment(fix.allocator()));
}

test "Empty" {
    const ur = try parse("x-://@:?#");

    try expectEqualStrings("x-:", ur.rawScheme());
    try expectEqualStrings("//@:", ur.rawAuthority());
    try expectEqualStrings("@", ur.rawUserinfo());
    try expectEqualStrings("", ur.rawHost());
    try expectEqualStrings(":", ur.rawPort());
    try expectEqualStrings("", ur.rawPath());
    try expectEqualStrings("?", ur.rawQuery());
    try expectEqualStrings("#", ur.rawFragment());

    try expect(ur.equalsScheme("x-"));
    try expect(!ur.equalsScheme("x"));
    try expect(ur.equalsUserinfo(""));
    try expect(!ur.equalsUserinfo("@"));
    try expect(ur.equalsHost(""));
    try expect(!ur.equalsHost("//@"));
    try expectEqual(@as(?u16, null), ur.portAsU16());
    try expect(ur.equalsPath(""));
    try expect(!ur.equalsPath("/"));
    try expect(ur.equalsQuery(""));
    try expect(!ur.equalsQuery("?"));
    try expect(ur.equalsFragment(""));
    try expect(!ur.equalsFragment("#"));

    var buf: [5]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buf);
    try expectEqualStrings("", try ur.userinfo(fix.allocator()));
    try expectEqualStrings("", try ur.host(fix.allocator()));
    try expectEqualStrings("", try ur.path(fix.allocator()));
    try expectEqualStrings("", try ur.query(fix.allocator()));
    try expectEqualStrings("", try ur.fragment(fix.allocator()));
}

// Parse all components after raw_scheme, which can be none.
fn sinceScheme(ur: *Urview, offset: usize) ParseError!void {
    ur.authority_offset = @intCast(offset & 0xffff);

    // “The authority component is preceded by a double slash ("//") and is
    // terminated by the next slash ("/"), question mark ("?"), or number
    // sign ("#") character, or by the end of the URI.”
    if (ur.uri_ptr[offset] != '/' or ur.uri_ptr[offset + 1] != '/') {
        ur.userinfo_offset = @intCast(offset & 0xffff);
        ur.host_offset = @intCast(offset & 0xffff);
        ur.port_offset = @intCast(offset & 0xffff);
        ur.path_offset = @intCast(offset & 0xffff);
        return pathContinue(ur, offset);
    }
    var i = offset + 2;

    ur.userinfo_offset = @intCast(i & 0xffff);
    // Host offset is adjusted when userinfo is found.
    ur.host_offset = @intCast(i & 0xffff);

    // Colon (":") characters are used as a port separator, as an IPv6
    // addresses separator, and they may occur in userinfo.
    var colon_count: usize = 0;
    var last_colon: usize = 0;

    // • any IPv4address matches reg-name
    // • any reg-name matches userinfo
    while (true) {
        if (reg_name_chars[ur.uri_ptr[i]] != 0) {
            // either userinfo or reg-name
            i += 1;
        } else switch (ur.uri_ptr[i]) {
            0 => {
                ur.path_offset = @intCast(i & 0xffff);
                ur.query_offset = @intCast(i & 0xffff);
                ur.fragment_offset = @intCast(i & 0xffff);
                ur.uri_len = @intCast(i);
                return authorityEnd(ur, i, colon_count, last_colon);
            },
            // userinfo
            '@' => {
                if (ur.userinfo_offset > ur.host_offset)
                    return ParseError.MalformedAuthority;
                i += 1;
                ur.host_offset = @intCast(i & 0xffff);
                colon_count = 0; // reset for host count
            },
            // either userinfo or port separator or invalid
            ':' => {
                colon_count += 1;
                last_colon = i;
                i += 1;
            },
            '/' => {
                try authorityEnd(ur, i, colon_count, last_colon);
                return pathContinue(ur, i);
            },
            '?' => {
                try authorityEnd(ur, i, colon_count, last_colon);
                ur.path_offset = @intCast(i & 0xffff);
                return queryContinue(ur, i);
            },
            '#' => {
                try authorityEnd(ur, i, colon_count, last_colon);
                ur.path_offset = @intCast(i & 0xffff);
                ur.query_offset = @intCast(i & 0xffff);
                return fragmentContinue(ur, i);
            },
            '[' => {
                if (i != ur.host_offset) return ParseError.MalformedAuthority;
                return asIpLiteral(ur, i);
            },
            '%' => { // pct-encoded
                try verifyProcentEncoding(ur.uri_ptr, i);
                i += 3;
            },
            else => return ParseError.IllegalAuthorityCharacter,
        }
    }
    unreachable;
}

fn authorityEnd(ur: *Urview, end: usize, colon_count: usize, last_colon: usize) ParseError!void {
    switch (colon_count) {
        0 => {
            ur.port_offset = @intCast(end & 0xffff);
        },
        1 => {
            ur.port_offset = @intCast(last_colon & 0xffff);

            // match port from RFC 3986, subsection 3.2.3
            for (ur.uri_ptr[last_colon + 1 .. end]) |c|
                if (c < '0' or c > '9')
                    return ParseError.IllegalPortCharacter;
        },
        else => return ParseError.MalformedAuthority,
    }
}

// Parses authority p since offset "[".
fn asIpLiteral(ur: *Urview, offset: usize) ParseError!void {
    // “The use of "::" indicates one or more groups of 16 bits of zeros.
    // The "::" can only appear once in an address.  The "::" can also be
    // used to compress leading or trailing zeros in an address.”
    // — “IPv6 Addressing Architecture” RFC 3513, subsection 2.2
    var zeroes_once = false;

    var i = offset + 1;
    switch (ur.uri_ptr[i]) {
        0 => return ParseError.AddressViolation, // not closed with "]"
        'v' => return asIpFuture(ur, offset),
        ':' => {
            if (ur.uri_ptr[i + 1] != ':')
                return ParseError.AddressViolation;
            i += 2;
            zeroes_once = true;
        },
        else => {},
    }

    var h16n: usize = 0; // number of 16-bit pieces
    var hexn: usize = 0; // number of digits (max 4)

    // match IP-literal from RFC 3986, subsection 3.2.2 with a jump table
    while (true) : (i += 1) switch (ur.uri_ptr[i]) {
        0 => return ParseError.AddressViolation, // not closed with "]"
        '0'...'9', 'a'...'f', 'A'...'F' => { // HEXDIG
            if (hexn == 0) h16n += 1;
            hexn += 1;
        },
        ':' => {
            if (hexn == 0) {
                if (zeroes_once) return ParseError.AddressViolation;
                zeroes_once = true;
            } else if (hexn > 4) {
                return ParseError.AddressViolation;
            }
            hexn = 0;
        },
        ']' => {
            if (!zeroes_once and h16n != 8 or zeroes_once and h16n > 7)
                return ParseError.AddressViolation;
            return ipLiteralEnd(ur, i);
        },

        '.' => {
            // The last number (counted by h16n) was not hex. At least one h16
            // is required by “URI Generic Syntax” RFC 3986, which complies to:
            //
            // “The "IPv4-Compatible IPv6 address" is now deprecated because the
            // current IPv6 transition mechanisms no longer use these addresses.
            // New or updated implementations are not required to support this
            // address type.”
            // — “IPv6 Addressing Architecture” RFC4219, subsection 2.5.5.1

            if (h16n < 2 or !zeroes_once and h16n != 6 + 1 or zeroes_once and h16n > 5 + 1)
                return ParseError.AddressViolation;

            return ip4inIp6Continue(ur, i - hexn);
        },

        // percent character ("%"), encoded as "%25", marks a zone identifier
        '%' => {
            if (ur.uri_ptr[i + 1] != '2' or ur.uri_ptr[i + 2] != '5' or !zeroes_once and h16n != 8 or zeroes_once and h16n > 7)
                return ParseError.AddressViolation;
            i += 3;
            var zone_start = i;

            // match ZoneID from “IPv6 Zone IDs in URIs” RFC 6874, section 2
            while (true) switch (ur.uri_ptr[i]) {
                // unreserved
                'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => i += 1,
                // pct-encoded
                '%' => {
                    try verifyProcentEncoding(ur.uri_ptr, i);
                    i += 3;
                },
                ']' => {
                    if (i <= zone_start) return ParseError.AddressViolation;
                    return ipLiteralEnd(ur, i);
                },
                else => return ParseError.AddressViolation,
            };
        },

        else => return ParseError.AddressViolation,
    };
    unreachable;
}

// AsIpFuture parses authority s since offset "[v".
fn asIpFuture(ur: *Urview, offset: usize) ParseError!void {
    var i = offset + 2;

    // match IPvFuture from RFC 3986, subsection 3.2.2
    if (hex_table[ur.uri_ptr[i]] > 15) return ParseError.AddressViolation;
    i += 1;
    while (ur.uri_ptr[i] != '.') : (i += 1)
        if (hex_table[ur.uri_ptr[i]] > 15)
            return ParseError.AddressViolation;

    const start = i;

    while (true) : (i += 1) switch (ur.uri_ptr[i]) {
        0 => return ParseError.AddressViolation, // not closed with "]"
        // unreserved
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => continue,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => continue,
        ':' => continue,
        ']' => {
            // need one or more characters
            if (i < start + 1) return ParseError.AddressViolation;
            return ipLiteralEnd(ur, i);
        },
        else => return ParseError.AddressViolation,
    };
    unreachable;
}

test "IP Future" {
    const ur = try parse("e://[v007.~]:777353");
    try expectEqualStrings("[v007.~]", ur.rawHost());
    try expectEqualStrings(":777353", ur.rawPort());
    try expectEqual(@as(?u16, null), ur.portAsU16());
}

fn ip4inIp6Continue(ur: *Urview, offset: usize) ParseError!void {
    var i = offset;
    var octn: usize = 1; // octet count (need 4)
    var decn: usize = 0; // decimal count (max 3)

    // match IPv4address from RFC 3986, subsection 3.2.2
    while (true) : (i += 1) switch (ur.uri_ptr[i]) {
        0 => return ParseError.AddressViolation, // not closed with "]"
        '0'...'9' => {
            decn += 1;
        },
        '.' => {
            _ = parseInt(u8, ur.uri_ptr[i - decn .. i], 10) catch
                return ParseError.AddressViolation;
            if (decn == 0 or ur.uri_ptr[i - decn] == '0')
                return ParseError.AddressViolation;
            octn += 1;
            decn = 0;
        },
        ']' => {
            _ = parseInt(u8, ur.uri_ptr[i - decn .. i], 10) catch
                return ParseError.AddressViolation;
            if (decn == 0 or octn != 4 or ur.uri_ptr[i - decn] == '0')
                return ParseError.AddressViolation;

            return ipLiteralEnd(ur, i);
        },
        else => return ParseError.AddressViolation,
    };
    unreachable;
}

// ipLiteralEnd continues from end "]".
fn ipLiteralEnd(ur: *Urview, end: usize) ParseError!void {
    var i = end + 1;
    ur.port_offset = @intCast(i & 0xffff);

    switch (ur.uri_ptr[i]) {
        0 => {
            if (i > 0xffff) return ParseError.StringTooBig;
            ur.path_offset = @intCast(i);
            ur.query_offset = @intCast(i);
            ur.fragment_offset = @intCast(i);
            ur.uri_len = @intCast(i);
            return;
        },
        '/' => {
            return pathContinue(ur, i);
        },
        '?' => {
            ur.path_offset = @intCast(i & 0xffff);
            return queryContinue(ur, i);
        },
        '#' => {
            ur.path_offset = @intCast(i & 0xffff);
            ur.query_offset = @intCast(i & 0xffff);
            return fragmentContinue(ur, i);
        },

        ':' => {
            i += 1;

            // match port from RFC 3986, subsection 3.2.3
            while (true) : (i += 1) switch (ur.uri_ptr[i]) {
                '0'...'9' => continue,

                0 => {
                    if (i > 0xffff) return ParseError.StringTooBig;
                    ur.path_offset = @intCast(i);
                    ur.query_offset = @intCast(i);
                    ur.fragment_offset = @intCast(i);
                    ur.uri_len = @intCast(i);
                    return;
                },
                '/' => {
                    return pathContinue(ur, i);
                },
                '?' => {
                    ur.path_offset = @intCast(i & 0xffff);
                    return queryContinue(ur, i);
                },
                '#' => {
                    ur.path_offset = @intCast(i & 0xffff);
                    ur.query_offset = @intCast(i & 0xffff);
                    return fragmentContinue(ur, i);
                },

                else => return ParseError.IllegalPortCharacter,
            };
            unreachable;
        },

        // trailer after address ended (with "]")
        else => return ParseError.MalformedAuthority,
    }
    unreachable;
}

// PathContinue parses p at offset.
fn pathContinue(ur: *Urview, offset: usize) ParseError!void {
    ur.path_offset = @intCast(offset & 0xffff);
    var i = offset;

    // match path from RFC 3986, subsection 3.3 with a jump table
    while (true) {
        if (path_chars[ur.uri_ptr[i]] != 0) {
            i += 1;
        } else switch (ur.uri_ptr[i]) {
            0 => {
                if (i > 0xffff) return ParseError.StringTooBig;
                ur.query_offset = @intCast(i);
                ur.fragment_offset = @intCast(i);
                ur.uri_len = @intCast(i);
                return;
            },
            '?' => {
                return queryContinue(ur, i);
            },
            '#' => {
                ur.query_offset = @intCast(i & 0xffff);
                return fragmentContinue(ur, i);
            },
            '%' => {
                try verifyProcentEncoding(ur.uri_ptr, i);
                i += 3;
            },
            else => return ParseError.IllegalPathCharacter,
        }
    }
    unreachable;
}

// QueryContinue parses p since offset "?".
//
// “The query component is indicated by the first question mark ("?")
// character and terminated by a number sign ("#") character or by the end
// of the URI.”
fn queryContinue(ur: *Urview, offset: usize) ParseError!void {
    ur.query_offset = @intCast(offset & 0xffff);
    var i = offset + 1;

    // match query from RFC 3986, subsection 3.4 with a jump table
    while (true) {
        if (query_chars[ur.uri_ptr[i]] != 0) {
            i += 1;
        } else switch (ur.uri_ptr[i]) {
            0 => {
                if (i > 0xffff) return ParseError.StringTooBig;
                ur.fragment_offset = @intCast(i);
                ur.uri_len = @intCast(i);
                return;
            },
            '#' => {
                return fragmentContinue(ur, i);
            },
            '%' => {
                try verifyProcentEncoding(ur.uri_ptr, i);
                i += 3;
            },
            else => return ParseError.IllegalQueryCharacter,
        }
    }
    unreachable;
}

// FragmentContinue parses p since offset "#".
//
// “A fragment identifier component is indicated by the presence of a
// number sign ("#") character and terminated by the end of the URI.”
fn fragmentContinue(ur: *Urview, offset: usize) ParseError!void {
    ur.fragment_offset = @intCast(offset & 0xffff);
    var i = offset + 1;

    // match fragment from RFC 3986, subsection 3.5 with a jump table
    while (true) {
        if (fragment_chars[ur.uri_ptr[i]] != 0) {
            i += 1;
        } else switch (ur.uri_ptr[i]) {
            0 => {
                if (i > 0xffff) return ParseError.StringTooBig;
                ur.uri_len = @intCast(i);
                return;
            },
            '%' => {
                try verifyProcentEncoding(ur.uri_ptr, i);
                i += 3;
            },
            else => return ParseError.IllegalFragmentCharacter,
        }
    }
}

fn resolvePercentEncodings(raw: []const u8, m: Allocator) error{OutOfMemory}![:0]u8 {
    return resolvePercentEncodingsWithToLower(raw, false, m);
}

fn resolvePercentEncodingsToLower(raw: []const u8, m: Allocator) error{OutOfMemory}![:0]u8 {
    return resolvePercentEncodingsWithToLower(raw, true, m);
}

fn resolvePercentEncodingsWithToLower(raw: []const u8, comptime toLower: bool, m: Allocator) error{OutOfMemory}![:0]u8 {
    var i: usize = 0; // raw index
    var n: usize = 0; // output count [octets]
    while (raw.len - i > 2) : (n += 1)
        i += if (raw[i] == '%') 3 else 1;
    n += raw.len - i;

    // output
    if (!toLower and n >= raw.len) return m.dupeZ(u8, raw);
    var b = try m.allocSentinel(u8, n, 0);

    // write pointer
    var p = b.ptr;
    i = 0;
    while (raw.len - i > 2) : (i += 1) {
        var c = raw[i];
        if (c == '%') {
            c = (hex_table[raw[i + 1]] << 4) | hex_table[raw[i + 2]];
            i += 2;
        }
        if (toLower and c <= 'Z' and c >= 'A') c += 'a' - 'A';
        p[0] = c;
        p += 1;
    }

    while (i < raw.len) : (i += 1) {
        p[0] = raw[i];
        p += 1;
    }
    return b;
}

test "Case Normalization" {
    // “URI Generic Syntax” RFC 3986, subsection 6.2.2.1
    const ur = try parse("HTTP://www.EXAMPLE.com/");

    const s = ur.scheme(test_allocator) catch "<out of memory>";
    defer test_allocator.free(s);
    try expectEqualStrings("http", s);

    const h = ur.host(test_allocator) catch "<out of memory>";
    defer test_allocator.free(h);
    try expectEqualStrings("www.example.com", h);
}

fn verifyProcentEncoding(p: [*:0]const u8, i: usize) ParseError!void {
    if (hex_table[p[i + 1]] > 15 or hex_table[p[i + 2]] > 15)
        return ParseError.BrokenPercentEncoding;
}

const hex_table = buildHexTable();

fn buildHexTable() [256]u8 {
    var table: [256]u8 = undefined;
    for (0..256) |c| table[c] = switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => 0xff,
    };
    return table;
}

// EqualsString returns whether the raw input with any and all of its
// percent-encodings resolved equals match.
fn equalsString(raw: []const u8, match: []const u8) bool {
    var i: usize = 0;
    for (match) |c| {
        if (i >= raw.len) return false;
        var d = raw[i];
        i += 1;

        if (d == '%' and i + 1 < raw.len) {
            d = (hex_table[raw[i]] << 4) | hex_table[raw[i + 1]];
            i += 2;
        }

        if (c != d) return false;
    }
    return i >= raw.len; // match all
}

const reg_name_chars: [256]u1 = buildRegNameChars();

fn buildRegNameChars() [256]u1 {
    var chars: [256]u1 = undefined;
    // match reg-name from RFC 3986, subsection 3.2.2
    for (0..256) |c| chars[c] = switch (c) {
        // unreserved
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => 1,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => 1,
        else => 0,
    };
    return chars;
}

const path_chars: [256]u1 = buildPathChars();

fn buildPathChars() [256]u1 {
    var chars: [256]u1 = undefined;
    // match path from RFC 3986, subsection 3.3
    for (0..256) |c| chars[c] = switch (c) {
        // unreserved
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => 1,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => 1,
        // pchar
        ':', '@' => 1,
        // path
        '/' => 1,
        else => 0,
    };
    return chars;
}

const query_chars: [256]u1 = buildQueryChars();
const fragment_chars: [256]u1 = query_chars;

fn buildQueryChars() [256]u1 {
    var chars: [256]u1 = undefined;
    // match query from RFC 3986, subsection 3.4
    for (0..256) |c| chars[c] = switch (c) {
        // unreserved
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => 1,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => 1,
        // pchar
        ':', '@' => 1,
        // query
        '/', '?' => 1,
        else => 0,
    };
    return chars;
}
