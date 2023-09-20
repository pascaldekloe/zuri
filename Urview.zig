//! Strict readings of URIs.

const std = @import("std");
const parseInt = std.fmt.parseInt;
const Allocator = std.mem.Allocator;

const test_allocator = std.testing.allocator;
const failing_allocator = std.testing.failing_allocator;
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
uri_ptr: [*]const u8,
uri_size: u16,

// The seven offsets plus the overall (URI) size fits nicely into 16 bits.
// The userinfo offset could be calculated by comparing the authority and path
// offsets at the expense of an exectuion branche.

// Offsets are set (to non-zero) regardless of the component's precence.
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
    return ur.uri_ptr[ur.fragment_offset..ur.uri_size];
}

/// The fragment component is optional.
pub fn hasFragment(ur: Urview) bool {
    return ur.fragment_offset < ur.uri_size;
}

/// Scheme returns the component in lower-case. Caller owns the retured memory.
pub fn scheme(ur: Urview, m: Allocator) error{OutOfMemory}![]u8 {
    const raw = ur.uri_ptr[0 .. ur.authority_offset - 1];

    var b = try m.alloc(u8, raw.len);
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
pub fn userinfo(ur: Urview, m: Allocator) error{OutOfMemory}![]u8 {
    const offset = ur.userinfo_offset;
    const end = ur.host_offset - 1; // trim '@'
    if (offset >= end) return "";
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
pub fn host(ur: Urview, m: Allocator) error{OutOfMemory}![]u8 {
    if (ur.host_offset >= ur.port_offset) return "";
    return resolvePercentEncodingsToLower(ur.uri_ptr[ur.host_offset..ur.port_offset], m);
}

/// EqualsHost returns whether the component with any and all percent-encodings
/// resolved equals match. Absent components don't equal any match.
pub fn equalsHost(ur: Urview, match: []const u8) bool {
    if (ur.authority_offset >= ur.path_offset) return false;
    return equalsString(ur.rawHost(), match);
}

/// Port returns the number with zero for absent or out-of-bounds.
pub fn port(ur: Urview) u16 {
    const offset = ur.port_offset + 1; // trim ':'
    const end = ur.path_offset;
    if (offset >= end) return 0;
    return parseInt(u16, ur.uri_ptr[offset..end], 10) catch 0;
}

/// Path returns the component with any and all percent-encodings resolved. None
/// of the applicable standards put any constraints on the byte content. The
/// return may or may not be a valid UTF-8 string. Caller owns the returned
/// memory.
pub fn path(ur: Urview, m: Allocator) error{OutOfMemory}![]u8 {
    const raw = ur.rawPath();
    if (raw.len == 0) return "";
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
pub fn pathNorm(ur: *const Urview, comptime encodedSlashOut: []const u8, m: Allocator) error{OutOfMemory}![]u8 {
    const raw = ur.rawPath();
    if (raw.len < 2) {
        // no normalization possible
        if (raw.len == 0) return "";
        return m.dupe(u8, raw);
    }

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
    var out = try m.alloc(u8, size);
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
pub fn query(ur: Urview, m: Allocator) error{OutOfMemory}![]u8 {
    const offset = ur.query_offset + 1; // trim '?'
    const end = ur.fragment_offset;
    if (offset >= end) return "";
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
pub fn fragment(ur: Urview, m: Allocator) error{OutOfMemory}![]u8 {
    const offset = ur.fragment_offset + 1; // trim '#'
    const end = ur.uri_size;
    if (offset >= end) return "";
    return resolvePercentEncodings(ur.uri_ptr[offset..end], m);
}

/// EqualsFragment returns whether the component with any and all percent-
/// encodings resolved equals match. Absent components don't equal any match.
pub fn equalsFragment(ur: Urview, match: []const u8) bool {
    const offset = ur.fragment_offset + 1; // trim '#'
    const end = ur.uri_size;
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
pub fn parse(s: []const u8) ParseError!Urview {
    if (s.len > (1 << 16) - 1) return ParseError.StringTooBig;

    // match scheme from RFC 3986, subsection 3.1
    match_scheme: for (s, 0..) |c, i| switch (c) {
        // ALPHA from RFC 2234, subsection 6.1
        'A'...'Z', 'a'...'z' => continue,
        // DIGIT from RFC 2234, subsection 6.1
        '0'...'9', '+', '-', '.' => if (i == 0) break :match_scheme,
        ':' => {
            if (i == 0) break :match_scheme;
            var ur = Urview{
                .uri_ptr = s.ptr,
                .uri_size = @intCast(s.len),
                .authority_offset = @intCast(i + 1),
                .path_offset = @intCast(s.len),
                .query_offset = @intCast(s.len),
                .fragment_offset = @intCast(s.len),
            };
            try sinceScheme(&ur, s[i + 1 ..]);
            return ur;
        },
        else => break :match_scheme,
    };
    return ParseError.NoScheme;
}

test "Examples" {
    const samples = [_][]const u8{
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
    const ur = try parse("x-odbc://admin:fe:main@[0::192.168.57.2]:5432/cms?SELECT%20*%20FROM%20users;#80%E2%80%93160");

    try expectEqualStrings("x-odbc:", ur.rawScheme());
    try expectEqualStrings("//admin:fe:main@[0::192.168.57.2]:5432", ur.rawAuthority());
    try expectEqualStrings("admin:fe:main@", ur.rawUserinfo());
    try expectEqualStrings("[0::192.168.57.2]", ur.rawHost());
    try expectEqualStrings(":5432", ur.rawPort());
    try expectEqualStrings("/cms", ur.rawPath());
    try expectEqualStrings("?SELECT%20*%20FROM%20users;", ur.rawQuery());
    try expectEqualStrings("#80%E2%80%93160", ur.rawFragment());

    try expect(ur.equalsScheme("x-odbc"));
    try expect(ur.equalsUserinfo("admin:fe:main"));
    try expect(!ur.equalsUserinfo("admin:fe:main@"));
    try expect(ur.equalsHost("[0::192.168.57.2]"));
    try expect(!ur.equalsHost("0::192.168.57.2"));
    try expect(!ur.equalsHost("192.168.57.2"));
    try expectEqual(@as(u16, 5432), ur.port());
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
    try expect(ur.port() == 0);
    try expect(ur.equalsPath(""));
    try expect(!ur.equalsFragment(""));

    const s = try ur.scheme(test_allocator);
    defer test_allocator.free(s);
    try expectEqualStrings("x11", s);
    try expectEqualStrings("", try ur.userinfo(failing_allocator));
    try expectEqualStrings("", try ur.host(failing_allocator));
    try expectEqual(@as(u16, 0), ur.port());
    try expectEqualStrings("", try ur.path(failing_allocator));
    try expectEqualStrings("", try ur.query(failing_allocator));
    try expectEqualStrings("", try ur.fragment(failing_allocator));
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
    try expect(ur.port() == 0);
    try expect(ur.equalsPath(""));
    try expect(!ur.equalsPath("/"));
    try expect(ur.equalsQuery(""));
    try expect(!ur.equalsQuery("?"));
    try expect(ur.equalsFragment(""));
    try expect(!ur.equalsFragment("#"));

    try expectEqualStrings("", try ur.userinfo(failing_allocator));
    try expectEqualStrings("", try ur.host(failing_allocator));
    try expectEqualStrings("", try ur.path(failing_allocator));
    try expectEqualStrings("", try ur.query(failing_allocator));
    try expectEqualStrings("", try ur.fragment(failing_allocator));
}

// Parse all components after raw_scheme, which can be none.
fn sinceScheme(ur: *Urview, s: []const u8) ParseError!void {
    // “The authority component is preceded by a double slash ("//") and is
    // terminated by the next slash ("/"), question mark ("?"), or number
    // sign ("#") character, or by the end of the URI.”
    if (s.len < 2 or s[0] != '/' or s[1] != '/') {
        ur.userinfo_offset = ur.authority_offset;
        ur.host_offset = ur.authority_offset;
        ur.port_offset = ur.authority_offset;
        ur.path_offset = ur.authority_offset;
        return pathContinue(ur, s);
    }
    var i: usize = 2;

    ur.userinfo_offset = ur.authority_offset + 2;
    // Host offset is adjusted when userinfo is found.
    ur.host_offset = ur.userinfo_offset;

    // Colon (":") characters are used as a port separator, as an IPv6
    // addresses separator, and they may occur in userinfo.
    var colon_count: usize = 0;
    var last_colon: usize = 0;

    // • any IPv4address matches reg-name
    // • any reg-name matches userinfo
    while (i < s.len) {
        if (reg_name_chars[s[i]] != 0) {
            // either userinfo or reg-name
            i += 1;
        } else switch (s[i]) {
            // userinfo
            '@' => {
                if (ur.userinfo_offset > ur.host_offset)
                    return ParseError.MalformedAuthority;
                i += 1;
                ur.host_offset = ur.authority_offset + @as(u16, @intCast(i));
                colon_count = 0; // reset for host count
            },
            // either userinfo or port separator or invalid
            ':' => {
                colon_count += 1;
                last_colon = i;
                i += 1;
            },
            '/' => {
                try authoritySet(ur, s[0..i], colon_count, last_colon);
                ur.path_offset = ur.authority_offset + @as(u16, @intCast(i));
                return pathContinue(ur, s[i..]);
            },
            '?' => {
                try authoritySet(ur, s[0..i], colon_count, last_colon);
                ur.query_offset = ur.path_offset;
                return queryContinue(ur, s[i..]);
            },
            '#' => {
                try authoritySet(ur, s[0..i], colon_count, last_colon);
                ur.query_offset = ur.path_offset;
                ur.fragment_offset = ur.path_offset;
                return verifyFragment(s[i..]);
            },
            '[' => {
                if (i != 2 + @as(usize, ur.host_offset - ur.userinfo_offset))
                    return ParseError.MalformedAuthority;
                return asIpLiteral(ur, s, i);
            },
            '%' => { // pct-encoded
                try verifyProcentEncoding(s, i);
                i += 3;
            },
            else => return ParseError.IllegalAuthorityCharacter,
        }
    }

    try authoritySet(ur, s, colon_count, last_colon);
    ur.query_offset = ur.path_offset;
    ur.fragment_offset = ur.path_offset;
}

fn authoritySet(ur: *Urview, s: []const u8, colon_count: usize, last_colon: usize) ParseError!void {
    ur.path_offset = ur.authority_offset + @as(u16, @intCast(s.len));

    switch (colon_count) {
        0 => {
            ur.port_offset = ur.path_offset;
        },
        1 => {
            ur.port_offset = ur.authority_offset + @as(u16, @intCast(last_colon));

            // match port from RFC 3986, subsection 3.2.3
            for (s[last_colon + 1 ..]) |c|
                if (c < '0' or c > '9')
                    return ParseError.IllegalPortCharacter;
        },
        else => return ParseError.MalformedAuthority,
    }
}

// Parses authority s since "[" at start.
fn asIpLiteral(ur: *Urview, s: []const u8, start: usize) ParseError!void {
    // “The use of "::" indicates one or more groups of 16 bits of zeros.
    // The "::" can only appear once in an address.  The "::" can also be
    // used to compress leading or trailing zeros in an address.”
    // — “IPv6 Addressing Architecture” RFC 3513, subsection 2.2
    var zeroes_once = false;

    var i = start + 1;
    if (i >= s.len) return ParseError.AddressViolation;
    switch (s[i]) {
        'v' => return asIpFuture(ur, s, start),
        ':' => {
            if (i + 1 >= s.len or s[i + 1] != ':')
                return ParseError.AddressViolation;
            i += 2;
            zeroes_once = true;
        },
        else => {},
    }

    var h16n: usize = 0; // number of 16-bit pieces
    var hexn: usize = 0; // number of digits (max 4)

    // match IP-literal from RFC 3986, subsection 3.2.2 with a jump table
    while (i < s.len) : (i += 1) switch (s[i]) {
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
            return ipLiteralEnd(ur, s, i);
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

            return Ip4inIp6Continue(ur, s, i - hexn);
        },

        // percent character ("%"), encoded as "%25", marks a zone identifier
        '%' => {
            if (i + 2 >= s.len or s[i + 1] != '2' or s[i + 2] != '5' or !zeroes_once and h16n != 8 or zeroes_once and h16n > 7)
                return ParseError.AddressViolation;
            i += 3;
            var zone_start = i;

            // match ZoneID from “IPv6 Zone IDs in URIs” RFC 6874, section 2
            while (i < s.len) switch (s[i]) {
                // unreserved
                'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => i += 1,
                // pct-encoded
                '%' => {
                    try verifyProcentEncoding(s, i);
                    i += 3;
                },
                ']' => {
                    if (i <= zone_start) return ParseError.AddressViolation;
                    return ipLiteralEnd(ur, s, i);
                },
                else => return ParseError.AddressViolation,
            };
        },

        else => return ParseError.AddressViolation,
    };

    return ParseError.AddressViolation; // not closed with "]"
}

// AsIpFuture parses authority s since "[v" at start.
fn asIpFuture(ur: *Urview, s: []const u8, start: usize) ParseError!void {
    // match IPvFuture from RFC 3986, subsection 3.2.2
    if (start + 4 > s.len or s[start + 3] != '.') return ParseError.AddressViolation;
    switch (s[start + 2]) {
        '0'...'9', 'a'...'f', 'A'...'F' => {}, // HEXDIG
        else => return ParseError.AddressViolation,
    }

    var i = start + 4;
    while (i < s.len) : (i += 1) switch (s[i]) {
        // unreserved
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => continue,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => continue,
        ':' => continue,
        ']' => {
            if (i < start + 5) return ParseError.AddressViolation;
            return ipLiteralEnd(ur, s, i);
        },
        else => return ParseError.AddressViolation,
    };
    return ParseError.AddressViolation; // not closed with "]"
}

fn Ip4inIp6Continue(ur: *Urview, s: []const u8, start: usize) ParseError!void {
    var i = start;
    var octn: usize = 1; // octet count (need 4)
    var decn: usize = 0; // decimal count (max 3)

    // match IPv4address from RFC 3986, subsection 3.2.2
    while (i < s.len) : (i += 1) switch (s[i]) {
        '0'...'9' => {
            decn += 1;
        },
        '.' => {
            _ = parseInt(u8, s[i - decn .. i], 10) catch
                return ParseError.AddressViolation;
            if (decn == 0 or s[i - decn] == '0')
                return ParseError.AddressViolation;
            octn += 1;
            decn = 0;
        },
        ']' => {
            _ = parseInt(u8, s[i - decn .. i], 10) catch
                return ParseError.AddressViolation;
            if (decn == 0 or octn != 4 or s[i - decn] == '0')
                return ParseError.AddressViolation;

            return ipLiteralEnd(ur, s, i);
        },
        else => return ParseError.AddressViolation,
    };
    return ParseError.AddressViolation; // not closed with "]"
}

// ipLiteralEnd continues from end "]" in authority s.
fn ipLiteralEnd(ur: *Urview, s: []const u8, end: usize) ParseError!void {
    var i = end + 1;
    ur.port_offset = ur.authority_offset + @as(u16, @intCast(i));
    if (i >= s.len) return;

    switch (s[i]) {
        '/' => {
            ur.path_offset = ur.port_offset;
            return pathContinue(ur, s[i..]);
        },
        '?' => {
            ur.path_offset = ur.port_offset;
            ur.query_offset = ur.port_offset;
            return queryContinue(ur, s[i..]);
        },
        '#' => {
            ur.path_offset = ur.port_offset;
            ur.query_offset = ur.port_offset;
            ur.fragment_offset = ur.port_offset;
            return verifyFragment(s[i..]);
        },

        ':' => {
            i += 1;

            // match port from RFC 3986, subsection 3.2.3
            while (i < s.len) : (i += 1) switch (s[i]) {
                '0'...'9' => continue,

                '/' => {
                    ur.path_offset = ur.authority_offset + @as(u16, @intCast(i));
                    return pathContinue(ur, s[i..]);
                },
                '?' => {
                    ur.path_offset = ur.authority_offset + @as(u16, @intCast(i));
                    ur.query_offset = ur.path_offset;
                    return queryContinue(ur, s[i..]);
                },
                '#' => {
                    ur.path_offset = ur.authority_offset + @as(u16, @intCast(i));
                    ur.query_offset = ur.path_offset;
                    ur.fragment_offset = ur.query_offset;
                    return verifyFragment(s[i..]);
                },

                else => return ParseError.IllegalPortCharacter,
            };
        },

        // trailer after address ended (with "]")
        else => return ParseError.MalformedAuthority,
    }
}

// PathContinue parses s as the path component.
fn pathContinue(ur: *Urview, s: []const u8) ParseError!void {
    // match path from RFC 3986, subsection 3.3 with a jump table
    var i: usize = 0;
    while (i < s.len) {
        if (path_chars[s[i]] != 0) {
            i += 1;
        } else switch (s[i]) {
            '%' => {
                try verifyProcentEncoding(s, i);
                i += 3;
            },
            '?' => {
                ur.query_offset = ur.path_offset + @as(u16, @intCast(i));
                return queryContinue(ur, s[i..]);
            },
            '#' => {
                ur.query_offset = ur.path_offset + @as(u16, @intCast(i));
                ur.fragment_offset = ur.query_offset;
                return verifyFragment(s[i..]);
            },
            else => return ParseError.IllegalPathCharacter,
        }
    }
}

// QueryContinue parses s after "?".
//
// “The query component is indicated by the first question mark ("?")
// character and terminated by a number sign ("#") character or by the end
// of the URI.”
fn queryContinue(ur: *Urview, s: []const u8) ParseError!void {
    // match query from RFC 3986, subsection 3.4 with a jump table
    var i: usize = 1;
    while (i < s.len) {
        if (query_chars[s[i]] != 0) {
            i += 1;
        } else switch (s[i]) {
            // pct-encoded
            '%' => {
                try verifyProcentEncoding(s, i);
                i += 3;
            },
            '#' => {
                ur.fragment_offset = ur.query_offset + @as(u16, @intCast(i));
                return verifyFragment(s[i..]);
            },
            else => return ParseError.IllegalQueryCharacter,
        }
    }
}

// VerifyFragment parses s after "#".
//
// “A fragment identifier component is indicated by the presence of a
// number sign ("#") character and terminated by the end of the URI.”
fn verifyFragment(s: []const u8) ParseError!void {
    // match fragment from RFC 3986, subsection 3.5 with a jump table
    var i: usize = 1;
    while (i < s.len) {
        if (fragment_chars[s[i]] != 0) {
            i += 1;
        } else {
            if (s[i] != '%') return ParseError.IllegalFragmentCharacter;
            try verifyProcentEncoding(s, i);
            i += 3;
        }
    }
}

fn resolvePercentEncodings(raw: []const u8, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
    return resolvePercentEncodingsWithToLower(raw, false, m);
}

fn resolvePercentEncodingsToLower(raw: []const u8, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
    return resolvePercentEncodingsWithToLower(raw, true, m);
}

fn resolvePercentEncodingsWithToLower(raw: []const u8, comptime toLower: bool, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
    var i: usize = 0; // raw index
    var n: usize = 0; // output count [octets]
    while (raw.len - i > 2) : (n += 1)
        i += if (raw[i] == '%') 3 else 1;
    n += raw.len - i;

    // output
    if (!toLower and n >= raw.len) return m.dupe(u8, raw);
    var b = try m.alloc(u8, n);

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

fn verifyProcentEncoding(s: []const u8, i: usize) ParseError!void {
    if (i + 2 >= s.len or (hex_table[s[i + 1]] | hex_table[s[i + 2]]) & 0xf0 != 0)
        return ParseError.BrokenPercentEncoding;
}

const hex_table: [256]u8 = buildHexTable();

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
