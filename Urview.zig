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

/// Urview contains a lossless decomposition with all URI components as is. Use
/// parse to obtain a valid instance. The input string equals the concatenation
/// of raw_scheme, raw_authority, raw_path, raw_query and raw_fragment.
const Urview = @This();

/// The scheme component ends with ":". It may contain upper-case letters.
raw_scheme: []const u8,

/// The authority component, if any, starts with "//".
raw_authority: []const u8 = "",
/// The userinfo component, if any, ends with "@".
raw_userinfo: []const u8 = "",
/// The host component can be a registered name, or an IP address.
raw_host: []const u8 = "",
/// The port component, if any, starts with ":".
raw_port: []const u8 = "",

/// The path compoment, if any, starts with "/" when (raw_)authority is
/// present.
raw_path: []const u8 = "",

/// The query compoment, if any, starts with "?".
raw_query: []const u8 = "",

/// The fragment component, if any, starts with "#".
raw_fragment: []const u8 = "",

/// Scheme returns the value normalized to lower-case.
pub fn scheme(ur: *const Urview, m: Allocator) error{OutOfMemory}![]u8 {
    if (ur.raw_scheme.len < 2) return "";
    const s = ur.raw_scheme[0 .. ur.raw_scheme.len - 1];

    var b = try m.alloc(u8, s.len);
    for (s, 0..) |c, i| {
        if (c < 'A' or c > 'Z') {
            b[i] = c;
        } else {
            b[i] = c + ('a' - 'A');
        }
    }
    return b;
}

/// HasScheme returns whether the value normalized to lower-case equals match.
pub fn hasScheme(ur: *const Urview, comptime match: []const u8) bool {
    // compile-time validation of match
    inline for (match) |c| switch (c) {
        'a'...'z', '0'...'9', '+', '-', '.' => continue,
        'A'...'Z' => @compileError("upper-case in scheme (never matches)"),
        else => @compileError("illegal character in scheme (never matches)"),
    };
    if (match.len == 0 or match[0] < 'a' or match[0] > 'z')
        @compileError("scheme without letter start (never matches)");

    if (match.len + 1 != ur.raw_scheme.len) return false;
    inline for (match, 0..) |c, i| {
        var r = ur.raw_scheme.ptr[i];
        if (r != c and (c < 'a' or c > 'z' or c - ('a' - 'A') != r))
            return false;
    }
    return true;
}

/// Userinfo returns the value with any and all of its percent-encodings
/// resolved. None of the applicable standards put any constraints on the
/// byte content. The return may or may not be a valid UTF-8 string.
pub fn userinfo(ur: *const Urview, m: Allocator) error{OutOfMemory}![]u8 {
    if (ur.raw_userinfo.len < 2) return "";
    return unescape(ur.raw_userinfo[0 .. ur.raw_userinfo.len - 1], m);
}

/// HasUserinfo returns whether the userinfo component is present, and
/// whether its value with any and all of its percent-encodings resolved
/// equals match.
pub fn hasUserinfo(ur: *const Urview, match: []const u8) bool {
    if (ur.raw_userinfo.len == 0) return false;
    return equalString(ur.raw_userinfo[0 .. ur.raw_userinfo.len - 1], match);
}

/// Host returns the value with any and all of its percent-encodings
/// resolved. None of the applicable standards put any constraints on the
/// byte content. The return may or may not be a valid UTF-8 string.
pub fn host(ur: *const Urview, m: Allocator) error{OutOfMemory}![]u8 {
    if (ur.raw_host.len == 0) return "";
    return unescape(ur.raw_host, m);
}

/// HasHost returns whether the authority component is present, and whether
/// the host value with any and all of its percent-encodings resolved equals
/// match.
pub fn hasHost(ur: *const Urview, match: []const u8) bool {
    if (ur.raw_authority.len == 0) return false;
    return equalString(ur.raw_host, match);
}

/// Port returns the value with zero for undefined or out-of-bounds.
pub fn port(ur: *const Urview) u16 {
    if (ur.raw_port.len < 2) return 0;
    return parseInt(u16, ur.raw_port[1..], 10) catch 0;
}

/// Path returns the value with any and all of its percent-encodings
/// resolved. None of the applicable standards put any constraints on the
/// byte content. The return may or may not be a valid UTF-8 string.
pub fn path(ur: *const Urview, m: Allocator) error{OutOfMemory}![]u8 {
    if (ur.raw_path.len == 0) return "";
    return unescape(ur.raw_path, m);
}

/// HasPath returns whether the value with any and all percent-encodings
/// resolved equals match.
pub fn hasPath(ur: *const Urview, match: []const u8) bool {
    return equalString(ur.raw_path, match);
}

/// PathNorm returns the path with any and all of its percent-encodings resolved
/// normalized conform the “Normalization and Comparison” rules of RFC 3986. Use
/// Urview from parse(3) returns exclusively. Results are undefined for invalid
/// raw_path values. None of the applicable standards put any constraints on the
/// byte content. The return may or may not be a valid UTF-8 string.
///
/// Any and all percent-encoded slashes ("%2F") are written as encodedSlashOut.
/// Valid options include:
///
///  • plain "/" undoes slash-escapes
///  • Unicode Fullwidth Solidus U+FF0F ("／")
///  • Unicode Object Replacement Charactacter U+FFFC can be “used as
///    placeholder in text for an otherwise unspecified object”
///  • Empty "" drops escaped slashes
///
pub fn pathNorm(ur: *const Urview, comptime encodedSlashOut: []const u8, m: Allocator) error{OutOfMemory}![]u8 {
    // TODO(pascaldekloe): validate uppercase percent encodings in encodedSlashOut

    // path is assumed to be valid
    const raw = ur.raw_path;
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
    for (tests) |t| {
        const ur = Urview{ .raw_scheme = "file", .raw_path = t.path };
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
    try expectEqualStrings("///host.example.com/I%2FO/", ur.raw_path);

    // replace "%2F" with zero string
    const got = try ur.pathNorm("", std.testing.allocator);
    defer std.testing.allocator.free(got);
    try expectEqualStrings("/host.example.com/IO", got);
}

/// Query returns the value with any and all percent-encodings resolved. None of
/// the applicable standards put any constraints on the byte content. The return
/// may or may not be a valid UTF-8 string.
pub fn query(ur: *const Urview, m: Allocator) error{OutOfMemory}![]u8 {
    if (ur.raw_query.len < 2) return "";
    return unescape(ur.raw_query[1..], m);
}

/// HasQuery returns whether a query component is present, and whether its
/// value with any and all percent-encodings resolved equals match.
pub fn hasQuery(ur: *const Urview, match: []const u8) bool {
    if (ur.raw_query.len == 0) return false;
    return equalString(ur.raw_query[1..], match);
}

/// Fragment returns the value with any and all percent-encodings resolved. None
/// of the applicable standards put any constraints on the byte content. The
/// return may or may not be a valid UTF-8 string.
pub fn fragment(ur: *const Urview, m: Allocator) error{OutOfMemory}![]u8 {
    if (ur.raw_fragment.len < 2) return "";
    return unescape(ur.raw_fragment[1..], m);
}

/// HasFragment returns whether a fragment component is present, and whether
/// its value with any and all percent-encodings resolved equals match.
pub fn hasFragment(ur: *const Urview, match: []const u8) bool {
    if (ur.raw_fragment.len == 0) return false;
    return equalString(ur.raw_fragment[1..], match);
}

// ParseError tries to be explicity about the source of conflict.
pub const ParseError = error{
    /// A scheme prefix is the only required component of a URI.
    NoScheme,

    /// Each component has its own constraints. Only characters "A"–"Z",
    /// "a"–"z", "0"–"9", "-", ".", "_" and "~" are safe to use without
    /// reservation.
    IllegalCharacter,

    /// IPv6 addresses (within square brackets "[" and "]") have a strict
    /// syntax definition. Note that zone identifiers are permitted since
    /// RFC 6874.
    IllegalAddress,

    /// The port number must consist of decimals exclusively.
    PortNotNumber,

    /// Every percent ("%") character must be followed by two hex digits.
    BrokenEscape,
};

/// Parse returns a mapping of s if and only if s is a valid URI.
pub fn parse(s: []const u8) ParseError!Urview {
    // match scheme from RFC 3986, subsection 3.1
    for (s, 0..) |c, i| switch (c) {
        // ALPHA from RFC 2234, subsection 6.1
        'A'...'Z', 'a'...'z' => continue,
        // DIGIT from RFC 2234, subsection 6.1
        '0'...'9', '+', '-', '.' => if (i == 0) return ParseError.NoScheme,
        ':' => {
            var ur = Urview{ .raw_scheme = s[0 .. i + 1] };
            try sinceScheme(&ur, s[i + 1 ..]);
            return ur;
        },
        else => return ParseError.NoScheme,
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

        // ensure lossless mapping
        try expectFmt(s, "{s}{s}{s}{s}{s}", .{ ur.raw_scheme, ur.raw_authority, ur.raw_path, ur.raw_query, ur.raw_fragment });

        // verify constraints from the field comments
        try expectStringEndsWith(ur.raw_scheme, ":");
        if (ur.raw_authority.len != 0) {
            try expectFmt(ur.raw_authority, "//{s}{s}{s}", .{ ur.raw_userinfo, ur.raw_host, ur.raw_port });
            if (ur.raw_userinfo.len != 0) try expectStringEndsWith(ur.raw_userinfo, "@");
            if (ur.raw_port.len != 0) try expectStringStartsWith(ur.raw_port, ":");
        } else {
            const empty: []const u8 = "";
            try expectEqual(empty, ur.raw_userinfo);
            try expectEqual(empty, ur.raw_host);
            try expectEqual(empty, ur.raw_port);
        }
        if (ur.raw_path.len != 0 and ur.raw_authority.len != 0) try expectStringStartsWith(ur.raw_path, "/");
        if (ur.raw_query.len != 0) try expectStringStartsWith(ur.raw_query, "?");
        if (ur.raw_fragment.len != 0) try expectStringStartsWith(ur.raw_fragment, "#");
    }
}

test "Upper-Case URN" {
    // sample from “Using ISBNs as URNs” RFC 3187, subsection 3.2
    const ur = try parse("URN:ISBN:0-395-36341-1");

    try expect(ur.hasScheme("urn"));

    const s = try ur.scheme(test_allocator);
    defer test_allocator.free(s);
    try expectEqualStrings("urn", s);

    try expect(ur.hasPath("ISBN:0-395-36341-1"));
    try expect(!ur.hasPath("isbn:0-395-36341-1"));

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

    try expectEqualStrings("x-odbc:", ur.raw_scheme);
    try expectEqualStrings("//admin:fe:main@[0::192.168.57.2]:5432", ur.raw_authority);
    try expectEqualStrings("admin:fe:main@", ur.raw_userinfo);
    try expectEqualStrings("[0::192.168.57.2]", ur.raw_host);
    try expectEqualStrings(":5432", ur.raw_port);
    try expectEqualStrings("/cms", ur.raw_path);
    try expectEqualStrings("?SELECT%20*%20FROM%20users;", ur.raw_query);
    try expectEqualStrings("#80%E2%80%93160", ur.raw_fragment);

    try expect(ur.hasScheme("x-odbc"));
    try expect(ur.hasUserinfo("admin:fe:main"));
    try expect(!ur.hasUserinfo("admin:fe:main@"));
    try expect(ur.hasHost("[0::192.168.57.2]"));
    try expect(!ur.hasHost("0::192.168.57.2"));
    try expect(!ur.hasHost("192.168.57.2"));
    try expectEqual(@as(u16, 5432), ur.port());
    try expect(ur.hasPath("/cms"));
    try expect(!ur.hasPath("cms"));
    try expect(ur.hasFragment("80–160"));
    try expect(!ur.hasFragment("80%E2%80%93160"));
    try expect(!ur.hasFragment("#80%E2%80%93160"));

    const q = try ur.query(test_allocator);
    defer test_allocator.free(q);
    try expectEqualStrings("SELECT * FROM users;", q);

    const f = try ur.fragment(test_allocator);
    defer test_allocator.free(f);
    try expectEqualStrings("80–160", f);
}

test "Absent" {
    const ur = try parse("X11:");

    try expect(ur.hasScheme("x11"));
    try expect(!ur.hasScheme("ssh"));
    try expect(!ur.hasUserinfo(""));
    try expect(!ur.hasHost(""));
    try expect(ur.port() == 0);
    try expect(ur.hasPath(""));
    try expect(!ur.hasFragment(""));

    try expectEqualStrings("", try ur.path(failing_allocator));
    try expectEqualStrings("", try ur.query(failing_allocator));
    try expectEqualStrings("", try ur.fragment(failing_allocator));
}

test "Empty" {
    const ur = try parse("x-://@:?#");

    try expect(ur.hasScheme("x-"));
    try expect(!ur.hasScheme("x"));
    try expect(ur.hasUserinfo(""));
    try expect(!ur.hasUserinfo("@"));
    try expect(ur.hasHost(""));
    try expect(!ur.hasHost("//"));
    try expect(ur.port() == 0);
    try expect(ur.hasPath(""));
    try expect(!ur.hasPath("/"));
    try expect(ur.hasFragment(""));
    try expect(!ur.hasFragment("#"));

    try expectEqualStrings("", try ur.userinfo(failing_allocator));
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
        return pathContinue(ur, s);
    }
    var i: usize = 2;

    // Colon (":") characters are used as a port separator, as an IPv6
    // addresses separator, and they may occur in userinfo.
    var colon_count: usize = 0;
    var last_colon: usize = 0;

    // • any IPv4address matches reg-name
    // • any reg-name matches userinfo
    while (i < s.len) {
        if (reg_name_chars[s[i]] != 0) {
            // either userinfo or reg-name; no escape needed
            i += 1;
        } else switch (s[i]) {
            // userinfo
            '@' => {
                if (ur.raw_userinfo.len != 0) return ParseError.IllegalCharacter;
                i += 1;
                ur.raw_userinfo = s[2..i];
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
                return pathContinue(ur, s[i..]);
            },
            '?' => {
                try authoritySet(ur, s[0..i], colon_count, last_colon);
                return queryContinue(ur, s[i..]);
            },
            '#' => {
                try authoritySet(ur, s[0..i], colon_count, last_colon);
                return fragmentContinue(ur, s[i..]);
            },
            '[' => {
                if (i != 2 + ur.raw_userinfo.len)
                    return ParseError.IllegalCharacter;
                return asIpLiteral(ur, s, i);
            },
            '%' => { // pct-encoded
                try checkEscape(s, i);
                i += 3;
            },
            else => return ParseError.IllegalCharacter,
        }
    }

    return authoritySet(ur, s, colon_count, last_colon);
}

fn authoritySet(ur: *Urview, s: []const u8, colon_count: usize, last_colon: usize) ParseError!void {
    ur.raw_authority = s;

    switch (colon_count) {
        0 => {
            ur.raw_host = s[2 + ur.raw_userinfo.len ..];
        },
        1 => {
            ur.raw_host = s[2 + ur.raw_userinfo.len .. last_colon];
            ur.raw_port = s[last_colon..];

            // match port from RFC 3986, subsection 3.2.3
            for (ur.raw_port[1..]) |c|
                if (c < '0' or c > '9')
                    return ParseError.PortNotNumber;
        },
        else => return ParseError.PortNotNumber,
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
    if (i >= s.len) return ParseError.IllegalAddress;
    switch (s[i]) {
        'v' => return asIpFuture(ur, s, start),
        ':' => {
            if (i + 1 >= s.len or s[i + 1] != ':')
                return ParseError.IllegalAddress;
            i += 2;
            zeroes_once = true;
        },
        else => {},
    }

    var h16n: usize = 0; // number of 16-bit pieces
    var hexn: usize = 0; // number of digits (max 4)

    // match IP-literal from RFC 3986, subsection 3.2.2 with a jump table
    while (i < s.len) : (i += 1) switch (s[i]) {
        inline '0'...'9', 'a'...'f', 'A'...'F' => { // HEXDIG
            if (hexn == 0) h16n += 1;
            hexn += 1;
        },
        ':' => {
            if (hexn == 0) {
                if (zeroes_once) return ParseError.IllegalAddress;
                zeroes_once = true;
            } else if (hexn > 4) {
                return ParseError.IllegalAddress;
            }
            hexn = 0;
        },
        ']' => {
            if (!zeroes_once and h16n != 8 or zeroes_once and h16n > 7)
                return ParseError.IllegalAddress;
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
                return ParseError.IllegalAddress;

            return Ip4inIp6Continue(ur, s, i - hexn);
        },

        // escaped percent ("%") character ("%25") separates zone identifier
        '%' => {
            if (i + 2 >= s.len or s[i + 1] != '2' or s[i + 2] != '5' or !zeroes_once and h16n != 8 or zeroes_once and h16n > 7)
                return ParseError.IllegalAddress;
            i += 3;
            var zone_start = i;

            // match ZoneID from “IPv6 Zone IDs in URIs” RFC 6874, section 2
            while (i < s.len) switch (s[i]) {
                // unreserved
                inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => i += 1,
                // pct-encoded
                '%' => {
                    try checkEscape(s, i);
                    i += 3;
                },
                ']' => {
                    if (i <= zone_start) return ParseError.IllegalAddress;
                    return ipLiteralEnd(ur, s, i);
                },
                inline else => return ParseError.IllegalAddress,
            };
        },

        inline else => return ParseError.IllegalAddress,
    };

    return ParseError.IllegalAddress; // not closed with "]"
}

// AsIpFuture parses authority s since "[v" at start.
fn asIpFuture(ur: *Urview, s: []const u8, start: usize) ParseError!void {
    // match IPvFuture from RFC 3986, subsection 3.2.2
    if (start + 4 > s.len or s[start + 3] != '.') return ParseError.IllegalAddress;
    switch (s[start + 2]) {
        '0'...'9', 'a'...'f', 'A'...'F' => {}, // HEXDIG
        else => return ParseError.IllegalAddress,
    }

    var i = start + 4;
    while (i < s.len) : (i += 1) switch (s[i]) {
        // unreserved
        inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => continue,
        // sub-delims
        inline '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => continue,
        ':' => continue,
        ']' => {
            if (i < start + 5) return ParseError.IllegalAddress;
            return ipLiteralEnd(ur, s, i);
        },
        inline else => return ParseError.IllegalAddress,
    };
    return ParseError.IllegalAddress; // not closed with "]"
}

fn Ip4inIp6Continue(ur: *Urview, s: []const u8, start: usize) ParseError!void {
    var i = start;
    var octn: usize = 1; // octet count (need 4)
    var decn: usize = 0; // decimal count (max 3)

    // match IPv4address from RFC 3986, subsection 3.2.2
    while (i < s.len) : (i += 1) switch (s[i]) {
        inline '0'...'9' => {
            decn += 1;
        },
        '.' => {
            _ = parseInt(u8, s[i - decn .. i], 10) catch
                return ParseError.IllegalAddress;
            if (decn == 0 or s[i - decn] == '0')
                return ParseError.IllegalAddress;
            octn += 1;
            decn = 0;
        },
        ']' => {
            _ = parseInt(u8, s[i - decn .. i], 10) catch
                return ParseError.IllegalAddress;
            if (decn == 0 or octn != 4 or s[i - decn] == '0')
                return ParseError.IllegalAddress;

            return ipLiteralEnd(ur, s, i);
        },
        inline else => return ParseError.IllegalAddress,
    };
    return ParseError.IllegalAddress; // not closed with "]"
}

// ipLiteralEnd continues from end "]" in authority s.
fn ipLiteralEnd(ur: *Urview, s: []const u8, end: usize) ParseError!void {
    var i = end + 1;
    ur.raw_host = s[2 + ur.raw_userinfo.len .. i];
    if (i >= s.len) {
        ur.raw_authority = s;
        return;
    }

    switch (s[i]) {
        '/' => {
            ur.raw_authority = s[0..i];
            return pathContinue(ur, s[i..]);
        },
        '?' => {
            ur.raw_authority = s[0..i];
            return queryContinue(ur, s[i..]);
        },
        '#' => {
            ur.raw_authority = s[0..i];
            return fragmentContinue(ur, s[i..]);
        },

        ':' => {
            const port_start = i;
            i += 1;

            // match port from RFC 3986, subsection 3.2.3
            while (i < s.len) : (i += 1) switch (s[i]) {
                '0'...'9' => continue,

                '/' => {
                    ur.raw_authority = s[0..i];
                    ur.raw_port = s[port_start..i];
                    return pathContinue(ur, s[i..]);
                },
                '?' => {
                    ur.raw_authority = s[0..i];
                    ur.raw_port = s[port_start..i];
                    return queryContinue(ur, s[i..]);
                },
                '#' => {
                    ur.raw_authority = s[0..i];
                    ur.raw_port = s[port_start..i];
                    return fragmentContinue(ur, s[i..]);
                },

                else => return ParseError.PortNotNumber,
            };
        },

        else => return ParseError.IllegalCharacter,
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
                try checkEscape(s, i);
                i += 3;
            },
            '?' => {
                ur.raw_path = s[0..i];
                return queryContinue(ur, s[i..]);
            },
            '#' => {
                ur.raw_path = s[0..i];
                return fragmentContinue(ur, s[i..]);
            },
            inline else => return ParseError.IllegalCharacter,
        }
    }
    ur.raw_path = s;
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
                try checkEscape(s, i);
                i += 3;
            },
            '#' => {
                ur.raw_query = s[0..i];
                return fragmentContinue(ur, s[i..]);
            },
            inline else => return ParseError.IllegalCharacter,
        }
    }
    ur.raw_query = s;
}

// FragmentContinue parses s after "#".
//
// “A fragment identifier component is indicated by the presence of a
// number sign ("#") character and terminated by the end of the URI.”
fn fragmentContinue(ur: *Urview, s: []const u8) ParseError!void {
    // match fragment from RFC 3986, subsection 3.5 with a jump table
    var i: usize = 1;
    while (i < s.len) {
        if (fragment_chars[s[i]] != 0) {
            i += 1;
        } else {
            if (s[i] != '%') return ParseError.IllegalCharacter;
            try checkEscape(s, i);
            i += 3;
        }
    }
    ur.raw_fragment = s;
}

// Unescape resolves percent-encodings.
fn unescape(raw: []const u8, allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
    // count output size
    var n: usize = 0;
    var i: usize = 0;
    while (raw.len - i > 2) : (n += 1)
        i += if (raw[i] == '%') 3 else 1;
    n += raw.len - i;

    // output
    var b = try allocator.alloc(u8, n);
    if (b.len == raw.len) {
        @memcpy(b, raw);
        return b;
    }

    // write pointer
    var p = b.ptr;
    i = 0;
    while (raw.len - i > 2) : (p += 1) {
        if (raw[i] != '%') {
            p[0] = raw[i];
            i += 1;
        } else {
            p[0] = (hex_table[raw[i + 1]] << 4) | hex_table[raw[i + 2]];
            i += 3;
        }
    }

    while (i < raw.len) {
        p[0] = raw[i];
        p += 1;
        i += 1;
    }

    return b;
}

fn checkEscape(s: []const u8, i: usize) ParseError!void {
    if (i + 2 >= s.len or (hex_table[s[i + 1]] | hex_table[s[i + 2]]) & 0xf0 != 0)
        return ParseError.BrokenEscape;
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

// EqualString returns whether the raw input with any and all of its
// percent-encodings resolved equals match.
fn equalString(raw: []const u8, match: []const u8) bool {
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
