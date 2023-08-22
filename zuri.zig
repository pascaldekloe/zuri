//! URI/IRI reading

const std = @import("std");
const testing = std.testing;
const errorf = std.debug.print;
const Allocator = std.mem.Allocator;

/// Parts contains a lossless decomposition with all URI components as is. Use
/// parse to obtain a valid instance. The input string equals the concatenation
/// of raw_scheme, raw_authority, raw_path, raw_query and raw_fragment.
pub const Parts = struct {
    /// The scheme component ends with ':'. It may contain upper-case letters.
    raw_scheme: []const u8,

    /// The authority component, if any, starts with "//".
    raw_authority: []const u8 = "",
    /// The userinfo component, if any, ends with '@'.
    raw_userinfo: []const u8 = "",
    /// The host component can be a registered name, or an IP address.
    raw_host: []const u8 = "",
    /// The port component, if any, starts with ':'.
    raw_port: []const u8 = "",

    /// The path compoment, if any, starts with '/' when the URI has an
    /// authority component.
    raw_path: []const u8 = "",

    /// The query compoment, if any, starts with '?'.
    raw_query: []const u8 = "",

    /// The fragment component, if any, starts with '#'.
    raw_fragment: []const u8 = "",

    /// Scheme returns the value normalized to lower-case.
    pub fn scheme(p: *const Parts, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
        if (p.raw_scheme.len < 2) return "";
        const s = p.raw_scheme[0 .. p.raw_scheme.len - 1];

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
    pub fn hasScheme(p: *const Parts, comptime match: []const u8) bool {
        // compile-time validation of match
        inline for (match) |c| {
            switch (c) {
                'a'...'z', '0'...'9', '+', '-', '.' => continue,
                'A'...'Z' => @compileError("upper-case in scheme (never matches)"),
                else => @compileError("illegal character in scheme (never matches)"),
            }
        }
        if (match.len == 0 or match[0] < 'a' or match[0] > 'z')
            @compileError("without letter start (never matches)");

        if (match.len + 1 != p.raw_scheme.len) return false;
        inline for (match, 0..) |c, i| {
            var r = p.raw_scheme.ptr[i];
            if (r != c and (c < 'a' or c > 'z' or c - ('a' - 'A') != r))
                return false;
        }
        return true;
    }

    /// Userinfo returns the value with any and all of its percent-encodings
    /// resolved.
    pub fn userinfo(p: *const Parts, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
        if (p.raw_userinfo.len < 2) return "";
        return unescape(p.raw_userinfo[0 .. p.raw_userinfo.len - 1], m);
    }

    /// HasUserinfo returns whether the userinfo component is present, and
    /// whether its value with any and all of its percent-encodings resolved
    /// equals match.
    pub fn hasUserinfo(p: *const Parts, match: []const u8) bool {
        if (p.raw_userinfo.len == 0) return false;
        return equalString(p.raw_userinfo[0 .. p.raw_userinfo.len - 1], match);
    }

    /// Host returns the value with any and all of its percent-encodings
    /// resolved.
    pub fn host(p: *const Parts, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
        if (p.raw_host.len == 0) return "";
        return unescape(p.raw_host, m);
    }

    /// HasHost returns whether the authority component is present, and whether
    /// the host value with any and all of its percent-encodings resolved equals
    /// match.
    pub fn hasHost(p: *const Parts, match: []const u8) bool {
        if (p.raw_authority.len == 0) return false;
        return equalString(p.raw_host, match);
    }

    /// Port returns the value with zero for undefined or out-of-bounds.
    pub fn port(p: *const Parts) u16 {
        if (p.raw_port.len < 2) return 0;
        return std.fmt.parseInt(u16, p.raw_port[1..], 10) catch 0;
    }

    /// Path returns the value with any and all of its percent-encodings
    /// resolved.
    pub fn path(p: *const Parts, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
        if (p.raw_path.len == 0) return "";
        return unescape(p.raw_path, m);
    }

    /// HasPath returns whether the value with any and all percent-encodings
    /// resolved equals match.
    pub fn hasPath(p: *const Parts, match: []const u8) bool {
        return equalString(p.raw_path, match);
    }

    /// Query returns the value with any and all percent-encodings resolved.
    pub fn query(p: *const Parts, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
        if (p.raw_query.len < 2) return "";
        return unescape(p.raw_query[1..], m);
    }

    /// HasQuery returns whether a query component is present, and whether its
    /// value with any and all percent-encodings resolved equals match.
    pub fn hasQuery(p: *const Parts, match: []const u8) bool {
        if (p.raw_query.len == 0) return false;
        return equalString(p.raw_query[1..], match);
    }

    /// Fragment returns the value with any and all percent-encodings resolved.
    pub fn fragment(p: *const Parts, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
        if (p.raw_fragment.len < 2) return "";
        return unescape(p.raw_fragment[1..], m);
    }

    /// HasFragment returns whether a fragment component is present, and whether
    /// its value with any and all percent-encodings resolved equals match.
    pub fn hasFragment(p: *const Parts, match: []const u8) bool {
        if (p.raw_fragment.len == 0) return false;
        return equalString(p.raw_fragment[1..], match);
    }
};

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
pub fn parse(s: []const u8) ParseError!Parts {
    // match scheme from RFC 3986, subsection 3.1 with a jump table
    for (s, 0..) |c, i| switch (c) {
        // ALPHA from RFC 2234, subsection 6.1
        inline 'A'...'Z', 'a'...'z' => continue,
        // DIGIT from RFC 2234, subsection 6.1
        inline '0'...'9', '+', '-', '.' => if (i == 0) return ParseError.NoScheme,
        ':' => {
            var p = Parts{ .raw_scheme = s[0 .. i + 1] };
            try sinceScheme(&p, s[i + 1 ..]);
            return p;
        },
        inline else => return ParseError.NoScheme,
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
        var p = parse(s) catch |err| {
            errorf("\ngot error {} for {s}\n", .{ err, s });
            return err;
        };

        // ensure lossless mapping
        try testing.expectFmt(s, "{s}{s}{s}{s}{s}", .{ p.raw_scheme, p.raw_authority, p.raw_path, p.raw_query, p.raw_fragment });

        // verify constraints from the field comments
        try testing.expectStringEndsWith(p.raw_scheme, ":");
        if (p.raw_authority.len != 0) {
            try testing.expectFmt(p.raw_authority, "//{s}{s}{s}", .{ p.raw_userinfo, p.raw_host, p.raw_port });
            if (p.raw_userinfo.len != 0) try testing.expectStringEndsWith(p.raw_userinfo, "@");
            if (p.raw_port.len != 0) try testing.expectStringStartsWith(p.raw_port, ":");
        } else {
            const empty: []const u8 = "";
            try testing.expectEqual(empty, p.raw_userinfo);
            try testing.expectEqual(empty, p.raw_host);
            try testing.expectEqual(empty, p.raw_port);
        }
        if (p.raw_path.len != 0 and p.raw_authority.len != 0) try testing.expectStringStartsWith(p.raw_path, "/");
        if (p.raw_query.len != 0) try testing.expectStringStartsWith(p.raw_query, "?");
        if (p.raw_fragment.len != 0) try testing.expectStringStartsWith(p.raw_fragment, "#");
    }
}

test "Upper-Case URN" {
    // sample from “Using ISBNs as URNs” RFC 3187, subsection 3.2
    var p = try parse("URN:ISBN:0-395-36341-1");

    try testing.expect(p.hasScheme("urn"));

    var scheme = try p.scheme(testing.allocator);
    defer testing.allocator.free(scheme);
    try testing.expectEqualStrings("urn", scheme);

    try testing.expect(p.hasPath("ISBN:0-395-36341-1"));
    try testing.expect(!p.hasPath("isbn:0-395-36341-1"));

    var path = try p.path(testing.allocator);
    defer testing.allocator.free(path);
    try testing.expectEqualStrings("ISBN:0-395-36341-1", path);
}

test "Tricky" {
    var p = try parse("bang://AD2%5cBill%40live.com@?C:%5cProgram+Files%5C*.EXE");

    var userinfo = try p.userinfo(testing.allocator);
    defer testing.allocator.free(userinfo);
    try testing.expectEqualStrings("AD2\\Bill@live.com", userinfo);

    var query = try p.query(testing.allocator);
    defer testing.allocator.free(query);
    try testing.expectEqualStrings("C:\\Program+Files\\*.EXE", query);
}

test "Bloat" {
    var p = try parse("x-odbc://admin:fe:main@[0::192.168.57.2]:5432/cms?SELECT%20*%20FROM%20users;#80%E2%80%93160");

    try testing.expectEqualStrings("x-odbc:", p.raw_scheme);
    try testing.expectEqualStrings("//admin:fe:main@[0::192.168.57.2]:5432", p.raw_authority);
    try testing.expectEqualStrings("admin:fe:main@", p.raw_userinfo);
    try testing.expectEqualStrings("[0::192.168.57.2]", p.raw_host);
    try testing.expectEqualStrings(":5432", p.raw_port);
    try testing.expectEqualStrings("/cms", p.raw_path);
    try testing.expectEqualStrings("?SELECT%20*%20FROM%20users;", p.raw_query);
    try testing.expectEqualStrings("#80%E2%80%93160", p.raw_fragment);

    try testing.expect(p.hasScheme("x-odbc"));
    try testing.expect(p.hasUserinfo("admin:fe:main"));
    try testing.expect(!p.hasUserinfo("admin:fe:main@"));
    try testing.expect(p.hasHost("[0::192.168.57.2]"));
    try testing.expect(!p.hasHost("0::192.168.57.2"));
    try testing.expect(!p.hasHost("192.168.57.2"));
    try testing.expectEqual(@as(u16, 5432), p.port());
    try testing.expect(p.hasPath("/cms"));
    try testing.expect(!p.hasPath("cms"));
    try testing.expect(p.hasFragment("80–160"));
    try testing.expect(!p.hasFragment("80%E2%80%93160"));
    try testing.expect(!p.hasFragment("#80%E2%80%93160"));

    var query = try p.query(testing.allocator);
    defer testing.allocator.free(query);
    try testing.expectEqualStrings("SELECT * FROM users;", query);

    var fragment = try p.fragment(testing.allocator);
    defer testing.allocator.free(fragment);
    try testing.expectEqualStrings("80–160", fragment);
}

test "absent" {
    var p = try parse("X11:");

    try testing.expect(p.hasScheme("x11"));
    try testing.expect(!p.hasScheme("ssh"));
    try testing.expect(!p.hasUserinfo(""));
    try testing.expect(!p.hasHost(""));
    try testing.expect(p.port() == 0);
    try testing.expect(p.hasPath(""));
    try testing.expect(!p.hasFragment(""));

    try testing.expectEqualStrings("", try p.path(testing.failing_allocator));
    try testing.expectEqualStrings("", try p.query(testing.failing_allocator));
    try testing.expectEqualStrings("", try p.fragment(testing.failing_allocator));
}

test "empty" {
    var p = try parse("x-://@:?#");

    try testing.expect(p.hasScheme("x-"));
    try testing.expect(!p.hasScheme("x"));
    try testing.expect(p.hasUserinfo(""));
    try testing.expect(!p.hasUserinfo("@"));
    try testing.expect(p.hasHost(""));
    try testing.expect(!p.hasHost("//"));
    try testing.expect(p.port() == 0);
    try testing.expect(p.hasPath(""));
    try testing.expect(!p.hasPath("/"));
    try testing.expect(p.hasFragment(""));
    try testing.expect(!p.hasFragment("#"));

    try testing.expectEqualStrings("", try p.userinfo(testing.failing_allocator));
    try testing.expectEqualStrings("", try p.path(testing.failing_allocator));
    try testing.expectEqualStrings("", try p.query(testing.failing_allocator));
    try testing.expectEqualStrings("", try p.fragment(testing.failing_allocator));
}

// Parse all components after raw_scheme, which can be none.
fn sinceScheme(p: *Parts, s: []const u8) ParseError!void {
    // “The authority component is preceded by a double slash ("//") and is
    // terminated by the next slash ("/"), question mark ("?"), or number
    // sign ("#") character, or by the end of the URI.”
    if (s.len < 2 or s[0] != '/' or s[1] != '/') {
        return pathContinue(p, s);
    }
    var i: usize = 2;

    // Colon (":") characters are used as a port separator, as an IPv6
    // addresses separator, and they may occur in userinfo.
    var colon_count: usize = 0;
    var last_colon: usize = 0;

    // match authoritiry from RFC 3986, subsection 3.2 with a jump table
    while (i < s.len) switch (s[i]) {
        // unreserved
        inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => i += 1,
        // sub-delims
        inline '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => i += 1,
        // userinfo
        '@' => {
            if (p.raw_userinfo.len != 0) return ParseError.IllegalCharacter;
            i += 1;
            p.raw_userinfo = s[2..i];
            colon_count = 0; // reset for host count
        },
        // either userinfo or port separator or invalid
        ':' => {
            colon_count += 1;
            last_colon = i;
            i += 1;
        },
        '/' => {
            try authoritySet(p, s[0..i], colon_count, last_colon);
            return pathContinue(p, s[i..]);
        },
        '?' => {
            try authoritySet(p, s[0..i], colon_count, last_colon);
            return queryContinue(p, s[i..]);
        },
        '#' => {
            try authoritySet(p, s[0..i], colon_count, last_colon);
            return fragmentContinue(p, s[i..]);
        },
        '[' => {
            if (i != 2 + p.raw_userinfo.len)
                return ParseError.IllegalCharacter;
            return asIpLiteral(p, s, i);
        },
        '%' => { // pct-encoded
            try checkEscape(s, i);
            i += 3;
        },
        inline else => return ParseError.IllegalCharacter,
    };

    return authoritySet(p, s, colon_count, last_colon);
}

fn authoritySet(p: *Parts, s: []const u8, colon_count: usize, last_colon: usize) ParseError!void {
    p.raw_authority = s;

    switch (colon_count) {
        0 => {
            p.raw_host = s[2 + p.raw_userinfo.len ..];
        },
        1 => {
            p.raw_host = s[2 + p.raw_userinfo.len .. last_colon];
            p.raw_port = s[last_colon..];

            // match port from RFC 3986, subsection 3.2.3
            for (p.raw_port[1..]) |c|
                if (c < '0' or c > '9')
                    return ParseError.PortNotNumber;
        },
        else => return ParseError.PortNotNumber,
    }
}

// Parses authority s since "[" at start.
fn asIpLiteral(p: *Parts, s: []const u8, start: usize) ParseError!void {
    // “The use of "::" indicates one or more groups of 16 bits of zeros.
    // The "::" can only appear once in an address.  The "::" can also be
    // used to compress leading or trailing zeros in an address.”
    // — “IPv6 Addressing Architecture” RFC 3513, subsection 2.2
    var zeroes_once = false;

    var i = start + 1;
    if (i >= s.len) return ParseError.IllegalAddress;
    switch (s[i]) {
        'v' => return asIpFuture(p, s, start),
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
            return ipLiteralEnd(p, s, i);
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

            return Ip4inIp6Continue(p, s, i - hexn);
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
                    return ipLiteralEnd(p, s, i);
                },
                inline else => return ParseError.IllegalAddress,
            };
        },

        inline else => return ParseError.IllegalAddress,
    };

    return ParseError.IllegalAddress; // not closed with "]"
}

// AsIpFuture parses authority s since "[v" at start.
fn asIpFuture(p: *Parts, s: []const u8, start: usize) ParseError!void {
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
            return ipLiteralEnd(p, s, i);
        },
        inline else => return ParseError.IllegalAddress,
    };
    return ParseError.IllegalAddress; // not closed with "]"
}

fn Ip4inIp6Continue(p: *Parts, s: []const u8, start: usize) ParseError!void {
    var i = start;
    var octn: usize = 1; // octet count (need 4)
    var decn: usize = 0; // decimal count (max 3)

    // match IPv4address from RFC 3986, subsection 3.2.2
    while (i < s.len) : (i += 1) switch (s[i]) {
        inline '0'...'9' => {
            decn += 1;
        },
        '.' => {
            var v = std.fmt.parseInt(u8, s[i - decn .. i], 10) catch
                return ParseError.IllegalAddress;
            if (decn == 0 or s[i - decn] == '0' or v == 0)
                return ParseError.IllegalAddress;
            octn += 1;
            decn = 0;
        },
        ']' => {
            var v = std.fmt.parseInt(u8, s[i - decn .. i], 10) catch
                return ParseError.IllegalAddress;
            if (decn == 0 or octn != 4 or s[i - decn] == '0' or v == 0)
                return ParseError.IllegalAddress;

            return ipLiteralEnd(p, s, i);
        },
        inline else => return ParseError.IllegalAddress,
    };
    return ParseError.IllegalAddress; // not closed with "]"
}

// ipLiteralEnd continues from end "]" in authority s.
fn ipLiteralEnd(p: *Parts, s: []const u8, end: usize) ParseError!void {
    var i = end + 1;
    p.raw_host = s[2 + p.raw_userinfo.len .. i];
    if (i >= s.len) {
        p.raw_authority = s;
        return;
    }

    switch (s[i]) {
        '/' => {
            p.raw_authority = s[0..i];
            return pathContinue(p, s[i..]);
        },
        '?' => {
            p.raw_authority = s[0..i];
            return queryContinue(p, s[i..]);
        },
        '#' => {
            p.raw_authority = s[0..i];
            return fragmentContinue(p, s[i..]);
        },

        ':' => {
            const port_start = i;
            i += 1;

            // match port from RFC 3986, subsection 3.2.3
            while (i < s.len) : (i += 1) switch (s[i]) {
                '0'...'9' => continue,

                '/' => {
                    p.raw_authority = s[0..i];
                    p.raw_port = s[port_start..i];
                    return pathContinue(p, s[i..]);
                },
                '?' => {
                    p.raw_authority = s[0..i];
                    p.raw_port = s[port_start..i];
                    return queryContinue(p, s[i..]);
                },
                '#' => {
                    p.raw_authority = s[0..i];
                    p.raw_port = s[port_start..i];
                    return fragmentContinue(p, s[i..]);
                },

                else => return ParseError.PortNotNumber,
            };
        },

        else => return ParseError.IllegalCharacter,
    }
}

// PathContinue parses s as the path component.
fn pathContinue(p: *Parts, s: []const u8) ParseError!void {
    // match path from RFC 3986, subsection 3.3 with a jump table
    var i: usize = 0;
    while (i < s.len) switch (s[i]) {
        // unreserved
        inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => i += 1,
        // sub-delims
        inline '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => i += 1,
        // pchar, slash
        inline ':', '@', '/' => i += 1,
        // pct-encoded
        '%' => {
            try checkEscape(s, i);
            i += 3;
        },
        '?' => {
            p.raw_path = s[0..i];
            return queryContinue(p, s[i..]);
        },
        '#' => {
            p.raw_path = s[0..i];
            return fragmentContinue(p, s[i..]);
        },
        inline else => return ParseError.IllegalCharacter,
    };
    p.raw_path = s;
}

// QueryContinue parses s after "?".
//
// “The query component is indicated by the first question mark ("?")
// character and terminated by a number sign ("#") character or by the end
// of the URI.”
fn queryContinue(p: *Parts, s: []const u8) ParseError!void {
    // match query from RFC 3986, subsection 3.4 with a jump table
    var i: usize = 1;
    while (i < s.len) switch (s[i]) {
        // unreserved
        inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => i += 1,
        // sub-delims
        inline '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => i += 1,
        // pchar & query
        inline ':', '@', '/', '?' => i += 1,
        // pct-encoded
        '%' => {
            try checkEscape(s, i);
            i += 3;
        },
        '#' => {
            p.raw_query = s[0..i];
            return fragmentContinue(p, s[i..]);
        },
        inline else => return ParseError.IllegalCharacter,
    };
    p.raw_query = s;
}

// FragmentContinue parses s after "#".
//
// “A fragment identifier component is indicated by the presence of a
// number sign ("#") character and terminated by the end of the URI.”
fn fragmentContinue(p: *Parts, s: []const u8) ParseError!void {
    // match fragment from RFC 3986, subsection 3.5 with a jump table
    var i: usize = 1;
    while (i < s.len) switch (s[i]) {
        // unreserved
        inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => i += 1,
        // sub-delims
        inline '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => i += 1,
        // pchar & fragment
        inline ':', '@', '/', '?' => i += 1,
        // pct-encoded
        '%' => {
            try checkEscape(s, i);
            i += 3;
        },
        inline else => return ParseError.IllegalCharacter,
    };
    p.raw_fragment = s;
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
            p[0] = (hexval(raw[i + 1]) << 4) | hexval(raw[i + 2]);
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
    if (i + 2 >= s.len or (hexval(s[i + 1]) | hexval(s[i + 2])) & 0xf0 != 0)
        return ParseError.BrokenEscape;
}

fn hexval(c: u8) (u8) {
    return switch (c) {
        inline '0'...'9' => c - '0',
        inline 'a'...'f' => c - 'a' + 10,
        inline 'A'...'F' => c - 'A' + 10,
        inline else => 0x10,
    };
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
            d = (hexval(raw[i]) << 4) | hexval(raw[i + 1]);
            i += 2;
        }

        if (c != d) return false;
    }
    return i >= raw.len; // match all
}

/// NewUrl returns a valid URL/URI.
pub fn newUrl(comptime scheme: []const u8, userinfo: ?[]const u8, hostname: []const u8, port: ?u16, path_segs: []const []const u8, m: Allocator) error{OutOfMemory}![]u8 {
    schemeCheck(scheme); // compile-time validation

    // buffer decimal port number
    var port_serial: [5]u8 = undefined; // range "0"–"65535"
    var port_offset = port_serial.len;
    if (port) |portv| {
        var v: usize = @intCast(portv);
        while (true) {
            port_offset -= 1;
            var decimal: u8 = @intCast(@mod(v, 10));
            port_serial[port_offset] = '0' + decimal;
            v /= 10;
            if (v == 0) break;
        }
    }

    // count output bytes
    var size = scheme.len + 3;
    if (port) |_| size += 1 + port_serial.len - port_offset;
    if (userinfo) |u| {
        size += 1; // "@"
        for (u) |c| {
            size += switch (c) {
                // unreserved ∪ sub-delims ∪ colon
                'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':' => 1,
                else => 3,
            };
        }
    }
    for (hostname) |c| {
        size +%= switch (c) {
            // unreserved ∪ sub-delims
            'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => 1,
            else => 3,
        };
    }
    for (path_segs) |seg| {
        size += 1; // "/"
        for (seg) |c| {
            size +%= switch (c) {
                // unreserved ∪ sub-delims ∪ pchar
                'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@' => 1,
                else => 3,
            };
        }
    }

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

    if (userinfo) |u| {
        for (u) |c| {
            switch (c) {
                // unreserved ∪ sub-delims ∪ colon
                'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':' => {
                    p[0] = c;
                    p += 1;
                },
                else => {
                    percentEncode(&p, c);
                },
            }
        }

        p[0] = '@';
        p += 1;
    }

    for (hostname) |c| {
        switch (c) {
            // unreserved ∪ sub-delims
            'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => {
                p[0] = c;
                p += 1;
            },
            else => {
                percentEncode(&p, c);
            },
        }
    }

    if (port) |_| {
        p[0] = ':';
        p += 1;
        for (port_serial[port_offset..]) |c| {
            p[0] = c;
            p += 1;
        }
    }

    for (path_segs) |seg| {
        p[0] = '/';
        p += 1;

        for (seg) |c| {
            switch (c) {
                // unreserved ∪ sub-delims ∪ pchar
                'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@' => {
                    p[0] = c;
                    p += 1;
                },
                else => {
                    percentEncode(&p, c);
                },
            }
        }
    }

    return b;
}

test "URL construction" {
    // allocate URIs without free to get readable errors (on single line)
    var buffer: [1024]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fix.allocator();

    // “Internationalized Resource Identifiers” RFC 3987, subsection 3.2.1
    try testing.expectEqualStrings("http://xn--99zt52a.example.org/%E2%80%AE", try newUrl("http", null, "xn--99zt52a.example.org", null, &.{"\u{202E}"}, allocator));

    // “IMAP URL Scheme” RFC 2192, section 10
    try testing.expectEqualStrings("imap://michael@minbari.org/users.*;type=list", try newUrl("imap", "michael", "minbari.org", null, &.{"users.*;type=list"}, allocator));
    try testing.expectEqualStrings("imap://psicorp.org/~peter/%E6%97%A5%E6%9C%AC%E8%AA%9E/%E5%8F%B0%E5%8C%97", try newUrl("imap", null, "psicorp.org", null, &.{ "~peter", "日本語", "台北" }, allocator));

    // “POP URL Scheme” RFC 2384, section 7
    try testing.expectEqualStrings("pop://rg;AUTH=+APOP@mail.eudora.com:8110", try newUrl("pop", "rg;AUTH=+APOP", "mail.eudora.com", 8110, &.{}, allocator));

    // port zero is sometimes used in configruation to match any free port
    try testing.expectEqualStrings("wss://syncd%40cluster2@ferep%3Atun0:0", try newUrl("wss", "syncd@cluster2", "ferep:tun0", 0, &.{}, allocator));
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

pub const FormatError = error{
    NotUtf8, // illegal byte sequence in input string
};

/// NewUrn returns a valid URN/URI. The specifics string must be valid UTF-8.
/// An upper-case prefix ("URN:") is returned if and only namespace contains
/// upper-case letters exclusively. The escape_set opts in percent-encoding for
/// octets in the specifics string which would otherwise get included as is,
/// namely 'A'—'Z', 'a'—'z', '0'—'9', '-', '.', '_', '~', '!', '$', '&', '\'',
/// '(', ')', '*', '+', ',', ';', '=', ':', '@' and '/'.
pub fn newUrn(comptime namespace: []const u8, specifics: []const u8, comptime escape_set: []const u8, m: Allocator) error{ OutOfMemory, NotUtf8 }![]u8 {
    const prefix = comptime urnPrefixFromNamespaceCheck(namespace);

    // “In particular, with regard to characters outside the ASCII range,
    // URNs that appear in protocols or that are passed between systems MUST
    // use only Unicode characters encoded in UTF-8 and further encoded as
    // required by RFC 3986.”
    // — RFC 8141, subsection 2.2
    if (!std.unicode.utf8ValidateSlice(specifics)) return FormatError.NotUtf8;

    // compile-time validation
    inline for (escape_set) |c| switch (c) {
        // unreserved
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => continue,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => continue,
        // pchar ∪ NSS
        ':', '@', '/' => continue,
        else => @compileError("escape set with redundant escape characer"),
    };

    // allocate output
    var size: usize = prefix.len;
    // match NSS from RFC 3986, section 2 with a jump table
    for (specifics, 0..) |c, i| size += switch (c) {
        // unreserved ∪ sub-delims ∪ pchar ∪ NSS
        inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@', '/' => pass: {
            if (c == '/' and i == 0) break :pass 3;
            inline for (escape_set) |o|
                if (o == c) break :pass 3;
            break :pass 1;
        },
        inline else => 3,
    };
    var b = try m.alloc(u8, size);

    // write pointer
    inline for (prefix, 0..) |c, i| b[i] = c;
    var p = b.ptr + prefix.len;

    for (specifics, 0..) |c, i| spec_char: {
        inline for (escape_set) |o| if (o == c) {
            percentEncode(&p, o);
            break :spec_char;
        };

        // match NSS from RFC 3986, section 2 with a jump table
        switch (c) {
            // unreserved ∪ sub-delims ∪ pchar ∪ NSS
            inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@' => {
                withEscapeSet(&p, c, escape_set);
            },
            // NSS
            '/' => {
                if (i == 0) {
                    percentEncode(&p, '/');
                } else {
                    withEscapeSet(&p, '/', escape_set);
                }
            },
            inline else => {
                // It seems like the quota adds up in a function
                // and the default of 1k was hit here. 🤔
                @setEvalBranchQuota(1200);
                percentEncode(&p, c);
            },
        }
    }

    return b;
}

test "URN construction" {
    // allocate URIs without free to get readable errors (on single line)
    var buffer: [4096]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fix.allocator();

    try testing.expectEqualStrings("urn:example:", try newUrn("example", "", "", allocator));
    try testing.expectEqualStrings("urn:Example:0", try newUrn("Example", "0", "", allocator));
    try testing.expectEqualStrings("URN:EXAMPLE:z", try newUrn("EXAMPLE", "z", "", allocator));

    try testing.expectEqualStrings("urn:did:%2Fpath/", try newUrn("did", "/path/", "", allocator));
    try testing.expectEqualStrings("urn:did:%2Fpath%2F", try newUrn("did", "/path/", "/", allocator));

    try testing.expectEqualStrings("urn:oid:1:3:6:1:4:1:28114", try newUrn("oid", "1:3:6:1:4:1:28114", ".", allocator));

    // “A URN Namespace for Public Identifiers” RFC 3151, section 3
    try testing.expectEqualStrings("urn:publicid:3%2B3=6", try newUrn("publicid", "3+3=6", "+:/;'", allocator));
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
            if (i == namespace.len - 1)
                @compileError("URN namespace identifier with hyphen suffix");
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

    for (params) |param| {
        size += 1; // "?" or "&"
        size += paramSize(param.key);

        if (param.value) |s| {
            size += 1; // "="
            size += paramSize(s);
        }
    }

    if (fragment) |s| {
        size += 1; // "#"

        // match fragment from RFC 3986, subsection 3.5 with a size table
        for (s) |c| size += switch (c) {
            // unreserved
            inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => 1,
            // sub-delims
            inline '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => 1,
            // pchar & fragment
            inline ':', '@', '/', '?' => 1,
            inline else => 3,
        };
    }

    var b = try m.alloc(u8, size);
    @memcpy(b.ptr, uri);

    // write pointer
    var p = b.ptr + uri.len;

    for (params, 0..) |param, i| {
        p[0] = if (i == 0) '?' else '&';
        p += 1;

        for (param.key) |c| switch (c) {
            // query − "=&+"
            inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '!', '$', '\'', '(', ')', '*', ',', ';', ':', '@', '/', '?' => {
                p[0] = c;
                p += 1;
            },
            ' ' => {
                p[0] = '+';
                p += 1;
            },
            inline else => percentEncode(&p, c),
        };

        if (param.value) |s| {
            p[0] = '=';
            p += 1;

            for (s) |c| switch (c) {
                // query − "=&+"
                inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '!', '$', '\'', '(', ')', '*', ',', ';', ':', '@', '/', '?' => {
                    p[0] = c;
                    p += 1;
                },
                ' ' => {
                    p[0] = '+';
                    p += 1;
                },
                inline else => {
                    // It seems like the quota adds up in a function
                    // and the default of 1k was hit here. 🤔
                    @setEvalBranchQuota(2000);
                    percentEncode(&p, c);
                },
            };
        }
    }

    if (fragment) |s| {
        p[0] = '#';
        p += 1;

        // match fragment from RFC 3986, subsection 3.5 with a jump table
        for (s) |c| switch (c) {
            inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@', '/', '?' => {
                p[0] = c;
                p += 1;
            },
            inline else => {
                percentEncode(&p, c);
            },
        };
    }

    return b;
}

test "Params and/or Fragment" {
    // allocate URIs without free to get readable errors (on single line)
    var buffer: [4096]u8 = undefined;
    var fix = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fix.allocator();

    try testing.expectEqualStrings("arbitrary", try addParamsAndOrFragment("arbitrary", &.{}, null, allocator));
    try testing.expectEqualStrings("arbitrary?foo", try addParamsAndOrFragment("arbitrary", &.{.{ .key = "foo" }}, null, allocator));
    try testing.expectEqualStrings("arbitrary?foo=bar", try addParamsAndOrFragment("arbitrary", &.{.{ .key = "foo", .value = "bar" }}, null, allocator));
    try testing.expectEqualStrings("arbitrary?%26%3D=%3D%26&%E2%98%A0%EF%B8%8F", try addParamsAndOrFragment("arbitrary", &.{ .{ .key = "&=", .value = "=&" }, .{ .key = "☠️" } }, null, allocator));

    try testing.expectEqualStrings("arbitrary#", try addParamsAndOrFragment("arbitrary", &.{}, "", allocator));
    try testing.expectEqualStrings("arbitrary#toc", try addParamsAndOrFragment("arbitrary", &.{}, "toc", allocator));

    // '+' = ' ' 🤡
    try testing.expectEqualStrings("arbitrary?+&+=+#%20", try addParamsAndOrFragment("arbitrary", &.{ .{ .key = " " }, .{ .key = " ", .value = " " } }, " ", allocator));
    try testing.expectEqualStrings("arbitrary?%2B=%2B&%2B#+", try addParamsAndOrFragment("arbitrary", &.{ .{ .key = "+", .value = "+" }, .{ .key = "+" } }, "+", allocator));
}

fn paramSize(s: []const u8) usize {
    var n: usize = 0;
    for (s) |c| n += switch (c) {
        // unreserved
        inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => 1,
        // sub-delims − "=&+"
        '!', '$', '\'', '(', ')', '*', ',', ';' => 1,
        // query
        ':', '@', '/', '?' => 1,
        // space is mapped to +
        ' ' => 1,
        inline else => 3,
    };
    return n;
}

fn withEscapeSet(p: *[*]u8, c: u8, comptime escape_set: []const u8) void {
    inline for (escape_set) |o| if (o == c) {
        percentEncode(p, o);
        return;
    };

    p.*[0] = c;
    p.* += 1;
    return;
}

const hex_table = "0123456789ABCDEF";

inline fn percentEncode(p: *[*]u8, o: u8) void {
    p.*[0] = '%';
    p.*[1] = hex_table[o >> 4];
    p.*[2] = hex_table[o & 15];
    p.* += 3;
}
