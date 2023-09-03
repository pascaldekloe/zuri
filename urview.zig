/// Strict parsing and formatting of URIs.
const std = @import("std");
const Allocator = std.mem.Allocator;

const expect = std.testing.expect;
const expectFmt = std.testing.expectFmt;
const expectEqual = std.testing.expectEqual;
const expectEqualStrings = std.testing.expectEqualStrings;
const expectStringEndsWith = std.testing.expectStringEndsWith;
const expectStringStartsWith = std.testing.expectStringStartsWith;

/// View contains a lossless decomposition with all URI components as is. Use
/// parse to obtain a valid instance. The input string equals the concatenation
/// of raw_scheme, raw_authority, raw_path, raw_query and raw_fragment.
pub const View = struct {
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

    /// The path compoment, if any, starts with '/' when (raw_)authority is
    /// present.
    raw_path: []const u8 = "",

    /// The query compoment, if any, starts with '?'.
    raw_query: []const u8 = "",

    /// The fragment component, if any, starts with '#'.
    raw_fragment: []const u8 = "",

    /// Scheme returns the value normalized to lower-case.
    pub fn scheme(v: *const View, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
        if (v.raw_scheme.len < 2) return "";
        const s = v.raw_scheme[0 .. v.raw_scheme.len - 1];

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
    pub fn hasScheme(v: *const View, comptime match: []const u8) bool {
        // compile-time validation of match
        inline for (match) |c| switch (c) {
            'a'...'z', '0'...'9', '+', '-', '.' => continue,
            'A'...'Z' => @compileError("upper-case in scheme (never matches)"),
            else => @compileError("illegal character in scheme (never matches)"),
        };
        if (match.len == 0 or match[0] < 'a' or match[0] > 'z')
            @compileError("without letter start (never matches)");

        if (match.len + 1 != v.raw_scheme.len) return false;
        inline for (match, 0..) |c, i| {
            var r = v.raw_scheme.ptr[i];
            if (r != c and (c < 'a' or c > 'z' or c - ('a' - 'A') != r))
                return false;
        }
        return true;
    }

    /// Userinfo returns the value with any and all of its percent-encodings
    /// resolved.
    pub fn userinfo(v: *const View, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
        if (v.raw_userinfo.len < 2) return "";
        return unescape(v.raw_userinfo[0 .. v.raw_userinfo.len - 1], m);
    }

    /// HasUserinfo returns whether the userinfo component is present, and
    /// whether its value with any and all of its percent-encodings resolved
    /// equals match.
    pub fn hasUserinfo(v: *const View, match: []const u8) bool {
        if (v.raw_userinfo.len == 0) return false;
        return equalString(v.raw_userinfo[0 .. v.raw_userinfo.len - 1], match);
    }

    /// Host returns the value with any and all of its percent-encodings
    /// resolved.
    pub fn host(v: *const View, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
        if (v.raw_host.len == 0) return "";
        return unescape(v.raw_host, m);
    }

    /// HasHost returns whether the authority component is present, and whether
    /// the host value with any and all of its percent-encodings resolved equals
    /// match.
    pub fn hasHost(v: *const View, match: []const u8) bool {
        if (v.raw_authority.len == 0) return false;
        return equalString(v.raw_host, match);
    }

    /// Port returns the value with zero for undefined or out-of-bounds.
    pub fn port(v: *const View) u16 {
        if (v.raw_port.len < 2) return 0;
        return std.fmt.parseInt(u16, v.raw_port[1..], 10) catch 0;
    }

    /// Path returns the value with any and all of its percent-encodings
    /// resolved.
    pub fn path(v: *const View, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
        if (v.raw_path.len == 0) return "";
        return unescape(v.raw_path, m);
    }

    /// HasPath returns whether the value with any and all percent-encodings
    /// resolved equals match.
    pub fn hasPath(v: *const View, match: []const u8) bool {
        return equalString(v.raw_path, match);
    }

    /// Query returns the value with any and all percent-encodings resolved.
    pub fn query(v: *const View, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
        if (v.raw_query.len < 2) return "";
        return unescape(v.raw_query[1..], m);
    }

    /// HasQuery returns whether a query component is present, and whether its
    /// value with any and all percent-encodings resolved equals match.
    pub fn hasQuery(v: *const View, match: []const u8) bool {
        if (v.raw_query.len == 0) return false;
        return equalString(v.raw_query[1..], match);
    }

    /// Fragment returns the value with any and all percent-encodings resolved.
    pub fn fragment(v: *const View, m: std.mem.Allocator) error{OutOfMemory}![]u8 {
        if (v.raw_fragment.len < 2) return "";
        return unescape(v.raw_fragment[1..], m);
    }

    /// HasFragment returns whether a fragment component is present, and whether
    /// its value with any and all percent-encodings resolved equals match.
    pub fn hasFragment(v: *const View, match: []const u8) bool {
        if (v.raw_fragment.len == 0) return false;
        return equalString(v.raw_fragment[1..], match);
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
pub fn parse(s: []const u8) ParseError!View {
    // match scheme from RFC 3986, subsection 3.1
    for (s, 0..) |c, i| switch (c) {
        // ALPHA from RFC 2234, subsection 6.1
        'A'...'Z', 'a'...'z' => continue,
        // DIGIT from RFC 2234, subsection 6.1
        '0'...'9', '+', '-', '.' => if (i == 0) return ParseError.NoScheme,
        ':' => {
            var v = View{ .raw_scheme = s[0 .. i + 1] };
            try sinceScheme(&v, s[i + 1 ..]);
            return v;
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
        var v = parse(s) catch |err| {
            std.debug.print("got error {} for {s}\n", .{ err, s });
            return err;
        };

        // ensure lossless mapping
        try expectFmt(s, "{s}{s}{s}{s}{s}", .{ v.raw_scheme, v.raw_authority, v.raw_path, v.raw_query, v.raw_fragment });

        // verify constraints from the field comments
        try expectStringEndsWith(v.raw_scheme, ":");
        if (v.raw_authority.len != 0) {
            try expectFmt(v.raw_authority, "//{s}{s}{s}", .{ v.raw_userinfo, v.raw_host, v.raw_port });
            if (v.raw_userinfo.len != 0) try expectStringEndsWith(v.raw_userinfo, "@");
            if (v.raw_port.len != 0) try expectStringStartsWith(v.raw_port, ":");
        } else {
            const empty: []const u8 = "";
            try expectEqual(empty, v.raw_userinfo);
            try expectEqual(empty, v.raw_host);
            try expectEqual(empty, v.raw_port);
        }
        if (v.raw_path.len != 0 and v.raw_authority.len != 0) try expectStringStartsWith(v.raw_path, "/");
        if (v.raw_query.len != 0) try expectStringStartsWith(v.raw_query, "?");
        if (v.raw_fragment.len != 0) try expectStringStartsWith(v.raw_fragment, "#");
    }
}

test "Upper-Case URN" {
    var m = std.testing.allocator;

    // sample from “Using ISBNs as URNs” RFC 3187, subsection 3.2
    var v = try parse("URN:ISBN:0-395-36341-1");

    try expect(v.hasScheme("urn"));

    var scheme = try v.scheme(m);
    defer m.free(scheme);
    try expectEqualStrings("urn", scheme);

    try expect(v.hasPath("ISBN:0-395-36341-1"));
    try expect(!v.hasPath("isbn:0-395-36341-1"));

    var path = try v.path(m);
    defer m.free(path);
    try expectEqualStrings("ISBN:0-395-36341-1", path);
}

test "Tricky" {
    var m = std.testing.allocator;

    var v = try parse("bang://AD2%5cBill%40live.com@?C:%5cProgram+Files%5C*.EXE");

    var userinfo = try v.userinfo(m);
    defer m.free(userinfo);
    try expectEqualStrings("AD2\\Bill@live.com", userinfo);

    var query = try v.query(m);
    defer m.free(query);
    try expectEqualStrings("C:\\Program+Files\\*.EXE", query);
}

test "Bloat" {
    const v = try parse("x-odbc://admin:fe:main@[0::192.168.57.2]:5432/cms?SELECT%20*%20FROM%20users;#80%E2%80%93160");

    try expectEqualStrings("x-odbc:", v.raw_scheme);
    try expectEqualStrings("//admin:fe:main@[0::192.168.57.2]:5432", v.raw_authority);
    try expectEqualStrings("admin:fe:main@", v.raw_userinfo);
    try expectEqualStrings("[0::192.168.57.2]", v.raw_host);
    try expectEqualStrings(":5432", v.raw_port);
    try expectEqualStrings("/cms", v.raw_path);
    try expectEqualStrings("?SELECT%20*%20FROM%20users;", v.raw_query);
    try expectEqualStrings("#80%E2%80%93160", v.raw_fragment);

    try expect(v.hasScheme("x-odbc"));
    try expect(v.hasUserinfo("admin:fe:main"));
    try expect(!v.hasUserinfo("admin:fe:main@"));
    try expect(v.hasHost("[0::192.168.57.2]"));
    try expect(!v.hasHost("0::192.168.57.2"));
    try expect(!v.hasHost("192.168.57.2"));
    try expectEqual(@as(u16, 5432), v.port());
    try expect(v.hasPath("/cms"));
    try expect(!v.hasPath("cms"));
    try expect(v.hasFragment("80–160"));
    try expect(!v.hasFragment("80%E2%80%93160"));
    try expect(!v.hasFragment("#80%E2%80%93160"));

    var m = std.testing.allocator;

    var query = try v.query(m);
    defer m.free(query);
    try expectEqualStrings("SELECT * FROM users;", query);

    var fragment = try v.fragment(m);
    defer m.free(fragment);
    try expectEqualStrings("80–160", fragment);
}

test "Absent" {
    const v = try parse("X11:");

    try expect(v.hasScheme("x11"));
    try expect(!v.hasScheme("ssh"));
    try expect(!v.hasUserinfo(""));
    try expect(!v.hasHost(""));
    try expect(v.port() == 0);
    try expect(v.hasPath(""));
    try expect(!v.hasFragment(""));

    try expectEqualStrings("", try v.path(std.testing.failing_allocator));
    try expectEqualStrings("", try v.query(std.testing.failing_allocator));
    try expectEqualStrings("", try v.fragment(std.testing.failing_allocator));
}

test "Empty" {
    const v = try parse("x-://@:?#");

    try expect(v.hasScheme("x-"));
    try expect(!v.hasScheme("x"));
    try expect(v.hasUserinfo(""));
    try expect(!v.hasUserinfo("@"));
    try expect(v.hasHost(""));
    try expect(!v.hasHost("//"));
    try expect(v.port() == 0);
    try expect(v.hasPath(""));
    try expect(!v.hasPath("/"));
    try expect(v.hasFragment(""));
    try expect(!v.hasFragment("#"));

    try expectEqualStrings("", try v.userinfo(std.testing.failing_allocator));
    try expectEqualStrings("", try v.path(std.testing.failing_allocator));
    try expectEqualStrings("", try v.query(std.testing.failing_allocator));
    try expectEqualStrings("", try v.fragment(std.testing.failing_allocator));
}

// Parse all components after raw_scheme, which can be none.
fn sinceScheme(v: *View, s: []const u8) ParseError!void {
    // “The authority component is preceded by a double slash ("//") and is
    // terminated by the next slash ("/"), question mark ("?"), or number
    // sign ("#") character, or by the end of the URI.”
    if (s.len < 2 or s[0] != '/' or s[1] != '/') {
        return pathContinue(v, s);
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
            if (v.raw_userinfo.len != 0) return ParseError.IllegalCharacter;
            i += 1;
            v.raw_userinfo = s[2..i];
            colon_count = 0; // reset for host count
        },
        // either userinfo or port separator or invalid
        ':' => {
            colon_count += 1;
            last_colon = i;
            i += 1;
        },
        '/' => {
            try authoritySet(v, s[0..i], colon_count, last_colon);
            return pathContinue(v, s[i..]);
        },
        '?' => {
            try authoritySet(v, s[0..i], colon_count, last_colon);
            return queryContinue(v, s[i..]);
        },
        '#' => {
            try authoritySet(v, s[0..i], colon_count, last_colon);
            return fragmentContinue(v, s[i..]);
        },
        '[' => {
            if (i != 2 + v.raw_userinfo.len)
                return ParseError.IllegalCharacter;
            return asIpLiteral(v, s, i);
        },
        '%' => { // pct-encoded
            try checkEscape(s, i);
            i += 3;
        },
        inline else => return ParseError.IllegalCharacter,
    };

    return authoritySet(v, s, colon_count, last_colon);
}

fn authoritySet(v: *View, s: []const u8, colon_count: usize, last_colon: usize) ParseError!void {
    v.raw_authority = s;

    switch (colon_count) {
        0 => {
            v.raw_host = s[2 + v.raw_userinfo.len ..];
        },
        1 => {
            v.raw_host = s[2 + v.raw_userinfo.len .. last_colon];
            v.raw_port = s[last_colon..];

            // match port from RFC 3986, subsection 3.2.3
            for (v.raw_port[1..]) |c|
                if (c < '0' or c > '9')
                    return ParseError.PortNotNumber;
        },
        else => return ParseError.PortNotNumber,
    }
}

// Parses authority s since "[" at start.
fn asIpLiteral(v: *View, s: []const u8, start: usize) ParseError!void {
    // “The use of "::" indicates one or more groups of 16 bits of zeros.
    // The "::" can only appear once in an address.  The "::" can also be
    // used to compress leading or trailing zeros in an address.”
    // — “IPv6 Addressing Architecture” RFC 3513, subsection 2.2
    var zeroes_once = false;

    var i = start + 1;
    if (i >= s.len) return ParseError.IllegalAddress;
    switch (s[i]) {
        'v' => return asIpFuture(v, s, start),
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
            return ipLiteralEnd(v, s, i);
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

            return Ip4inIp6Continue(v, s, i - hexn);
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
                    return ipLiteralEnd(v, s, i);
                },
                inline else => return ParseError.IllegalAddress,
            };
        },

        inline else => return ParseError.IllegalAddress,
    };

    return ParseError.IllegalAddress; // not closed with "]"
}

// AsIpFuture parses authority s since "[v" at start.
fn asIpFuture(v: *View, s: []const u8, start: usize) ParseError!void {
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
            return ipLiteralEnd(v, s, i);
        },
        inline else => return ParseError.IllegalAddress,
    };
    return ParseError.IllegalAddress; // not closed with "]"
}

fn Ip4inIp6Continue(v: *View, s: []const u8, start: usize) ParseError!void {
    var i = start;
    var octn: usize = 1; // octet count (need 4)
    var decn: usize = 0; // decimal count (max 3)

    // match IPv4address from RFC 3986, subsection 3.2.2
    while (i < s.len) : (i += 1) switch (s[i]) {
        inline '0'...'9' => {
            decn += 1;
        },
        '.' => {
            _ = std.fmt.parseInt(u8, s[i - decn .. i], 10) catch
                return ParseError.IllegalAddress;
            if (decn == 0 or s[i - decn] == '0')
                return ParseError.IllegalAddress;
            octn += 1;
            decn = 0;
        },
        ']' => {
            _ = std.fmt.parseInt(u8, s[i - decn .. i], 10) catch
                return ParseError.IllegalAddress;
            if (decn == 0 or octn != 4 or s[i - decn] == '0')
                return ParseError.IllegalAddress;

            return ipLiteralEnd(v, s, i);
        },
        inline else => return ParseError.IllegalAddress,
    };
    return ParseError.IllegalAddress; // not closed with "]"
}

// ipLiteralEnd continues from end "]" in authority s.
fn ipLiteralEnd(v: *View, s: []const u8, end: usize) ParseError!void {
    var i = end + 1;
    v.raw_host = s[2 + v.raw_userinfo.len .. i];
    if (i >= s.len) {
        v.raw_authority = s;
        return;
    }

    switch (s[i]) {
        '/' => {
            v.raw_authority = s[0..i];
            return pathContinue(v, s[i..]);
        },
        '?' => {
            v.raw_authority = s[0..i];
            return queryContinue(v, s[i..]);
        },
        '#' => {
            v.raw_authority = s[0..i];
            return fragmentContinue(v, s[i..]);
        },

        ':' => {
            const port_start = i;
            i += 1;

            // match port from RFC 3986, subsection 3.2.3
            while (i < s.len) : (i += 1) switch (s[i]) {
                '0'...'9' => continue,

                '/' => {
                    v.raw_authority = s[0..i];
                    v.raw_port = s[port_start..i];
                    return pathContinue(v, s[i..]);
                },
                '?' => {
                    v.raw_authority = s[0..i];
                    v.raw_port = s[port_start..i];
                    return queryContinue(v, s[i..]);
                },
                '#' => {
                    v.raw_authority = s[0..i];
                    v.raw_port = s[port_start..i];
                    return fragmentContinue(v, s[i..]);
                },

                else => return ParseError.PortNotNumber,
            };
        },

        else => return ParseError.IllegalCharacter,
    }
}

// PathContinue parses s as the path component.
fn pathContinue(v: *View, s: []const u8) ParseError!void {
    // match path from RFC 3986, subsection 3.3 with a jump table
    var i: usize = 0;
    while (i < s.len) switch (s[i]) {
        // unreserved
        inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => i += 1,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => i += 1,
        // pchar, slash
        ':', '@', '/' => i += 1,
        // pct-encoded
        '%' => {
            try checkEscape(s, i);
            i += 3;
        },
        '?' => {
            v.raw_path = s[0..i];
            return queryContinue(v, s[i..]);
        },
        '#' => {
            v.raw_path = s[0..i];
            return fragmentContinue(v, s[i..]);
        },
        inline else => return ParseError.IllegalCharacter,
    };
    v.raw_path = s;
}

// QueryContinue parses s after "?".
//
// “The query component is indicated by the first question mark ("?")
// character and terminated by a number sign ("#") character or by the end
// of the URI.”
fn queryContinue(v: *View, s: []const u8) ParseError!void {
    // match query from RFC 3986, subsection 3.4 with a jump table
    var i: usize = 1;
    while (i < s.len) switch (s[i]) {
        // unreserved
        inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => i += 1,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => i += 1,
        // pchar & query
        ':', '@', '/', '?' => i += 1,
        // pct-encoded
        '%' => {
            try checkEscape(s, i);
            i += 3;
        },
        '#' => {
            v.raw_query = s[0..i];
            return fragmentContinue(v, s[i..]);
        },
        inline else => return ParseError.IllegalCharacter,
    };
    v.raw_query = s;
}

// FragmentContinue parses s after "#".
//
// “A fragment identifier component is indicated by the presence of a
// number sign ("#") character and terminated by the end of the URI.”
fn fragmentContinue(v: *View, s: []const u8) ParseError!void {
    // match fragment from RFC 3986, subsection 3.5 with a jump table
    var i: usize = 1;
    while (i < s.len) switch (s[i]) {
        // unreserved
        inline 'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => i += 1,
        // sub-delims
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => i += 1,
        // pchar & fragment
        ':', '@', '/', '?' => i += 1,
        // pct-encoded
        '%' => {
            try checkEscape(s, i);
            i += 3;
        },
        inline else => return ParseError.IllegalCharacter,
    };
    v.raw_fragment = s;
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
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => 0x10,
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
