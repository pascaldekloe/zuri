//! Strict writings of URNs and opaque URIs.

const std = @import("std");
const Allocator = std.mem.Allocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;

const expect = std.testing.expect;
const expectEqualStrings = std.testing.expectEqualStrings;

/// Urname contains components for opaque URI construction.
const Urname = @This();

separator: u8 = ':',

/// The opaque path consists of segments separated by a separator. Any separator
/// occurences in the segements escape with percent-encoding.
segments: []const []const u8 = &[0][]u8{},

/// Parameters append to the query component in order of appearance, in the form
/// of: key ?( "=" value ) *( "&" key ?( "=" value ))
params: []const Param = &.{},

fragment: ?[]const u8 = null,

/// NewUri returns a valid URI. Caller owns the memory.
pub fn newUri(ur: *const Urname, comptime scheme: []const u8, m: Allocator) error{OutOfMemory}![]u8 {
    schemeCheck(scheme); // compile-time validation

    // count output bytes
    var size = scheme.len + 1;
    if (ur.segments.len != 0) size += ur.segments.len - 1;
    for (ur.segments) |s| size += segmentSize(s, ur.separator);
    size += ur.params.len; // "?" or "&"
    for (ur.params) |param| size += param.size();
    if (ur.fragment) |s| size += fragmentSize(s);

    // output + write pointer
    var b = try m.alloc(u8, size);
    var p = b.ptr;
    inline for (scheme ++ ":") |c| {
        p[0] = c;
        p += 1;
    }

    writeSegments(&p, ur.segments, ur.separator);
    for (ur.params, 0..) |param, i| {
        p[0] = if (i == 0) '?' else '&';
        p += 1;
        param.write(&p);
    }
    if (ur.fragment) |s| writeFragment(&p, s);
    return b;
}

test "URI Construction" {
    // allocate URIs without free to get readable errors (on single line)
    var buffer: [1024]u8 = undefined;
    var fix = FixedBufferAllocator.init(&buffer);
    const allocator = fix.allocator();

    // https://developer.spotify.com/documentation/web-api/concepts/spotify-uris-ids
    try expectEqualStrings("spotify:track:6rqhFgbbKwnb9MLmUQDhG6", try (&Urname{ .segments = &.{ "track", "6rqhFgbbKwnb9MLmUQDhG6" } }).newUri("spotify", allocator));
    try expectEqualStrings("spotify:user:1185903410:playlist:6YAnJeVC7tgOiocOG23Dd", try (&Urname{ .segments = &.{ "user", "1185903410", "playlist", "6YAnJeVC7tgOiocOG23Dd" } }).newUri("spotify", allocator));

    // “SIP: Session Initiation Protocol” RFC 3261, subsection 19.1.3j
    try expectEqualStrings("sips:alice@atlanta.com?subject=project%20x&priority=urgent", try (&Urname{ .segments = &.{"alice@atlanta.com"}, .params = &[_]Param{ .{ .key = "subject", .value = "project x" }, .{ .key = "priority", .value = "urgent" } } }).newUri("sips", allocator));

    // “Decentralized Identifiers (DIDs) v1.0” W3C Recommendation, example 3
    try expectEqualStrings("did:example:123?service=agent&relativeRef=/credentials#degree", try (&Urname{ .segments = &.{ "example", "123" }, .params = &[_]Param{ .{ .key = "service", .value = "agent" }, .{ .key = "relativeRef", .value = "/credentials" } }, .fragment = "degree" }).newUri("did", allocator));
}

/// NewUrn returns either a valid URN/URI or the empty string when specifics is
/// empty. An upper-case scheme "URN:" is used if and only if namespace contains
/// upper-case letters and if it contains no lower-case letters. The escape_set
/// opts in percent-encoding for octets in the specifics string which would
/// otherwise get included as is, namely "A"–"Z", "a"–"z", "0"–"9", "(", ")",
/// "+", ",", "-", ".", ":", "=", "@", ";", "$", "_", "!", "*", and "'".
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

    // “A UUID URN Namespace” RFC 4122, section 3
    try expectEqualStrings("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6", try newUrn("uuid", "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", "", allocator));

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

fn segmentSize(s: []const u8, sep: u8) usize {
    var n: usize = 0;
    for (s) |c| {
        n += if (n == sep) 3 else segment_char_sizes[c];
    }
    return n;
}

fn writeSegments(p: *[*]u8, segs: []const []const u8, sep: u8) void {
    if (segs.len == 0) return;
    for (segs, 0..) |s, i| {
        if (i != 0) {
            p.*[0] = sep;
            p.* += 1;
        }

        for (s) |c| {
            if (c != sep and param_char_sizes[c] & 2 == 0) {
                p.*[0] = c;
                p.* += 1;
            } else {
                percentEncode(p, c);
            }
        }
    }
}

/// Param embodies a common format for the query component.
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

fn writeParamValue(p: *[*]u8, s: []const u8) void {
    for (s) |c| {
        if (param_char_sizes[c] & 2 == 0) {
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

const hex_digits = "0123456789ABCDEF";

inline fn percentEncode(p: *[*]u8, o: u8) void {
    p.*[0] = '%';
    p.*[1] = hex_digits[o >> 4];
    p.*[2] = hex_digits[o & 15];
    p.* += 3;
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
        // sub-delims − "=" − "+"
        '!', '$', '\'', '(', ')', '*', '+', ',', ';' => 1,
        // query
        ':', '@', '/', '?' => 1,
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
