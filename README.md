# ZURI

## About

… a library for strict URI handling, written in the Zig programming language.

No stable release yet. 🚧 I'm still learning the language.

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).

[![CI](https://github.com/pascaldekloe/zuri/actions/workflows/ci.yml/badge.svg)](https://github.com/pascaldekloe/zuri/actions/workflows/ci.yml)


## Interface

The API is split in a parsing `Urview.zig`, and the formatting `Urlink.zig` and
`Urname.zig`.


### Urview.zig

Run `make Urview-doc` to see the full interface documentation at `Urview-doc/index.html`.

```zig
/// Parse returns a mapping of s if and only if s is a valid URI.
fn parse(s: []const u8) ParseError!Urview
```

Urview contains a lossless decomposition with all URI components as is.

```zig
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
```

Use any of the dedicated methods to resolve and/or compare values.

```zig
/// Fragment returns the value with any and all percent-encodings resolved. None
/// of the applicable standards put any constraints on the byte content. The
/// return may or may not be a valid UTF-8 string.
fn fragment(ur: *const Urview, m: Allocator) error{OutOfMemory}![]u8

/// HasFragment returns whether a fragment component is present, and whether
/// its value with any and all percent-encodings resolved equals match.
fn hasFragment(ur: *const Urview, match: []const u8) bool
```


### Urlink.zig

Run `make Urlink-doc` to see the full interface documentation at `Urlink-doc/index.html`.

```zig
/// NewUrl returns a valid URL/URI. Caller owns the memory.
fn newUrl(ur: *const Urlink, comptime scheme: []const u8, m: Allocator) error{OutOfMemory}![]u8

/// NewSearchUrl is like newUrl, yet it encodes query parameters conform the
/// application/x-www-form-urlencoded convention, i.e., space characters (" ")
/// are written as plus characters ("+") rather than percent encoding "%20". Use
/// is intended for the "http", "https", "ws" and "wss" schemes.
fn newSearchUrl(ur: *const Urlink, comptime scheme: []const u8, m: Allocator) error{OutOfMemory}![]u8
```

Urlink contains components for URL construction.

```zig
userinfo: ?[]const u8 = null,

/// Host is either a registered name or an IPv4 address. Use newIp6Url for IPv6
/// addresses.
host: []const u8 = "",

/// The default port number for the respective protocol should be omitted, i.e.,
/// specify non-standard values only.
port: ?u16 = null,

/// Path segments are separated by a slash character ("/"), including a leading
/// one [root]. Put an empty string last for a tailing slash.
segments: []const []const u8 = &[0][]u8{},

/// Parameters append to the query component in order of appearance, in the form
/// of: key ?( "=" value ) *( "&" key ?( "=" value ))
params: []const Param = &.{},

fragment: ?[]const u8 = null,
```


### Urname.zig

Run `make Urname-doc` to see the full interface documentation at `Urname-doc/index.html`.

```zig
/// NewUrn returns either a valid URN/URI or the empty string when specifics is
/// empty. An upper-case scheme "URN:" is used if and only if namespace contains
/// upper-case letters and if it contains no lower-case letters. The escape_set
/// opts in percent-encoding for octets in the specifics string which would
/// otherwise get included as is, namely "A"–"Z", "a"–"z", "0"–"9", "(", ")",
/// "+", ",", "-", ".", ":", "=", "@", ";", "$", "_", "!", "*", and "'".
fn newUrn(comptime namespace: []const u8, specifics: []const u8, comptime escape_set: []const u8, m: Allocator) error{OutOfMemory}![]u8

/// NewUri returns a valid URI. Caller owns the memory.
fn newUri(ur: *const Urname, comptime scheme: []const u8, m: Allocator) error{OutOfMemory}![]u8
```

Urname contains components for opaque URI construction.

```zig
separator: u8 = ':',

/// The opaque path consists of segments separated by a separator. Any separator
/// occurences in the segements escape with percent-encoding.
segments: []const []const u8 = &[0][]u8{},

/// Parameters append to the query component in order of appearance, in the form
/// of: key ?( "=" value ) *( "&" key ?( "=" value ))
params: []const Param = &.{},

fragment: ?[]const u8 = null,
```


## Benchmark

The following results were measured on an Apple M1. Run `make bench.out` to see
on your machine.

```
benchmark newUrl with host www.w3.org and path { 1999, 02, 22-rdf-syntax-ns }
URL construction took 27 ns on average, including free
benchmark newIp6Url with address { 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114 } and path { 1999, 02, 22-rdf-syntax-ns }
IPv6 URL construction took 33 ns on average, including free
benchmark newUrn with namespace specific part 99/02/22-rdf-syntax-ns#Description
URN construction took 21 ns on average, including free
benchmark parse with http://www.w3.org/1999/02/22-rdf-syntax-ns#Description
parse took 27 ns on average
```


## Standard Compliance

 * “URI Generic Syntax” RFC 3986, previously RFC 2396
 * “Uniform Resource Locators (URL)” RFC 1738
 * “IPv6 Zone IDs in URIs” RFC 6874
 * “URN Syntax” RFC 2141

“Uniform Resource Names (URNs)” RFC 8141 is omitted on purpose. The publication
introduces an odd query syntax with many constraints and no explaination of its
inted nor use. The subtile incompatibilites with both more restrictive rules as
well as more permissive rules are simply not worthy.
