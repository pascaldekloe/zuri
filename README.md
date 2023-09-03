# ZURI

## About

… a library for strict URI handling, written in the Zig programming language.

No stable release yet. 🚧 I'm still learning the language.

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).

[![CI](https://github.com/pascaldekloe/zuri/actions/workflows/ci.yml/badge.svg)](https://github.com/pascaldekloe/zuri/actions/workflows/ci.yml)


## Interface

Run `make doc` to see the full interface documentation at `doc/index.html'.


### Parse

```zig
/// Parse returns a mapping of s if and only if s is a valid URI.
fn parse(s: []const u8) ParseError!View
```

View contains a lossless decomposition with all URI components as is.

```zig
/// The scheme component ends with ‘:’. It may contain upper-case letters.
raw_scheme: []const u8,

/// The authority component, if any, starts with “//”.
raw_authority: []const u8 = "",

/// The userinfo component, if any, ends with ‘@’.
raw_userinfo: []const u8 = "",

/// The host component can be a registered name, or an IP address.
raw_host: []const u8 = "",

/// The port component, if any, starts with ‘:’.
raw_port: []const u8 = "",

/// The path compoment, if any, starts with ‘/’ when (raw_)authority is present.
raw_path: []const u8 = "",

/// The query compoment, if any, starts with ‘?’.
raw_query: []const u8 = "",

/// The fragment component, if any, starts with ‘#’.
raw_fragment: []const u8 = "",
```

The components have dedicated methods to resolve and/or compare values.

```zig
/// Fragment returns the value with any and all percent-encodings resolved.
fn fragment(v: *const View, m: std.mem.Allocator) error{OutOfMemory}![]u8

/// HasFragment returns whether a fragment component is present, and whether
/// its value with any and all percent-encodings resolved equals match.
fn hasFragment(v: *const View, match: []const u8) bool
```

### Format

URI construction goes by type as each format has its own constraints.

```zig
/// NewUrl returns a valid URL/URI.
fn newUrl(comptime scheme: []const u8, userinfo: ?[]const u8, hostname: []const u8, port: ?u16, path_segs: []const []const u8, m: Allocator) error{OutOfMemory}![]u8
```

```zig
/// NewUrn returns either a valid URN/URI or the empty string when specifics is
/// empty. An upper-case scheme "URN:" is used if and only if namespace contains
/// upper-case letters and if it contains no lower-case letters. The escape_set
/// opts in percent-encoding for octets in the specifics string which would
/// otherwise get included as is, namely 'A'–'Z', 'a'–'z', '0'–'9', '(', ')',
/// '+', ',', '-', '.', ':', '=', '@', ';', '$', '_', '!', '*', and '\''.
pub fn newUrn(comptime namespace: []const u8, specifics: []const u8, comptime escape_set: []const u8, m: Allocator) error{OutOfMemory}![]u8
```

```zig
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
pub fn addParamsAndOrFragment(uri: []const u8, params: []const QueryParam, fragment: ?[]const u8, m: Allocator) error{OutOfMemory}![]u8
```


## Benchmark

The following results were measured on an Apple M1. Run `make bench.out` to see
on your machine.

```
benchmark newUrl with host www.w3.org and path { 1999, 02, 22-rdf-syntax-ns }
URL construction took 26 ns on average, including free
benchmark newIp6Url with address { 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114 } and path { 1999, 02, 22-rdf-syntax-ns }
IPv6 URL construction took 32 ns on average, including free
benchmark newUrn with namespace specific part 99/02/22-rdf-syntax-ns#Description
URN construction took 22 ns on average, including free
benchmark parse with http://www.w3.org/1999/02/22-rdf-syntax-ns#Description
parse took 40 ns on average
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
