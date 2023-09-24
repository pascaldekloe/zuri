# ZURI

## About

… a library for strict URI handling, written in the Zig programming language.

No stable release yet. 🚧 I'm still learning the language.

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).

[![CI](https://github.com/pascaldekloe/zuri/actions/workflows/ci.yml/badge.svg)](https://github.com/pascaldekloe/zuri/actions/workflows/ci.yml)


## Library

Header file `zuri.h` describes libzuri in full. See `demo.c` for a quick start.

    make libzuri.a
    sudo make install PREFIX=/usr/local

Such installation can be undone with `sudo make uninstall PREFIX=/usr/local`.


## Zig Interface

The Zig API is split in a parsing `Urview.zig`, a formatting `Urlink.zig` and a
formatting `Urname.zig`. Run `make Urview-doc Urlink-doc Urname-doc` to see the
respective `index.html` files.


### Urview.zig

```zig
/// Parse returns a projection of s if and only if s is a valid URI.
fn parse(s: []const u8) ParseError!Urview
```

`Urview` provides read-only access to URI components. Input passed to `parse`
always equals the concatenation of the `rawScheme`, `rawAuthority`, `rawPath`,
`rawQuery` and `rawFragment` readings.

```zig
/// The raw fragment component starts with "#" when present.
fn rawFragment(ur: Urview) []const u8

/// Fragment returns the component with any and all percent-encodings resolved.
/// None of the applicable standards put any constraints on the byte content.
/// The return may or may not be a valid UTF-8 string. Caller owns the returned
/// memory.
fn fragment(ur: Urview, m: Allocator) error{OutOfMemory}![]u8

/// ContainsFragment returns whether the component with any and all percent-
/// encodings resolved equals match. Absent components don't equal any match.
fn containsFragment(ur: Urview, match: []const u8) bool
```

Run `make Urview-doc` to see the full interface documentation at `Urview-doc/index.html`.


### Urlink.zig

Run `make Urlink-doc` to see the full interface documentation at `Urlink-doc/index.html`.

```zig
/// NewUrl returns a valid URL/URI. Caller owns the memory.
fn newUrl(ur: *const Urlink, comptime scheme: []const u8, m: Allocator) error{OutOfMemory}![]u8

/// NewWebUrl is like newUrl, yet it encodes query parameters conform the
/// application/x-www-form-urlencoded convention, i.e., space characters (" ")
/// are written as plus characters ("+") rather than percent encoding "%20". Use
/// is intended for the "http", "https", "ws" and "wss" schemes.
fn newWebUrl(ur: *const Urlink, comptime scheme: []const u8, m: Allocator) error{OutOfMemory}![]u8
```

Urlink contains components for URL construction.


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
benchmark newUrl does http://www.w3.org/1999/02/22-rdf-syntax-ns.
URL construction took 23.1 ns on average
benchmark newIp6Url does http://[6874:7470:3a2f:2f77:7777:2e77:332e:6f72]/1999/02/22-rdf-syntax-ns.
IPv6 URL construction took 30.3 ns on average
benchmark newUrn does urn:bench:99%2F02%2F22-rdf-syntax-ns%23Description.
URN construction took 21.8 ns on average
benchmark parse does http://www.w3.org/1999/02/22-rdf-syntax-ns#Description.
parse took 23.8 ns on average
``


## Standard Compliance

 * “URI Generic Syntax” RFC 3986, previously RFC 2396
 * “Uniform Resource Locators (URL)” RFC 1738
 * “IPv6 Zone IDs in URIs” RFC 6874
 * “URN Syntax” RFC 2141

“Uniform Resource Names (URNs)” RFC 8141 is omitted on purpose. The publication
introduces an odd query syntax with many constraints and no explaination of its
inted nor use. The subtile incompatibilites with both more restrictive rules as
well as more permissive rules are simply not worthy.
