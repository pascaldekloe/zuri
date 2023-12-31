# ZURI

## About

… a library for strict URI handling, written in the Zig programming language.
The project was an experiment to learn about new and old technologies.
Unfortunately, the Zig lizzard turned out to be inheritly unreliable
[by choice](https://github.com/ziglang/zig/issues/17668#issuecomment-1778172138).
⚠️ The code plus setup is left as a reference only.

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).

[![CI](https://github.com/pascaldekloe/zuri/actions/workflows/ci.yml/badge.svg)](https://github.com/pascaldekloe/zuri/actions/workflows/ci.yml)


## Library

Header file `zuri.h` describes libzuri in full. See `demo.c` for a quick start.

	make demo
	./demo

Install or unstall `libzuri.a` with header and CMake configuration from Makefile
directly as follows.

    make install PREFIX=~/local
	make uninstall PREFIX=~/local

The `package` directory offers a few more installation options, including a
Homebrew formula.

	make dist/linux-amd64.deb
	make dist/linux-arm64.deb


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
fn rawScheme(ur: Urview) []const u8
fn rawAuthority(ur: Urview) []const u8
fn hasAuthority(ur: Urview) bool
fn rawUserinfo(ur: Urview) []const u8
fn hasUserinfo(ur: Urview) bool
fn rawHost(ur: Urview) []const u8
fn hasHost(ur: Urview) bool
fn hasIp6Address(ur: Urview) bool
fn rawIp6Zone(ur: Urview) []const u8
fn rawPort(ur: Urview) []const u8
fn hasPort(ur: Urview) bool
fn rawPath(ur: Urview) []const u8
fn hasPath(ur: Urview) bool
fn rawQuery(ur: Urview) []const u8
fn hasQuery(ur: Urview) bool
fn rawFragment(ur: Urview) []const u8
fn hasFragment(ur: Urview) bool
```

Each URI component has dedicated methods for parsing and comparison, including
support for international domain names (IDN/punycode), IPv6 addresses and path
normalization.


```zig
fn scheme(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8
fn equalsScheme(ur: Urview, comptime match: []const u8) bool
fn userinfo(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8
fn equalsUserinfo(ur: Urview, match: []const u8) bool
fn host(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8
fn equalsHost(ur: Urview, match: []const u8) bool
fn domainName(ur: Urview) []const u8
fn internationalDomainName(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8
fn ip6Address(ur: Urview) ?[16]u8
fn ip6Zone(ur: Urview, m: Allocator) error{OutOfMemory}![]const u8
fn equalsIp6Zone(ur: Urview, match: []const u8) bool
fn portAsU16(ur: Urview) ?u16
fn path(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8
fn equalsPath(ur: Urview, match: []const u8) bool
fn pathNorm(ur: *const Urview, comptime encodedSlashOut: []const u8, m: Allocator) error{OutOfMemory}![:0]u8
fn query(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8
fn equalsQuery(ur: Urview, match: []const u8) bool
fn readParam(ur: Urview, buf: []u8, key: []const u8) usize
fn readWebParam(ur: Urview, buf: []u8, key: []const u8) usize
fn params(ur: Urview, m: Allocator) error{OutOfMemory}![]Param
fn webParams(ur: Urview, m: Allocator) error{OutOfMemory}![]Param
fn fragment(ur: Urview, m: Allocator) error{OutOfMemory}![:0]u8
fn equalsFragment(ur: Urview, match: []const u8) bool
```


### Urlink.zig

`Urlink` contains components for URL construction.

```zig
/// NewUrl returns a valid URL/URI. Caller owns the returned memory.
fn newUrl(ur: *const Urlink, comptime scheme: []const u8, m: Allocator) error{OutOfMemory}![]u8

/// NewIp6Url is like newUrl, yet it formats addr as an IPv6 address instead of
/// using the host field.
fn newIp6Url(ur: *const Urlink, comptime scheme: []const u8, addr: [16]u8, m: Allocator) error{OutOfMemory}![:0]u8
```


### Urname.zig

`Urname` contains components for opaque URI construction.

```zig
/// NewUri returns a valid URI. Caller owns the memory.
fn newUri(ur: *const Urname, comptime scheme: []const u8, m: Allocator) error{OutOfMemory}![]u8
```

```zig
/// NewUrn returns either a valid URN/URI or the empty string when specifics is
/// empty. An upper-case scheme "URN:" is used if and only if namespace contains
/// upper-case letters and if it contains no lower-case letters. The escape_set
/// opts in percent-encoding for octets in the specifics string which would
/// otherwise get included as is, namely "A"–"Z", "a"–"z", "0"–"9", "(", ")",
/// "+", ",", "-", ".", ":", "=", "@", ";", "$", "_", "!", "*", and "'".
fn newUrn(comptime namespace: []const u8, specifics: []const u8, comptime escape_set: []const u8, m: Allocator) error{OutOfMemory}![]u8
```


## Benchmark

The following results were measured on an Apple M1. Run `make bench` to see for
your machine.

```
benchmark newUrl does http://www.w3.org/1999/02/22-rdf-syntax-ns.
URL construction took 25.4 ns on average
benchmark newIp6Url does http://[6874:7470:3a2f:2f77:7777:2e77:332e:6f72]/1999/02/22-rdf-syntax-ns.
IPv6 URL construction took 31.8 ns on average
benchmark newUrn does urn:bench:99%2F02%2F22-rdf-syntax-ns%23Description.
URN construction took 23.7 ns on average
benchmark parse does http://www.w3.org/1999/02/22-rdf-syntax-ns#Description.
parse took 23.2 ns on average
```


## Standard Compliance

 * “URI Generic Syntax” RFC 3986, previously RFC 2396
 * “Uniform Resource Locators (URL)” RFC 1738
 * “IPv6 Zone IDs in URIs” RFC 6874
 * “URN Syntax” RFC 2141
 * “Domain Concepts and Facilities” RFC 1034
 * “IDNA” RFC 3490
 * “IDNA Punycode” RFC 3492

“Uniform Resource Names (URNs)” RFC 8141 is omitted on purpose. The publication
introduces an odd query syntax with many constraints and no explaination of its
inted nor use. The subtile incompatibilites with both more restrictive rules as
well as more permissive rules are simply not worthy.
