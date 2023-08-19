# ZURI

## About

… a library for strict URI/URL/URN/… handling, written in the Zig programming
language.

No stable release yet. 🚧 I'm still learning the language.

This is free and unencumbered software released into the
[public domain](https://creativecommons.org/publicdomain/zero/1.0).

[![CI](https://github.com/pascaldekloe/zuri/actions/workflows/ci.yml/badge.svg)](https://github.com/pascaldekloe/zuri/actions/workflows/ci.yml)


## Interface

Run `make doc` to see the full interface documentation at `doc/index.html'.


### Parse

```
// Parse returns a mapping of s if and only if s is a valid URI.
fn parse(s: []const u8) ParseError!Parts
```

Parts contains a lossless decomposition with all URL components as is.

```
// The scheme component ends with ‘:’. It may contain upper-case letters.
raw_scheme: []const u8,

// The authority component, if any, starts with “//”.
raw_authority: []const u8 = "",

// The userinfo component, if any, ends with ‘@’.
raw_userinfo: []const u8 = "",

// The host component can be a registered name, or an IP address.
raw_host: []const u8 = "",

// The port component, if any, starts with ‘:’.
raw_port: []const u8 = "",

// The path compoment, if any, starts with ‘/’ when the URL has an authority component.
raw_path: []const u8 = "",

// The query compoment, if any, starts with ‘?’.
raw_query: []const u8 = "",

// The fragment component, if any, starts with ‘#’.
raw_fragment: []const u8 = "",
```

Components have dedicated methods to resolved and/or compare values, like:

```
// Fragment returns the value with any and all percent-encodings resolved.
fn fragment(p: *const Parts, allocator: std.mem.Allocator) error{OutOfMemory}![]u8

// HasFragment returns whether a fragment component is present, and whether its value with any and all percent-encodings resolved equals match.
fn hasFragment(p: *const Parts, match: []const u8) bool
```

### Format

```
// NewURL returns a valid URI.
fn newURL(comptime scheme: []const u8, userinfo: ?[]const u8, hostname: []const u8, port: ?u16, path_segs: []const []const u8, m: Allocator) error{OutOfMemory}![]u8
```


## Benchmark

The following results were measured on an Apple M1. Run `make bench.out` to see
on your machine.

```
URL construction with host and 3-segment path took 152 on average, including free
parse http://www.example.com/path/to%20a/long-name took 30 ns on average
```


## Standard Compliance

 * “Uniform Resource Locators (URL)” RFC 1738
 * “URI Generic Syntax” RFC 2396
 * “IPv6 Literal Addresses in URL's” RFC 2732
 * “URI Generic Syntax” RFC 3986
 * “IPv6 Zone IDs in URIs” RFC 6874
