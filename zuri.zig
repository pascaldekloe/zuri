// A subsection of the Zig API gets exposed as a library in here.
// See uri.h for the definition/documentation.

const Urview = @import("./Urview.zig");
const Urlink = @import("./Urlink.zig");
const StringTooBig = Urview.ParseError.StringTooBig;

const std = @import("std");

const zuri2k = extern struct {
    scheme_ptr: [*]const c_char,
    scheme_len: usize,

    userinfo_ptr: ?[*]const c_char,
    userinfo_len: usize,

    host_ptr: ?[*]const c_char,
    host_len: usize,

    path_ptr: ?[*]const c_char,
    path_len: usize,

    query_ptr: ?[*]const c_char,
    query_len: usize,

    fragment_ptr: ?[*]const c_char,
    fragment_len: usize,

    port: u16,

    buf: [2048]u8,
};

var no_error: [*:0]const u8 = "NoError";

export fn zuri_error_name(errno: c_uint) [*:0]const u8 {
    if (errno == 0) return no_error;
    return @errorName(@errorFromInt(@intCast(errno))).ptr;
}

export fn zuri_parse2k(dst: *zuri2k, uri: [*]const c_char, len: usize) c_uint {
    if (@bitSizeOf(c_char) != 8) @compileError("need 8-bit bytes");
    const ur = Urview.parse(@as([*]const u8, @ptrCast(uri))[0..len]) catch |err| return @intFromError(err);

    // allocate fields from struct buf
    var fix = std.heap.FixedBufferAllocator.init(&dst.buf);
    const m = fix.allocator();

    const s = ur.scheme(m) catch return @intFromError(StringTooBig);
    dst.scheme_ptr = @ptrCast(s);
    dst.scheme_len = s.len;

    if (!ur.hasAuthority()) {
        dst.userinfo_ptr = null;
        dst.userinfo_len = 0;
        dst.host_ptr = null;
        dst.host_len = 0;
        dst.port = 0;
    } else {
        const u = ur.userinfo(m) catch return @intFromError(StringTooBig);
        dst.userinfo_ptr = @ptrCast(u);
        dst.userinfo_len = u.len;

        const h = ur.host(m) catch return @intFromError(StringTooBig);
        dst.host_ptr = @ptrCast(h);
        dst.host_len = h.len;

        dst.port = ur.port();
    }

    if (!ur.hasPath()) {
        dst.path_ptr = null;
        dst.path_len = 0;
    } else {
        const p = ur.pathNorm("/", m) catch return @intFromError(StringTooBig);
        dst.path_ptr = @ptrCast(p);
        dst.path_len = p.len;
    }

    if (!ur.hasQuery()) {
        dst.query_ptr = null;
        dst.query_len = 0;
    } else {
        const q = ur.query(m) catch return @intFromError(StringTooBig);
        dst.query_ptr = @ptrCast(q);
        dst.query_len = q.len;
    }

    if (!ur.hasFragment()) {
        dst.fragment_ptr = null;
        dst.fragment_len = 0;
    } else {
        const f = ur.fragment(m) catch return @intFromError(StringTooBig);
        dst.fragment_ptr = @ptrCast(f);
        dst.fragment_len = f.len;
    }

    return 0;
}

export fn zuri_read2k(src: *zuri2k, buf: [*]c_char, cap: usize) usize {
    if (@bitSizeOf(c_char) != 8) @compileError("need 8-bit bytes");
    const scheme = @as([*]const u8, @ptrCast(src.scheme_ptr))[0..src.scheme_len];
    if (scheme.len == 0) return 1;
    for (scheme, 0..) |c, i| switch (c) {
        'A'...'Z', 'a'...'z' => continue,
        '0'...'9', '+', '-', '.' => if (i == 0) return 1,
        else => return 1,
    };

    var ur = Urlink{};
    if (src.userinfo_ptr) |p| ur.userinfo = @as([*]const u8, @ptrCast(p))[0..src.userinfo_len];
    if (src.host_ptr) |p| ur.host = @as([*]const u8, @ptrCast(p))[0..src.host_len];
    if (src.port != 0) ur.port = src.port;
    ur.path = @as([*]const u8, @ptrCast(src.path_ptr))[0..src.path_len];
    ur.query = @as([*]const u8, @ptrCast(src.query_ptr))[0..src.query_len];
    if (src.fragment_ptr) |p| ur.fragment = @as([*]const u8, @ptrCast(p))[0..src.fragment_len];

    // Write to buffer as an allocotar.
    // No data written when output exceeds the capacity.
    var p: [*]u8 = @ptrCast(buf);
    var fix = std.heap.FixedBufferAllocator.init(p[scheme.len - 1 .. cap]);

    var s = ur.newUrl("z", fix.allocator()) catch return 0;
    for (scheme, 0..) |c, i| buf[i] = switch (c) {
        // “… should only produce lowercase scheme names for consistency.”
        // — RFC 3986, subsection 3.1
        'A'...'Z' => @intCast(c + ('a' - 'A')),
        else => @intCast(c),
    };
    return @intCast(s.len + scheme.len - 1);
}
