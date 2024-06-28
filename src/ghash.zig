const std = @import("std");
const mem = std.mem;
const Ghash = std.crypto.onetimeauth.Ghash;

pub const Fd = enum(usize) {
    Unreachable = 0,
    GhashKey = 1,
    GhashStream = 2,
    GhashDigest = 3,
};

pub const Env = struct {
    const Inner = struct {
        extern "env" fn read(fd: Fd, ptr: [*]u8, len: usize) usize;
        extern "env" fn write(fd: Fd, ptr: [*]const u8, len: usize) usize;
    };
    pub inline fn read(fd: Fd, buf: []u8) usize {
        return Inner.read(fd, buf.ptr, buf.len);
    }
    pub inline fn write(fd: Fd, buf: []const u8) usize {
        return Inner.write(fd, buf.ptr, buf.len);
    }
};

var inst: Ghash = undefined;
pub export fn Ghash_init() void {
    var key: [Ghash.key_length]u8 = undefined;
    _ = Env.read(.GhashKey, &key);
    inst = Ghash.init(&key);
}
pub export fn Ghash_update() void {
    var buffer: [65536]u8 = undefined;
    while (true) {
        const amt = Env.read(.GhashStream, &buffer);
        if (amt == 0) break;
        inst.update(buffer[0..amt]);
    }
    return;
}
pub export fn Ghash_pad() void {
    return @call(.always_inline, Ghash.pad, .{&inst});
}
pub export fn Ghash_final() void {
    var out: [Ghash.mac_length]u8 = undefined;
    inst.final(&out);
    _ = Env.write(.GhashDigest, &out);
}
