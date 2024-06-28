const std = @import("std");
const mem = std.mem;
const Ghash = std.crypto.onetimeauth.Ghash;
const AES = std.crypto.core.aes;

pub const Fd = enum(usize) {
    Unreachable = 0,
    AesKey = 1,
    AesIv = 2,
    AesAad = 3,
    AesTag = 4,
    AesReadableStream = 5,
    AesWritableStream = 6,
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

pub const buffer_length = 65536 * 2;
const zeros = [_]u8{0} ** 16;

fn AesGcmStream(comptime Aes: anytype) type {
    return struct {
        const Self = @This();
        pub const block_length = AES.Block.block_length;
        pub const tag_length = 16;
        pub const iv_length = 12;
        pub const key_length = Aes.key_bits / 8;
        aes: AES.AesEncryptCtx(Aes) = undefined,
        mac: Ghash = undefined,
        iv: [16]u8 = undefined,
        counter: u128 = undefined,
        ad_len: usize = 0,
        len: usize = 0,
        leftover: usize = 0,
        src: *[buffer_length]u8 = undefined,
        dst: *[buffer_length]u8 = undefined,
        pub fn init(
            key: *const [key_length]u8,
            src: *[buffer_length]u8,
            dst: *[buffer_length]u8,
        ) Self {
            var self = Self{ .src = src, .dst = dst };
            const buffer = src;
            self.aes = Aes.initEnc(key.*);
            const aes = &self.aes;

            var h: [16]u8 = undefined;
            aes.encrypt(&h, &zeros);

            self.mac = Ghash.init(&h);
            const mac = &self.mac;
            while (true) {
                const amt = Env.read(.AesAad, buffer);
                if (amt == 0) break;
                mac.update(buffer[0..amt]);
                self.ad_len += amt;
            }
            mac.pad();

            var iv: [16]u8 = undefined;
            _ = Env.read(.AesIv, iv[0..iv_length]);
            mem.writeInt(u32, iv[iv_length..][0..4], 1, .big);
            self.iv = iv;
            mem.writeInt(u32, iv[iv_length..][0..4], 2, .big);
            self.counter = mem.readInt(u128, &iv, .big);
            return self;
        }
        pub fn update(
            self: *Self,
            comptime @"🔐": @TypeOf(Exports.@"🔐"),
            comptime withSuffixTag: u1,
        ) void {
            const src = self.src;
            const dst = self.dst;
            self.leftover += Env.read(.AesReadableStream, src[self.leftover..]);
            var i: usize = 0;
            while (switch (@"🔐" == .decrypt and withSuffixTag != 0) {
                true => i + 32 <= self.leftover,
                false => i + 16 <= self.leftover,
            }) : (i += 16) {
                var counter: [16]u8 = undefined;
                mem.writeInt(u128, &counter, self.counter, .big);
                self.counter +%= 1;
                self.aes.xor(dst[i..][0..block_length], src[i..][0..block_length], counter);
            }
            if (i > 0) {
                self.len += i;
                self.mac.update(switch (@"🔐") {
                    .encrypt => dst,
                    .decrypt => src,
                }[0..i]);
                _ = Env.write(.AesWritableStream, dst[0..i]);
                const leftover = self.leftover - i;
                if (leftover > 0) {
                    if (leftover > i) {
                        @memcpy(dst[0..leftover], src[i..self.leftover]);
                        @memcpy(src[0..leftover], dst[0..leftover]);
                    } else {
                        @memcpy(src[0..leftover], src[i..self.leftover]);
                    }
                }
                self.leftover = leftover;
            }
        }
        pub fn final(
            self: *Self,
            comptime @"🔐": @TypeOf(Exports.@"🔐"),
            comptime withSuffixTag: u1,
        ) u32 {
            const leftover = if (@"🔐" == .decrypt and withSuffixTag != 0)
                self.leftover - 16
            else
                self.leftover;
            const input_tag = if (@"🔐" == .decrypt and withSuffixTag != 0)
                @as([16]u8, self.src[leftover..self.leftover][0..16].*);

            if (leftover > 0) {
                var counter: [16]u8 = undefined;
                mem.writeInt(u128, &counter, self.counter, .big);
                self.aes.xor(self.dst[0..16], self.src[0..16], counter);
                self.len += leftover;
                self.mac.update(switch (@"🔐") {
                    .encrypt => self.dst,
                    .decrypt => self.src,
                }[0..leftover]);
                self.mac.pad();
            }

            var tag: [16]u8 = undefined;
            var final_block: [16]u8 = undefined;
            mem.writeInt(u64, final_block[0..8], @as(u64, self.ad_len) * 8, .big);
            mem.writeInt(u64, final_block[8..16], @as(u64, self.len) * 8, .big);
            self.mac.update(&final_block);
            self.mac.final(&tag);

            var t: [16]u8 = undefined;
            self.aes.encrypt(&t, &self.iv);

            tag = AES.Block.fromBytes(&tag).xorBytes(&t);
            return if (withSuffixTag != 0)
                switch (@"🔐") {
                    .encrypt => do: {
                        self.dst[leftover..][0..16].* = tag;
                        _ = Env.write(.AesWritableStream, self.dst[0 .. leftover + 16]);
                        break :do 0;
                    },
                    .decrypt => do: {
                        if (leftover > 0) {
                            _ = Env.write(.AesWritableStream, self.dst[0..leftover]);
                        }
                        break :do if (std.crypto.utils.timingSafeEql(
                            [16]u8,
                            tag,
                            input_tag,
                        )) 0 else 1;
                    },
                }
            else do: {
                if (leftover > 0) {
                    _ = Env.write(.AesWritableStream, self.dst[0..leftover]);
                }
                _ = Env.write(.AesTag, &tag);
                break :do 0;
            };
        }
    };
}

pub const Aes128GcmStream = AesGcmStream(AES.Aes128);
pub const Aes256GcmStream = AesGcmStream(AES.Aes256);

pub const Exports = struct {
    var aes: enum {
        aes128,
        aes256,
    } = undefined;
    var aes128: Aes128GcmStream = undefined;
    var aes256: Aes256GcmStream = undefined;
    var @"🔐": enum {
        encrypt,
        decrypt,
    } = undefined;
    var withSuffixTag: u1 = undefined;
    var src: [buffer_length]u8 = undefined;
    var dst: [buffer_length]u8 = undefined;
    pub inline fn update(ctx: anytype) void {
        return switch (@"🔐") {
            inline else => |i| switch (withSuffixTag) {
                inline else => |j| ctx.update(i, j),
            },
        };
    }
    pub inline fn final(ctx: anytype) u32 {
        return switch (@"🔐") {
            inline else => |i| switch (withSuffixTag) {
                inline else => |j| ctx.final(i, j),
            },
        };
    }
};
pub export fn Aes_init(init: u32) void {
    var key: [64]u8 = undefined;
    Exports.aes = switch (Env.read(.AesKey, &key)) {
        16 => do: {
            Exports.aes128 = Aes128GcmStream.init(
                key[0..16],
                &Exports.src,
                &Exports.dst,
            );
            break :do .aes128;
        },
        32 => do: {
            Exports.aes256 = Aes256GcmStream.init(
                key[0..32],
                &Exports.src,
                &Exports.dst,
            );
            break :do .aes256;
        },
        else => unreachable,
    };
    Exports.@"🔐" = if (init & 0b1 != 0) .encrypt else .decrypt;
    Exports.withSuffixTag = if (init & 0b10 != 0) 1 else 0;
}
pub export fn Aes_update() void {
    return switch (Exports.aes) {
        .aes128 => Exports.update(&Exports.aes128),
        .aes256 => Exports.update(&Exports.aes256),
    };
}
pub export fn Aes_final() u32 {
    return switch (Exports.aes) {
        .aes128 => Exports.final(&Exports.aes128),
        .aes256 => Exports.final(&Exports.aes256),
    };
}
