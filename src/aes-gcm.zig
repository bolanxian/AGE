const builtin = @import("builtin");
const std = @import("std");
const io = std.io;
const mem = std.mem;
const Ghash = std.crypto.onetimeauth.Ghash;
const AES = std.crypto.core.aes;
const AnyReader = io.AnyReader;
const AnyWriter = io.AnyWriter;
const isWasm = builtin.cpu.arch.isWasm();

pub const EncryptOrDecrypt = enum {
    encrypt,
    decrypt,
};
pub const Fd = enum(usize) {
    Unreachable = 0,
    AesKey = 1,
    AesIv = 2,
    AesAad = 3,
    AesTag = 4,
    AesReadableStream = 5,
    AesWritableStream = 6,
};

pub const Context = if (isWasm) struct {
    const Self = @This();
    _: void = {},
    const Inner = struct {
        extern "env" fn read(fd: Fd, ptr: [*]u8, len: usize) usize;
        extern "env" fn write(fd: Fd, ptr: [*]const u8, len: usize) usize;
    };
    pub inline fn read(_: *const Self, fd: Fd, buf: []u8) usize {
        return Inner.read(fd, buf.ptr, buf.len);
    }
    pub inline fn write(_: *const Self, fd: Fd, buf: []const u8) usize {
        return Inner.write(fd, buf.ptr, buf.len);
    }
} else struct {
    const Self = @This();
    reader: AnyReader,
    writer: AnyWriter,
    @"error": ?anyerror = null,
    aad: []const u8,
    iv: []const u8,
    tag: []u8,
    pub fn init(
        reader: AnyReader,
        writer: AnyWriter,
        aad: []const u8,
        iv: []const u8,
        tag: []u8,
    ) Self {
        return .{
            .reader = reader,
            .writer = writer,
            .aad = aad,
            .iv = iv,
            .tag = tag,
        };
    }
    pub inline fn read(self: *const Self, fd: Fd, buf: []u8) usize {
        switch (fd) {
            .AesIv => {
                const len = @min(buf.len, self.iv.len);
                @memcpy(buf[0..len], self.iv[0..len]);
                return len;
            },
            .AesAad => {
                const len = @min(buf.len, self.aad.len);
                @memcpy(buf[0..len], self.aad[0..len]);
                return len;
            },
            .AesReadableStream => self.reader.readAll(buf) catch |err| {
                self.@"error" = err;
                return 0;
            },
            else => return 0,
        }
    }
    pub inline fn write(self: *const Self, fd: Fd, buf: []const u8) usize {
        switch (fd) {
            .AesTag => {
                const len = @min(self.tag.len, buf.len);
                @memcpy(self.tag[0..len], buf[0..len]);
                return len;
            },
            .AesWritableStream => self.writer.writeAll(buf) catch |err| {
                self.@"error" = err;
                return 0;
            },
            else => return 0,
        }
    }
};

pub const buffer_length = 65536 * 2;

fn AesGcmStream(comptime Aes: type) type {
    return struct {
        const Self = @This();
        pub const block_length = AES.Block.block_length;
        pub const zeros = [_]u8{0} ** block_length;
        pub const tag_length = 16;
        pub const iv_length = 12;
        pub const key_length = Aes.key_bits / 8;
        ctx: Context,
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
            ctx: Context,
            key: *const [key_length]u8,
            src: *[buffer_length]u8,
            dst: *[buffer_length]u8,
        ) Self {
            var self = Self{ .ctx = ctx, .src = src, .dst = dst };
            const buffer = src;
            self.aes = Aes.initEnc(key.*);
            const aes = &self.aes;

            var h: [16]u8 = undefined;
            aes.encrypt(&h, &zeros);

            self.mac = Ghash.init(&h);
            const mac = &self.mac;
            while (true) {
                const amt = self.ctx.read(.AesAad, buffer);
                if (amt == 0) break;
                mac.update(buffer[0..amt]);
                self.ad_len += amt;
            }
            mac.pad();

            var iv: [16]u8 = undefined;
            _ = self.ctx.read(.AesIv, iv[0..iv_length]);
            mem.writeInt(u32, iv[iv_length..][0..4], 1, .big);
            self.iv = iv;
            mem.writeInt(u32, iv[iv_length..][0..4], 2, .big);
            self.counter = mem.readInt(u128, &iv, .big);
            return self;
        }
        pub fn update(
            self: *Self,
            comptime @"🔐": EncryptOrDecrypt,
            comptime withSuffixTag: u1,
        ) void {
            const src = self.src;
            const dst = self.dst;
            self.leftover += self.ctx.read(.AesReadableStream, src[self.leftover..]);
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
                _ = self.ctx.write(.AesWritableStream, dst[0..i]);
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
            comptime @"🔐": EncryptOrDecrypt,
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
                        _ = self.ctx.write(.AesWritableStream, self.dst[0 .. leftover + 16]);
                        break :do 0;
                    },
                    .decrypt => do: {
                        if (leftover > 0) {
                            _ = self.ctx.write(.AesWritableStream, self.dst[0..leftover]);
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
                    _ = self.ctx.write(.AesWritableStream, self.dst[0..leftover]);
                }
                _ = self.ctx.write(.AesTag, &tag);
                break :do 0;
            };
        }
    };
}

pub const Aes128GcmStream = AesGcmStream(AES.Aes128);
pub const Aes256GcmStream = AesGcmStream(AES.Aes256);

const Wasm = struct {
    const Self = @This();
    var self: Self = undefined;
    ctx: Context = .{},
    aes: union(enum) {
        aes128: Aes128GcmStream,
        aes256: Aes256GcmStream,
    } = undefined,
    @"🔐": EncryptOrDecrypt,
    withSuffixTag: u1,
    src: [buffer_length]u8 = undefined,
    dst: [buffer_length]u8 = undefined,
    inline fn create(ctx: Context, key: []const u8, src: *[buffer_length]u8, dst: *[buffer_length]u8) @TypeOf(self.aes) {
        return switch (key.len) {
            16 => .{
                .aes128 = Aes128GcmStream.init(ctx, key[0..16], src, dst),
            },
            32 => .{
                .aes256 = Aes256GcmStream.init(ctx, key[0..32], src, dst),
            },
            else => unreachable,
        };
    }
    pub fn init(init_code: u32) callconv(.C) void {
        var key: [64]u8 = undefined;
        self = .{
            .@"🔐" = if (init_code & 0b1 != 0) .encrypt else .decrypt,
            .withSuffixTag = if (init_code & 0b10 != 0) 1 else 0,
        };
        self.aes = create(self.ctx, key[0..self.ctx.read(.AesKey, &key)], &self.src, &self.dst);
    }
    pub fn update() callconv(.C) void {
        return switch (self.aes) {
            inline else => |*aes| switch (self.@"🔐") {
                inline else => |i| switch (self.withSuffixTag) {
                    inline else => |j| aes.update(i, j),
                },
            },
        };
    }
    pub fn final() callconv(.C) u32 {
        return switch (self.aes) {
            inline else => |*aes| switch (self.@"🔐") {
                inline else => |i| switch (self.withSuffixTag) {
                    inline else => |j| aes.final(i, j),
                },
            },
        };
    }
    comptime {
        @export(init, .{ .name = "Aes_init" });
        @export(update, .{ .name = "Aes_update" });
        @export(final, .{ .name = "Aes_final" });
    }
};
comptime {
    if (isWasm) _ = Wasm;
}
