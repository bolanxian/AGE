const builtin = @import("builtin");
const std = @import("std");
const zip = @import("zip.zig");
const fs = std.fs;
const mem = std.mem;
const log = std.log.default;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Argon2 = std.crypto.pwhash.argon2;
const nano = std.time.nanoTimestamp;

pub const AgeHeader = packed struct(u96) {
    pub const MAGIC: u32 = @bitCast(@as([4]u8, "AGE ".*));
    magic: u32 = MAGIC,
    m: u32,
    t: u16,
    p: u8,
    salt_len: u8,
};

pub fn kdf(allocator: mem.Allocator, derived: []u8, password: []const u8, salt: []const u8, m: u32, t: u16, p: u8) !void {
    const start = nano();
    log.info("Argon2 启动", .{});
    try Argon2.kdf(
        allocator,
        derived,
        password,
        salt,
        .{ .m = m, .t = t, .p = p },
        .argon2id,
    );
    const dur = @as(f64, @floatFromInt(nano() - start));
    log.info("Argon2 完成: {d:.3}s", .{dur / std.time.ns_per_s});
}

pub fn encrypt(allocator: mem.Allocator, msg: []const u8, password: []const u8, salt: []const u8, m: u32, t: u16, p: u8) ![]u8 {
    var derived: [32]u8 = undefined;
    try kdf(allocator, &derived, password, salt, m, t, p);

    const data = try allocator.alloc(u8, zip.Size(AgeHeader) + salt.len + msg.len + 16);
    errdefer allocator.free(data);
    zip.packTo(data, AgeHeader{ .m = m, .t = t, .p = p, .salt_len = @intCast(salt.len) });
    @memcpy(data[zip.Size(AgeHeader)..][0..salt.len], salt);

    const encrypted = data[zip.Size(AgeHeader) + salt.len ..];
    const key: *[16]u8 = derived[0..16];
    const iv: *[12]u8 = derived[16..28];
    const tag: *[16]u8 = encrypted[msg.len..][0..16];
    Aes128Gcm.encrypt(encrypted[0..msg.len], tag, msg, "", iv.*, key.*);
    return data;
}

pub fn decrypt(allocator: mem.Allocator, header: *AgeHeader, data: []const u8, password: []const u8) ![]u8 {
    header.* = try zip.unpack(AgeHeader, data);
    const salt = data[zip.Size(AgeHeader)..][0..header.salt_len];
    var derived: [32]u8 = undefined;
    try kdf(allocator, &derived, password, salt, header.m, header.t, header.p);

    const encrypted = data[zip.Size(AgeHeader) + header.salt_len ..];
    const msg = try allocator.alloc(u8, encrypted.len - 16);
    errdefer allocator.free(msg);
    const key: *[16]u8 = derived[0..16];
    const iv: *[12]u8 = derived[16..28];
    const tag: *const [16]u8 = encrypted[msg.len..][0..16];
    try Aes128Gcm.decrypt(msg, encrypted[0..msg.len], tag.*, "", iv.*, key.*);
    return msg;
}

pub fn withSuffix(allocator: mem.Allocator, path: []const u8) ![]const u8 {
    return mem.concat(allocator, u8, &[_][]const u8{ path, ".zip" });
}
comptime {
    if (builtin.cpu.arch.endian() != .little)
        @compileError("Only support little endian");
}

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
pub fn main() !void {
    if (builtin.os.tag == .windows) {
        _ = std.os.windows.kernel32.SetConsoleOutputCP(65001);
    }

    const allocator = gpa.allocator();
    const cwd = fs.cwd();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        const dir = try fs.path.relative(allocator, ".", args[0]);
        defer allocator.free(dir);
        log.info("usage : {s} <enc|dec> <filename> <password>", .{dir});
        return;
    }
    if (mem.eql(u8, args[1], "enc")) {
        const input = try cwd.openFile(args[2], .{});
        defer input.close();

        const msg = try input.readToEndAlloc(allocator, std.math.maxInt(u32));
        defer allocator.free(msg);

        var salt: [16]u8 = undefined;
        try std.posix.getrandom(&salt);
        const encrypted = try encrypt(allocator, msg, args[3], &salt, 512 * 1024, 5, 4);
        defer allocator.free(encrypted);

        const output_name = try withSuffix(allocator, args[2]);
        defer allocator.free(output_name);

        const output = try cwd.createFile(output_name, .{});
        defer output.close();

        try zip.write(
            output.writer().any(),
            "!encrypted.txt",
            "本文件已加密",
            try zip.Date.fromFile(input),
            &[_][]const u8{encrypted},
        );
    } else if (mem.eql(u8, args[1], "dec")) {
        const input_name = try withSuffix(allocator, args[2]);
        defer allocator.free(input_name);

        const input = try cwd.openFile(input_name, .{});
        defer input.close();

        const data = zip.read(allocator, input) catch |err| return switch (err) {
            error.InvalidMagicNumber => {
                log.err("不是 zip 文件", .{});
            },
            error.NoExtraData => {
                log.err("没有额外数据", .{});
            },
            else => err,
        };
        defer allocator.free(data);

        var header: AgeHeader = undefined;
        const decrypted = decrypt(allocator, &header, data, args[3]) catch |err| return switch (err) {
            error.InvalidMagicNumber => {
                log.err("额外数据错误", .{});
            },
            error.AuthenticationFailed => {
                log.err("密码错误", .{});
            },
            else => err,
        };
        defer allocator.free(decrypted);
        log.info("$argon2id$v=19$m={d},t={d},p={d}$", .{ header.m, header.t, header.p });

        const output = try cwd.createFile(args[2], .{});
        defer output.close();

        try output.writeAll(decrypted);
    } else {
        log.err("error: unknown command: {s}", .{args[1]});
    }
}
