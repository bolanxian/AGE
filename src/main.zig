const builtin = @import("builtin");
const std = @import("std");
const zip = @import("zip.zig");
const fs = std.fs;
const mem = std.mem;
const log = std.log.default;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Argon2 = std.crypto.pwhash.argon2;
const nano = std.time.nanoTimestamp;

pub fn kdf(allocator: mem.Allocator, derived: []u8, password: []const u8, salt: []const u8, m: u32, t: u16, p: u16) !void {
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
    log.info("Argon2 完成: {d:.3}s", .{dur / 1000_000_000});
}

pub fn encrypt(allocator: mem.Allocator, msg: []const u8, password: []const u8, salt: []const u8, m: u32, t: u16, p: u16) ![]u8 {
    var derived: [32]u8 = undefined;
    try kdf(allocator, &derived, password, salt, m, t, p);

    const data = try allocator.alloc(u8, zip.LocalFileHeader.SIZE + salt.len + msg.len + 16);
    errdefer allocator.free(data);
    data[0..zip.LocalFileHeader.SIZE].* = zip.pack(
        zip.LocalFileHeader,
        .{ .crc32 = m, ._3 = t, ._2 = p, .name_len = @intCast(salt.len), .comp_size = 0, .size = 0 },
    );
    std.mem.copyForwards(u8, data[zip.LocalFileHeader.SIZE..][0..salt.len], salt);

    const encrypted = data[zip.LocalFileHeader.SIZE + salt.len ..];
    const key: *[16]u8 = derived[0..16];
    const iv: *[12]u8 = derived[16..28];
    const tag: *[16]u8 = encrypted[msg.len..][0..16];
    Aes128Gcm.encrypt(encrypted[0..msg.len], tag, msg, "", iv.*, key.*);
    return data;
}

pub fn decrypt(allocator: mem.Allocator, data: []const u8, password: []const u8) ![]u8 {
    const header = try zip.unpack(zip.LocalFileHeader, data);
    const salt = data[zip.LocalFileHeader.SIZE..][0..header.name_len];
    var derived: [32]u8 = undefined;
    try kdf(allocator, &derived, password, salt, header.crc32, header._3, header._2);

    const encrypted = data[zip.LocalFileHeader.SIZE + header.name_len + header.extra_len ..];
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

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
pub fn main() !void {
    if (builtin.os.tag == .windows) {
        _ = std.os.windows.kernel32.SetConsoleOutputCP(65001);
    }

    const alloc = gpa.allocator();
    const cwd = fs.cwd();
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len < 3) {
        log.info("usage : {s} <enc|dec> <filename> <password>", .{args[0]});
        return;
    }
    if (mem.eql(u8, args[1], "enc")) {
        const input = try cwd.openFile(args[2], .{});
        defer input.close();

        const msg = try input.readToEndAlloc(alloc, std.math.maxInt(u32));
        defer alloc.free(msg);

        var salt: [16]u8 = undefined;
        try std.posix.getrandom(&salt);
        const encrypted = try encrypt(alloc, msg, args[3], &salt, 512 * 1024, 5, 4);
        defer alloc.free(encrypted);

        const output_name = try withSuffix(alloc, args[2]);
        defer alloc.free(output_name);

        const output = try cwd.createFile(output_name, .{});
        defer output.close();

        try zip.write(
            output,
            "!encrypted.txt",
            "本文件已加密",
            encrypted,
        );
    } else if (mem.eql(u8, args[1], "dec")) {
        const input_name = try withSuffix(alloc, args[2]);
        defer alloc.free(input_name);

        const input = try cwd.openFile(input_name, .{});
        defer input.close();

        const data = zip.read(alloc, input) catch |err| return switch (err) {
            error.InvalidMagicNumber => {
                log.err("不是 zip 文件", .{});
            },
            error.NoExtraData => {
                log.err("没有额外数据", .{});
            },
            else => err,
        };
        defer alloc.free(data);

        const decrypted = decrypt(alloc, data, args[3]) catch |err| return switch (err) {
            error.AuthenticationFailed => {
                log.err("密码错误", .{});
            },
            else => err,
        };
        defer alloc.free(decrypted);

        const output = try cwd.createFile(args[2], .{});
        defer output.close();

        try output.writeAll(decrypted);
    } else {
        log.err("error: unknown command: {s}", .{args[1]});
    }
}
