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

    const data = try allocator.alloc(u8, zip.sizeOf(AgeHeader) + salt.len + msg.len + 16);
    errdefer allocator.free(data);
    zip.packTo(data, AgeHeader{ .m = m, .t = t, .p = p, .salt_len = @intCast(salt.len) });
    @memcpy(data[zip.sizeOf(AgeHeader)..][0..salt.len], salt);

    const encrypted = data[zip.sizeOf(AgeHeader) + salt.len ..];
    const key: *[16]u8 = derived[0..16];
    const iv: *[12]u8 = derived[16..28];
    const tag: *[16]u8 = encrypted[msg.len..][0..16];
    Aes128Gcm.encrypt(encrypted[0..msg.len], tag, msg, "", iv.*, key.*);
    return data;
}

pub fn decrypt(allocator: mem.Allocator, header: *AgeHeader, data: []const u8, password: []const u8) ![]u8 {
    header.* = try zip.unpack(AgeHeader, data);
    const salt = data[zip.sizeOf(AgeHeader)..][0..header.salt_len];
    var derived: [32]u8 = undefined;
    try kdf(allocator, &derived, password, salt, header.m, header.t, header.p);

    const encrypted = data[zip.sizeOf(AgeHeader) + header.salt_len ..];
    const msg = try allocator.alloc(u8, encrypted.len - 16);
    errdefer allocator.free(msg);
    const key: *[16]u8 = derived[0..16];
    const iv: *[12]u8 = derived[16..28];
    const tag: *const [16]u8 = encrypted[msg.len..][0..16];
    try Aes128Gcm.decrypt(msg, encrypted[0..msg.len], tag.*, "", iv.*, key.*);
    return msg;
}

comptime {
    if (builtin.cpu.arch.endian() != .little)
        @compileError("Only support little endian");
}
fn help(allocator: mem.Allocator, args: [][:0]u8) !void {
    const arg0 = try fs.path.relative(allocator, ".", args[0]);
    defer allocator.free(arg0);
    log.info("Usage : {s} <\"e\" | \"d\"> <input file> <output file> <password>", .{arg0});
    return;
}

const options: zip.Writer.Options = .{
    .version = .hasDeflateOrCrypto,
    .bit_flag = .{ .crypto = true },
    .compress_method = .store,
};
fn main_encrypt(allocator: mem.Allocator, dir: fs.Dir, input_file: []const u8, output_file: []const u8, password: []const u8) !void {
    const input = try dir.openFile(input_file, .{});
    defer input.close();

    const msg = try input.readToEndAlloc(allocator, std.math.maxInt(u32));
    defer allocator.free(msg);

    var salt: [16]u8 = undefined;
    try std.posix.getrandom(&salt);
    const encrypted = try encrypt(allocator, msg, password, &salt, 512 * 1024, 5, 4);
    defer allocator.free(encrypted);

    const output = try dir.createFile(output_file, .{});
    defer output.close();

    const name = if (mem.lastIndexOfAny(u8, input_file, "\\/")) |index|
        input_file[index + 1 ..]
    else
        input_file;

    var output_buffer: [4096]u8 = undefined;
    var output_writer = output.writer(&output_buffer);
    var writer = zip.Writer.init(allocator, &output_writer.interface, options);
    defer writer.deinit();
    var header: zip.LocalFileHeader = .{
        .version = options.version,
        .bit_flag = options.bit_flag,
        .compress_method = options.compress_method,
        .date = try zip.Date.fromFile(input),
        .crc32 = AgeHeader.MAGIC,
        .compress_size = 0,
        .size = @intCast(msg.len),
        .name_len = 0,
    };
    try writer.writeCustom(name, encrypted, &header);
    try writer.end();
}
fn main_decrypt(allocator: mem.Allocator, dir: fs.Dir, input_file: []const u8, output_file: []const u8, password: []const u8) !void {
    const input = try dir.openFile(input_file, .{});
    defer input.close();

    var reader = zip.Reader.init(allocator, input) catch |err| return switch (err) {
        error.InvalidMagicNumber => {
            log.err("不是 zip 文件", .{});
        },
        else => err,
    };
    defer reader.deinit(allocator);
    const entry = do: while (reader.next()) |entry| {
        const head = &entry.central;
        inline for (@typeInfo(zip.Writer.Options).@"struct".fields) |field| {
            const name = field.name;
            const a = @field(head, name);
            const b = @field(options, name);
            if (a != b) continue :do;
        }
        break :do entry;
    } else {
        log.err("没有合适的文件", .{});
        return;
    };
    const data = entry.read(allocator) catch |err| return switch (err) {
        error.InvalidMagicNumber, error.InvalidZipHeader => {
            log.err("文件头部错误", .{});
        },
        else => err,
    };
    defer allocator.free(data);

    var header: AgeHeader = undefined;
    const decrypted = decrypt(allocator, &header, data, password) catch |err| return switch (err) {
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

    const output = try dir.createFile(output_file, .{});
    defer output.close();

    try output.writeAll(decrypted);
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

    if (args.len < 2 or args[1].len != 1) {
        return help(allocator, args);
    }
    switch (args[1][0]) {
        'e' => {
            if (args.len != 5) return help(allocator, args);
            try main_encrypt(allocator, cwd, args[2], args[3], args[4]);
        },
        'd' => {
            if (args.len != 5) return help(allocator, args);
            try main_decrypt(allocator, cwd, args[2], args[3], args[4]);
        },
        'o' => {
            if (args.len != 2) return help(allocator, args);
            const open = @import("./file-dialog.zig").open;
            var stdout = std.fs.File.stdout();
            if (try open(allocator, "打开文件", "All Files (*.*)\x00*.*\x00")) |file| {
                defer allocator.free(file);
                try stdout.writeAll(file);
            }
        },
        else => {
            log.err("error: unknown command: {s}", .{args[1]});
        },
    }
}
