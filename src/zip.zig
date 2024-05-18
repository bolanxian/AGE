const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const Crc32 = std.hash.Crc32;

pub const Date = packed union {
    value: u32,
    data: packed struct {
        double_seconds: u5 = 0,
        minutes: u6 = 0,
        hours: u5 = 0,
        date: u5 = 1,
        month: u4 = 1,
        year: u7 = 0,
    },
};
pub const LocalFileHeader = packed struct {
    pub const SIZE = 30;
    pub const MAGIC = 0x04034b50;
    magic: u32 = MAGIC,
    version: u16 = 0x0A,
    _2: u16 = 0,
    _3: u16 = 0,
    date: Date = .{ .data = .{} },
    crc32: u32,
    comp_size: u32,
    size: u32,
    name_len: u16,
    extra_len: u16 = 0,
};
pub const CentralDirectoryHeader = packed struct {
    pub const SIZE = 46;
    pub const MAGIC = 0x02014b50;
    magic: u32 = MAGIC,
    _1: u16 = 0x3F,
    version: u16 = 0x0A,
    _3: u16 = 0,
    _4: u16 = 0,
    date: Date = .{ .data = .{} },
    crc32: u32,
    comp_size: u32,
    size: u32,
    name_len: u16,
    extra_len: u16 = 0,
    comment_len: u16 = 0,
    _12: u16 = 0,
    _13: u16 = 0,
    _14: u32 = 0,
    offset: u32 = 0,
};
pub const EndOfCentralDirectory = packed struct {
    pub const SIZE = 22;
    pub const MAGIC = 0x06054b50;
    magic: u32 = MAGIC,
    _1: u16 = 0,
    _2: u16 = 0,
    _3: u16 = 1,
    _4: u16 = 1,
    size: u32,
    offset: u32,
    _5: u16 = 0,
};
pub inline fn pack(comptime T: type, self: T) [T.SIZE]u8 {
    return @bitCast(self);
}
pub inline fn unpack(comptime T: type, data: []const u8) !T {
    const inst: T = @bitCast(data[0..T.SIZE].*);
    if (inst.magic != T.MAGIC) {
        return error.InvalidMagicNumber;
    }
    return inst;
}

pub fn write(
    file: fs.File,
    name: []const u8,
    content: []const u8,
    extra: []const u8,
) !void {
    const crc32 = Crc32.hash(content);
    const size: u32 = @intCast(content.len);
    const name_len: u16 = @intCast(name.len);
    try file.writeAll(&pack(LocalFileHeader, .{
        .crc32 = crc32,
        .comp_size = size,
        .size = size,
        .name_len = name_len,
    }));
    try file.writeAll(name);
    try file.writeAll(content);
    try file.writeAll(extra);
    try file.writeAll(&pack(CentralDirectoryHeader, .{
        .crc32 = crc32,
        .comp_size = size,
        .size = size,
        .name_len = name_len,
    }));
    try file.writeAll(name);
    try file.writeAll(&pack(EndOfCentralDirectory, .{
        .size = @intCast(CentralDirectoryHeader.SIZE + name.len),
        .offset = @intCast(LocalFileHeader.SIZE + name.len + content.len + extra.len),
    }));
}

pub fn read(alloc: mem.Allocator, file: fs.File) ![]u8 {
    var _eocd: [EndOfCentralDirectory.SIZE]u8 = undefined;
    try file.seekFromEnd(-EndOfCentralDirectory.SIZE);
    _ = try file.readAll(&_eocd);
    const eocd = try unpack(EndOfCentralDirectory, &_eocd);
    const offset = do: {
        const header = try alloc.alloc(u8, eocd.size);
        defer alloc.free(header);
        try file.seekTo(eocd.offset);
        _ = try file.readAll(header);
        var offset: u64 = 0;
        var i: usize = 0;
        while (i < header.len) {
            const central = try unpack(CentralDirectoryHeader, header[i..]);
            offset = central.offset + LocalFileHeader.SIZE + central.name_len + central.extra_len + central.comp_size;
            i += CentralDirectoryHeader.SIZE + central.name_len + central.extra_len + central.comment_len;
        }
        break :do offset;
    };
    const size = eocd.offset - offset;
    if (size == 0) {
        return error.NoExtraData;
    }
    try file.seekTo(offset);
    const data = try alloc.alloc(u8, size);
    errdefer alloc.free(data);
    _ = try file.readAll(data);
    return data;
}
