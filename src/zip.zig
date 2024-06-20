const std = @import("std");
const mem = std.mem;
const File = std.fs.File;
const AnyWriter = std.io.AnyWriter;
const Crc32 = std.hash.Crc32;

pub const Date = packed struct(u32) {
    double_seconds: u5 = 0,
    minutes: u6 = 0,
    hours: u5 = 0,
    date: u5 = 1,
    month: u4 = 1,
    year: u7 = 0,
};
pub const LocalFileHeader = packed struct(u240) {
    pub const MAGIC = 0x04034b50;
    magic: u32 = MAGIC,
    version: u16 = 0x0A,
    _2: u16 = 0,
    _3: u16 = 0,
    date: Date = .{},
    crc32: u32,
    comp_size: u32,
    size: u32,
    name_len: u16,
    extra_len: u16 = 0,
};
pub const CentralDirectoryHeader = packed struct(u368) {
    pub const MAGIC = 0x02014b50;
    magic: u32 = MAGIC,
    _1: u16 = 0x3F,
    version: u16 = 0x0A,
    _3: u16 = 0,
    _4: u16 = 0,
    date: Date = .{},
    crc32: u32,
    comp_size: u32,
    size: u32,
    name_len: u16,
    extra_len: u16 = 0,
    comment_len: u16 = 0,
    _12: u16 = 0,
    _13: u16 = 0,
    _14: u32 = 0,
    offset: u32,
};
pub const EndOfCentralDirectory = packed struct(u176) {
    pub const MAGIC = 0x06054b50;
    magic: u32 = MAGIC,
    _1: u16 = 0,
    _2: u16 = 0,
    _3: u16 = 1,
    _4: u16 = 1,
    size: u32,
    offset: u32,
    _7: u16 = 0,
};

pub fn Int(comptime T: type) type {
    return @typeInfo(T).Struct.backing_integer.?;
}
pub fn Size(comptime T: type) comptime_int {
    return @typeInfo(Int(T)).Int.bits / 8;
}
pub fn Array(comptime T: type) type {
    return [Size(T)]u8;
}

pub inline fn pack(comptime T: type, self: T) Array(T) {
    return @bitCast(mem.nativeToLittle(Int(T), @bitCast(self)));
}
pub inline fn packTo(comptime T: type, data: []u8, self: T) void {
    data[0..Size(T)].* = pack(T, self);
}
pub inline fn unpack(comptime T: type, data: []const u8) !T {
    const inst: T = @bitCast(mem.littleToNative(Int(T), @bitCast(data[0..Size(T)].*)));
    try if (inst.magic != T.MAGIC)
        error.InvalidMagicNumber;
    return inst;
}

pub fn write(
    file: AnyWriter,
    name: []const u8,
    content: []const u8,
    extra: []const []const u8,
) AnyWriter.Error!void {
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
    const extra_len = do: {
        var len: usize = 0;
        for (extra) |data| {
            len += data.len;
            try file.writeAll(data);
        }
        break :do len;
    };
    try file.writeAll(&pack(CentralDirectoryHeader, .{
        .crc32 = crc32,
        .comp_size = size,
        .size = size,
        .name_len = name_len,
        .offset = 0,
    }));
    try file.writeAll(name);
    try file.writeAll(&pack(EndOfCentralDirectory, .{
        .size = @intCast(Size(CentralDirectoryHeader) + name.len),
        .offset = @intCast(Size(LocalFileHeader) + name.len + content.len + extra_len),
    }));
}

pub const ReadError = mem.Allocator.Error || File.ReadError || File.SeekError || error{
    InvalidMagicNumber,
    NoExtraData,
};
pub fn read(alloc: mem.Allocator, file: File) ReadError![]u8 {
    const eocd = do: {
        const T = EndOfCentralDirectory;
        try file.seekFromEnd(-Size(T));
        var eocd: Array(T) = undefined;
        _ = try file.readAll(&eocd);
        break :do try unpack(T, &eocd);
    };
    const offset = do: {
        try file.seekTo(eocd.offset);
        const header = try alloc.alloc(u8, eocd.size);
        defer alloc.free(header);
        _ = try file.readAll(header);
        var offset: u64 = 0;
        var i: usize = 0;
        while (i < header.len) {
            const central = try unpack(CentralDirectoryHeader, header[i..]);
            offset = central.offset + Size(LocalFileHeader) + central.name_len + central.extra_len + central.comp_size;
            i += Size(CentralDirectoryHeader) + central.name_len + central.extra_len + central.comment_len;
        }
        break :do offset;
    };
    const size = eocd.offset - offset;
    if (size == 0) {
        return ReadError.NoExtraData;
    }
    try file.seekTo(offset);
    const data = try alloc.alloc(u8, size);
    errdefer alloc.free(data);
    _ = try file.readAll(data);
    return data;
}
