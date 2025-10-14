const std = @import("std");
const ft = @import("file-time.zig");
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
    pub fn fromSystemTime(systemTime: *const ft.SYSTEMTIME) Date {
        return .{
            .year = @intCast(systemTime.wYear - 1980),
            .month = @intCast(systemTime.wMonth),
            .date = @intCast(systemTime.wDay),
            .hours = @intCast(systemTime.wHour),
            .minutes = @intCast(systemTime.wMinute),
            .double_seconds = @intCast(@divFloor(systemTime.wSecond, 2)),
        };
    }
    pub fn fromHandle(hFile: ft.HANDLE) !Date {
        var time: ft.FILETIME = undefined;
        var localTime: ft.FILETIME = undefined;
        var systemTime: ft.SYSTEMTIME = undefined;
        try ft.GetFileTime(hFile, null, null, &time);
        try ft.FileTimeToLocalFileTime(&time, &localTime);
        try ft.FileTimeToSystemTime(&localTime, &systemTime);
        return Date.fromSystemTime(&systemTime);
    }
    pub fn fromFile(file: File) !Date {
        return Date.fromHandle(file.handle);
    }
};
pub const LocalFileHeader = packed struct(u240) {
    pub const MAGIC = 0x04034b50;
    magic: u32 = MAGIC,
    version: u16 = 0x14,
    bit_flag: u16 = 0x01,
    comp_method: u16 = 0,
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
    version: u16 = 0x14,
    bit_flag: u16 = 0x01,
    comp_method: u16 = 0,
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
    return @typeInfo(T).@"struct".backing_integer.?;
}
pub fn Size(comptime T: type) comptime_int {
    return @typeInfo(Int(T)).int.bits / 8;
}
pub fn Array(comptime T: type) type {
    return [Size(T)]u8;
}

pub inline fn pack(self: anytype) Array(@TypeOf(self)) {
    return @bitCast(mem.nativeToLittle(Int(@TypeOf(self)), @bitCast(self)));
}
pub inline fn packTo(data: []u8, self: anytype) void {
    data[0..Size(@TypeOf(self))].* = pack(self);
}
pub inline fn unpack(comptime T: type, data: []const u8) !T {
    const inst: T = @bitCast(mem.littleToNative(Int(T), @bitCast(data[0..Size(T)].*)));
    try if (inst.magic != T.MAGIC)
        error.InvalidMagicNumber;
    return inst;
}
pub const default = LocalFileHeader{
    .crc32 = 0,
    .comp_size = 0,
    .size = 0,
    .name_len = 0,
};

pub fn write(
    file: AnyWriter,
    name: []const u8,
    content: []const u8,
    header: *LocalFileHeader,
) AnyWriter.Error!void {
    header.name_len = @intCast(name.len);
    header.comp_size = @intCast(content.len);
    try file.writeAll(&pack(header.*));
    try file.writeAll(name);
    try file.writeAll(content);
    try file.writeAll(&pack(CentralDirectoryHeader{
        .date = header.date,
        .crc32 = header.crc32,
        .comp_size = header.comp_size,
        .size = header.size,
        .name_len = header.name_len,
        .offset = 0,
    }));
    try file.writeAll(name);
    try file.writeAll(&pack(EndOfCentralDirectory{
        .size = @intCast(Size(CentralDirectoryHeader) + name.len),
        .offset = @intCast(Size(LocalFileHeader) + name.len + content.len),
    }));
}

pub const ReadError = mem.Allocator.Error || File.ReadError || File.SeekError || error{
    InvalidMagicNumber,
    NoExtraData,
};
pub const ZipReader = struct {
    const Self = @This();
    file: File,
    header: []const u8,
    offset: usize = 0,
    pub fn init(allocator: mem.Allocator, file: File) !Self {
        const eocd = do: {
            const T = EndOfCentralDirectory;
            try file.seekFromEnd(-Size(T));
            var eocd: Array(T) = undefined;
            _ = try file.readAll(&eocd);
            break :do try unpack(T, &eocd);
        };
        try file.seekTo(eocd.offset);
        const header = try allocator.alloc(u8, eocd.size);
        errdefer allocator.free(header);
        _ = try file.readAll(header);

        return .{
            .file = file,
            .header = header,
        };
    }
    pub fn next(self: *Self) ?ZipEntry {
        if (self.offset < self.header.len) {
            const central = unpack(CentralDirectoryHeader, self.header[self.offset..]) catch return null;
            self.offset += Size(CentralDirectoryHeader);
            const name = self.header[self.offset..][0..central.name_len];
            const entry = ZipEntry.init(self.file, central, name);
            self.offset += central.name_len + central.extra_len + central.comment_len;
            return entry;
        }
        return null;
    }
    pub fn deinit(self: *const Self, allocator: mem.Allocator) void {
        allocator.free(self.header);
    }
};
pub const ZipEntry = struct {
    const Self = @This();
    file: File,
    central: CentralDirectoryHeader,
    name: []const u8,
    pub fn init(
        file: File,
        central: CentralDirectoryHeader,
        name: []const u8,
    ) Self {
        return .{
            .file = file,
            .central = central,
            .name = name,
        };
    }
    pub fn read(self: *const Self, allocator: mem.Allocator) ![]u8 {
        const central = &self.central;
        try self.file.seekTo(central.offset);
        var buffer: Array(LocalFileHeader) = undefined;
        _ = try self.file.readAll(&buffer);
        const header = try unpack(LocalFileHeader, &buffer);
        inline for (.{
            "version", "bit_flag",  "comp_method", "date",
            "crc32",   "comp_size", "size",        "name_len",
        }) |name| {
            const a = @field(header, name);
            const b = @field(central, name);
            if (a != b) return error.InvalidZipHeader;
        }
        const data = try allocator.alloc(u8, central.comp_size);
        errdefer allocator.free(data);
        try self.file.seekTo(central.offset + Size(LocalFileHeader) + header.name_len + header.extra_len);
        _ = try self.file.readAll(data);
        return data;
    }
};
