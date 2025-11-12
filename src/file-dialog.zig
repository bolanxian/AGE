const std = @import("std");
const heap = std.heap;
const mem = std.mem;
const zeroes = mem.zeroes;
const wide_to_string = std.unicode.utf16LeToUtf8Alloc;
const string_to_wide = std.unicode.utf8ToUtf16LeAllocZ;

const windows = std.os.windows;
const HWND = windows.HWND;
const WORD = windows.WORD;
const DWORD = windows.DWORD;
const LPWSTR = windows.LPWSTR;
const LPCWSTR = windows.LPCWSTR;
const LPARAM = windows.LPARAM;
const WPARAM = windows.WPARAM;
const HINSTANCE = windows.HINSTANCE;
const BOOL = windows.BOOL;
pub const OPENFILENAMEW = extern struct {
    lStructSize: DWORD = @sizeOf(@This()),
    hwndOwner: ?HWND = null,
    hInstance: ?HINSTANCE = null,
    lpstrFilter: ?LPCWSTR = null,
    lpstrCustomFilter: ?LPWSTR = null,
    nMaxCustFilter: DWORD = 0,
    nFilterIndex: DWORD = 0,
    lpstrFile: ?LPWSTR = null,
    nMaxFile: DWORD = 0,
    lpstrFileTitle: ?LPWSTR = null,
    nMaxFileTitle: DWORD = 0,
    lpstrInitialDir: ?LPCWSTR = null,
    lpstrTitle: ?LPCWSTR = null,
    Flags: DWORD = 0,
    nFileOffset: WORD = 0,
    nFileExtension: WORD = 0,
    lpstrDefExt: ?LPCWSTR = null,
    lCustData: LPARAM = 0,
    lpfnHook: ?*anyopaque = null,
    lpTemplateName: ?LPCWSTR = null,
    pvReserved: ?*anyopaque = null,
    dwReserved: DWORD = 0,
    FlagsEx: DWORD = 0,
};
extern "Comdlg32" fn GetOpenFileNameW(lpofn: *OPENFILENAMEW) callconv(.winapi) BOOL;
pub const OFN_HIDEREADONLY: DWORD = 0x00000004;
pub const OFN_EXPLORER: DWORD = 0x00080000;

pub fn openW(title: [:0]const u16, filter: [:0]const u16, flags: DWORD) ?[4096:0]u16 {
    var file = zeroes([4096:0]u16);
    var ofn: OPENFILENAMEW = .{};
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = &file;
    ofn.nMaxFile = file.len;
    ofn.lpstrTitle = title;
    ofn.Flags = flags;
    return if (GetOpenFileNameW(&ofn) != 0) file else null;
}
pub fn open(arena: mem.Allocator, title: []const u8, filter: []const u8) !?[]u8 {
    const titlew = try string_to_wide(arena, title);
    defer arena.free(titlew);
    const filterw = try string_to_wide(arena, filter);
    defer arena.free(filterw);
    if (openW(titlew, filterw, OFN_EXPLORER | OFN_HIDEREADONLY)) |fileOwned| {
        const file = mem.trimEnd(u16, &fileOwned, &.{0});
        return try wide_to_string(arena, file);
    }
    return null;
}

pub fn main() !void {
    var arena_state: heap.ArenaAllocator = .init(heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var stdout_state = std.fs.File.stdout().writer(&.{});
    const stdout = &stdout_state.interface;

    const filter = "All Files (*.*)\x00*.*\x00";
    const title = "打开文件";
    if (try open(arena, title, filter)) |file| {
        defer arena.free(file);
        try stdout.writeAll(file);
    }
}

test open {
    const allocator = std.testing.allocator;
    const filter = "All Files (*.*)\x00*.*\x00";
    const title = "打开文件";
    if (try open(allocator, title, filter)) |file| {
        defer allocator.free(file);
    }
}
