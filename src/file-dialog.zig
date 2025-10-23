const std = @import("std");
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
const OFN_HIDEREADONLY: DWORD = 0x00000004;
const OFN_EXPLORER: DWORD = 0x00080000;
extern "Comdlg32" fn GetOpenFileNameW(lpofn: *OPENFILENAMEW) callconv(.winapi) BOOL;

pub fn open(allocator: mem.Allocator, title: [:0]const u8, filter: [:0]const u8) !?[]u8 {
    const titlew = try string_to_wide(allocator, title);
    defer allocator.free(titlew);
    const filterw = try string_to_wide(allocator, filter);
    defer allocator.free(filterw);
    var filew = zeroes([4096:0]u16);

    var ofn: OPENFILENAMEW = .{};
    ofn.lpstrFilter = filterw;
    ofn.lpstrFile = &filew;
    ofn.nMaxFile = filew.len;
    ofn.lpstrTitle = titlew;
    ofn.Flags = OFN_EXPLORER | OFN_HIDEREADONLY;

    if (GetOpenFileNameW(&ofn) != 0) {
        var iter = mem.splitScalar(u16, &filew, 0);
        while (iter.next()) |namew| {
            if (namew.len == 0) break;
            return try wide_to_string(allocator, namew);
        }
    }
    return null;
}

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
pub fn main() !void {
    const allocator = gpa.allocator();
    const stdout = std.io.getStdOut().writer();

    const filter = "All Files (*.*)\x00*.*\x00";
    const title = "打开文件";
    if (try open(allocator, title, filter)) |file| {
        defer allocator.free(file);
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
