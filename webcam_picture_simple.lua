-- webcam_picture_simple.lua
-- Simple webcam capture using VFW (Video for Windows) API
-- Much safer than DirectShow for DLL worker threads
-- Logs to %TEMP%\COMPUTERNAME_WEBCAM_PICTURE_YYYYMMDD_HHMMSS.log

local jit = require("jit")
jit.off(true, true)

local ffi = require("ffi")
local bit = require("bit")

-- Global log file handle
local LOG_HANDLE = nil

ffi.cdef[[
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef int BOOL;
typedef void* HANDLE;
typedef void* HWND;
typedef char* LPSTR;
typedef const char* LPCSTR;
typedef wchar_t* LPWSTR;
typedef DWORD* LPDWORD;

// File operations
HANDLE CreateFileA(LPCSTR, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
BOOL WriteFile(HANDLE, const void*, DWORD, LPDWORD, void*);
BOOL FlushFileBuffers(HANDLE);
BOOL CloseHandle(HANDLE);
DWORD GetTempPathA(DWORD, LPSTR);
DWORD GetComputerNameA(LPSTR, LPDWORD);

// VFW (Video for Windows) API
HWND capCreateCaptureWindowA(
    LPCSTR lpszWindowName,
    DWORD dwStyle,
    int x, int y,
    int nWidth, int nHeight,
    HWND hWndParent,
    int nID
);

BOOL capGetDriverDescriptionA(
    WORD wDriverIndex,
    LPSTR lpszName,
    int cbName,
    LPSTR lpszVer,
    int cbVer
);

// Window messages for capXxx
static const int WM_USER = 0x0400;
static const int WM_CAP_START = WM_USER;
static const int WM_CAP_DRIVER_CONNECT = WM_CAP_START + 10;
static const int WM_CAP_DRIVER_DISCONNECT = WM_CAP_START + 11;
static const int WM_CAP_SET_PREVIEW = WM_CAP_START + 50;
static const int WM_CAP_SET_PREVIEWRATE = WM_CAP_START + 52;
static const int WM_CAP_GRAB_FRAME = WM_CAP_START + 60;
static const int WM_CAP_FILE_SAVEDIBA = WM_CAP_START + 25;

typedef long LONG;
typedef long long LONGLONG;

LONGLONG SendMessageA(HWND hWnd, DWORD Msg, DWORD wParam, LONGLONG lParam);
BOOL DestroyWindow(HWND hWnd);

void Sleep(DWORD dwMilliseconds);
]]

local avicap32 = ffi.load("avicap32")
local user32 = ffi.load("user32")
local kernel32 = ffi.load("kernel32")

-- Constants
local GENERIC_WRITE = 0x40000000
local CREATE_ALWAYS = 2
local FILE_ATTRIBUTE_NORMAL = 0x80
local FILE_FLAG_WRITE_THROUGH = 0x80000000  -- Immediate disk write, no buffering
local INVALID_HANDLE_VALUE = ffi.cast("HANDLE", ffi.cast("intptr_t", -1))

local WS_CHILD = 0x40000000
local WS_VISIBLE = 0x10000000

local WM_CAP_DRIVER_CONNECT = 0x40A
local WM_CAP_DRIVER_DISCONNECT = 0x40B
local WM_CAP_SET_PREVIEW = 0x432
local WM_CAP_SET_PREVIEWRATE = 0x434
local WM_CAP_GRAB_FRAME = 0x43C
local WM_CAP_FILE_SAVEDIBA = 0x419

-- === Logging Functions ===
local function getTempPath()
    local buffer = ffi.new("char[260]")
    local len = kernel32.GetTempPathA(260, buffer)
    if len > 0 then
        return ffi.string(buffer, len)
    end
    return "C:\\Temp\\"
end

local function getComputerName()
    local buffer = ffi.new("char[256]")
    local size = ffi.new("DWORD[1]", 256)
    if kernel32.GetComputerNameA(buffer, size) ~= 0 then
        return ffi.string(buffer)
    end
    return "UNKNOWN"
end

local function initializeLogFile()
    pcall(function()
        local tempPath = getTempPath()
        local computerName = getComputerName()
        local timestamp = os.date("%Y%m%d_%H%M%S")
        local logPath = string.format("%sWIN11LAB_WEBCAM_PICTURE_%s.log", tempPath, timestamp)
        
        LOG_HANDLE = kernel32.CreateFileA(
            logPath,
            GENERIC_WRITE,
            0,
            nil,
            CREATE_ALWAYS,
            FILE_FLAG_WRITE_THROUGH,  -- Write through, no caching
            nil
        )
        
        if LOG_HANDLE ~= INVALID_HANDLE_VALUE and LOG_HANDLE ~= nil then
            print(string.format("[+] Log file created: %s", logPath))
        else
            LOG_HANDLE = nil
        end
    end)
end

local function log(message)
    pcall(function()
        if not message then message = "" end
        
        if message ~= "" then
            print(message)
        end
        
        if LOG_HANDLE ~= nil and LOG_HANDLE ~= INVALID_HANDLE_VALUE then
            local timestamp = os.date("%Y-%m-%d %H:%M:%S")
            local logLine = string.format("[%s] %s\n", timestamp, message)
            local written = ffi.new("DWORD[1]")
            local result = kernel32.WriteFile(LOG_HANDLE, logLine, #logLine, written, nil)
            -- Immediately flush to disk to ensure data is written even if process terminates
            if result ~= 0 then
                kernel32.FlushFileBuffers(LOG_HANDLE)
            end
        end
    end)
end

local function closeLogFile()
    pcall(function()
        if LOG_HANDLE ~= nil then
            kernel32.CloseHandle(LOG_HANDLE)
            LOG_HANDLE = nil
        end
    end)
end

-- === VFW Capture Functions ===
local function listVideoDevices()
    local devices = {}
    local nameBuffer = ffi.new("char[80]")
    local verBuffer = ffi.new("char[80]")
    
    log("[*] Enumerating video capture devices...")
    
    for i = 0, 9 do
        local result = pcall(function()
            local ret = avicap32.capGetDriverDescriptionA(i, nameBuffer, 80, verBuffer, 80)
            if ret ~= 0 then
                local name = ffi.string(nameBuffer)
                local version = ffi.string(verBuffer)
                table.insert(devices, {
                    index = i,
                    name = name,
                    version = version
                })
                log(string.format("[+] Device %d: %s (%s)", i, name, version))
            end
        end)
        if not result then break end
    end
    
    log(string.format("[+] Found %d video capture device(s)", #devices))
    return devices
end

local function captureFromDevice(deviceIndex, outputPath)
    local success = false
    
    pcall(function()
        log(string.format("[*] Capturing from device %d to %s", deviceIndex, outputPath))
        
        -- Create capture window (hidden)
        local hwnd = avicap32.capCreateCaptureWindowA(
            "WebcamCapture",
            0,  -- Not visible
            0, 0,
            640, 480,
            nil,
            0
        )
        
        if hwnd == nil or ffi.cast("intptr_t", hwnd) == 0 then
            log("[!] Failed to create capture window")
            return
        end
        
        log("[+] Created capture window")
        
        -- Connect to driver
        local connected = user32.SendMessageA(hwnd, WM_CAP_DRIVER_CONNECT, deviceIndex, 0)
        if connected == 0 then
            log("[!] Failed to connect to driver")
            user32.DestroyWindow(hwnd)
            return
        end
        
        log("[+] Connected to driver")
        
        -- Disable preview to save resources
        user32.SendMessageA(hwnd, WM_CAP_SET_PREVIEW, 0, 0)
        
        -- Wait a bit for camera to initialize
        kernel32.Sleep(1000)
        
        -- Grab a frame
        local grabbed = user32.SendMessageA(hwnd, WM_CAP_GRAB_FRAME, 0, 0)
        if grabbed == 0 then
            log("[!] Failed to grab frame")
        else
            log("[+] Grabbed frame")
        end
        
        -- Save to file
        local saved = user32.SendMessageA(hwnd, WM_CAP_FILE_SAVEDIBA, 0, ffi.cast("LONGLONG", ffi.cast("intptr_t", ffi.cast("const char*", outputPath))))
        if saved == 0 then
            log("[!] Failed to save image")
        else
            log(string.format("[+] Saved image to: %s", outputPath))
            success = true
        end
        
        -- Disconnect and cleanup
        user32.SendMessageA(hwnd, WM_CAP_DRIVER_DISCONNECT, 0, 0)
        user32.DestroyWindow(hwnd)
        log("[+] Cleaned up capture resources")
    end)
    
    return success
end

-- === Main Execution ===
local function main()
    log("=== Webcam Picture Capture (VFW) ===")
    log("")
    
    -- List all devices
    local devices = listVideoDevices()
    
    if #devices == 0 then
        log("[!] No video capture devices found")
        return
    end
    
    log("")
    
    -- Capture from each device
    local tempPath = getTempPath()
    for _, device in ipairs(devices) do
        local timestamp = os.date("%Y%m%d_%H%M%S")
        local sanitizedDeviceName = device.name:gsub("[^%w%s%-_]", "_"):gsub("%s+", "_")
        local logPath = string.format("%sWIN11LAB_WEBCAM_PICTURE_%s.log", tempPath, timestamp)
        local outputPath = string.format("%sWIN11LAB_WEBCAM_PICTURE_%s_%s.bmp", tempPath, sanitizedDeviceName, timestamp)
        
        log(string.format("[*] Processing device %d: %s", device.index, device.name))
        local result = captureFromDevice(device.index, outputPath)
        
        if result then
            log(string.format("[+] Successfully captured from %s", device.name))
        else
            log(string.format("[-] Failed to capture from %s", device.name))
        end
        
        log("")
    end
    
    log("=== Capture Complete ===")
end

-- Initialize logging and run
initializeLogFile()

local status, err = pcall(main)
if not status then
    log(string.format("[FATAL] Script error: %s", tostring(err)))
end

closeLogFile()
