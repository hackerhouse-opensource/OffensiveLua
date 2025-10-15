-- screenshot_withhiddenwindows.lua
-- Desktop screenshot + individual window capture (attempts to capture all visible windows)
-- Note: Non-foreground/hidden windows may appear black due to GDI limitations
-- Disable JIT for thread safety
jit.off()

local ffi = require("ffi")
local bit = require("bit")

-- Windows API definitions
ffi.cdef[[
    typedef void* HWND;
    typedef void* HDC;
    typedef void* HGDIOBJ;
    typedef void* HBITMAP;
    typedef unsigned long DWORD;
    typedef int BOOL;
    typedef long LONG;
    typedef unsigned short WORD;
    typedef unsigned int UINT;
    typedef BOOL (*WNDENUMPROC)(HWND, long);

    typedef struct {
        WORD  bfType;
        DWORD bfSize;
        WORD  bfReserved1;
        WORD  bfReserved2;
        DWORD bfOffBits;
    } BITMAPFILEHEADER;

    typedef struct {
        DWORD biSize;
        LONG  biWidth;
        LONG  biHeight;
        WORD  biPlanes;
        WORD  biBitCount;
        DWORD biCompression;
        DWORD biSizeImage;
        LONG  biXPelsPerMeter;
        LONG  biYPelsPerMeter;
        DWORD biClrUsed;
        DWORD biClrImportant;
    } BITMAPINFOHEADER;

    typedef struct {
        BITMAPINFOHEADER bmiHeader;
        DWORD bmiColors[3];
    } BITMAPINFO;

    HWND GetDesktopWindow();
    HWND GetForegroundWindow();
    HDC GetDC(HWND hWnd);
    int ReleaseDC(HWND hWnd, HDC hDC);
    HDC CreateCompatibleDC(HDC hdc);
    int DeleteDC(HDC hdc);
    HBITMAP CreateCompatibleBitmap(HDC hdc, int cx, int cy);
    HGDIOBJ SelectObject(HDC hdc, HGDIOBJ h);
    BOOL DeleteObject(HGDIOBJ ho);
    BOOL BitBlt(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop);
    int GetDIBits(HDC hdc, HBITMAP hbm, UINT start, UINT cLines, void *lpvBits, BITMAPINFO *lpbmi, UINT usage);
    int GetDeviceCaps(HDC hdc, int index);
    BOOL EnumWindows(WNDENUMPROC lpEnumFunc, long lParam);
    int GetWindowTextA(HWND hWnd, char* lpString, int nMaxCount);
    BOOL IsWindowVisible(HWND hWnd);
    int GetWindowTextLengthA(HWND hWnd);
    DWORD GetWindowThreadProcessId(HWND hWnd, DWORD* lpdwProcessId);
    BOOL GetWindowRect(HWND hWnd, void* lpRect);
    BOOL PrintWindow(HWND hWnd, HDC hdcBlt, UINT nFlags);
    BOOL GetClientRect(HWND hWnd, void* lpRect);
    HDC GetWindowDC(HWND hWnd);
    BOOL ClientToScreen(HWND hWnd, void* lpPoint);
]]

local gdi32 = ffi.load("gdi32")
local user32 = ffi.load("user32")

-- Compatibility for older Lua versions
local unpack = table.unpack or unpack

-- Constants
local SRCCOPY = 0x00CC0020
local HORZRES = 8
local VERTRES = 10
local DIB_RGB_COLORS = 0
local PW_CLIENTONLY = 0x00000001

-- Helper functions
local function getTempPath()
    return os.getenv("TEMP") or os.getenv("TMP") or "C:\\Windows\\Temp"
end

local function getComputerName()
    return os.getenv("COMPUTERNAME") or "UNKNOWN"
end

local function getFormattedTimestamp()
    return os.date("%Y%m%d_%H%M%S")
end

local function getScreenshotFilePath()
    return getTempPath() .. "\\" .. getComputerName() .. "_SCREENSHOT_" .. getFormattedTimestamp() .. ".bmp"
end

local function getLogFilePath()
    return getTempPath() .. "\\" .. getComputerName() .. "_SCREENSHOT_" .. getFormattedTimestamp() .. ".log"
end

-- Log message to both file and stdout
local logFile = nil
local function logMsg(message)
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local logMessage = timestamp .. " - " .. message
    
    -- Write to stdout
    print(logMessage)
    
    -- Write to log file
    if logFile then
        logFile:write(logMessage .. "\n")
        logFile:flush()  -- Ensure immediate write
    end
end

-- Enumerate all visible windows
local windowList = {}
local function enumWindowsCallback(hwnd, lParam)
    if user32.IsWindowVisible(hwnd) ~= 0 then
        local length = user32.GetWindowTextLengthA(hwnd)
        if length > 0 then
            local buffer = ffi.new("char[?]", length + 1)
            user32.GetWindowTextA(hwnd, buffer, length + 1)
            local title = ffi.string(buffer)
            
            if title and title ~= "" then
                local pidBuffer = ffi.new("DWORD[1]")
                user32.GetWindowThreadProcessId(hwnd, pidBuffer)
                local pid = pidBuffer[0]
                
                table.insert(windowList, {
                    hwnd = tostring(hwnd),
                    title = title,
                    pid = pid
                })
            end
        end
    end
    return 1  -- Continue enumeration
end

local function enumerateWindows()
    windowList = {}
    local callback = ffi.cast("WNDENUMPROC", enumWindowsCallback)
    user32.EnumWindows(callback, 0)
    callback:free()
    return windowList
end

-- Function to sanitize filename (remove invalid characters)
local function sanitizeFilename(filename)
    -- Remove or replace invalid filename characters
    local sanitized = filename:gsub('[<>:"/\\|?*]', '_')
    sanitized = sanitized:gsub('%s+', '_')  -- Replace spaces with underscores
    -- Limit length to avoid path issues
    if #sanitized > 100 then
        sanitized = sanitized:sub(1, 100)
    end
    return sanitized
end

-- Function to capture a single window to BMP file
local function captureWindow(hwnd, pid, title, timestamp)
    -- Get window dimensions (full window including frame)
    local rect = ffi.new("struct { long left; long top; long right; long bottom; }")
    if user32.GetWindowRect(hwnd, rect) == 0 then
        logMsg("  WARNING: Failed to get window rect for: " .. title)
        return false
    end
    
    local width = rect.right - rect.left
    local height = rect.bottom - rect.top
    
    -- Skip windows that are too small or too large (likely hidden, minimized, or invalid)
    if width <= 10 or height <= 10 or width > 10000 or height > 10000 then
        logMsg("  SKIP: Invalid dimensions " .. width .. "x" .. height .. " for: " .. title)
        return false
    end
    
    -- Get the window DC (includes the entire window, not just client area)
    local windowDC = user32.GetWindowDC(hwnd)
    if windowDC == nil then
        logMsg("  WARNING: Failed to get window DC for: " .. title)
        return false
    end
    
    -- Create compatible DC and bitmap
    local memDC = gdi32.CreateCompatibleDC(windowDC)
    if memDC == nil then
        logMsg("  WARNING: Failed to create compatible DC for: " .. title)
        user32.ReleaseDC(hwnd, windowDC)
        return false
    end
    
    local hBitmap = gdi32.CreateCompatibleBitmap(windowDC, width, height)
    if hBitmap == nil then
        logMsg("  WARNING: Failed to create compatible bitmap for: " .. title)
        gdi32.DeleteDC(memDC)
        user32.ReleaseDC(hwnd, windowDC)
        return false
    end
    
    gdi32.SelectObject(memDC, hBitmap)
    
    -- Use BitBlt to copy the entire window (including frame and decorations)
    -- Source coordinates are 0,0 because GetWindowDC gives us DC for the whole window
    local result = gdi32.BitBlt(memDC, 0, 0, width, height, windowDC, 0, 0, SRCCOPY)
    if result == 0 then
        logMsg("  WARNING: BitBlt failed for window: " .. title)
        gdi32.DeleteObject(hBitmap)
        gdi32.DeleteDC(memDC)
        user32.ReleaseDC(hwnd, windowDC)
        return false
    end
    
    -- Setup BITMAPINFO
    local bmi = ffi.new("BITMAPINFO")
    bmi.bmiHeader.biSize = ffi.sizeof("BITMAPINFOHEADER")
    bmi.bmiHeader.biWidth = width
    bmi.bmiHeader.biHeight = height
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bmi.bmiHeader.biCompression = 0
    bmi.bmiHeader.biSizeImage = 0
    
    -- Calculate image size
    local bytesPerPixel = 4
    local rowSize = width * bytesPerPixel
    if rowSize % 4 ~= 0 then
        rowSize = rowSize + (4 - (rowSize % 4))
    end
    local imageSize = rowSize * height
    local bitmapData = ffi.new("uint8_t[?]", imageSize)
    
    -- Get bitmap bits
    result = gdi32.GetDIBits(memDC, hBitmap, 0, height, bitmapData, bmi, DIB_RGB_COLORS)
    if result == 0 then
        logMsg("  WARNING: GetDIBits failed for: " .. title)
        gdi32.DeleteObject(hBitmap)
        gdi32.DeleteDC(memDC)
        user32.ReleaseDC(hwnd, windowDC)
        return false
    end
    
    -- Create filename: COMPUTERNAME_SCREENSHOT_PID_PROCESSNAME_TIMESTAMP.bmp
    local sanitizedTitle = sanitizeFilename(title)
    local filename = getTempPath() .. "\\" .. getComputerName() .. "_SCREENSHOT_" .. 
                     pid .. "_" .. sanitizedTitle .. "_" .. timestamp .. ".bmp"
    
    -- Manually construct BMP file header
    local fileHeaderSize = 14
    local infoHeaderSize = ffi.sizeof("BITMAPINFOHEADER")
    local fileSize = fileHeaderSize + infoHeaderSize + imageSize
    local dataOffset = fileHeaderSize + infoHeaderSize
    
    local fileHeaderBytes = {
        0x42, 0x4D,
        bit.band(fileSize, 0xFF),
        bit.band(bit.rshift(fileSize, 8), 0xFF),
        bit.band(bit.rshift(fileSize, 16), 0xFF),
        bit.band(bit.rshift(fileSize, 24), 0xFF),
        0x00, 0x00,
        0x00, 0x00,
        bit.band(dataOffset, 0xFF),
        bit.band(bit.rshift(dataOffset, 8), 0xFF),
        bit.band(bit.rshift(dataOffset, 16), 0xFF),
        bit.band(bit.rshift(dataOffset, 24), 0xFF)
    }
    local fileHeader = string.char(unpack(fileHeaderBytes))
    
    -- Write BMP file
    local file = io.open(filename, "wb")
    if not file then
        logMsg("  WARNING: Failed to create file: " .. filename)
        gdi32.DeleteObject(hBitmap)
        gdi32.DeleteDC(memDC)
        user32.ReleaseDC(hwnd, windowDC)
        return false
    end
    
    file:write(fileHeader)
    file:write(ffi.string(bmi.bmiHeader, ffi.sizeof("BITMAPINFOHEADER")))
    file:write(ffi.string(bitmapData, imageSize))
    file:close()
    
    -- Cleanup
    gdi32.DeleteObject(hBitmap)
    gdi32.DeleteDC(memDC)
    user32.ReleaseDC(hwnd, windowDC)
    
    logMsg("  CAPTURED: " .. filename .. " (" .. width .. "x" .. height .. ")")
    return true
end

-- Main screenshot capture function
local function captureScreenshot()
    local outputFile = getScreenshotFilePath()
    local logFilePath = getLogFilePath()
    
    -- Open log file
    logFile = io.open(logFilePath, "w")
    if not logFile then
        print("ERROR: Failed to open log file: " .. logFilePath)
        return
    end
    
    logMsg("Starting screenshot capture")
    logMsg("Output file: " .. outputFile)
    logMsg("Log file: " .. logFilePath)
    
    -- Enumerate and log visible windows
    logMsg("=== Enumerating Visible Windows ===")
    local windows = enumerateWindows()
    logMsg("Found " .. #windows .. " visible windows")
    
    -- Get foreground window
    local fgWnd = user32.GetForegroundWindow()
    local fgTitle = ""
    if fgWnd ~= nil then
        local length = user32.GetWindowTextLengthA(fgWnd)
        if length > 0 then
            local buffer = ffi.new("char[?]", length + 1)
            user32.GetWindowTextA(fgWnd, buffer, length + 1)
            fgTitle = ffi.string(buffer)
        end
    end
    logMsg("Foreground Window: " .. (fgTitle ~= "" and fgTitle or "(None)"))
    logMsg("")
    
    -- Log all windows
    for i, win in ipairs(windows) do
        local isForeground = (win.title == fgTitle) and " [FOREGROUND]" or ""
        logMsg(string.format("  [%d] PID:%d HWND:%s%s", i, win.pid, win.hwnd, isForeground))
        logMsg("      Title: " .. win.title)
    end
    logMsg("=== End Window Enumeration ===")
    logMsg("")
    
    -- Capture individual window screenshots
    logMsg("=== Capturing Individual Window Screenshots ===")
    local capturedCount = 0
    local timestamp = getFormattedTimestamp()
    
    for i, win in ipairs(windows) do
        logMsg("Capturing window [" .. i .. "]: " .. win.title)
        -- Convert HWND string back to pointer
        local hwndPtr = ffi.cast("HWND", tonumber(win.hwnd:match("0x%x+")))
        if captureWindow(hwndPtr, win.pid, win.title, timestamp) then
            capturedCount = capturedCount + 1
        end
    end
    
    logMsg("=== Window Screenshots Complete: " .. capturedCount .. "/" .. #windows .. " captured ===")
    logMsg("")

    -- Get desktop window and DC
    local desktopWnd = user32.GetDesktopWindow()
    local desktopDC = user32.GetDC(desktopWnd)
    if desktopDC == nil then
        logMsg("ERROR: Failed to get desktop DC")
        return
    end

    -- Get screen dimensions
    local screenWidth = gdi32.GetDeviceCaps(desktopDC, HORZRES)
    local screenHeight = gdi32.GetDeviceCaps(desktopDC, VERTRES)
    logMsg("Screen dimensions: " .. screenWidth .. "x" .. screenHeight)

    -- Create compatible DC and bitmap
    local memDC = gdi32.CreateCompatibleDC(desktopDC)
    local hBitmap = gdi32.CreateCompatibleBitmap(desktopDC, screenWidth, screenHeight)
    gdi32.SelectObject(memDC, hBitmap)

    -- Copy screen to bitmap
    if gdi32.BitBlt(memDC, 0, 0, screenWidth, screenHeight, desktopDC, 0, 0, SRCCOPY) == 0 then
        logMsg("ERROR: BitBlt failed")
        gdi32.DeleteObject(hBitmap)
        gdi32.DeleteDC(memDC)
        user32.ReleaseDC(desktopWnd, desktopDC)
        return
    end
    logMsg("Screen captured to bitmap")

    -- Setup BITMAPINFO structure for GetDIBits
    -- First call to get the actual bitmap info
    local bmi = ffi.new("BITMAPINFO")
    bmi.bmiHeader.biSize = ffi.sizeof("BITMAPINFOHEADER")
    bmi.bmiHeader.biWidth = screenWidth
    bmi.bmiHeader.biHeight = screenHeight  -- POSITIVE for bottom-up DIB (standard BMP format)
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bmi.bmiHeader.biCompression = 0  -- BI_RGB
    bmi.bmiHeader.biSizeImage = 0

    -- Calculate image size: For 32-bit BMP, each row is width * 4 bytes
    -- Rows must be aligned to 4-byte boundary (DWORD aligned)
    local bytesPerPixel = 4  -- 32 bits = 4 bytes
    local rowSize = screenWidth * bytesPerPixel
    -- Align to 4-byte boundary
    if rowSize % 4 ~= 0 then
        rowSize = rowSize + (4 - (rowSize % 4))
    end
    local imageSize = rowSize * screenHeight
    
    logMsg("Calculated row size: " .. rowSize .. ", image size: " .. imageSize)
    
    local bitmapData = ffi.new("uint8_t[?]", imageSize)

    -- Get bitmap bits
    local result = gdi32.GetDIBits(memDC, hBitmap, 0, screenHeight, bitmapData, bmi, DIB_RGB_COLORS)
    if result == 0 then
        logMsg("ERROR: GetDIBits failed")
        gdi32.DeleteObject(hBitmap)
        gdi32.DeleteDC(memDC)
        user32.ReleaseDC(desktopWnd, desktopDC)
        return
    end
    logMsg("Bitmap data retrieved: " .. imageSize .. " bytes")

    -- Manually construct BMP file header (14 bytes, packed with #pragma pack(2))
    -- BITMAPFILEHEADER must be packed to 2-byte alignment
    local fileHeaderSize = 14
    local infoHeaderSize = ffi.sizeof("BITMAPINFOHEADER")
    local fileSize = fileHeaderSize + infoHeaderSize + imageSize
    local dataOffset = fileHeaderSize + infoHeaderSize
    
    -- Manually pack BITMAPFILEHEADER (14 bytes total)
    local fileHeaderBytes = {
        0x42, 0x4D,                                          -- bfType ('BM') - 2 bytes
        bit.band(fileSize, 0xFF),                            -- bfSize - 4 bytes (little endian)
        bit.band(bit.rshift(fileSize, 8), 0xFF),
        bit.band(bit.rshift(fileSize, 16), 0xFF),
        bit.band(bit.rshift(fileSize, 24), 0xFF),
        0x00, 0x00,                                          -- bfReserved1 - 2 bytes
        0x00, 0x00,                                          -- bfReserved2 - 2 bytes
        bit.band(dataOffset, 0xFF),                          -- bfOffBits - 4 bytes (little endian)
        bit.band(bit.rshift(dataOffset, 8), 0xFF),
        bit.band(bit.rshift(dataOffset, 16), 0xFF),
        bit.band(bit.rshift(dataOffset, 24), 0xFF)
    }
    local fileHeader = string.char(unpack(fileHeaderBytes))

    -- Write BMP file
    local file = io.open(outputFile, "wb")
    if not file then
        logMsg("ERROR: Failed to open file for writing: " .. outputFile)
        gdi32.DeleteObject(hBitmap)
        gdi32.DeleteDC(memDC)
        user32.ReleaseDC(desktopWnd, desktopDC)
        return
    end

    -- Write headers and data
    file:write(fileHeader)
    file:write(ffi.string(bmi.bmiHeader, ffi.sizeof("BITMAPINFOHEADER")))
    file:write(ffi.string(bitmapData, imageSize))
    file:close()

    logMsg("BMP Header: Type=BM, Size=" .. fileSize .. ", OffBits=" .. dataOffset)
    logMsg("BMP Info: Width=" .. bmi.bmiHeader.biWidth .. 
           ", Height=" .. bmi.bmiHeader.biHeight .. 
           ", BitCount=" .. bmi.bmiHeader.biBitCount ..
           ", SizeImage=" .. bmi.bmiHeader.biSizeImage)
    logMsg("Desktop screenshot saved to " .. outputFile)

    -- Cleanup
    gdi32.DeleteObject(hBitmap)
    gdi32.DeleteDC(memDC)
    user32.ReleaseDC(desktopWnd, desktopDC)
    logMsg("Resources cleaned up successfully")
    logMsg("")
    logMsg("=== CAPTURE SESSION COMPLETE ===")
    logMsg("Total windows captured: " .. capturedCount)
    logMsg("Desktop screenshot: " .. outputFile)
    
    -- Close log file
    if logFile then
        logFile:close()
    end
end

-- Run the screenshot capture
captureScreenshot()
