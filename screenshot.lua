-- screenshot.lua
-- Simple screenshot capture using Windows GDI API
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
]]

local gdi32 = ffi.load("gdi32")
local user32 = ffi.load("user32")

-- Compatibility for older Lua versions
local unpack = table.unpack or unpack

local SRCCOPY = 0x00CC0020
local HORZRES = 8
local VERTRES = 10
local DIB_RGB_COLORS = 0

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

local function logMsg(message)
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    print(timestamp .. " - " .. message)
end

-- Main screenshot capture function
local function captureScreenshot()
    local outputFile = getScreenshotFilePath()
    logMsg("Starting screenshot capture")

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
    logMsg("Screenshot saved to " .. outputFile)

    -- Cleanup
    gdi32.DeleteObject(hBitmap)
    gdi32.DeleteDC(memDC)
    user32.ReleaseDC(desktopWnd, desktopDC)
    logMsg("Resources cleaned up successfully")
end

-- Run the screenshot capture
captureScreenshot()
