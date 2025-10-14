-- microphone_capture.lua
-- Captures audio from the default microphone for 15 minutes and saves it as a .wav file
-- Logs operations to a log file in the %TEMP% directory

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
typedef void* LPVOID;
typedef const char* LPCSTR;

typedef struct {
    WORD wFormatTag;
    WORD nChannels;
    DWORD nSamplesPerSec;
    DWORD nAvgBytesPerSec;
    WORD nBlockAlign;
    WORD wBitsPerSample;
    WORD cbSize;
} WAVEFORMATEX;

typedef struct {
    LPVOID lpData;
    DWORD dwBufferLength;
    DWORD dwBytesRecorded;
    LPVOID dwUser;
    DWORD dwFlags;
    DWORD dwLoops;
    LPVOID lpNext;
    DWORD reserved;
} WAVEHDR;

HANDLE CreateFileA(LPCSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE);
BOOL WriteFile(HANDLE, LPCSTR, DWORD, DWORD*, LPVOID);
BOOL CloseHandle(HANDLE);
DWORD GetTempPathA(DWORD, char*);
DWORD GetComputerNameA(char*, DWORD*);

BOOL waveInOpen(HANDLE*, DWORD, WAVEFORMATEX*, LPVOID, DWORD, DWORD);
BOOL waveInPrepareHeader(HANDLE, WAVEHDR*, DWORD);
BOOL waveInAddBuffer(HANDLE, WAVEHDR*, DWORD);
BOOL waveInStart(HANDLE);
BOOL waveInStop(HANDLE);
BOOL waveInReset(HANDLE);
BOOL waveInUnprepareHeader(HANDLE, WAVEHDR*, DWORD);
BOOL waveInClose(HANDLE);

BOOL FlushFileBuffers(HANDLE hFile);

void Sleep(DWORD dwMilliseconds);
]]

local kernel32 = ffi.load("kernel32")
local winmm = ffi.load("winmm")

-- Constants
local GENERIC_WRITE = 0x40000000
local CREATE_ALWAYS = 2
local FILE_ATTRIBUTE_NORMAL = 0x80
local INVALID_HANDLE_VALUE = ffi.cast("HANDLE", ffi.cast("intptr_t", -1))

-- Logging functions
local LOG_HANDLE = nil

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
    local logPath = string.format("%sWIN11LAB_MICROPHONE_CAPTURE_%s.log", tempPath, timestamp)

    LOG_HANDLE = kernel32.CreateFileA(
        logPath,
        GENERIC_WRITE,
        0,
        nil,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nil
    )

    if LOG_HANDLE ~= INVALID_HANDLE_VALUE then
        print(string.format("[+] Log file created: %s", logPath))
    else
        LOG_HANDLE = nil
    end
end

local function log(message)
    if LOG_HANDLE ~= nil then
        local timestamp = os.date("%Y-%m-%d %H:%M:%S")
        local logLine = string.format("[%s] %s\n", timestamp, message)
        local written = ffi.new("DWORD[1]")
        kernel32.WriteFile(LOG_HANDLE, logLine, #logLine, written, nil)
        -- Immediately flush to disk to ensure data is written
        kernel32.FlushFileBuffers(LOG_HANDLE)
    end
    if message ~= "" then
        print(message)  -- Print to stdout
    end
end

local function closeLogFile()
    if LOG_HANDLE ~= nil then
        kernel32.CloseHandle(LOG_HANDLE)
        LOG_HANDLE = nil
    end
end

-- Audio capture function
local function captureAudio()
    local waveFormat = ffi.new("WAVEFORMATEX")
    waveFormat.wFormatTag = 1  -- PCM
    waveFormat.nChannels = 1  -- Mono
    waveFormat.nSamplesPerSec = 44100
    waveFormat.wBitsPerSample = 16
    waveFormat.nBlockAlign = (waveFormat.nChannels * waveFormat.wBitsPerSample) / 8
    waveFormat.nAvgBytesPerSec = waveFormat.nSamplesPerSec * waveFormat.nBlockAlign
    waveFormat.cbSize = 0

    local hWaveIn = ffi.new("HANDLE[1]")
    local result = winmm.waveInOpen(hWaveIn, 0xFFFFFFFF, waveFormat, nil, 0, 0)
    if result ~= 0 then
        log("[!] Failed to open audio device")
        return
    end

    log("[+] Audio device opened")

    -- Reduce recording duration to 2 minutes
    local bufferSize = waveFormat.nAvgBytesPerSec * 2 * 60  -- 2 minutes

    -- Log audio capture device details
    log("[*] Using default audio capture device")

    local buffer = ffi.new("BYTE[?]", bufferSize)
    local waveHeader = ffi.new("WAVEHDR")
    waveHeader.lpData = buffer
    waveHeader.dwBufferLength = bufferSize
    waveHeader.dwFlags = 0

    winmm.waveInPrepareHeader(hWaveIn[0], waveHeader, ffi.sizeof(waveHeader))
    winmm.waveInAddBuffer(hWaveIn[0], waveHeader, ffi.sizeof(waveHeader))
    winmm.waveInStart(hWaveIn[0])

    log("[*] Recording audio...")
    ffi.C.Sleep(2 * 60 * 1000)  -- Sleep for 2 minutes

    winmm.waveInStop(hWaveIn[0])
    winmm.waveInReset(hWaveIn[0])
    winmm.waveInUnprepareHeader(hWaveIn[0], waveHeader, ffi.sizeof(waveHeader))
    winmm.waveInClose(hWaveIn[0])

    log("[+] Audio capture complete")

    -- Save to file
    local tempPath = getTempPath()
    local timestamp = os.date("%Y%m%d_%H%M%S")
    local outputPath = string.format("%sWIN11LAB_MICROPHONE_CAPTURE_%s.wav", tempPath, timestamp)
    local fileHandle = kernel32.CreateFileA(
        outputPath,
        GENERIC_WRITE,
        0,
        nil,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nil
    )

    if fileHandle == INVALID_HANDLE_VALUE then
        log("[!] Failed to create output file")
        return
    end

    -- Write valid WAV file header
    local function writeWavHeader(fileHandle, dataSize)
        local header = ffi.new("BYTE[44]")
        ffi.copy(header, "RIFF")
        ffi.cast("DWORD*", header + 4)[0] = 36 + dataSize  -- File size - 8 bytes
        ffi.copy(header + 8, "WAVEfmt ")
        ffi.cast("DWORD*", header + 16)[0] = 16  -- Subchunk1 size
        ffi.cast("WORD*", header + 20)[0] = 1  -- Audio format (PCM)
        ffi.cast("WORD*", header + 22)[0] = waveFormat.nChannels
        ffi.cast("DWORD*", header + 24)[0] = waveFormat.nSamplesPerSec
        ffi.cast("DWORD*", header + 28)[0] = waveFormat.nAvgBytesPerSec
        ffi.cast("WORD*", header + 32)[0] = waveFormat.nBlockAlign
        ffi.cast("WORD*", header + 34)[0] = waveFormat.wBitsPerSample
        ffi.copy(header + 36, "data")
        ffi.cast("DWORD*", header + 40)[0] = dataSize

        kernel32.WriteFile(fileHandle, header, 44, nil, nil)
    end

    -- Write WAV header before audio data
    writeWavHeader(fileHandle, bufferSize)

    kernel32.WriteFile(fileHandle, buffer, bufferSize, nil, nil)
    kernel32.CloseHandle(fileHandle)

    log(string.format("[+] Audio saved to: %s", outputPath))
end

-- Main execution
initializeLogFile()
log("=== Microphone Capture ===")

local status, err = pcall(captureAudio)
if not status then
    log(string.format("[FATAL] Script error: %s", tostring(err)))
end

closeLogFile()