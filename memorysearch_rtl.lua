-- memorysearch_rtl.lua
-- Rtl-backed memory searcher that safely scans the current process for ASCII and UTF-16LE strings.
-- Uses NtReadVirtualMemory and Rtl error translation to avoid hard faults when pages are inaccessible.

local ffi = require("ffi")
local bit = require("bit")

ffi.cdef[[
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef long NTSTATUS;
typedef unsigned long ULONG_PTR;
typedef ULONG_PTR SIZE_T;
typedef void* HANDLE;
typedef void* PVOID;

typedef struct {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION;

HANDLE GetCurrentProcess(void);
DWORD GetCurrentProcessId(void);
DWORD GetCurrentThreadId(void);
DWORD GetModuleFileNameA(HANDLE hModule, char* lpFilename, DWORD nSize);
DWORD GetCurrentDirectoryA(DWORD nBufferLength, char* lpBuffer);
SIZE_T VirtualQuery(PVOID lpAddress, MEMORY_BASIC_INFORMATION* lpBuffer, SIZE_T dwLength);

NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, SIZE_T* NumberOfBytesRead);
ULONG RtlNtStatusToDosError(NTSTATUS Status);
void RtlSetLastWin32ErrorAndNtStatusFromNtStatus(NTSTATUS Status);
]]

local kernel32 = ffi.load("kernel32")
local ntdll = ffi.load("ntdll")

-- === Configuration ===
local SEARCH_STRING = "password"       -- change as needed
local LOG_PATH = "c:/temp/memoryexploit.log"

local CHUNK_SIZE = 0x8000               -- 32 KB read window per chunk
local ADDRESS_LIMIT = 0x7FFF0000        -- user-mode ceiling for 32-bit
local CONTEXT_BEFORE = 96               -- bytes (or UTF-16 pairs) before match
local CONTEXT_AFTER = 96                -- bytes (or UTF-16 pairs) after match

-- === Constants ===
local MEM_COMMIT = 0x1000
local PAGE_NOACCESS = 0x01
local PAGE_GUARD = 0x100
local PAGE_READONLY = 0x02
local PAGE_READWRITE = 0x04
local PAGE_EXECUTE_READ = 0x20
local PAGE_EXECUTE_READWRITE = 0x40
local PAGE_WRITECOPY = 0x08
local PAGE_EXECUTE_WRITECOPY = 0x80

local STATUS_SUCCESS = 0x00000000
local STATUS_PARTIAL_COPY = 0x8000000D
local STATUS_ACCESS_VIOLATION = 0xC0000005

-- === Utility helpers ===
local function statusToString(status)
    if status == STATUS_SUCCESS then return "STATUS_SUCCESS" end
    if status == STATUS_PARTIAL_COPY then return "STATUS_PARTIAL_COPY" end
    if status == STATUS_ACCESS_VIOLATION then return "STATUS_ACCESS_VIOLATION" end
    return string.format("0x%08X", status)
end

local function writeLog(logFile, message)
    logFile:write(message)
    logFile:flush()
end

local function toUnicodeLE(str)
    local bytes = {}
    for i = 1, #str do
        local c = str:byte(i)
        bytes[#bytes + 1] = string.char(c, 0)
    end
    return table.concat(bytes)
end

local function isReadableProtection(protect)
    if protect == 0 then return false end
    if bit.band(protect, PAGE_NOACCESS) ~= 0 then return false end
    if bit.band(protect, PAGE_GUARD) ~= 0 then return false end
    local readableMask = bit.bor(PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_WRITECOPY)
    return bit.band(protect, readableMask) ~= 0
end

local function safeNtRead(processHandle, address, size)
    local buffer = ffi.new("uint8_t[?]", size)
    local bytesOut = ffi.new("SIZE_T[1]", 0)
    local status = ntdll.NtReadVirtualMemory(processHandle, ffi.cast("PVOID", address), buffer, size, bytesOut)
    local read = tonumber(bytesOut[0]) or 0
    if status ~= STATUS_SUCCESS and status ~= STATUS_PARTIAL_COPY then
        return nil, status, read
    end
    return ffi.string(buffer, read), status, read
end

local function hexdump(data, baseAddr, highlightOffset, highlightLen)
    local lines = {}
    local total = #data
    for lineOffset = 0, total - 1, 16 do
        local addr = baseAddr + lineOffset
        local hexParts, asciiParts = {}, {}
        for i = 0, 15 do
            local idx = lineOffset + i
            if idx < total then
                local byte = data:byte(idx + 1)
                local inMatch = idx >= highlightOffset and idx < highlightOffset + highlightLen
                if inMatch then
                    hexParts[#hexParts + 1] = string.format("[%02X]", byte)
                    local ch = (byte >= 32 and byte <= 126) and string.char(byte) or "."
                    asciiParts[#asciiParts + 1] = "[" .. ch .. "]"
                else
                    hexParts[#hexParts + 1] = string.format(" %02X ", byte)
                    asciiParts[#asciiParts + 1] = (byte >= 32 and byte <= 126) and string.char(byte) or "."
                end
            else
                hexParts[#hexParts + 1] = "    "
                asciiParts[#asciiParts + 1] = " "
            end
        end
        lines[#lines + 1] = string.format("%08X: %s | %s", addr, table.concat(hexParts, ""), table.concat(asciiParts, ""))
    end
    return table.concat(lines, "\n")
end

local function makeContext(processHandle, regionBase, regionEnd, matchAddr, matchLenBytes, isUnicode)
    local step = isUnicode and 2 or 1
    local beforeLimit = CONTEXT_BEFORE * step
    local afterLimit = CONTEXT_AFTER * step

    local startAddr = matchAddr - beforeLimit
    if startAddr < regionBase then startAddr = regionBase end

    local endAddr = matchAddr + matchLenBytes + afterLimit
    if endAddr > regionEnd then endAddr = regionEnd end

    if endAddr <= startAddr then
        return nil
    end

    local size = endAddr - startAddr
    local data, status = safeNtRead(processHandle, startAddr, size)
    if not data or #data == 0 then
        return nil, status
    end

    local matchOffset = matchAddr - startAddr
    local matchStartIdx = matchOffset + 1
    local matchEndIdx = matchStartIdx + matchLenBytes - 1

    local contextStartIdx = matchStartIdx
    local consumed = 0
    while contextStartIdx > step do
        local nextIdx = contextStartIdx - step
        if isUnicode then
            local b1 = data:byte(nextIdx)
            local b2 = data:byte(nextIdx + 1)
            if not b1 or not b2 or (b1 == 0 and b2 == 0) then break end
        else
            local b = data:byte(nextIdx)
            if not b or b == 0 then break end
        end
        consumed = consumed + step
        if consumed >= beforeLimit then break end
        contextStartIdx = nextIdx
    end

    local contextEndIdx = matchEndIdx
    consumed = 0
    while contextEndIdx + step <= #data do
        local nextIdx = contextEndIdx + step
        if isUnicode then
            local b1 = data:byte(nextIdx)
            local b2 = data:byte(nextIdx + 1)
            if not b1 or not b2 or (b1 == 0 and b2 == 0) then break end
        else
            local b = data:byte(nextIdx)
            if not b or b == 0 then break end
        end
        consumed = consumed + step
        if consumed >= afterLimit then break end
        contextEndIdx = nextIdx
    end

    local window = data:sub(contextStartIdx, contextEndIdx)
    local highlightOffset = matchStartIdx - contextStartIdx
    return {
        base = startAddr + (contextStartIdx - 1),
        data = window,
        highlightOffset = highlightOffset - 1,
        highlightLen = matchLenBytes
    }
end

local function logMatch(logFile, label, idx, address, contextInfo, isUnicode)
    writeLog(logFile, string.format("\n[%s MATCH %d]\n", label, idx))
    writeLog(logFile, string.format("Address: 0x%08X\n", address))
    writeLog(logFile, string.format("Encoding: %s\n", isUnicode and "UTF-16LE" or "ASCII"))
    if contextInfo then
        writeLog(logFile, "Context Hexdump:\n")
        writeLog(logFile, hexdump(contextInfo.data, contextInfo.base, contextInfo.highlightOffset, contextInfo.highlightLen))
        writeLog(logFile, "\n")
    else
        writeLog(logFile, "Context unavailable (access denied)\n")
    end
end

local function scanRegion(processHandle, logFile, baseAddr, regionSize, searchers)
    local regionEnd = baseAddr + regionSize
    local offset = 0

    while offset < regionSize do
        local toRead = math.min(CHUNK_SIZE, regionSize - offset)
        local readAddr = baseAddr + offset
        local chunk, status = safeNtRead(processHandle, readAddr, toRead)

        if chunk and #chunk > 0 then
            for _, search in ipairs(searchers) do
                local tail = search.tail
                local combined = tail .. chunk
                local tailLen = #tail
                local patternLen = search.patternLen

                if patternLen > 0 and #combined >= patternLen then
                    local searchStart = math.max(1, tailLen - patternLen + 1)
                    local pos = searchStart
                    while true do
                        local found = string.find(combined, search.pattern, pos, true)
                        if not found then break end
                        local foundEnd = found + patternLen - 1
                        if foundEnd > tailLen then
                            local combinedZero = found - 1
                            local absoluteAddr = readAddr - tailLen + combinedZero
                            local context = makeContext(processHandle, baseAddr, regionEnd, absoluteAddr, patternLen, search.isUnicode)
                            search.count = search.count + 1
                            logMatch(logFile, search.label, search.count, absoluteAddr, context, search.isUnicode)
                        end
                        pos = found + search.step
                    end
                end

                local maxTail = math.min(#combined, search.tailSize)
                search.tail = combined:sub(#combined - maxTail + 1)
            end
        elseif status and status ~= STATUS_PARTIAL_COPY then
            local winErr = ntdll.RtlNtStatusToDosError(status)
            writeLog(logFile, string.format("Read failed at 0x%08X (status=%s, win32=%d)\n", readAddr, statusToString(status), tonumber(winErr)))
        end

        offset = offset + toRead
    end
end

local function main()
    local logFile, err = io.open(LOG_PATH, "w")
    if not logFile then
        error("Unable to open log file: " .. tostring(err))
    end

    writeLog(logFile, "=== Rtl-backed Memory Search ===\n")
    writeLog(logFile, string.format("Search term: '%s'\n", SEARCH_STRING))
    writeLog(logFile, string.format("PID: %d TID: %d\n", kernel32.GetCurrentProcessId(), kernel32.GetCurrentThreadId()))

    local exeBuf = ffi.new("char[260]")
    if kernel32.GetModuleFileNameA(nil, exeBuf, 260) > 0 then
        writeLog(logFile, string.format("Executable: %s\n", ffi.string(exeBuf)))
    end

    local cwdBuf = ffi.new("char[260]")
    if kernel32.GetCurrentDirectoryA(260, cwdBuf) > 0 then
        writeLog(logFile, string.format("CWD: %s\n", ffi.string(cwdBuf)))
    end

    local searchers = {
        {
            label = "ASCII",
            pattern = SEARCH_STRING,
            patternLen = #SEARCH_STRING,
            step = 1,
            isUnicode = false,
            tail = "",
            tailSize = math.max(64, #SEARCH_STRING * 2),
            count = 0,
        },
        {
            label = "UTF16",
            pattern = toUnicodeLE(SEARCH_STRING),
            patternLen = #SEARCH_STRING * 2,
            step = 2,
            isUnicode = true,
            tail = "",
            tailSize = math.max(128, #SEARCH_STRING * 4),
            count = 0,
        }
    }

    local processHandle = kernel32.GetCurrentProcess()
    local address = 0
    local regions = 0
    local readableRegions = 0

    while address < ADDRESS_LIMIT do
        local mbi = ffi.new("MEMORY_BASIC_INFORMATION")
        local result = kernel32.VirtualQuery(ffi.cast("PVOID", address), mbi, ffi.sizeof(mbi))
        if result == 0 then
            break
        end

        local baseAddr = tonumber(ffi.cast("ULONG_PTR", mbi.BaseAddress))
        local regionSize = tonumber(mbi.RegionSize)
        local state = tonumber(mbi.State)
        local protect = tonumber(mbi.Protect)

        regions = regions + 1
        writeLog(logFile, string.format("\n[REGION %d] 0x%08X - 0x%08X size=%d KB protect=0x%03X state=0x%03X\n",
            regions, baseAddr, baseAddr + regionSize, math.floor(regionSize / 1024), protect or 0, state or 0))

        if regionSize == 0 then
            address = baseAddr + 0x1000
        else
            if state == MEM_COMMIT and isReadableProtection(protect) then
                readableRegions = readableRegions + 1
                scanRegion(processHandle, logFile, baseAddr, regionSize, searchers)
            else
                writeLog(logFile, "  Skipped (not committed/readable)\n")
            end
            address = baseAddr + regionSize
        end
    end

    writeLog(logFile, "\n=== SUMMARY ===\n")
    writeLog(logFile, string.format("Regions inspected: %d\n", regions))
    writeLog(logFile, string.format("Readable regions: %d\n", readableRegions))
    for _, search in ipairs(searchers) do
        writeLog(logFile, string.format("%s matches: %d\n", search.label, search.count))
    end

    logFile:close()
    print(string.format("Scan complete. %d regions inspected, results logged to %s", regions, LOG_PATH))
end

local ok, err = pcall(main)
if not ok then
    local fallback = io.open(LOG_PATH, "w")
    if fallback then
        fallback:write("Scanner failed: " .. tostring(err) .. "\n")
        fallback:close()
    end
    error(err)
end
