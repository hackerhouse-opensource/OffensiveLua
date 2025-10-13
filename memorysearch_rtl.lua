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
typedef uintptr_t SIZE_T;
typedef void* HANDLE;
typedef void* PVOID;
typedef int BOOL;
typedef long LONG;
typedef int64_t LONGLONG;
typedef uint64_t ULONGLONG;
typedef char* LPSTR;
typedef DWORD* PDWORD;

/* Struct for native 32-bit processes */
typedef struct {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

/* Struct for 32-bit process querying a 64-bit process (WoW64) */
typedef struct {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    DWORD RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION32, *PMEMORY_BASIC_INFORMATION32;

typedef struct {
    DWORD LowPart;
    LONG HighPart;
} LUID;

typedef struct {
    LUID Luid;
    DWORD Attributes;
} LUID_AND_ATTRIBUTES;

typedef struct {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
} TOKEN_PRIVILEGES;

BOOL QueryFullProcessImageNameA(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize);

HANDLE GetCurrentProcess(void);
DWORD GetCurrentProcessId(void);
SIZE_T VirtualQueryEx(HANDLE hProcess, PVOID lpAddress, PVOID lpBuffer, SIZE_T dwLength);
DWORD GetLastError(void);
BOOL CloseHandle(HANDLE hObject);
BOOL IsWow64Process(HANDLE hProcess, BOOL* Wow64Process);
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
BOOL ReadProcessMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, SIZE_T* NumberOfBytesRead);
ULONG RtlNtStatusToDosError(NTSTATUS Status);
void RtlSetLastWin32ErrorAndNtStatusFromNtStatus(NTSTATUS Status);
BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, HANDLE* TokenHandle);
BOOL LookupPrivilegeValueA(const char* lpSystemName, const char* lpName, LUID* lpLuid);
BOOL AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, TOKEN_PRIVILEGES* NewState, DWORD BufferLength, TOKEN_PRIVILEGES* PreviousState, DWORD* ReturnLength);
]]

local kernel32 = ffi.load("kernel32")
local ntdll = ffi.load("ntdll")
local advapi32 = ffi.load("advapi32")

-- === Configuration ===
local SEARCH_STRING = "password"       -- change as needed
local LOG_PATH = "c:/temp/memoryexploit.log"

local CHUNK_SIZE = 0x1000               -- 4 KB read window per chunk
local ADDRESS_LIMIT = 0x7FFFFFFFFFFFFFFF
local CONTEXT_BEFORE = 96               -- bytes (or UTF-16 pairs) before match
local CONTEXT_AFTER = 64                -- bytes (or UTF-16 pairs) after match

-- === Constants ===
local PROCESS_QUERY_INFORMATION = 0x0400
local PROCESS_VM_READ = 0x0010

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

local TOKEN_ADJUST_PRIVILEGES = 0x0020
local TOKEN_QUERY = 0x0008
local SE_PRIVILEGE_ENABLED = 0x00000002

-- === Utility helpers ===
local function enableDebugPrivilege()
    local hToken = ffi.new("HANDLE[1]")
    local success = advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        bit.bor(TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY),
        hToken
    )
    
    if success == 0 then
        return false, "OpenProcessToken failed: " .. kernel32.GetLastError()
    end
    
    local luid = ffi.new("LUID")
    success = advapi32.LookupPrivilegeValueA(nil, "SeDebugPrivilege", luid)
    
    if success == 0 then
        kernel32.CloseHandle(hToken[0])
        return false, "LookupPrivilegeValueA failed: " .. kernel32.GetLastError()
    end
    
    local tp = ffi.new("TOKEN_PRIVILEGES")
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    
    success = advapi32.AdjustTokenPrivileges(hToken[0], 0, tp, 0, nil, nil)
    local lastErr = kernel32.GetLastError()
    kernel32.CloseHandle(hToken[0])
    
    if success == 0 then
        return false, "AdjustTokenPrivileges failed: " .. lastErr
    end
    
    -- ERROR_NOT_ALL_ASSIGNED (1300) means privilege wasn't granted
    if lastErr == 1300 then
        return false, "SeDebugPrivilege not available (ERROR_NOT_ALL_ASSIGNED)"
    end
    
    return true
end

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
    return bit.band(protect, PAGE_READWRITE) ~= 0
end

-- Helper function to read memory safely
local function safeNtRead(processHandle, address, size)
    local buffer = ffi.new("uint8_t[?]", size)
    local bytesRead = ffi.new("SIZE_T[1]")
    
    local status = ntdll.NtReadVirtualMemory(processHandle, address, buffer, size, bytesRead)

    if status ~= STATUS_SUCCESS and status ~= STATUS_PARTIAL_COPY then
        if status ~= STATUS_ACCESS_VIOLATION then
            writeLog(logFile, string.format("  NtReadVirtualMemory failed at 0x%08X (status=%s)\n", address, statusToString(status)))
        end
        return nil
    end

    return ffi.string(buffer, bytesRead[0])
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

-- Main execution
function main()
    local logFile = assert(io.open(LOG_PATH, "a"))
    writeLog(logFile, "\n--------------------------------------------------\n")

    local function getProcessName(pHandle)
        local size = ffi.new("DWORD[1]", 260)
        local buffer = ffi.new("char[?]", size[0])
        local success = kernel32.QueryFullProcessImageNameA(pHandle, 0, buffer, size)
        if success ~= 0 then
            return ffi.string(buffer)
        end
        return "N/A"
    end

    -- Initial log entries
    writeLog(logFile, "Memory search log\n")
    writeLog(logFile, string.format("Scan start: %s\n", os.date("%Y-%m-%d %H:%M:%S")))

    local privOk, privErr = enableDebugPrivilege()
    writeLog(logFile, string.format("SeDebugPrivilege: %s\n", privOk and "ENABLED" or "DISABLED (" .. (privErr or "unknown error") .. ")"))

    -- Architecture detection
    local pointerSize = ffi.sizeof(ffi.typeof("void*"))
    local is32bitCode = (pointerSize == 4)
    writeLog(logFile, string.format("Pointer size: %d bytes (32-bit code: %s)\n", pointerSize, tostring(is32bitCode)))

    local wow64Result = ffi.new("BOOL[1]")
    local wow64Success = kernel32.IsWow64Process(kernel32.GetCurrentProcess(), wow64Result)
    local isWow64Process = (wow64Result[0] ~= 0)
    writeLog(logFile, string.format("IsWow64Process call success: %s, returned: %d (process is WoW64: %s)\n", tostring(wow64Success ~= 0), wow64Result[0], tostring(isWow64Process)))

    local use32bitStruct = is32bitCode  -- Use 32-bit struct if code is 32-bit, regardless of process
    writeLog(logFile, string.format("Will use 32-bit MEMORY_BASIC_INFORMATION struct: %s\n", tostring(use32bitStruct)))

    local search_ascii = SEARCH_STRING
    local search_unicode = toUnicodeLE(SEARCH_STRING)

    local searchers = {
        {
            label = "ASCII",
            pattern = search_ascii,
            patternLen = #search_ascii,
            isUnicode = false,
            step = 1,
            tail = "",
            tailSize = math.max(0, #search_ascii - 1),
            count = 0
        },
        {
            label = "UTF-16LE",
            pattern = search_unicode,
            patternLen = #search_unicode,
            isUnicode = true,
            step = 2,
            tail = "",
            tailSize = math.max(0, #search_unicode - 2),
            count = 0
        }
    }
    
    local processId = kernel32.GetCurrentProcessId()
    local processHandle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION + PROCESS_VM_READ, false, processId)

    if processHandle == nil or tonumber(ffi.cast("intptr_t", processHandle)) == 0 then
        writeLog(logFile, string.format("\n[ERROR] OpenProcess failed (Win32=%d)\n", kernel32.GetLastError()))
        logFile:close()
        print("Scan failed: Could not open process handle.")
        return
    end
    
    writeLog(logFile, string.format("Process Name: %s\n", getProcessName(processHandle)))
    writeLog(logFile, string.format("Opened handle to PID %d: 0x%X\n", processId, tonumber(ffi.cast("intptr_t", processHandle))))

    local address = 0x10000 -- Start scan above first 64K
    local regions, readableRegions = 0, 0
    local firstQueryFailed = false

    -- Main memory query loop
    while address < ADDRESS_LIMIT do
        local baseAddr, regionSize, state, protect
        local querySuccess = false
        local mbi

        if use32bitStruct then
            mbi = ffi.new("MEMORY_BASIC_INFORMATION32")
        else
            mbi = ffi.new("MEMORY_BASIC_INFORMATION")
        end

        local result = kernel32.VirtualQueryEx(processHandle, ffi.cast("PVOID", address), mbi, ffi.sizeof(mbi))

        if result > 0 then
            querySuccess = true
            baseAddr = tonumber(ffi.cast("intptr_t", mbi.BaseAddress))
            regionSize = tonumber(mbi.RegionSize)
            state = tonumber(mbi.State)
            protect = tonumber(mbi.Protect)
        end

        if not querySuccess then
            if regions == 0 then
                firstQueryFailed = true
                local lastErr = kernel32.GetLastError()
                writeLog(logFile, string.format("\n[ERROR] Initial memory query failed at address 0x%X (Win32=%d)\n", address, lastErr))
            end
            break
        end

        regions = regions + 1
        
        -- Safety check for invalid region data
        if not baseAddr or not regionSize then
            writeLog(logFile, string.format("\n[REGION %d] INVALID DATA baseAddr=%s regionSize=%s\n",
                regions, tostring(baseAddr), tostring(regionSize)))
            break
        end
        
        writeLog(logFile, string.format("\n[REGION %d] 0x%08X - 0x%08X size=%d KB protect=0x%03X state=0x%03X\n",
            regions, baseAddr, baseAddr + regionSize, math.floor(regionSize / 1024), protect or 0, state or 0))

        if regionSize == 0 then
            writeLog(logFile, "  WARNING: Zero-sized region, advancing by 4KB\n")
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
        
        -- Sanity check: if address didn't advance, force it forward
        if address <= baseAddr then
            writeLog(logFile, string.format("  WARNING: Address didn't advance (was 0x%08X), forcing +4KB\n", address))
            address = baseAddr + 0x1000
        end
    end

    kernel32.CloseHandle(processHandle)

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
