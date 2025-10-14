-- memorysearch.lua
-- Memory searcher for ASCII and UTF-16LE strings
-- Safe for execution in DLL worker threads with LuaJIT

local jit = require("jit")
-- disable JIT optimizations for FFI callbacks and error handling
jit.off(true, true)

local ffi = require("ffi")
local bit = require("bit")

-- === Configuration ===
local SEARCH_STRING = "password"
local CHUNK_SIZE = 0x1000
local MAX_STRING_CONCAT_SIZE = 0x10000
local ADDRESS_LIMIT = 0x7FFFFFFFFFFFFFFF
local CONTEXT_BEFORE = 96
local CONTEXT_AFTER = 64
local MAX_REGIONS_TO_SCAN = 10000

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
typedef SIZE_T ULONG_PTR;

typedef struct {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION32, *PMEMORY_BASIC_INFORMATION32;

typedef struct {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    DWORD __alignment1;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
    DWORD __alignment2;
} MEMORY_BASIC_INFORMATION64, *PMEMORY_BASIC_INFORMATION64;

typedef MEMORY_BASIC_INFORMATION32 MEMORY_BASIC_INFORMATION;

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
BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, HANDLE* TokenHandle);
BOOL LookupPrivilegeValueA(const char* lpSystemName, const char* lpName, LUID* lpLuid);
BOOL AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, TOKEN_PRIVILEGES* NewState, DWORD BufferLength, TOKEN_PRIVILEGES* PreviousState, DWORD* ReturnLength);
DWORD GetCurrentThreadId(void);
BOOL EnumProcessModules(HANDLE hProcess, HANDLE* lphModule, DWORD cb, DWORD* lpcbNeeded);
DWORD GetModuleBaseNameA(HANDLE hProcess, HANDLE hModule, LPSTR lpBaseName, DWORD nSize);
BOOL GetModuleInformation(HANDLE hProcess, HANDLE hModule, void* lpmodinfo, DWORD cb);
typedef struct {
    PVOID lpBaseOfDll;
    DWORD SizeOfImage;
    PVOID EntryPoint;
} MODULEINFO, *LPMODULEINFO;

DWORD GetEnvironmentVariableA(const char* lpName, char* lpBuffer, DWORD nSize);
]]

local kernel32 = ffi.load("kernel32")
local advapi32 = ffi.load("advapi32")
local psapi = ffi.load("psapi")

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

-- === Utility helpers ===
local TOKEN_QUERY = 0x0008
local SE_PRIVILEGE_ENABLED = 0x00000002

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

local function getTempPath()
    local buffer = ffi.new("char[?]", 260)
    local size = kernel32.GetEnvironmentVariableA("TEMP", buffer, 260)
    if size > 0 and size < 260 then
        return ffi.string(buffer)
    end
    return "c:/temp"
end

local function generateLogPath(processName, pid, tid)
    local tempPath = getTempPath()
    local baseName = processName:match("([^/\\]+)$") or "unknown"
    baseName = baseName:gsub("%.", "_")
    local timestamp = os.date("%Y%m%d_%H%M%S")
    return string.format("%s/%s_PID%d_TID%d_%s.log", tempPath, baseName, pid, tid, timestamp)
end

local function writeLog(logFile, message)
    logFile:write(message)
    logFile:flush()
end

-- Track active log for helpers that lack direct access
local currentLogFile = nil

local function debugLog(fmt, ...)
    if currentLogFile then
        writeLog(currentLogFile, string.format(fmt, ...))
    end
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
    -- Exclude PAGE_GUARD and PAGE_NOACCESS
    if bit.band(protect, PAGE_GUARD) ~= 0 or protect == PAGE_NOACCESS then
        return false
    end
    -- Check for any readable protection flags
    local readable = bit.bor(PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, 
                             PAGE_EXECUTE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_WRITECOPY)
    return bit.band(protect, readable) ~= 0
end

local function safeRead(processHandle, address, size)
    if size <= 0 or size > CHUNK_SIZE * 4 then
        return nil, false
    end
    
    local buffer = ffi.new("uint8_t[?]", size)
    local bytesRead = ffi.new("SIZE_T[1]")
    
    local success, result = pcall(function()
        return kernel32.ReadProcessMemory(processHandle, ffi.cast("PVOID", address), buffer, size, bytesRead)
    end)
    
    if not success then
        debugLog("  ReadProcessMemory pcall raised at 0x%08X: %s\n", address, tostring(result))
        return nil, false
    end
    
    if result == 0 then
        return nil, false
    end
    
    local actualBytesRead = tonumber(bytesRead[0])
    if actualBytesRead == 0 or actualBytesRead > size then
        return nil, false
    end
    
    local strSuccess, strResult = pcall(ffi.string, buffer, actualBytesRead)
    if not strSuccess then
        debugLog("  ffi.string failed at 0x%08X: %s\n", address, tostring(strResult))
        return nil, false
    end
    
    return strResult, true
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
    -- Validate parameters
    if not processHandle or not regionBase or not regionEnd or not matchAddr or not matchLenBytes then
        return nil
    end
    
    if matchAddr < regionBase or matchAddr >= regionEnd then
        return nil
    end
    
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
    
    -- Limit context size to prevent excessive memory operations
    if size > CHUNK_SIZE * 4 then
        size = CHUNK_SIZE * 4
        endAddr = startAddr + size
    end
    
    local data, ok = safeRead(processHandle, startAddr, size)
    if not data or #data == 0 then
        return nil, status
    end

    local matchOffset = matchAddr - startAddr
    local matchStartIdx = matchOffset + 1
    local matchEndIdx = matchStartIdx + matchLenBytes - 1
    
    -- Bounds checking
    local dataLen = #data
    if matchStartIdx < 1 or matchStartIdx > dataLen or matchEndIdx > dataLen then
        return nil
    end

    local contextStartIdx = matchStartIdx
    local consumed = 0
    local iterations = 0
    local maxIterations = CONTEXT_BEFORE + 10  -- Safety limit
    
    while contextStartIdx > step and iterations < maxIterations do
        iterations = iterations + 1
        local nextIdx = contextStartIdx - step
        
        if nextIdx < 1 then break end
        
        -- Protected byte access
        local byteOk = true
        if isUnicode then
            if nextIdx + 1 > dataLen then break end
            local b1Success, b1 = pcall(string.byte, data, nextIdx)
            local b2Success, b2 = pcall(string.byte, data, nextIdx + 1)
            if not b1Success or not b2Success or not b1 or not b2 or (b1 == 0 and b2 == 0) then 
                break 
            end
        else
            if nextIdx > dataLen then break end
            local bSuccess, b = pcall(string.byte, data, nextIdx)
            if not bSuccess or not b or b == 0 then 
                break 
            end
        end
        
        consumed = consumed + step
        if consumed >= beforeLimit then break end
        contextStartIdx = nextIdx
    end

    local contextEndIdx = matchEndIdx
    consumed = 0
    iterations = 0
    
    while contextEndIdx + step <= dataLen and iterations < maxIterations do
        iterations = iterations + 1
        local nextIdx = contextEndIdx + step
        
        if nextIdx > dataLen then break end
        
        -- Protected byte access
        if isUnicode then
            if nextIdx + 1 > dataLen then break end
            local b1Success, b1 = pcall(string.byte, data, nextIdx)
            local b2Success, b2 = pcall(string.byte, data, nextIdx + 1)
            if not b1Success or not b2Success or not b1 or not b2 or (b1 == 0 and b2 == 0) then 
                break 
            end
        else
            local bSuccess, b = pcall(string.byte, data, nextIdx)
            if not bSuccess or not b or b == 0 then 
                break 
            end
        end
        
        consumed = consumed + step
        if consumed >= afterLimit then break end
        contextEndIdx = nextIdx
    end
    
    -- Validate indices before substring extraction
    if contextStartIdx < 1 or contextEndIdx > dataLen or contextStartIdx > contextEndIdx then
        return nil
    end

    -- Protected substring extraction
    local subSuccess, window = pcall(string.sub, data, contextStartIdx, contextEndIdx)
    if not subSuccess or not window then
        return nil
    end
    
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
    local consecutiveFailures = 0
    local maxConsecutiveFailures = 10  -- Abort region after 10 consecutive failures

    while offset < regionSize do
        local toRead = math.min(CHUNK_SIZE, regionSize - offset)
        local readAddr = baseAddr + offset
        local chunk, ok = safeRead(processHandle, readAddr, toRead)

        if chunk and #chunk > 0 then
            consecutiveFailures = 0  -- Reset failure counter on success
            
            -- Process each search pattern with protected string operations
            for _, search in ipairs(searchers) do
                local tail = search.tail
                local tailLen = #tail
                local chunkLen = #chunk
                
                -- Prevent excessive string concatenation that exhausts stack
                if tailLen + chunkLen > MAX_STRING_CONCAT_SIZE then
                    -- Trim tail to reasonable size
                    tail = tail:sub(math.max(1, tailLen - search.tailSize))
                    tailLen = #tail
                end
                
                local combined = tail .. chunk
                local combinedLen = #combined
                local patternLen = search.patternLen

                if patternLen > 0 and combinedLen >= patternLen then
                    local searchStart = math.max(1, tailLen - patternLen + 1)
                    local pos = searchStart
                    local matchLimit = 1000  -- Prevent infinite loop on repetitive patterns
                    local matchCount = 0
                    
                    while matchCount < matchLimit do
                        -- Protected string search
                        local findSuccess, found = pcall(string.find, combined, search.pattern, pos, true)
                        if not findSuccess or not found then 
                            break 
                        end
                        
                        matchCount = matchCount + 1
                        local foundEnd = found + patternLen - 1
                        
                        if foundEnd > tailLen then
                            local combinedZero = found - 1
                            local absoluteAddr = readAddr - tailLen + combinedZero
                            
                            -- Protected context extraction
                            local ctxSuccess, context = pcall(makeContext, processHandle, baseAddr, regionEnd, absoluteAddr, patternLen, search.isUnicode)
                            if ctxSuccess then
                                search.count = search.count + 1
                                logMatch(logFile, search.label, search.count, absoluteAddr, context, search.isUnicode)
                            end
                        end
                        
                        pos = found + search.step
                        if pos > combinedLen then
                            break
                        end
                    end
                end

                -- Update tail with size limit
                local maxTail = math.min(combinedLen, search.tailSize)
                if maxTail > 0 and maxTail <= combinedLen then
                    local subSuccess, newTail = pcall(string.sub, combined, combinedLen - maxTail + 1)
                    if subSuccess then
                        search.tail = newTail
                    else
                        search.tail = ""  -- Reset on error
                    end
                else
                    search.tail = ""
                end
            end
        else
            consecutiveFailures = consecutiveFailures + 1
            
            if consecutiveFailures >= maxConsecutiveFailures then
                writeLog(logFile, string.format("  Aborting region scan after %d consecutive failures at 0x%08X\n", consecutiveFailures, readAddr))
                break
            end
            
            if status and status ~= STATUS_PARTIAL_COPY and status ~= STATUS_ACCESS_VIOLATION then
                local winSuccess, winErr = pcall(ntdll.RtlNtStatusToDosError, status)
                local errCode = winSuccess and tonumber(winErr) or 0
                writeLog(logFile, string.format("  Read failed at 0x%08X (status=%s, win32=%d)\n", readAddr, statusToString(status), errCode))
            end
        end

        offset = offset + toRead
        
        -- Safety check for offset advancement
        if offset <= 0 or offset > regionSize then
            writeLog(logFile, string.format("  WARNING: Invalid offset advancement detected (offset=%d, regionSize=%d)\n", offset, regionSize))
            break
        end
    end
end

local function logLoadedModules(processHandle, logFile)
    writeLog(logFile, "\n=== LOADED MODULES ===\n")
    local modules = ffi.new("HANDLE[1024]")
    local needed = ffi.new("DWORD[1]")
    local success = psapi.EnumProcessModules(processHandle, modules, ffi.sizeof(modules), needed)
    if success == 0 then
        writeLog(logFile, "Failed to enumerate modules\n")
        return
    end
    local moduleCount = needed[0] / ffi.sizeof("HANDLE")
    for i = 0, moduleCount - 1 do
        local modInfo = ffi.new("MODULEINFO")
        success = psapi.GetModuleInformation(processHandle, modules[i], modInfo, ffi.sizeof(modInfo))
        if success ~= 0 then
            local baseName = ffi.new("char[256]")
            psapi.GetModuleBaseNameA(processHandle, modules[i], baseName, 256)
            local baseAddr = tonumber(ffi.cast("intptr_t", modInfo.lpBaseOfDll))
            local size = modInfo.SizeOfImage
            writeLog(logFile, string.format("Module: %s - 0x%08X - 0x%08X (%d KB)\n", 
                ffi.string(baseName), baseAddr, baseAddr + size, size / 1024))
        end
    end
end

function main()
    local pid = kernel32.GetCurrentProcessId()
    local tid = kernel32.GetCurrentThreadId()
    local processHandle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION + PROCESS_VM_READ, false, pid)
    
    if processHandle == nil or tonumber(ffi.cast("intptr_t", processHandle)) == 0 then
        print("Scan failed: Could not open process handle.")
        return
    end
    
    local function getProcessName(pHandle)
        local size = ffi.new("DWORD[1]", 260)
        local buffer = ffi.new("char[?]", size[0])
        local success = kernel32.QueryFullProcessImageNameA(pHandle, 0, buffer, size)
        if success ~= 0 then
            return ffi.string(buffer)
        end
        return "unknown"
    end
    
    local processName = getProcessName(processHandle)
    local logPath = generateLogPath(processName, pid, tid)
    local logFile = assert(io.open(logPath, "w"))
    writeLog(logFile, "\n--------------------------------------------------\n")
    currentLogFile = logFile

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
    
    writeLog(logFile, string.format("Process Name: %s\n", processName))
    writeLog(logFile, string.format("Opened handle to PID %d: 0x%X\n", pid, tonumber(ffi.cast("intptr_t", processHandle))))
    writeLog(logFile, string.format("Current Thread ID: %d\n", tid))

    logLoadedModules(processHandle, logFile)

    local address = 0x10000 -- Start scan above first 64K
    local regions, readableRegions = 0, 0
    local firstQueryFailed = false
    local lastAddress = 0

    -- Main memory query loop with safety limits
    while address < ADDRESS_LIMIT and regions < MAX_REGIONS_TO_SCAN do
        local baseAddr, regionSize, state, protect
        local querySuccess = false
        local mbi

        if use32bitStruct then
            mbi = ffi.new("MEMORY_BASIC_INFORMATION32")
        else
            mbi = ffi.new("MEMORY_BASIC_INFORMATION64")
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
        
        -- Detect infinite loop condition
        if address == lastAddress then
            writeLog(logFile, string.format("\n[ERROR] Infinite loop detected at address 0x%08X, aborting scan\n", address))
            break
        end
        lastAddress = address
        
        writeLog(logFile, string.format("\n[REGION %d] 0x%08X - 0x%08X size=%d KB protect=0x%03X state=0x%03X\n",
            regions, baseAddr, baseAddr + regionSize, math.floor(regionSize / 1024), protect or 0, state or 0))

        if regionSize == 0 then
            writeLog(logFile, "  WARNING: Zero-sized region, advancing by 4KB\n")
            address = baseAddr + 0x1000
        else
            if state == MEM_COMMIT and isReadableProtection(protect) then
                readableRegions = readableRegions + 1
                
                -- Progress indicator for console (every 10 regions)
                if readableRegions % 10 == 0 then
                    print(string.format("Scanning... %d regions inspected, %d readable", regions, readableRegions))
                end
                
                -- Protected region scan with timeout detection
                local scanSuccess, scanErr = pcall(scanRegion, processHandle, logFile, baseAddr, regionSize, searchers)
                if not scanSuccess then
                    writeLog(logFile, string.format("  ERROR: Region scan failed: %s\n", tostring(scanErr)))
                end
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
        
        -- Additional safety: detect address overflow/wraparound
        if address < baseAddr then
            writeLog(logFile, string.format("\n[ERROR] Address wraparound detected (prev=0x%08X, current=0x%08X), aborting\n", baseAddr, address))
            break
        end
    end
    
    -- Check if we hit the region limit
    if regions >= MAX_REGIONS_TO_SCAN then
        writeLog(logFile, string.format("\n[WARNING] Reached maximum region scan limit (%d), terminating early\n", MAX_REGIONS_TO_SCAN))
    end

    logLoadedModules(processHandle, logFile)

    kernel32.CloseHandle(processHandle)

    writeLog(logFile, "\n=== SUMMARY ===\n")
    writeLog(logFile, string.format("Regions inspected: %d\n", regions))
    writeLog(logFile, string.format("Readable regions: %d\n", readableRegions))
    for _, search in ipairs(searchers) do
        writeLog(logFile, string.format("%s matches: %d\n", search.label, search.count))
    end

    logFile:close()
    currentLogFile = nil
    print(string.format("Scan complete. %d regions inspected, %d readable, results logged to %s", regions, readableRegions, logPath))
end

local ok, err = pcall(main)
if not ok then
    print(string.format("FATAL: Scanner failed - %s", tostring(err)))
    print(debug.traceback())
    os.exit(1)
end
