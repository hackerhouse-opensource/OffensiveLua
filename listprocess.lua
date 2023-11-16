local ffi = require("ffi")

ffi.cdef[[
    typedef unsigned long DWORD;
    typedef void* HANDLE;
    typedef long LONG;
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

    HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
    int Process32First(HANDLE hSnapshot, PROCESSENTRY32* lppe);
    int Process32Next(HANDLE hSnapshot, PROCESSENTRY32* lppe);
    void CloseHandle(HANDLE hObject);
]]

local TH32CS_SNAPPROCESS = 0x00000002
local INVALID_HANDLE_VALUE = ffi.cast("HANDLE", -1)

function listProcesses()
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
        until ffi.C.Process32Next(snapshot, pe32) == 0
    end

    ffi.C.CloseHandle(snapshot)
end

listProcesses()
