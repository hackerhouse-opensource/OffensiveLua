-- read from a registry key.

local ffi = require("ffi")

-- Load the Windows Registry API library
local advapi32 = ffi.load("advapi32")

-- Define Windows API functions and constants
ffi.cdef[[
    typedef void* HKEY;
    typedef unsigned long DWORD;
    typedef long LONG;
    typedef const char* LPCSTR;

    LONG RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, HKEY* phkResult);
    LONG RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, DWORD* lpReserved, DWORD* lpType, void* lpData, DWORD* lpcbData);
    void SetLastError(DWORD dwErrCode);
    void* GetProcessHeap();
    void* HeapAlloc(void* hHeap, DWORD dwFlags, size_t dwBytes);
    void HeapFree(void* hHeap, DWORD dwFlags, void* lpMem);
]]

-- Constants
local HKEY_LOCAL_MACHINE = ffi.cast("HKEY", 0x80000002)
local REG_SZ = 1

-- Function to read a registry value
function readRegistryValue(key, subKey, valueName)
    local hKey = ffi.new("HKEY[1]")
    local result = advapi32.RegOpenKeyA(key, subKey, hKey)

    if result == 0 then
        local bufferSize = 512
        local buffer = ffi.C.HeapAlloc(ffi.C.GetProcessHeap(), 0, bufferSize)
        local lpType = ffi.new("DWORD[1]", REG_SZ)
        local lpcbData = ffi.new("DWORD[1]", bufferSize)

        result = advapi32.RegQueryValueExA(hKey[0], valueName, nil, lpType, buffer, lpcbData)

        if result == 0 then
            if lpType[0] == REG_SZ then
                local str = ffi.string(buffer, lpcbData[0])
                ffi.C.HeapFree(ffi.C.GetProcessHeap(), 0, buffer)
                return str
            end
        end

        ffi.C.HeapFree(ffi.C.GetProcessHeap(), 0, buffer)
    end

    return nil
end

-- Example usage
local value = readRegistryValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProgramFilesDir")
if value then
    print("Program Files Directory: " .. value)
else
    print("Failed to read the registry value.")
end

