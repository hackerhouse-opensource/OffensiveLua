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
    LONG RegCreateKeyA(HKEY hKey, LPCSTR lpSubKey, HKEY* phkResult);
    LONG RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const void* lpData, DWORD cbData);
    void SetLastError(DWORD dwErrCode);
    void* GetProcessHeap();
    void* HeapAlloc(void* hHeap, DWORD dwFlags, size_t dwBytes);
    void HeapFree(void* hHeap, DWORD dwFlags, void* lpMem);
]]

-- Constants
local HKEY_CURRENT_USER = ffi.cast("HKEY", 0x80000001)
local REG_SZ = 1

-- Function to write a registry value
function writeRegistryValue(key, subKey, valueName, valueData)
    local hKey = ffi.new("HKEY[1]")
    local result = advapi32.RegCreateKeyA(key, subKey, hKey)

    if result == 0 then
        local data = ffi.new("const char[?]", #valueData + 1, valueData)
        local dataSize = ffi.sizeof(data)

        result = advapi32.RegSetValueExA(hKey[0], valueName, 0, REG_SZ, data, dataSize)

        if result == 0 then
            return true
        end
    end

    return false
end

-- Example usage to write a registry value
local success = writeRegistryValue(HKEY_CURRENT_USER, "Software\\MyApp", "MyValueName", "MyValueData")
if success then
    print("Successfully wrote the registry value.")
else
    print("Failed to write the registry value.")
end
