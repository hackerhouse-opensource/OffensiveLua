-- Output a file as hex for use with binrun.lua and binrundll.lua

local ffi = require("ffi")

-- Function to read a file and return its content as a hex array
local function readFileAsHexArray(filePath)
    local file = io.open(filePath, "rb")
    if not file then
        return nil
    end

    local content = file:read("*all")
    file:close()

    local hexArray = {}
    for i = 1, #content do
        local byte = string.byte(content, i)
        table.insert(hexArray, string.format("\\x%02X", byte))
    end

    return hexArray
end

-- Main function
local function main()
    local filePath = arg[1]

    if not filePath then
        print("Usage: lua script.lua <file_path>")
        return
    end

    local hexArray = readFileAsHexArray(filePath)

    if not hexArray then
        print("Failed to open or read the file.")
        return
    end

    -- Print the hex array as a C-style array for scripts
    print("local data = \"" .. table.concat(hexArray, "") .. "\";")
end

main()
