-- howami.lua function to simulate "whoami.exe" and list username, SID & privileges.
local ffi = require("ffi")
local kernel32 = ffi.load("kernel32")
local advapi32 = ffi.load("advapi32")

ffi.cdef[[
    typedef void* HANDLE;
    typedef unsigned long DWORD;
    typedef struct _TOKEN_USER {
        struct {
            DWORD dwVersion;
            DWORD dwValueType;
        } User;
        unsigned char UserSid[68]; 
    } TOKEN_USER;
    typedef struct _TOKEN_PRIVILEGES {
        DWORD PrivilegeCount;
        struct {
            int LUID;
            DWORD Attributes;
        } Privileges[1];
    } TOKEN_PRIVILEGES;

    HANDLE OpenProcess(DWORD dwDesiredAccess, int bInheritHandle, DWORD dwProcessId);
    int OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, HANDLE* TokenHandle);
    int OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, int OpenAsSelf, HANDLE* TokenHandle);
    int ImpersonateLoggedOnUser(HANDLE hToken);
    int OpenThread(DWORD dwDesiredAccess, int bInheritHandle, DWORD dwThreadId, HANDLE* ThreadHandle);
    int GetTokenInformation(HANDLE TokenHandle, int TokenInformationClass, void* TokenInformation, DWORD TokenInformationLength, DWORD* ReturnLength);
    void CloseHandle(HANDLE hObject);
    void SetLastError(DWORD dwErrCode);
    int LookupAccountSidA(const char* lpSystemName, const char* Sid, char* Name, DWORD* cchName, char* ReferencedDomainName, DWORD* cchReferencedDomainName, int* peUse);
    DWORD GetLastError();
]]

local PROCESS_QUERY_INFORMATION = 0x0400
local TOKEN_QUERY = 0x0008
local THREAD_QUERY_INFORMATION = 0x0040
local TokenUser = 1
local SecurityImpersonation = 2

function GetLastError()
    return kernel32.GetLastError()
end

-- convert SID to standard SID notation
function ConvertBinarySIDToStandardNotation(binarySid)
    -- The binary SID should be a byte array.
    local sidString = "S"
    -- Extract revision and authority fields.
    local revision = binarySid[1]
    local authority = binarySid[7] + (binarySid[6] * 256) + (binarySid[5] * 256 * 256) + (binarySid[4] * 256 * 256 * 256) + (binarySid[3] * 256 * 256 * 256 * 256) + (binarySid[2] * 256 * 256 * 256 * 256 * 256)
    -- Add the revision and authority to the SID string.
    sidString = sidString .. "-" .. revision .. "-" .. authority
    -- Iterate through the binary SID and extract subauthorities.
    local subauthorities = {}
    for i = 9, 68, 4 do
        local subauth = binarySid[i] + (binarySid[i + 1] * 256) + (binarySid[i + 2] * 256 * 256) + (binarySid[i + 3] * 256 * 256 * 256)
        table.insert(subauthorities, subauth)
    end
    -- Add the subauthorities to the SID string.
    for _, subauth in ipairs(subauthorities) do
        sidString = sidString .. "-" .. subauth
    end
    return sidString
end

-- GetUsernameAndSid
function GetUsernameAndSID(pid)
    local processHandle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid)
    if processHandle == nil then
        print("OpenProcess failed, error code: " .. GetLastError())
        return
    end

    local tokenHandle = ffi.new("HANDLE[1]")
    if kernel32.OpenProcessToken(processHandle, TOKEN_QUERY, tokenHandle) == 0 then
        print("OpenProcessToken failed, error code: " .. GetLastError())
        kernel32.CloseHandle(processHandle)
        return
    end

    local tokenUser = ffi.new("TOKEN_USER")
    local returnLength = ffi.new("DWORD[1]")

    if advapi32.GetTokenInformation(tokenHandle[0], TokenUser, tokenUser, ffi.sizeof(tokenUser), returnLength) == 0 then
        print("GetTokenInformation failed, error code: " .. GetLastError())
    else
        local name = ffi.new("char[260]")
        local domain = ffi.new("char[260]")
        local nameSize = ffi.new("DWORD[1]", 260)
        local domainSize = ffi.new("DWORD[1]", 260)
        local peUse = ffi.new("int[1]")

        if advapi32.LookupAccountSidA(nil, tokenUser.UserSid, name, nameSize, domain, domainSize, peUse) ~= 0 then
            print("Username: " .. ffi.string(name))
            local sidOutput = ConvertBinarySIDToStandardNotation(tokenUser.UserSid)
            print("SID: " .. sidOutput)
        else
            print("LookupAccountSidA failed, error code: " .. GetLastError())
        end
    end

    kernel32.CloseHandle(tokenHandle[0])
    kernel32.CloseHandle(processHandle)
end

-- Usage: lua howami.lua <ProcessID>
local args = { ... }
if #args ~= 1 then
    print("Usage: lua howami.lua <ProcessID>")
else
    local pid = tonumber(args[1])
    GetUsernameAndSID(pid)
end