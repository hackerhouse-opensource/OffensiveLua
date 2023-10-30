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
]]

local PROCESS_QUERY_INFORMATION = 0x0400
local TOKEN_QUERY = 0x0008
local THREAD_QUERY_INFORMATION = 0x0040
local TokenUser = 1
local SecurityImpersonation = 2

function GetLastError()
    return kernel32.GetLastError()
end

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
            local sidOutput = "SID: "
        for i = 1, ffi.sizeof(tokenUser.UserSid) do
            sidOutput = sidOutput .. string.format("%02X", tokenUser.UserSid[i])
        end
        print(sidOutput)
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
