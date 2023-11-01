-- Load the FFI library
local ffi = require("ffi")

-- Define the necessary Windows API functions and constants
ffi.cdef[[
    typedef void* HANDLE;
    HANDLE CreateEventA(void*, int, int, const char*);
    int SetEvent(HANDLE);
    int WaitForSingleObject(HANDLE, unsigned int);
    int CloseHandle(HANDLE);
    int GetLastError();
]]

-- Constants for event creation
local EVENT_ALL_ACCESS = 0x1F0003
local CREATE_EVENT_MANUAL_RESET = 0x0001
local CREATE_EVENT_INITIAL_STATE = 0x0002

-- Create an event
local event = ffi.C.CreateEventA(nil, CREATE_EVENT_MANUAL_RESET, CREATE_EVENT_INITIAL_STATE, "MyEvent")

if event == nil then
    local error_code = ffi.C.GetLastError()
    print("Error creating event, error code: " .. error_code)
else
    print("Event created successfully")

    -- Simulate some work
    for i = 1, 5 do
        print("Working...")
        -- Simulate work by waiting for a few seconds
        ffi.C.WaitForSingleObject(event, 5000)  -- Wait for 5 seconds

        -- Set the event to signaled state
        ffi.C.SetEvent(event)
    end

    -- Close the event handle
    ffi.C.CloseHandle(event)
    print("Event closed")
end
