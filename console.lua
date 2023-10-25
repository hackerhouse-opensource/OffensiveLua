local ffi = require("ffi")

-- Define the necessary Windows API functions and constants
ffi.cdef[[
   bool AllocConsole();
   bool FreeConsole();
   int printf(const char *format, ...);
   int GetLastError();
]]

-- Allocate a console
if ffi.C.AllocConsole() == 0 then
   print("Failed to allocate a console. Error code: " .. ffi.C.GetLastError())
   return
end

-- Print "Hello, World" to the console
ffi.C.printf("Hello, World\n")

-- Free the console when you're done
ffi.C.FreeConsole()