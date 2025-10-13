# OffensiveLuaEmbedded Behavior Changes

## Summary of Changes

The following behavioral changes have been implemented in OffensiveLuaEmbedded.exe:

### 1. Non-Interactive by Default ✓

- **Previous Behavior**: Interactive mode could be toggled
- **New Behavior**: Non-interactive is the default; use `-i` or `--interactive` to enable interactive debugging mode
- **Impact**: Scripts run silently without pausing unless you explicitly request interaction

### 2. Bytecode Dumping (`--dump-bytecode`) ✓

- **Previous Behavior**: Bytecode dump was enabled by default, printing bytecode analysis to console
- **New Behavior**:
  - Disabled by default
  - When `--dump-bytecode` is specified, creates a `.lbin` bytecode file
  - The `.lbin` file can be executed directly: `OffensiveLuaEmbedded.exe script.lbin`
- **Example**:

  ```powershell
  # Create bytecode file
  .\OffensiveLuaEmbedded.exe --dump-bytecode script.lua

  # Run bytecode file
  .\OffensiveLuaEmbedded.exe script.lbin
  ```

### 3. Trace Option (`--trace` / `-t`) ✓

- **Previous Behavior**: `--trace-lines` / `-t` logged every executed line
- **New Behavior**: Renamed to `--trace` / `-t` for brevity
- **Impact**: Same functionality, cleaner option name
- **Example Output**:
  ```
  [trace] script.lua:5 | local x = 10
  [trace] script.lua:6 | print(x)
  ```

### 4. VM Instrumentation (`--vm`) ✓ **NEW FEATURE**

- **New Option**: `--vm` instruments the Lua VM with detailed timing and diagnostic information
- **Provides**:
  - VM creation/destruction timestamps
  - Script execution start/end timestamps
  - Memory usage tracking (initial, peak, final, delta)
  - CPU cycle counting
  - VM lifetime statistics
- **Example Output**:

  ```
  [VM] Lua VM created at 16:47:13.812
  [VM] Initial process memory: 4764 KB
  [VM] Script execution started at 16:47:13.814
  [VM] Script execution ended at 16:47:13.815
  [VM] Lua VM destroyed at 16:47:13.816

  [VM Instrumentation Summary]
    VM Lifetime:        4 ms
    Execution Time:     0 ms
    Initial Memory:     4764 KB
    Peak Memory:        5972 KB
    Final Memory:       5972 KB
    Memory Delta:       1208 KB
    CPU Cycles:         13204773
  ```

### 5. Default Enabled Options

The following options remain **enabled by default**:

- `--count` / `-c`: Instruction sampling and hotline tracking
- `--memory` / `-m`: Memory summary after execution

Use `--no-count` or `--no-memory` to disable these features.

## Updated Help Output

```
Offensive LuaJIT Debugger
Usage: luadebug [options] <script.lua> [args...]
Options:
  --interactive, -i      Enable interactive debugging mode.
  --dump-bytecode        Create .lbin bytecode file.
  --trace, -t            Trace every executed line.
  --count, -c            Track instruction samples (default).
  --no-count             Disable instruction sampling.
  --memory, -m           Print memory summary after execution (default).
  --no-memory            Skip memory summary.
  --vm                   Instrument VM with timing and diagnostics.
  --help, -h             Show this help message.
```

## Technical Implementation Details

### VM Instrumentation Architecture

- Uses `std::chrono::high_resolution_clock` for precise timing
- Platform-specific memory tracking via Windows `GetProcessMemoryInfo()`
- CPU cycle counting via `__rdtsc()` intrinsic (x86/x64)
- Non-intrusive: Zero performance impact when disabled
- Periodic peak memory sampling during instruction hooks

### Code Changes

- Modified `DebugConfig` struct to add `instrumentVM` flag
- Created `VMInstrumentation` class with timing and memory tracking
- Updated `LuaApplication::run()` to integrate VM instrumentation
- Fixed Windows macro conflicts (`NOMINMAX` for `std::min`/`std::max`)
- Used safe `localtime_s()` for timestamp formatting

### Build

- Successfully compiled with MSVC (Visual Studio 2022)
- Release configuration for x86 platform
- No new dependencies required (uses existing Windows APIs)

## Usage Examples

### Basic execution (non-interactive, no bytecode)

```powershell
.\OffensiveLuaEmbedded.exe script.lua
```

### Create and run bytecode

```powershell
# Compile to bytecode
.\OffensiveLuaEmbedded.exe --dump-bytecode script.lua

# Execute bytecode
.\OffensiveLuaEmbedded.exe script.lbin
```

### Trace execution with VM instrumentation

```powershell
.\OffensiveLuaEmbedded.exe --trace --vm script.lua
```

### Interactive debugging

```powershell
.\OffensiveLuaEmbedded.exe -i script.lua
```

### Minimal output (no counters, no memory summary)

```powershell
.\OffensiveLuaEmbedded.exe --no-count --no-memory script.lua
```
