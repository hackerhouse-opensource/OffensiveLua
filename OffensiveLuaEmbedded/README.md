# OffensiveLuaEmbedded Debugger Usage Guide

## Overview

`OffensiveLuaEmbedded.exe` is an enhanced LuaJIT debugger that replaces `luajit.exe` for advanced script debugging and analysis. It provides comprehensive debugging capabilities including:

- **Interactive step-through debugging**
- **Breakpoints** (line-based)
- **Variable inspection** (locals, upvalues, globals)
- **Call stack traces**
- **Bytecode dumps**
- **Memory profiling**
- **Execution statistics** (line hit counts, instruction samples)
- **Expression evaluation** in script context

## Basic Usage

### Non-Interactive Mode (Run and Analyze)

Run a script and collect execution statistics without pausing:

```powershell
.\OffensiveLuaEmbedded.exe --no-interactive .\memorysearch_rtl.lua
```

**Output includes:**

- Memory usage summary
- Instruction sample counts
- Hot lines (most frequently executed)
- All script output

### Interactive Mode (Step-Through Debugging)

Launch with interactive debugger to step through code:

```powershell
.\OffensiveLuaEmbedded.exe --interactive .\test_debug.lua
```

The debugger will pause at the first executable line and display a prompt:

```
[pause] test_debug.lua:2 | local x = 10
(lua-debug)
```

## Command Line Options

| Option                  | Description                              |
| ----------------------- | ---------------------------------------- |
| `--interactive`, `-i`   | Enable interactive debugging (default)   |
| `--no-interactive`      | Run without stepping, collect stats only |
| `--dump-bytecode`, `-b` | Dump chunk bytecode at load (default)    |
| `--no-bytecode`         | Skip bytecode dump                       |
| `--trace-lines`, `-t`   | Log every line execution                 |
| `--count`, `-c`         | Track instruction samples (default)      |
| `--no-count`            | Disable instruction sampling             |
| `--memory`, `-m`        | Show memory summary (default)            |
| `--no-memory`           | Skip memory summary                      |
| `--help`, `-h`          | Show help message                        |

## Interactive Debugger Commands

### Navigation

- **`continue` / `c`** — Resume execution until next breakpoint
- **`step` / `s`** — Execute one Lua line, then pause
- **`quit` / `q`** — Abort execution immediately

### Breakpoints

- **`break [file:]line` / `b [file:]line`** — Set breakpoint
  - Examples:
    - `break 42` — Break at line 42 of current file
    - `break test.lua:15` — Break at line 15 of test.lua
- **`clear [file:]line`** — Remove breakpoint
- **`breakpoints` / `bp`** — List all active breakpoints

### Variable Inspection

- **`locals` / `l`** — Show all local variables in current scope
- **`upvalues` / `up`** — Show upvalues (closure variables) for current function
- **`globals [pattern]` / `g [pattern]`** — List globals, optionally filtered by pattern
  - Example: `globals http` — Show globals containing "http"

### Expression Evaluation

- **`print expr` / `p expr`** — Evaluate expression and show results
  - Example: `print x + y`
- **`eval code` / `exec code` / `x code`** — Execute arbitrary Lua code in current context
  - Example: `eval io.write("Debug message\n")`

### Call Stack & Analysis

- **`stack` / `bt`** — Show current call stack (backtrace)
- **`bytecode` / `bc`** — Dump bytecode for current function
- **`memory` / `mem`** — Display current memory usage
- **`stats`** — Show execution statistics (line hits, instruction count)

### Help

- **`help` / `h`** — Show command list

## Example Debug Session

### 1. Start Interactive Session

```powershell
PS> .\OffensiveLuaEmbedded.exe test_debug.lua
```

**Output:**

```
[info] Interactive debugging enabled. Type 'help' for commands.
[bytecode] test_debug.lua (1234 bytes)
  000000  1B 4C 4A 01 02 ...
[pause] test_debug.lua:2 | local x = 10
(lua-debug)
```

### 2. Inspect Variables

```
(lua-debug) step
[pause] test_debug.lua:3 | local y = 20
(lua-debug) locals
Locals:
  x = 10
(lua-debug) step
[pause] test_debug.lua:4 | local z = x + y
(lua-debug) print x + y
[result] 30
```

### 3. Set Breakpoint

```
(lua-debug) break 15
[info] Breakpoint added at test_debug.lua:15
(lua-debug) continue
Result: 30
[pause] test_debug.lua:15 | local result = factorial(5)
```

### 4. Examine Stack

```
(lua-debug) stack
Stack trace:
  [0] <anonymous> at test_debug.lua:15
(lua-debug) step
[pause] test_debug.lua:8 | if n <= 1 then
(lua-debug) locals
Locals:
  n = 5
(lua-debug) stack
Stack trace:
  [0] factorial at test_debug.lua:8
  [1] <anonymous> at test_debug.lua:15
```

### 5. Continue to Completion

```
(lua-debug) continue
Factorial of 5 is: 120
[memory] total: 256.00 KiB
[summary] Instruction samples: 1234, line events: 89
[summary] Hot lines:
   15 hits  test_debug.lua:11
   10 hits  test_debug.lua:8
    5 hits  test_debug.lua:9
```

## Practical Use Cases

### Debugging memorysearch_rtl.lua

**Quick profiling run:**

```powershell
.\OffensiveLuaEmbedded.exe --no-interactive --no-bytecode .\memorysearch_rtl.lua
```

This shows:

- Which lines are hottest (performance bottlenecks)
- Memory consumption
- Execution completed or error location

**Interactive troubleshooting:**

```powershell
.\OffensiveLuaEmbedded.exe -i .\memorysearch_rtl.lua
```

Then at prompt:

```
(lua-debug) break 125        # Set break at hot line
(lua-debug) continue          # Run to that line
(lua-debug) locals            # Inspect variables
(lua-debug) print regionSize  # Check specific values
(lua-debug) step              # Step through logic
```

### Finding Script Errors

When a script fails, interactive mode stops at the error line:

```powershell
.\OffensiveLuaEmbedded.exe problem_script.lua
```

The debugger shows:

- Exact line where error occurred
- Local variable values at failure point
- Call stack leading to error

Then use:

- `locals` — See what values caused the issue
- `stack` — Understand the call path
- `print expression` — Test hypotheses about the bug

## Script Arguments

Pass arguments to your script after the script name:

```powershell
.\OffensiveLuaEmbedded.exe myscript.lua arg1 arg2 arg3
```

Inside `myscript.lua`, access via `arg` table:

```lua
print(arg[1])  -- "arg1"
print(arg[2])  -- "arg2"
```

## Output Files

- Scripts write their own output (e.g., `memorysearch_rtl.lua` writes to `c:/temp/memoryexploit.log`)
- Debugger statistics appear in console after script completes
- Bytecode dumps appear in console if enabled

## Tips

1. **Start non-interactive first** to see if script completes successfully
2. **Use `--trace-lines`** to see every line executed (verbose but comprehensive)
3. **Set breakpoints early** in interactive mode if you know problem area
4. **Check `stats` frequently** to identify performance issues
5. **Use `print` commands** to test fix ideas without editing the script

## Comparison with luajit.exe

| Feature             | luajit.exe | OffensiveLuaEmbedded.exe |
| ------------------- | ---------- | ------------------------ |
| Run scripts         | ✓          | ✓                        |
| Interactive REPL    | ✓          | ✗ (use debugger instead) |
| Step debugging      | ✗          | ✓                        |
| Breakpoints         | ✗          | ✓                        |
| Variable inspection | ✗          | ✓                        |
| Profiling           | ✗          | ✓ (line hits, memory)    |
| Bytecode dump       | ✗          | ✓                        |
| Call stack          | ✗          | ✓                        |

## Troubleshooting

**Script doesn't pause in interactive mode:**

- Check that script has executable Lua code (not just comments/empty)
- Use `--trace-lines` to see if any lines execute

**"Missing Lua script path" error:**

- Ensure script path is provided: `.\OffensiveLuaEmbedded.exe script.lua`
- Use quotes if path has spaces: `".\my scripts\test.lua"`

**Memory usage high:**

- This is normal for scripts that scan large memory regions
- Check the `[memory]` output to see actual consumption
- Profiler overhead adds ~100-200 KB

**Hot lines show FFI/C code:**

- This is expected for scripts using FFI extensively
- Focus on Lua source lines for optimization targets

---

**Built:** October 2025  
**Compatible with:** LuaJIT 2.x scripts, FFI-based code, OffensiveLua toolkit scripts
