# Offensive Lua

Offensive Lua is a comprehensive collection of offensive security and red team scripts written in Lua with FFI (Foreign Function Interface). These scripts leverage the power and flexibility of LuaJIT on Microsoft Windows to perform advanced penetration testing and red teaming operations.

## Key Capabilities

- **Execution & Deployment**: Download, execute, and deploy payloads
- **Privilege Escalation**: UAC bypass techniques and privilege escalation
- **System Interaction**: Files, memory manipulation, networking, and registry operations
- **Remote Access**: Bind shells and reverse connections
- **Reconnaissance**: System enumeration and information gathering alternatives
- **Surveillance**: Audio/video capture, keylogging, and screenshot capabilities
- **Credential Harvesting**: Password vault dumping and credential extraction

## Why Lua for Offensive Security?

Lua is an exceptional choice for post-exploitation and offensive security scripting due to several strategic advantages:

- **Stealth & Evasion**: Lesser-known language with minimal security product signatures
- **Lightweight Footprint**: Extremely small runtime with minimal system impact
- **Memory Execution**: Runs interpreted or as bytecode directly from memory
- **Native Integration**: FFI enables direct interaction with Windows APIs and system libraries
- **Rapid Development**: Simple syntax allows for quick script adaptation and customization
- **Obfuscation Ready**: Trivial to obfuscate and modify for evasion purposes
- **JIT Performance**: Just-in-time compilation provides near-native execution speed
- **Embedding Flexibility**: Easy to embed within other applications or frameworks

|             Filename             | Description                                         |
| :------------------------------: | :-------------------------------------------------- |
|           bin2hex.lua            | Convert a binary to hex for binrun.lua              |
|            binrun.lua            | Writes a hex of EXE to a random location and exec's |
|          bindshell.lua           | bind a shell on TCP port 5000                       |
|  ComputerDefaultsUACBypass.lua   | Bypass UAC restrictions via ms-settings             |
|           console.lua            | Console App Example                                 |
|         downloadexec.lua         | Download & Exec over HTTP                           |
|    downloadexec_UACbypass.lua    | Download & BypassUAC & Exec over HTTP               |
|          efspotato.lua           | Incomplete efspotato                                |
|          eventcode.lua           | Example of Windows Event handler                    |
|          filewrite.lua           | Write a file                                        |
|            howami.lua            | Always whoami.exe never howami.lua                  |
|       keyboard_capture.lua       | Capture keyboard input and keystrokes               |
|         listprocess.lua          | List running processes                              |
|         memorysearch.lua         | searches memory for passwords                       |
|   memorysearch_stringdump.lua    | Dump strings from process memory                    |
|          messagebox.lua          | MessageBox Example                                  |
|      microphone_capture.lua      | Capture microphone audio                            |
|     OffensiveLuaEmbedded.exe     | Embedded LuaJIT interpreter with debugging features |
|           regread.lua            | Read from Registry                                  |
|           regwrite.lua           | Write to Registry                                   |
|         regwritedel.lua          | Write and Delete from Registry                      |
|           rickroll.lua           | Open a browser on URL                               |
|            runcmd.lua            | Run a command popen                                 |
|           runcmd2.lua            | Run a command os.execute                            |
|          runswhide.lua           | Run a command via CreateProcess with SW_HIDE        |
|          screenshot.lua          | Capture desktop screenshot                          |
| screenshot_withhiddenwindows.lua | Capture screenshot including hidden windows         |
|  uac_bypass_bluetooth_win10.lua  | Bypass UAC via Bluetooth on Windows10               |
|          vaultdump.lua           | Dump Windows Credential Manager and Password Vault  |
|  webcam_picture_directshow.lua   | Capture webcam picture using DirectShow             |
|    webcam_picture_simple.lua     | Capture webcam picture using simple method          |
|   webcam_video_directshow.lua    | Record webcam video using DirectShow                |
|     webcam_video_simple.lua      | Record webcam video using simple method             |

## Usage

The OffensiveLuaEmbedded.exe interpreter provides advanced debugging and execution capabilities essential for red team operations and offensive security development. These features enable operators to analyze script behavior, optimize performance, troubleshoot issues in hostile environments, and develop evasion techniques:

**Why Use Advanced Debugging?**

- **Single-step execution**: Step through scripts line-by-line to understand API interactions and identify detection points
- **Memory analysis**: Monitor memory usage patterns to minimize forensic footprints and optimize stealth
- **Bytecode inspection**: Analyze compiled bytecode for obfuscation effectiveness and anti-analysis techniques
- **Trace analysis**: Review script execution flow to identify bottlenecks or suspicious behavior patterns
- **Interactive debugging**: Test script modifications in real-time during engagements without recompilation
- **Performance profiling**: Optimize scripts for speed and resource efficiency in target environments

```
Offensive LuaJIT Debugger
Usage: OffensiveLuaEmbedded.exe [options] <script.lua> [args...]

Options:
  --interactive, -i      Enable interactive debugging mode.
  --dump-bytecode, -d    Create .lbin bytecode file with hexdump.
  --trace, -t            Trace every executed line.
  --count, -c            Track instruction samples.
  --memory, -m           Print memory summary after execution.
  --vm, -v               Instrument VM with timing and diagnostics.
  --version              Show version information.
  --help, -h             Show this help message.
```

### Example Usage

For instance, to read all the credentials from your current execution context in Microsoft Password Vault, run:

```bash
.\OffensiveLuaEmbedded.exe vaultdump.lua
```

This demonstrates the power of Offensive Lua - with a single command, you can dump the Windows credential store and extract stored passwords, tokens, and authentication data. The script leverages Windows APIs through FFI to access the Password Vault that applications use to securely store user credentials.

# OffensiveLuaEmbedded

An example Visual Studio 2022 project that can be used to embed LuaJIT into a binary for the purposes of running scripts. You will need to checkout the git submodules to get the latest LuaJIT branch.

**Important**: Read the comments throughout the source code to understand embedding nuances and pitfalls to avoid. The comments contain critical implementation details and best practices for successful LuaJIT embedding.

# More

You can learn more about Hacker House and Offensive Lua at our website:

- https://hacker.house/services

# License

These files are available under a Attribution-NonCommercial-NoDerivatives 4.0 International license.
