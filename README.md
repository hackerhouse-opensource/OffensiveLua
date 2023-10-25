# Offensive Lua

Offensive Lua is a collection of offensive security scripts written in Lua with FFI. 
The scripts run with LuaJIT (v2.0.5) on Microsoft Windows to perform common tasks.

- Run an EXE
- Bypass UAC
- File, Networking or Registry
- Common Tasks (e.g. bind a shell)

Lua is a lesser used but very useful choice for post-exploitation scripting language for
numerous reasons, it's bytecode interpreted via a virtual machine, supports JIT to native, 
this repository contains common actions that you may wish to achieve using Lua w/FFI on
Windows.

|            Filename            | Description                                         |
| :----------------------------: | :-------------------------------------------------- |
|          bin2hex.lua           | Convert a binary to hex for binrun.lua              |
|           binrun.lua           | Writes a hex of EXE to a random location and exec's |
|         bindshell.lua          | bind a shell on TCP port 5000                       |
| ComputerDefaultsUACBypass.lua  | Bypass UAC restrictions via ms-settings             |
|          console.lua           | Console App Example                                 |
|        downloadexec.lua        | Download & Exec over HTTP                           |
|   downloadexec_UACbypass.lua   | Download & BypassUAC & Exec over HTTP               |
|         filewrite.lua          | Write a file                                        |
|           luajit.exe           | LuaJIT compiled from our internal source tree.      |
|         messagebox.lua         | MessageBox Example                                  |
|          regread.lua           | Read from Registry                                  |
|          regwrite.lua          | Write to Registry                                   |
|        regwritedel.lua         | Write and Delete from Registry                      |
|          rickroll.lua          | Open a browser on URL                               |
|           runcmd.lua           | Run a command popen                                 |
|          runcmd2.lua           | Run a command os.execute                            |
|         runswhide.lua          | Run a command via CreateProcess with SW_HIDE        |
| uac_bypass_bluetooth_win10.lua | Bypass UAC via Bluetooth on Windows10               |

# License

These files are available under a Attribution-NonCommercial-NoDerivatives 4.0 International license.
