# Offensive Lua

Offensive Lua is a collection of offensive security scripts for performing offensive
security tasks under Lua. You can test with "luajit.exe binrun.lua". These scripts
run with Lua and FFI under Microsoft Windows to perform common operations such as:

- Run an EXE
- Bypass UAC
- Exploit File or Registry
- Common Tasks

Lua is a lesser used but useful post-exploitation scripting language, this repository contains
common actions that you may wish to achieve using Lua w/FFI on Windows hosts.

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
