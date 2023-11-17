# Offensive Lua

Offensive Lua is a collection of offensive security scripts written in Lua with FFI.
The scripts run with LuaJIT on Microsoft Windows to perform common red teaming tasks.

- Download and/or Run an EXE
- Bypass UAC
- Files, Memory, Networking & Registry
- Bind a shell
- whoami.exe alternatives

Lua is a lesser used but very useful choice for post-exploitation scripting language. It's
flexible, lightweight, easy to embed, runs interpreted or as bytecode from memory and allows
for JIT to interact with the host OS libraries. It is also trivial to obfuscate and is
very fast to learn and adapt.

|            Filename            | Description                                         |
| :----------------------------: | :-------------------------------------------------- |
|          bin2hex.lua           | Convert a binary to hex for binrun.lua              |
|           binrun.lua           | Writes a hex of EXE to a random location and exec's |
|         bindshell.lua          | bind a shell on TCP port 5000                       |
| ComputerDefaultsUACBypass.lua  | Bypass UAC restrictions via ms-settings             |
|          console.lua           | Console App Example                                 |
|        downloadexec.lua        | Download & Exec over HTTP                           |
|   downloadexec_UACbypass.lua   | Download & BypassUAC & Exec over HTTP               |
|         efspotato.lua          | Incomplete efspotato                                |
|         eventcode.lua          | Example of Windows Event handler                    |
|         filewrite.lua          | Write a file                                        |
|           howami.lua           | Always whoami.exe never howami.lua                  |
|           luajit.exe           | LuaJIT compiled from our internal source tree.      |
|        memorysearch.lua        | searches memory for passwords                       |
|         messagebox.lua         | MessageBox Example                                  |
|          regread.lua           | Read from Registry                                  |
|          regwrite.lua          | Write to Registry                                   |
|        regwritedel.lua         | Write and Delete from Registry                      |
|          rickroll.lua          | Open a browser on URL                               |
|           runcmd.lua           | Run a command popen                                 |
|          runcmd2.lua           | Run a command os.execute                            |
|         runswhide.lua          | Run a command via CreateProcess with SW_HIDE        |
| uac_bypass_bluetooth_win10.lua | Bypass UAC via Bluetooth on Windows10               |

# OffensiveLuaEmbedded

An example visual studio 2022 project that can be used to embed LuaJIT into a binary for
the purposes of running scripts. You will need to checkout the git submodules to get
the latest LuaJIT branch.

# More

You can learn more about Hacker House and Offensive Lua at our website:

- https://hacker.house/services

# License

These files are available under a Attribution-NonCommercial-NoDerivatives 4.0 International license.
