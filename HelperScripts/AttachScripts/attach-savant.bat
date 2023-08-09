runas /user:CLIENT\Administrator /savecred "\"C:\Savant\Savant.exe\""
timeout 1

runas /user:CLIENT\Administrator /savecred "\"C:\Program Files\Windows Kits\10\Debuggers\x86\windbg.exe\" -WF C:\windbg_custom.WEW -g -pn Savant.exe"