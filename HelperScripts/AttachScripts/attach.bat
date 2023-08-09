runas /user:CLIENT\Administrator /savecred "net stop \"Sync Breeze Enterprise\""
runas /user:CLIENT\Administrator /savecred "net start \"Sync Breeze Enterprise\""
timeout 1

runas /user:CLIENT\Administrator /savecred "\"C:\Program Files\Windows Kits\10\Debuggers\x86\windbg.exe\" -g -pn syncbrs.exe"