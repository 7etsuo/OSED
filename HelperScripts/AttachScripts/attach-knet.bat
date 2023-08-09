@REM tool by SilverStr
@REM Drop this attach-knet.bat onto your Desktop:

runas /user:CLIENT\Administrator /savecred "taskkill /IM Knet.exe /F"
runas /user:CLIENT\Administrator /savecred "cscript \"C:\Users\OffSec\Desktop\launchknet.vbs\""
timeout 4
runas /user:CLIENT\Administrator /savecred "\"C:\Program Files\Windows Kits\10\Debuggers\x86\windbg.exe\" -WF C:\windbg_custom.WEW -g -pn knet.exe"


@REM Then double click attach-knet.bat anytime you want to reset your env for a new cycle. 
@REM Do NOT touch anything once you double click, as the VBS is confguring KNet for you and is expecting the active windows properly.