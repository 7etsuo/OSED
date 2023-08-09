'  drop this launchknet.vbs onto the Desktop:

Set x = CreateObject("Wscript.Shell")
x.run """C:\Program Files\KNet\KNet.exe"""
Wscript.Sleep(1000)
x.SendKeys("%fo")
Wscript.Sleep(500)
x.SendKeys("%f")
Wscript.Sleep(1000)
x.SendKeys("+({END}){DEL}")
Wscript.Sleep(250)
x.SendKeys("C:\Installers\seh_overflow\extra_mile\02{ENTER}")
Wscript.Sleep(250)
x.SendKeys("index.html{ENTER}")
Wscript.Sleep(250)
x.SendKeys("index.html{ENTER}")
