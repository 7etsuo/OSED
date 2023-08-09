import ctypes
import struct

DEBUG = True

LOW_QWORD   = 1
HIGH_QWORD  = 0

qword_9ED208 = [0, 0] # dq 009ed208 L1 ; global stored here

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

    EDX = EAX = ESI = EDI = EBX = EDX = ECX = 0

    EBX = ctypes.c_uint32(qword_9ED208[LOW_QWORD]).value                # mov ebx, dword ptr qword_9ED208+4
    ESI = ctypes.c_uint32(qword_9ED208[HIGH_QWORD]).value               # mov esi, dword ptr qword_9ED208
    EAX = EBX                                                           # mov eax, ebx
    ECX = ctypes.c_uint32(0x15A).value                                  # mov ecx, 15Ah
    EBX = ctypes.c_uint32(0x4E35).value                                 # mov ebx, 4E35h
    if EAX != 0:
        EDX = ctypes.c_uint32((EAX * EBX) >> 32).value
        EAX = ctypes.c_uint32(EAX * EBX).value
    temp = ctypes.c_uint32(EAX).value                                   # xchg eax, ecx
    EAX  = ctypes.c_uint32(ECX).value                                   # xchg eax, ecx
    ECX  = ctypes.c_uint32(temp).value                                  # xchg eax, ecx
    EDX  = ctypes.c_uint32((EAX * ESI) >> 32).value                     # Store high bits in EDX for multiplication
    EAX  = ctypes.c_uint32(EAX * ESI).value                             # mul esi
    EAX  = ctypes.c_uint32(EAX + ECX).value                             # add eax, ecx
    temp = ctypes.c_uint32(EAX).value                                   # xchg eax, esi
    EAX  = ctypes.c_uint32(ESI).value                                   # xchg eax, esi
    ESI  = ctypes.c_uint32(temp).value                                  # xchg eax, esi
    EDX  = ctypes.c_uint32((EAX * EBX) >> 32).value                     # Store high bits in EDX for multiplication
    EAX  = ctypes.c_uint32(EAX * EBX).value                             # mul ebx
    EDX  = ctypes.c_uint32(EDX + ESI).value                             # add edx, esi
    SF   = ctypes.c_uint8(int(bool((EAX+1) & 0x80000000))).value        # sign flag
    EAX  = ctypes.c_uint32(EAX + 1).value                               # add eax, 1
    CF   = ctypes.c_uint8(int(bool((EAX+1) & 0x80000000)) ^ SF).value   # carry flag
    EDX  = ctypes.c_uint32(EDX + CF).value                              # adc edx, 0
    EBX  = ctypes.c_uint32(EAX).value                                   # mov ebx, eax
    ESI  = ctypes.c_uint32(EDX).value                                   # mov esi, edx
    qword_9ED208[HIGH_QWORD] = ctypes.c_uint32(EBX).value               # mov dword ptr qword_9ED208, ebx
    qword_9ED208[LOW_QWORD]  = ctypes.c_uint32(ESI).value               # mov dword ptr qword_9ED208+4, esi
    EAX = ctypes.c_uint32(ESI).value                                    # mov eax, esi
    EAX = ctypes.c_uint32(EAX & 0x7fffffff).value                       # and eax, 7fffffffh
    ESI = EBX = 0                                                       # For debugging
    return EAX

def decrypt_bytes(BUFFER_LEN, BUFFER, SEED_VALUE=0x037ba4d4):
    global EDX_GLOBAL

    if BUFFER_LEN == 0:
        return

    STORED_BUFFER = list(BUFFER)    # Convert bytes to list of integers
    XOR_KEY = 0

    EAX = seed_rng(SEED_VALUE)      # call seed_rng
    ECX = SEED_VALUE                # the pop ecx after the call to seed_rng
    EDX = 0                         # xor edx, edx

    for i in range(BUFFER_LEN):
        XOR_KEY = ctypes.c_uint8(get_large_random() % 256).value
        XOR_VAL = ctypes.c_uint8(STORED_BUFFER[i]).value
        STORED_BUFFER[i] = ctypes.c_uint8(XOR_KEY ^ XOR_VAL).value

        if DEBUG:
            print(f'[{i:04}]: {hex(XOR_VAL)[2:]:02} ^ {hex(XOR_KEY)[2:]:02} = {hex(STORED_BUFFER[i])[2:]:02}')

    return bytes(STORED_BUFFER)  # Convert back to bytes

def generate_checksum_value(checkval):
    EDI = ESI = EBX = EDX = ECX = EAX = 0
    # push ebp
    # mov ebp, esp
    # push ecx
    # push ebx
    EAX = ctypes.c_uint32(checkval).value           # mov eax, dword ptr [ebp+0ch]
    ECX = ctypes.c_uint16(0x00b1).value             # mov ecx, 0b1h
    EDX = 0                                         # xor edx, edx
    # EDX:EAX = div ecx
    EDX = ctypes.c_uint32(EAX % ECX).value          # EDX = remainder
    EAX = ctypes.c_uint32(int(EAX / ECX)).value     # EAX = dividend and quotient
    # ECX = divisor
    ECX = ctypes.c_int32(EDX * 0x00ab).value        # imul ecx, edx, 0abh
    EAX = ctypes.c_uint32(checkval).value           # mov eax, dword ptr [ebp+0ch]
    EBX = ctypes.c_uint16(0x00b1).value             # mov ebx, 0b1h
    EDX = 0                                         # xor edx, edx
    # EDX:EAX = div ebx
    EDX = ctypes.c_uint32(EAX % EBX).value          # EDX = remainder
    EAX = ctypes.c_uint32(int(EAX / EBX)).value     # EAX = quotient && dividend
    # EBX = divisor
    EAX = ctypes.c_uint32(EAX + EAX).value          # add eax, eax
    ECX = ctypes.c_uint32(ECX - EAX).value          # sub ecx, eax 
    result = ECX                                    # mov dword ptr [ebp+result], ecx
    AX = ctypes.c_uint16(result).value              # mov ax, word ptr [ebp - 4]
    AX = ctypes.c_uint16(AX & 0x7fff).value         # and ax, 7fffh
    # pop ebx
    # pop ecx
    # pop ebp
    EAX = ctypes.c_uint32(EAX & 0xFFFF0000).value   # ... test val
    EAX = ctypes.c_uint32(EAX | AX).value           # ... test val
    return AX                                       # retn


def deobfuscate_buffer_with_checksum(initial_checksum, buffer, buffer_len):

    if buffer_len == 0:
        return buffer

    buf = list(buffer) # Convert bytes to list of integers
    EDI = ESI = EBX = EDX = ECX = EAX = 0
    buffer_ptr = buf                 #
    # mov eax, [ebp+buffer]
    # mov [ebp+buffer_ptr], eax
    # push [ebp + initial_checksum]
    # push [ebp + lpThreadParameter]

    checksum = generate_checksum_value(initial_checksum)

    for i in range(buffer_len):
        checksum = generate_checksum_value(checksum)
        buf[i] = ctypes.c_uint8(buf[i] ^ checksum).value

    return bytes(buf) # Convert back to bytes

def main():

    size    = struct.pack('<L', 0xffff1f03) # does not get encoded; this is the size of everything (can be any size we want :D)

    encode  = struct.pack("<L", 0x85aae41b) # checksum needed by second encryption becomes  struct.pack("<L", 0x85aae41b)

    chval   = struct.pack("<L", 0x0000A953) # this is the checksum value that comes after the encryption routines
    sz_ch_1 = struct.pack("<L", 0x7fff8f81) # sz_check_one + sz_check_two need to == size
    sz_ch_2 = struct.pack("<L", 0x7fff8f81) # these 3 values are checked in an if statement after the encryption
    opcodes = encode + chval + sz_ch_1 + sz_ch_2

    # Evaluate expression: 2588 = 00000a1c
    # the value above is the 

    BUFFER = opcodes
    BUFFER += b"A"*0x26
    BUFFER_LEN = len(BUFFER)

    ENCRYPTED  = decrypt_bytes(BUFFER_LEN, BUFFER)

    DEOBSFUCATED = ENCRYPTED[4:]
    DEOBSFUCATED_LEN = len(DEOBSFUCATED)

    icvec = ENCRYPTED[:4]
    initial_checksum = ctypes.c_uint32(icvec[3] << 24 | icvec[2] << 16 | icvec[1] << 8 | icvec[0] << 0).value

    OBSFUCATED = deobfuscate_buffer_with_checksum(initial_checksum, DEOBSFUCATED, DEOBSFUCATED_LEN)

    if DEBUG:

        print("\nBUFFER")
        print_debug(BUFFER)
        print("END BUFFER\n")

        print("ENCRYPTED")
        print_debug(ENCRYPTED)
        print("END ENCRYPTED\n")

        print("OBSFUCATED")
        print(f"checksum:\t{hex(initial_checksum)}")
        print_debug(OBSFUCATED)
        print("OBSFUCATED\n")

if __name__ == '__main__':
    main()
