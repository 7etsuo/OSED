import ctypes
import struct

LOW_QWORD   = 1
HIGH_QWORD  = 0

qword_9ED208 = [0, 0] # dq 009ed208 L1 ; global stored here 

def seed_rng(seed_value):
    global qword_9ED208 # we need this to modify the global otherwise it's const
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
 

def decrypt_bytes(BUFFER_LEN, BUFFER, SEED_VALUE=0x037ba4d4, debug=False):
    global EDX_GLOBAL 

    STORED_BUFFER = list(BUFFER)    # Convert bytes to list of integers
    XOR_KEY = 0

    if BUFFER_LEN == 0: # this wont happen, but we may as well replicate the behavior of the application
        return

    STORED_BUFFER = list(BUFFER)    # Convert bytes to list of integers
    EAX = seed_rng(SEED_VALUE)      # call seed_rng
    ECX = SEED_VALUE                # the pop ecx after the call to seed_rng
    EDX = 0                         # xor edx, edx

    for i in range(BUFFER_LEN):
        # loop_start
        XOR_KEY = ctypes.c_uint8(get_large_random() % 256).value
        XOR_VAL = ctypes.c_uint8(STORED_BUFFER[i]).value
        STORED_BUFFER[i] = ctypes.c_uint8(XOR_KEY ^ XOR_VAL).value

        if debug: 
            print(f'[{i:04}]: {hex(XOR_VAL)[2:]:02} ^ {hex(XOR_KEY)[2:]:02} = {hex(STORED_BUFFER[i])[2:]:02}')

    BUFFER = bytes(STORED_BUFFER)  # Convert back to bytes

    if debug:
        count = 0
        for i in BUFFER:
            if count % 16 == 0:
                print(f"{count:04}:\t", end = "")
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
    b  = struct.pack("<L" ,0x00d8c9f4) 
    b += struct.pack("<L", 0xca20b55b)
    b += struct.pack("<L", 0xec4157e8)
    b += struct.pack("<L", 0x12daa0f2)
    b += struct.pack("<L", 0x44f26e97) 
    b += struct.pack("<L", 0x27ab04ee) 
    b += struct.pack("<L", 0xfd7f1ea9)
    b += struct.pack("<L", 0xc0c85d74)
    b += struct.pack("<L", 0x4934589f) 
    b += struct.pack("<L", 0x99f2fc50)
    
    BUFFER = b
    BUFFER_LEN = len(BUFFER)

    decrypt_bytes(BUFFER_LEN, BUFFER)

if __name__ == '__main__':
    main()

