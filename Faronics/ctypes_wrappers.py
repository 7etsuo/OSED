"""
snowcra5h@icloud.com 
"""
import ctypes, struct

def HIDWORD(qword):
    return qword >> 32

def LODWORD(qword):
    return qword & 0xFFFFFFFF

def WORD0(dword):
    return dword & 0xFFFF

def WORD1(dword):
    return (dword >> 16) & 0xFFFF

def WORD2(qword):
    return (qword >> 32) & 0xFFFF

def WORD3(qword):
    return (qword >> 48) & 0xFFFF

def HIBYTE(word):
    return (word >> 8) & 0xFF

def LOBYTE(word):
    return word & 0xFF

def ROR(x, n, bits = 32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))

def ROL(x, n, bits = 32):
    return ROR(x, bits - n, bits)

def BYTESWAP32(val):
    return ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) | ((val & 0xFF0000) >> 8) | ((val & 0xFF000000) >> 24)

def UINT64(val):
    return ctypes.c_uint64(val).value    

def INT64(val):
    return ctypes.c_int64(val).value

def UINT32(val):
    return ctypes.c_uint32(val).value    

def INT32(val):
    return ctypes.c_int32(val).value

def UINT16(val):
    return ctypes.c_uint16(val).value    

def INT16(val):
    return ctypes.c_int16(val).value

def UINT8(val):
    return ctypes.c_uint8(val).value    

def INT8(val):
    return ctypes.c_int8(val).value

class DWORD64:
    def __init__(self, value=0):
        self.value = ctypes.c_uint64(value).value

    def get_qword(self):
        return self.value

    def set_qword(self, qword_value):
        self.value = ctypes.c_uint64(qword_value).value

    def get_high_dword(self):
        return (self.value >> 32) & 0xFFFFFFFF

    def set_high_dword(self, dword_value):
        self.value = (self.value & 0xFFFFFFFF) | ((dword_value & 0xFFFFFFFF) << 32)

    def get_low_dword(self):
        return self.value & 0xFFFFFFFF

    def set_low_dword(self, dword_value):
        self.value = (self.value & 0xFFFFFFFF00000000) | (dword_value & 0xFFFFFFFF)

    def get_word(self, index):
        if index not in [0, 1, 2, 3]:
            raise ValueError("index must be in [0, 1, 2, 3]")
        return (self.value >> (16 * index)) & 0xFFFF

    def set_word(self, index, word_value):
        if index not in [0, 1, 2, 3]:
            raise ValueError("index must be in [0, 1, 2, 3]")
        self.value = (self.value & ~(0xFFFF << (16 * index))) | ((word_value & 0xFFFF) << (16 * index))

    def get_byte(self, index):
        if index not in range(8):
            raise ValueError("index must be in [0, 7]")
        return (self.value >> (8 * index)) & 0xFF

    def set_byte(self, index, byte_value):
        if index not in range(8):
            raise ValueError("index must be in [0, 7]")
        self.value = (self.value & ~(0xFF << (8 * index))) | ((byte_value & 0xFF) << (8 * index))
