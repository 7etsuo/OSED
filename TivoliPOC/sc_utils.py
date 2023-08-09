"""
    Example Usage:

    # Sample ROP gadget addresses (offsets from the base address) - these should be replaced with real gadget addresses
    POP_EAX = 0x12345
    POP_EBX = 0x23456
    POP_ECX = 0x34567
    XCHG_EAX_ECX = 0x45678
    INC_EAX = 0x56789

    # Let's say the base address of the binary is 0x08048000
    BASE_ADDR = 0x08048000

    # Create a ROP chain object with the base address
    rop = RopChain(base=BASE_ADDR)

    # Add gadgets to the ROP chain (the gadget addresses are treated as offsets from the base address)
    rop += POP_EAX
    rop.append_raw(0xdeadbeef)  # An example value to be placed in the EAX register
    rop += POP_EBX
    rop.append_raw(0xcafebabe)  # An example value to be placed in the EBX register
    rop += POP_ECX
    rop += XCHG_EAX_ECX
    rop += INC_EAX

    # Check the ROP chain for any bad characters (e.g., null bytes)
    sanity_check(rop.chain, [0x00])

    # Connect to a vulnerable server
    target_ip = "127.0.0.1"
    target_port = 12345
    sock = get_connection(target_ip, target_port)

    # Send the ROP chain to the server
    sock.sendall(rop.chain)

    # Close the connection
    sock.close()
"""

from struct import pack
from typing import List


class RopChain:
    def __init__(self, base=None, pack_str='<I', chain=b''):
        self.chain = chain
        self.base = base or 0
        self.pack_str = pack_str

    def __iadd__(self, other):
        if isinstance(other, int):
            self.chain += self._pack_32(self.base + other)
        elif isinstance(other, bytes):
            self.chain += other
        else:
            raise NotImplementedError
        return self

    def __len__(self) -> int:
        return len(self.chain)

    @staticmethod
    def p32(address) -> bytes:
        return pack('<I', address)

    def _pack_32(self, address) -> bytes:
        return pack(self.pack_str, address)

    def append_raw(self, address):
        """ just ignore the base address; useful for actual values in conjunction with pop r32 """
        self.chain += pack(self.pack_str, address)


def sanity_check(byte_str: bytes, bad_chars: List[int]):
    baddies = list()

    for bc in bad_chars:
        if bc in byte_str:
            print(f"[!] bad char found: {hex(bc)}")
            baddies.append(bc)

    if baddies:
        print(f"[=] {byte_str}")
        print("[!] Remove bad characters and try again")
        raise SystemExit
