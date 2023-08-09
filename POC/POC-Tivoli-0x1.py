import socket
import sys
from struct import pack

buf = pack(">i", 0x64)
buf += bytearray([0x41]*100)

def main():

	server = "192.168.211.10" # sys.argv[1]
	port = 11460

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))

	s.send(buf)
	s.close()

	print("[+] Packet sent")
	sys.exit(0)

if __name__ == "__main__":
 	main()
