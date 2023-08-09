import socket
import time


class SnowCrashNet:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.sock = None

    def ConnectServerCreateSocket(self, timeout=10):
        """Create a socket and establish a connection to the server."""
        while True:
            self._CreateSocket(timeout)
            try:
                self.sock.connect((self.ip, self.port))
                break
            except socket.error as e:
                print("[+] Attempting to establish connection")
                time.sleep(timeout)
        print("[+] Connection established")

    def _CreateSocket(self, timeout):
        """Create a new socket and set its timeout."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)

    def GetSocket(self):
        """Return the current socket."""
        return self.sock

    def RecvResponse(self):
        """Receive data from the server and return the response."""
        response = self.sock.recv(0x1024)
        print("[+] Response received")
        return response

    def SendPayload(self, payload):
        """Send the payload to the server."""
        self.sock.send(payload)
        print("[+] Packet sent")
