#!/usr/bin/env python
from socket import *
from telnetlib import *

SERVER = ("125.138.166.180", 11040)

s = socket(AF_INET, SOCK_STREAM)
s.connect(SERVER)

flag = ""
#flag = "key_is_Wh4t_i5_5trCmp!?"

for i in range(23):
	print "now flag " + flag
	for j in range(0x1f, 0x7e):
		s.send(flag + chr(j) + "\n")

		a = s.recv(10) + s.recv(10)
		print a + ":" + chr(j)

		if a == "no!\n":
			flag += chr(j-1)
			break

print flag 