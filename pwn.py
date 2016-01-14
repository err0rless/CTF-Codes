import socket		# socket connect
import telnetlib	# telnet connect
import paramiko		# ssh connect
import struct		# pack or unpack the data

# socket
def conns(Address, Port_number):
	# Connect Socket
	Sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	Sock.connect((Address, Port_number))

	return Sock

# socket, telnetlib
def connst(Address, Port_number):
	# Connect Socket & Telnet
	Sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	Sock.connect((Address, Port_number))
	Telnet = telnetlib.Telnet()
	Telnet.sock = Sock

	return Sock, Telnet

# paramiko, SSH
def connssh(Address, LoginID, LoginPW, portN):
	# Connect SSH, using paramiko.
	# install from http://www.paramiko.org/
	# ex) ssh.exec_command(p)[1].readlines()
	# exec_command = [stdin, stdout, stderr]
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(Address, port=portN, username=LoginID,password=LoginPW)

	return ssh

def shell(s, t="none", end_str="ISQhQCMkIUAjJHRpaHNfaXNfZGVmYXVsdF9lbmRfc3RyIUAjISQhQA=="):
	if t == "none":
		t = telnetlib.Telnet()
		t.sock = s

	while True:
		cmd = raw_input("$ ")
		if cmd == "exit": break
		elif cmd == "quit": break
		elif cmd == "": cmd = "echo ''"

		s.send(cmd + "; echo " + end_str + "\n")
		print t.read_until(end_str + "\n")[:-len(end_str)-2]

	return 1

def toUpper(buf=""):
	r = ""
	for i in buf:
		if (ord(i) >= ord('a')) and (ord(i) <= ord('z')):
			r += chr(ord(i) - 32)
		else:
			r += i
	return r

def toLower(buf=""):
	r = ""
	for i in buf:
		if (ord(i) >= ord('A')) and (ord(i) <= ord('Z')):
			r += chr(ord(i) + 32)
		else:
			r += i
	return r

# data dump
def dump(buf):
	# Dump the Data, No return value
	i = 1
	hexfmt = '%02x '
	posfmt = '%08x | '
	hexstr = ''
	asciistr = ''
	pos = 0x00000000;

	hexstr += posfmt % pos;
	for x in buf:
		hexstr += hexfmt % ord(x)
		if (ord(x) > 0x21 and ord(x) < 0x7E):
			asciistr += x;
		else:
			asciistr += '.';

		if (i % 16) == 0:
			hexstr += '| '
			hexstr += asciistr
			hexstr += '\n'
			asciistr = ''

			pos += 0x10;
			hexstr += posfmt % pos;
			i = 0
		i += 1

	if (i % 16) != 0:
		j = 16 - i + 1
		while j != 0: 
			hexstr += "   "
			j -= 1

		hexstr += '| '
		hexstr += asciistr
		hexstr += '\n'

	print hexstr,