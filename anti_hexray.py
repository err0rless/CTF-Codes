# ctf.inc0gnito.com Inc0gnito CTF reversing 100pts Anti-Hexray
# ssh anti_hexray@ssh.inc0gnito.com anti_hexray
import paramiko
import string

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("ssh.inc0gnito.com",
				username = "anti_hexray",
				password = "anti_hexray")

flag = ""

while len(flag) != 17: # no infinite loop :(
	for i in string.printable:
		p  = "/home/anti_hexray/anti_hexray \""
		p += flag + i
		p += "\" ; echo $?"

		result = ssh.exec_command(p)[1].readlines()
		# exec_command = stdin, stdout, stderr

		if result:
			if result[0] == "0\n":
				print flag
				flag += i
				break

print "\nLast flag is " + flag
# IcEwAll&Inc0gnito