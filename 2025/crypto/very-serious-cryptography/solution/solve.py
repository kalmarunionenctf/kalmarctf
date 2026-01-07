#import os
#os.environ['TERM'] = 'xterm-256color'
#os.environ['TERMINFO'] = '/usr/share/terminfo'
import pwn
#import itertools
#import hashlib 
#pwn.context.log_level = 'info'

#r = pwn.process(["python", "./chal.py"])

HOST, PORT = 'localhost', 2257
r = pwn.remote(HOST, PORT)

r.recvuntil(b"Recipient name: ")
r.sendline(b'aaaaaaaaaaa\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10')
r.recvuntil(b": ")
data = bytes.fromhex(r.recvline().decode())
xor1 = b"Dear aaaaaaaaaaa"
enc10s = pwn.xor(data[16:32], xor1)

win = False
for i in range(1, 17):
    r.recvuntil(b": ")
    r.sendline(b"a" * i)
    r.recvuntil(b": ")
    data = bytes.fromhex(r.recvline().decode().strip())
    s = pwn.xor(enc10s, data[-16:])

    if b"}" in s:
        s = s.decode()
        print("WIN")
        win = True
        for j in range(1, 5):
            r.recvuntil(b": ")
            print(s)
            r.sendline(b'aaaaaaaaaaa' + s.encode())
            r.recvuntil(b": ")
            data = bytes.fromhex(r.recvline().decode())
            enc_prev = pwn.xor(data[16:32], xor1)
            r.recvuntil(b": ")
            r.sendline(b"a" * i)
            r.recvuntil(b": ")
            data = bytes.fromhex(r.recvline().decode())
            s = pwn.xor(enc_prev, data[-16*(j+1):-16*j]).decode() + s
    
    if win:
        print("FINAL FLAG")
        print(s)
        break