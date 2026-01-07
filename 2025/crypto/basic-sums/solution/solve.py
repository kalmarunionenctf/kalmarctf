from pwn import remote
from Crypto.Util.number import long_to_bytes
from sage.all import crt

results = []
mods = []

for i in range(3,257):
    # with process(["python3 chal.py"], shell=True, level="debug") as rem:
    with remote("127.0.0.1", 2256, level="debug") as rem:
        rem.recvuntil(b'Give me a base!')
        rem.sendline(str(i).encode())
        rem.recvuntil(b'Here you go! ')
        result = int(rem.readline().strip())
        results.append(result)
        mods.append(i-1)

res = crt(results,mods)
print(res)
print(long_to_bytes(res).decode())