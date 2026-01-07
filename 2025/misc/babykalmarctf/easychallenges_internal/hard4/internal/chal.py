
import os

def xor(a,b):
    res = []
    for i in range(len(a)):
        res.append(a[i]^b[i])
    return bytes(res)


with open("flag.txt", "rb") as f:
    flag = f.read()

mask = os.urandom(len(flag))

with open("output.txt", "w") as f:
    f.write(xor(flag,mask).hex())