from sage.all import *
from ast import literal_eval

sol_vec = []

with open("output.txt", "r") as f:
    for i, line in enumerate(f.readlines()):
        if i == 11:
            enc = literal_eval(line)
            iv = enc[0]
            ct = enc[1]
            break
        if i == 10:
            sol_vec.append(Integer(line))
        else:
            sol_vec.append(Integer(line) - 1)

from itertools import product
k = 10
for bla in product([1, -1], repeat=k):
    System = []
    for i in range(k):
        row = [0 for _ in range(k+1)]
        row[0] = bla[i]
        row[i+1] = 1
        System.append(row)

    last_row = [1 for _ in range(k+1)]
    last_row[0] = 0
    System.append(last_row)

    try:
        sol = Matrix(System).solve_right(vector(sol_vec))
    except:
        continue
    if all(ell in ZZ for ell in sol):
        if all([is_pseudoprime(ell) for ell in sol[1:]]):
            print("GOT IT!")
            print(sol)
            break

import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

sha1 = hashlib.sha1()
sha1.update(str(prod(sol[1:])).encode('ascii'))
key = sha1.digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
print(unpad(cipher.decrypt(bytes.fromhex(ct)), 16))