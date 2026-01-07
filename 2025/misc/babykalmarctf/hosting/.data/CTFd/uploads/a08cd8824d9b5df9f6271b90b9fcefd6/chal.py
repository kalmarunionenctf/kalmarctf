from Crypto.Util.number import getPrime


with open("flag.txt", "rb") as f:
    flag = f.read()

flag = int.from_bytes(flag, 'big')

e = 65537

p,q,r = [getPrime(512) for _ in "pqr"]

print(f'n1 = {p*q}')
print(f'c1 = {pow(flag, e, p*q)}')
print(f'n2 = {q*r}')
print(f'c2 = {pow(flag, e, q*r)}')
print(f'n3 = {r*p}')
print(f'c3 = {pow(flag, e, r*p)}')