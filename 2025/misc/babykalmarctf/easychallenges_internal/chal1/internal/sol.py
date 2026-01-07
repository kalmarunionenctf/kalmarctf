
with open("output.txt", "rb") as f:
    exec(f.read())


from math import gcd
e = 65537

q = gcd(n1,n2)
r = gcd(n2,n3)
p = gcd(n3,n1)

flag1 = pow(c1, pow(e,-1,(p-1)*(q-1)), p*q )
flag2 = pow(c2, pow(e,-1,(r-1)*(q-1)), r*q )
flag3 = pow(c3, pow(e,-1,(p-1)*(r-1)), p*r )


assert flag1 == flag2 == flag3
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(flag1))
print(long_to_bytes(flag2))
print(long_to_bytes(flag3))