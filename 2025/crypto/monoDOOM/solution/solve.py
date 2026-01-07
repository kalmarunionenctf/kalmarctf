from sage.all import *
from chal import ladder, double, derive_secret
import itertools

# this is the correct differential addition from the cubical torsor point of view
def cubical_diff_add(P, Q, PmQ):
    XP, ZP = P
    XQ, ZQ = Q
    XPmQ, ZPmQ = PmQ
    a=XP+ZP
    b=XP-ZP
    c=XQ+ZQ
    d=XQ-ZQ
    da = d*a
    cb = c*b
    dapcb = da+cb
    damcb = da-cb
    XPQ=dapcb*dapcb / XPmQ
    ZPQ=damcb*damcb / ZPmQ
    return (XPQ/4, ZPQ/4)

# the cubical ladder will be used to compute our canonical lift
def cubical_ladder(A24, P, n):
    n = abs(n)
    P1, P2 = (1, 0), P
    if n == 0:
        return P1, P2
    for bit in bin(n)[2:]:
        Q = cubical_diff_add(P2, P1, P)
        if bit == "1":
            P2 = double(A24, P2)
            P1 = Q
        else:
            P1 = double(A24, P1)
            P2 = Q
    return P1

def ratio(P, Q):
    XP, ZP = P
    XQ, ZQ = Q
    if XP == 0:
        assert XQ == 0
        return (ZQ/ZP)
    else:
        l=XQ/XP
        assert (ZQ == l*ZP)
        return l

def monodromy_atk(F, ell, A, G, P):
    p = F.characteristic()
    A24=(A+2)/4

    xG = G[0]

    u = crt([0,1], [p-1, ell])
    Gthilde = cubical_ladder(A24, G, u) # "Canonical lift"
    Pthilde = cubical_ladder(A24, P, u) # "Canonical lift"

    l1 = ratio(Gthilde, G)
    l2 = ratio(Pthilde, P)

    zeta = F.multiplicative_generator()
    print("Solving dlogs")
    print(factor(p-1))
    #dlp_x = Mod((4*xG).log(zeta),p-1)
    dlp_x = (4*xG).log(zeta)
    print("Done")
    dlp_l2 = Mod(l2.log(zeta),p-1)
    print("Done")
    dlp_l1 = Mod(l1.log(zeta),p-1)
    print("Done")

    # l = len(bin(ord_G)) - k for small k
    l = 193

    #assert dlp_x*m*(2**l-m)+dlp_l1*m**2 == dlp_l2

    crt_mods = []
    crt_ins = []
    for ell, e in factor(p-1):
        print(f"Doing factor: {ell, e}")
        #if ell == 2: #Skip 2 because annoying
        #    continue
        R = Integers(ell**e)["X"]
        X=R.gen()
        
        f = X**2*(dlp_l1-dlp_x)+2**l*dlp_x*X - dlp_l2
        #print(ell, e)
        #print(dlp_l1, dlp_x, dlp_l2)
        if f.degree() == -1:
            crt_ins.append([Integer(a) for a in range(ell**e)])
        else:
            rts = [Integer(r) for r in f.roots(multiplicities=False)]
            assert len(rts) > 0
            crt_ins.append(rts)
        crt_mods.append(ell**e)
    
    for comb in itertools.product(*crt_ins):
        rec_m = crt(list(comb), crt_mods)
        print(rec_m)
        rec_P = ladder(A24, G, rec_m)
        if rec_P[0]/rec_P[1] == P[0]/P[1]:
            print("FOUND!!!")
            return rec_m
    
    assert False, "Didnt work :c"

p = 340824640496360275329125187555879171429601544029719477817787
F = GF(p)
A = F(285261811835788437932082156343256480312664037202203048186662)
            
G = (F(2024), F(1))
ord_G = 42603080062045034416140648444405950943345472415479119301079

from ast import literal_eval

with open("output.txt", "r") as f:
    f.readline()
    p_A = [F(c) for c in literal_eval(f.readline())]
    f.readline()
    p_B = [F(c) for c in literal_eval(f.readline())]
    iv, ct = literal_eval(f.readline())

print(p_A)
s_A = monodromy_atk(F, ord_G, A, G, p_A)

ss = derive_secret(A, p_B, s_A)

import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

sha1 = hashlib.sha1()
sha1.update(str(ss).encode('ascii'))
key = sha1.digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
print(unpad(cipher.decrypt(bytes.fromhex(ct)), 16))