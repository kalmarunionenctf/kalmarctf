#!/usr/bin/env sage

from Crypto.Cipher import ChaCha20
from chal import N, S, L, I
from lattice import reduce_flatter

exec(open("output.txt").read())
v = [int.from_bytes(bytes.fromhex(vi), 'little') for vi in v]
init = int.from_bytes(bytes.fromhex(init), 'little')
flagenc = bytes.fromhex(flagenc)

p = 2^130 - 5
F = GF(p)

lcg_state_mod = 2^128

class PolyCG:
    def __init__(self, r, s, m):
        self.r = int(r)
        self.s = int(s)
        self.m = int(m)

    def next(self):
        out = self.m.to_bytes(16, 'little')[S:S+L]
        self.m = ((((int(lcg_state_mod) + self.m) * self.r) % int(p)) + self.s) % int(lcg_state_mod)
        return out

if False: # Generate test data
    pcg = PolyCG(70780336743613816153812225659359600509, 56788499585436081527915300384963666489, 192029660491211978934898910749546655594)
    init = (pcg.s + (((int.from_bytes(b'init', 'little') + 256^4) * pcg.r) % p)) % 256^I
    v = []
    for i in range(N):
        v.append(int.from_bytes(pcg.next(), 'little'))

    key = b"".join([pcg.next() for _ in range(0, 32, L)])[:32]
    cipher = ChaCha20.new(key=key, nonce=b'\0'*8)
    flagenc = cipher.encrypt(b"A fake flag")
    print(f"flagenc = '{flagenc.hex()}'")

# First step: recover r using a variant of Stern's attack. Since we have two moduli (three really:
# mod p and mod 2^128 inside poly1305, then mod 2^104 for the values given out in the challenge, but
# 2^104 divides 2^128 so only two matter) the attack is less data efficient than Stern's. Estimating
# p as being roughly 16 bytes long, an estimate on the lattice determinant implies that we need
# about 2 * (16 / (L/2))^2 = 8 * 256 / 9 = 228 samples to solve, so I made the challenge give out
# 240 so that there would be enough.

# Length (i.e., degree - 1) of polynomial multiplies of (x - r)*(x - 1) to search for, where r is
# the LCG secret multiplier.
K = 11

leak_start = 256^S
leak_end = 256^(L + S)
high_part_max = floor(p / leak_end)
cost_mod = round(leak_start * p^(1/(K-1)) / high_part_max)

v_mat = matrix(ZZ, [[v[i + j] for j in range(K)] for i in range(N - K + 1)])

# cols: polynomial, wraparounds mod leak_end, wraparounds mod p.
A = block_matrix([
        [leak_start * identity_matrix(K, K),                 zero_matrix(K, N - K + 1),      zero_matrix(K, N - K + 1) ],
        [             zero_matrix(N - K + 1, K),  cost_mod * identity_matrix(N - K + 1),     zero_matrix(N - K + 1)    ],
        [leak_start * v_mat,                      leak_end * identity_matrix(N - K + 1), p * identity_matrix(N - K + 1)]
    ])

basis = reduce_flatter(A.transpose())

R.<x> = F['x']
polys = []
for b in basis:
    if b[:K] == [0] * K:
        continue

    poly = vector(bi // leak_start for bi in b[:K])
    poly = sum(pi * x^i for i, pi in enumerate(poly))
    print(poly)
    polys.append(poly)

    if len(polys) >= 3:
        break

g = gcd(polys)
print(g)
print(g.factor())
print(g.roots())

r = g.roots()[0][0]



# Step 2: Use the hint and r to recover the low bits of s.

s_base = init - ((int.from_bytes(b'init', 'little') + 256^4) * r).lift()



# Step 3: now that we have recovered r, find the initial state and the high bits of s using a
# lattice attack. All the remaining equations are linear (plus modulus operations), so can work as
# one big lattice. However, because it is linear we don't need as much data, so it's much more
# efficient to set
N_ = 30
# and skip the rest of the samples.
#
# This part of the solve is much more complicated than it needs to be, because I spent a long time
# tweaking it trying to get it to work without the hint. I was unable to get it to work without the
# hint, as without it the solution is very underdetermined. Changing s mostly just changes the fixed
# point of the LCG, and the low bits of the fixed point are not visible at all from the samples we
# are given.

# Let x_i = (r*(2^128 + m_{i - 1})) mod p, so that m_i = (x_i + s) mod 2^128.
# cols: 1, (s-s_base)/2^I, x_is (N_), wraparounds mod lcg_state_mod (N_), wraparounds mod leak_end (N_), wraparounds mod p (N_ - 1).
# rows: 1, s, x_is (N_), m_is (N_), m_is mod leak_start (N_), exact update constraints (N_ - 1).
A = [[0 for j in range(1 + 4*N_)] for i in range(1 + 4*N_)]

scale = p * 2^20
cost_s = round(scale / lcg_state_mod)
cost_x_is = round(scale / p)
cost_m_is = round(scale / lcg_state_mod)
cost_mod_leak_start = round(scale / leak_start)
cost_wraparounds_lcg_state_mod = round(scale / (p / lcg_state_mod))
cost_exact = scale * 2^40

# bigger than everything else, to force 1 to become the last vector, and to force it to only be used once.
A[0][0] = 2^10 * cost_exact

A[1][0] = -scale # Use constant offset to push towards middle of range.
A[1][0] += 2*cost_s * s_base
A[1][1] = 2*cost_s * 256^I

for i in range(N_):
    # x_is (N_)
    A[2 + i][0] = -scale # Use constant offset to push towards middle of range.
    A[2 + i][2 + i] = 2 * cost_x_is

    # m_is
    A[2 + 1*N_ + i][0] = -scale # Use constant offset to push towards middle of range.
    A[2 + 1*N_ + i][0] += 2*cost_m_is * s_base
    A[2 + 1*N_ + i][1] = 2*cost_m_is * 256^I
    A[2 + 1*N_ + i][2 + i] = 2*cost_m_is * 1
    A[2 + 1*N_ + i][2 + 1*N_ + i] = 2*cost_m_is * -lcg_state_mod

    # m_is mod leak_start (N_)
    A[2 + 2*N_ + i][0] = -scale # Use constant offset to push towards middle of range.
    A[2 + 2*N_ + i][0] += 2*cost_mod_leak_start * -leak_start * v[i + N - N_]
    A[2 + 2*N_ + i][0] += 2*cost_mod_leak_start * s_base
    A[2 + 2*N_ + i][1] = 2*cost_mod_leak_start * 256^I
    A[2 + 2*N_ + i][2 + i] = 2*cost_mod_leak_start * 1
    A[2 + 2*N_ + i][2 + 1*N_ + i] = 2*cost_mod_leak_start * -lcg_state_mod
    A[2 + 2*N_ + i][2 + 2*N_ + i] = 2*cost_mod_leak_start * -leak_end

    # exact update constraints
    # x_{i+1} = (r*(2^128 + m_i)) mod p
    if i < N_ - 1:
        A[2 + 3*N_ + i][0] = cost_exact * (r * lcg_state_mod).lift()
        A[2 + 3*N_ + i][0] += cost_exact * r.lift() * s_base
        A[2 + 3*N_ + i][1] = cost_exact * r.lift() * 256^I
        A[2 + 3*N_ + i][2 + i] = cost_exact * r.lift()
        A[2 + 3*N_ + i][2 + 1*N_ + i] = cost_exact * -(r * lcg_state_mod).lift()
        A[2 + 3*N_ + i][2 + i + 1] = cost_exact * -1
        A[2 + 3*N_ + i][2 + 3*N_ + i] = cost_exact * -p

A = matrix(ZZ, A)
#sol = vector(reduce_flatter(A.transpose())[-1])
sol = A.transpose().LLL()[-1]
if sol[0] < 0:
    sol = -sol
print(sol)

assert sol[0] == A[0][0]
for i in range(2+3*N_, 1+4*N_):
    assert(sol[i] == 0)

s = (sol[1] + scale) // (2 * cost_s)
m_last = (((sol[2 + N_ - 1] + scale) // (2 * cost_x_is)) + s) % lcg_state_mod
print(f"{s = }, {m_last = }")
pcg_guess = PolyCG(r, s, m_last)
pcg_guess.next()



# Step 4: use the reconstructed lcg to get the key and decrypt the flag.

key = b"".join([pcg_guess.next() for _ in range(0, 32, L)])[:32]
cipher = ChaCha20.new(key=key, nonce=b'\0'*8)
flag = cipher.decrypt(flagenc)
print(f"{flag = }")
