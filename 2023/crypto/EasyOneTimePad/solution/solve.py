#!/usr/bin/env python3

# Writeup/Solve script for "EasyOneTimePad" for KalmarCTF 2023
# by shalaamum

# This was intended as an easy crypto challenge, with the basic idea being that
# "one-time pads" are insecure when reusing the key, but after knowing that one
# still has to figure out how to actually extract the secret.

import itertools
import functools
import sage.all
import pwnlib.tubes.process
import pwnlib.tubes.remote
from challenge import PASS_LENGTH_BYTES

# The following writeup assumes that PASS_LENGTH_BYTES=32 for illustration, for
# the actual challenge PASS_LENGTH_BYTES was chosen to be larger, but this does
# not matter for how the solution works.
# While the password and the key have the same length, the password is
# converted to a hex string before xoring, which doubles its length. Therefore
# the same byte of the key is used twice to encrypt a byte of that hexstring,
# making this not a secure usage of one-time pads, for if r is a random byte
# and we know x ^ r as well as y ^ r, we can recover x ^ y = (x^r) ^ (y^r), so
# the first encryption already allows us to recover the second half of the
# password if we know the first half.
# We can think of this systematically in the following way.
# Let x=(x0, ..., x31) be the least significant halves of the password bytes.
# Then the first encryption allows us, by taking the xors as described above,
# to evaluate Ax, where A is the following matrix (over the ring F2[x]/x^8, in
# which addition corresponds to xor):
# (1 0 ... 0 1 0 ... 0)
# (0 1 ... 0 0 1 ... 0)
# (          .        )
# (          .        )
# (          .        )
# (0 0 ... 1 0 0 ... 1)
# This matrix can be described as the block matrix (id id), with id the
# identity 16x16 matrix.  This is a 16x32 matrix. The second encryption, which
# depends on our permutation, will allow us to add another 16 rows. We will
# then get a 32x32 matrix, and if that matrix were invertible, we would be able
# to recover the least significant four bits of each byte of the password.
# However, it will not be possible to make this matrix invertible: Every row
# contains zeroes and exactly two ones, and linear combinations in
# characteristic 2 of such rows will always have an even number of non-zero
# entries. But it is possible to obtain rank 31, with the additional rows as
# follows:
#  0 1 2 3        16
# (1 1 0 0 ... 0 0 0 0 0 0 0 ... 0 0 0)
# (0 0 1 1 ... 0 0 0 0 0 0 0 ... 0 0 0)
# (         .                         )
# (         .                         )
# (0 0 0 0 ... 1 1 0 0 0 0 0 ... 0 0 0)
# (0 0 0 0 ... 0 0 0 1 1 0 0 ... 0 0 0)
# (0 0 0 0 ... 0 0 0 0 0 1 1 ... 0 0 0)
# (                           .       )
# (                           .       )
# (0 0 0 0 ... 0 0 0 0 0 0 0 ... 1 1 0)
# (0 0 0 0 ... 0 0 1 0 0 0 0 ... 0 0 1)
# This corresponds to the permutation
# 0,2,...,14,17,...,29,16,1,3,...,15,18,...,30,31
# Choosing this permutation the upshot is that fixing e.g. x31 we will be able
# to determine all the other x0,...,x30 from x31. But note that all of these
# must be an ASCII character from '0' through '9' or 'a' through 'f'. So we can
# go through all 16 possibilities for x31 and check if the corresponding values
# of x0, ..., x30 all lie in that that set, and throw away values for x31 in
# which that is not the case. In the end, we guess one of the remaining
# possible values of x31 - hopefully there will actually be only one remaining.

F = sage.all.GF(2)
P = sage.all.PolynomialRing(F, ['x'])

# Simple function to convert integers to polynomials.
# The bits of the integer correspond to the coefficients of the polynomial,
# with the least significant bit corresponding to x^0
@functools.cache
def int_to_polynomial(value):
    x = P.gens()[0]
    value = int(value)
    assert value >= 0
    result = P(0)
    i = 1
    e = 0
    while i <= value:
        if i & value:
            result += x**e
        i = i << 1
        e += 1
    return result

# Convert a polynomial to the corresponding integer
@functools.cache
def polynomial_to_int(poly):
    return int(poly.change_ring(sage.all.ZZ)(2))

def solve_half(enc_id, enc_perm):
    # Solution for the part with only least or most significant 4 bits
    assert len(enc_id) == PASS_LENGTH_BYTES
    assert len(enc_perm) == PASS_LENGTH_BYTES
    # the return value of bytes.hex will only use these characters
    ALLOWED_CHARACTERS = '0123456789abcdef'

    print('Xoring to get relations...')
    # so here we carry out the xors for the two values that were xored with
    # the same random byte, so that we get (x ^ r) ^ (y ^ r) = x ^ y
    target = [enc_id[i] ^ enc_id[i + (PASS_LENGTH_BYTES // 2)]
                     for i in range(0, PASS_LENGTH_BYTES // 2)]
    target += [enc_perm[i] ^ enc_perm[i + (PASS_LENGTH_BYTES // 2)]
                     for i in range(0, PASS_LENGTH_BYTES // 2)]
    print('Constructing target vector without guess in polynomial ring...')
    target = [int_to_polynomial(x) for x in target]
    print('Constructing matrix')
    # This is the matrix that was discussed above...
    matrix_rows = []
    for i in range(PASS_LENGTH_BYTES // 2):
        matrix_rows.append(([0]*i + [1] + [0]*((PASS_LENGTH_BYTES // 2) - i - 1)) * 2)
    for i in itertools.chain(
            range(0, (PASS_LENGTH_BYTES // 2) - 1, 2),
            range((PASS_LENGTH_BYTES // 2) + 1, PASS_LENGTH_BYTES - 2, 2)):
        matrix_rows.append([0]*i + [1,1] + [0]*(PASS_LENGTH_BYTES - i - 2))
    matrix_rows.append(
            [0]*(PASS_LENGTH_BYTES // 2) + [1] + [0]*((PASS_LENGTH_BYTES // 2) - 2) + [1])
    # ...but we add an extra row so that the last component of Ax will be x31.
    # We do this so that we can obtain a unique preimage x for each guess of x31.
    matrix_rows.append([0]*(PASS_LENGTH_BYTES - 1) + [1])
    M = sage.all.matrix(P, matrix_rows)
    #print('Checking matrix rank...')
    #assert int(M.rank()) == PASS_LENGTH_BYTES
    possible_password = []
    for guess in ALLOWED_CHARACTERS:
        print(f'Guessing "{guess}" for the last byte')
        guess = int_to_polynomial(ord(guess))
        target_vector = sage.all.vector(target + [guess])
        password = []
        for x in M.solve_right(target_vector):
            # The solve_right does not return components in the polynomial
            # ring itself, but in the fraction field, so we check that the
            # result actually lies in the polynomial ring.
            assert x.is_integral()
            password.append(polynomial_to_int(x.numerator()))
        password = bytes(password)
        if all(chr(x) in ALLOWED_CHARACTERS for x in password):
            print(f'Found possible solution: {password.decode()}')
            # It is unlikely that we will find more than one possibility.
            possible_password.append(password)
    return possible_password


remote = pwnlib.tubes.process.process('./challenge.py')
#remote = pwnlib.tubes.remote.remote('3.120.132.103', 13338)
remote.recvuntil(b'pad: ')
enc_id = bytes.fromhex(remote.recvuntil(b'\n').strip().decode())
# The permutation
# 0,2,...,14,17,...,29,16,1,3,...,15,18,...,30,31
permutation = list(range(0,PASS_LENGTH_BYTES // 2, 2)) \
        + list(range((PASS_LENGTH_BYTES // 2) + 1,PASS_LENGTH_BYTES - 2, 2)) \
        + [PASS_LENGTH_BYTES // 2]
permutation += list(range(1,PASS_LENGTH_BYTES // 2, 2)) \
        + list(range((PASS_LENGTH_BYTES // 2) + 2,PASS_LENGTH_BYTES, 2)) \
        + [PASS_LENGTH_BYTES - 1]
remote.send(','.join([str(x) for x in permutation]).encode() + b'\n')
remote.recvuntil(b'pad: ')
enc_perm = bytes.fromhex(remote.recvuntil(b'\n').strip().decode())

print('Trying to solve for least significant bits...')
lsb = solve_half(enc_id[1::2], enc_perm[1::2])
print(f'Found {len(lsb)} solutions for the least significant bits!')

print('\nTrying to solve for most significant bits...')
msb = solve_half(enc_id[0::2], enc_perm[0::2])
print(f'Found {len(msb)} solutions for the most significant bits!')

# After we found the most and least significant 4 bits of each byte of the
# password, we just need to combine them and retrieve the flag!
lsb = lsb[0].decode()
msb = msb[0].decode()
password = []
for i in range(PASS_LENGTH_BYTES):
    password.append(int(lsb[i],16) + (int(msb[i],16)<<4))
password = bytes(password)
remote.recvuntil(b'password: ')
remote.send(password.hex().encode() + b'\n')
answer = remote.recvuntil(b'\n').decode()
print(answer)
