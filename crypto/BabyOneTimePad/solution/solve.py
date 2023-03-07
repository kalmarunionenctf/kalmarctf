#!/usr/bin/env python3

# Writeup/Solve script for "BabyOneTimePad" for KalmarCTF 2023
# by shalaamum

# This challenge was based on the original "EasyOneTimePad", and intended as an
# easier variant, by actually reusing the key in both encryptions, by using how
# default arguments work in Python. The idea for this change was by killerdog.
# Another difference in the released versions of BabyOneTimePad and
# EasyOneTimePad was the missing assert on the length of the permutation
# supplied by the user, but that was an unintended mistake that we fixed before
# releasing EasyOneTimePad. This solution uses a legitimate permutation and
# only uses that the same key is used in both encryptions.

import itertools
import functools
import pwnlib.tubes.process
import pwnlib.tubes.remote
from challenge import PASS_LENGTH_BYTES

# We will use n for PASS_LENGTH_BYTES.
# Let us denote the bytes of the password by P_0, P_1, ..., P_{n-1}.  As
# encryption first converts to hex we will let p'_i and p_i be the two bytes of
# the hexstring corresponding to P_i (where p'_i corresponds to the most
# significant four bits). 
# If we denote the random bytes by r_0, ..., r_{n-1}, then the first encryption
# will return
# r_0 ^ p'_0, r_1 ^ p_0, ...., r_{n-2} ^ p'_{n/2 - 1}, r_{n-1} ^ p_{n/2 - 1},
# r_0 ^ p'_{n/2}, ..., r_{n-1} ^ p_{n-1}
# As permutation we will use n-1, 0, 1, ..., n-2. The second encryption will
# then return
# r_0 ^ p'_{n-1}, r_1 ^ p_{n-1}, r_2 ^ p'_0, r_3 ^ p_0, ...
# What we can do now is guess r_0 and r_1. Then from the first encryption we
# will be able to obtain p'_0 and p_0 by looking at the first two bytes. Moving
# on to the second encryption we will in turn be able to use that to extract
# r_2 and r_3 by looking at the third and fourth byte. Continuing like this we
# can deduce the entire key. This only requires first half of the ciphertexts
# (plus two bytes of the second due to the permutation). We could continue
# directly with the second halves for consistency checks to rule out keys, but
# this is not necessary. We can just try to decrypt both cipertexts with the
# obtained key and check whether we get the same, and that only the characters
# 'a' to 'f' and '0' to '9' appear.  It is very unlikely that this will happen
# for keys that are not the correct one.


# This function extracts the full key in the manner described above based on
# the two ciphertexts as well as a guess for the first two bytes of the key
def full_key_from_first_two_bytes(enc_id, enc_perm, first_key_byte, second_key_byte):
    key = bytes([first_key_byte, second_key_byte])
    cleartext_hex = b''
    for i in range((PASS_LENGTH_BYTES // 2) - 1):
        cleartext_hex += bytes([enc_id[2*i] ^ key[2*i]])
        cleartext_hex += bytes([enc_id[2*i + 1] ^ key[2*i + 1]])
        key += bytes([enc_perm[2*i + 2] ^ cleartext_hex[2*i]])
        key += bytes([enc_perm[2*i + 3] ^ cleartext_hex[2*i + 1]])
    return key

def decrypt(key, enc):
    cleartext = bytes([key[i % len(key)] ^ x for i,x in enumerate(enc)])
    return cleartext

remote = pwnlib.tubes.process.process('./challenge.py')
#remote = pwnlib.tubes.remote.remote('3.120.132.103', 13337)
remote.recvuntil(b'pad: ')
enc_id = bytes.fromhex(remote.recvuntil(b'\n').strip().decode())
permutation = [PASS_LENGTH_BYTES - 1] + list(range(PASS_LENGTH_BYTES-1))
to_send = ','.join([str(x) for x in permutation]).encode()
remote.send(to_send + b'\n')
remote.recvuntil(b'pad: ')
enc_perm = bytes.fromhex(remote.recvuntil(b'\n').strip().decode())

cleartex_hex = None
# We bruteforce locally the first two bytes.
for first_key_byte, second_key_byte in itertools.product(range(256), repeat=2):
    # For each guess we deduce what the full key would need to be.
    key = full_key_from_first_two_bytes(enc_id, enc_perm, first_key_byte, second_key_byte)
    # Then we decrypt the hex of the password from both ciphertexts
    cleartext_from_id_hex = decrypt(key, enc_id)
    cleartext_from_perm_hex = decrypt(key, enc_perm)
    cleartext_from_perm_hex = cleartext_from_perm_hex[2:] + cleartext_from_perm_hex[:2]
    # If we get something inconsistent, the guess was wrong.
    if cleartext_from_perm_hex != cleartext_from_id_hex:
        continue
    cleartext_hex = cleartext_from_id_hex
    # If we do not get only hex characters, the guess is also wrong.
    if not all([x in '0123456789abcdef'.encode() for x in cleartext_hex]):
        continue
    break
if cleartext_hex is None:
    print('What happened?')
    quit()
remote.recvuntil(b'password: ')
remote.send(cleartext_hex + b'\n')
print(remote.recvline().strip().decode())
