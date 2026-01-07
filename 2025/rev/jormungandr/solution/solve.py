from pwn import *

flag = b'kalmar{__rabbit-H0LE-r3venge==}'

def ror_bytes(l):
    global flag

    ror_by = l % (len(flag) * 8)
    ror_chars = ror_by // 8
    ror_bits = ror_by & 7

    for _ in range(ror_chars):
        previous = flag[len(flag) - 1]
        for i in range(len(flag)):
            next_previous = flag[i]
            flag = flag[:i] + p8(previous) + flag[i + 1:]
            previous = next_previous

    carry = (flag[len(flag) - 1] << (8 - ror_bits)) & 0xff
    for i in range(len(flag)):
        next_carry = (flag[i] << (8 - ror_bits)) & 0xff
        flag = flag[:i] + p8((flag[i] >> ror_bits) | carry) + flag[i + 1:]
        carry = next_carry

def rol_bytes(l):
    global flag

    rol_by = l % (len(flag) * 8)
    rol_chars = rol_by // 8
    rol_bits = rol_by & 7

    for _ in range(rol_chars):
        previous = flag[0]
        for i in reversed(range(len(flag))):
            next_previous = flag[i]
            flag = flag[:i] + p8(previous) + flag[i + 1:]
            previous = next_previous

    carry = (flag[0] >> (8 - rol_bits))
    for i in reversed(range(len(flag))):
        next_carry = (flag[i] >> (8 - rol_bits))
        flag = flag[:i] + p8(((flag[i] << rol_bits) & 0xff) | carry) + flag[i + 1:]
        carry = next_carry

def xor_bytes(l):
    global flag
    for i in range(len(flag)):
        flag = flag[:i] + p8((flag[i] ^ l) & 0xff) + flag[i + 1:]

rounds = [flag]
print(flag.hex())
for round in range(12):
    key = 0x23 + ((1 << round) - 1)
    ror_bytes(key)
    xor_bytes(key)
    print(hex(key))
    print(flag.hex())
    rounds.append(flag)

print(rounds)
final = b'\xad\xa9\x19\x19\x99\xb5\xa1\xbb\xb9\xa1\x87\x95\xdd\xdd\x87\xa1\xa7\xa7\xb1\x8b\x39\xf3\x03\xfb\xe9\x39\x87\x05\x8f\xa9\xbf'

assert rounds[-1] == final
flag = final

for round in reversed(range(12)):
    key = 0x23 + ((1 << round) - 1)
    print(hex(key))
    xor_bytes(key)
    rol_bytes(key)

print(flag)
