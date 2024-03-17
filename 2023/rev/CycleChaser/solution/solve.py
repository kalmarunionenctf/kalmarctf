#!/usr/bin/env python3

# Writeup/Solve script for "CycleChaser" for KalmarCTF 2023
# by shalaamum

# For this challenge the source was not provided, so the first step is
# reversing the binary to gain an understanding of what is going on.  At the
# start we get printed the seed of a random number generator, but that part is
# actually not relevant for this version of the challenge (but will be relevant
# in the revenge version), and then we have to provide a nonnegative integer.
# The challenge then calculates the Collatz sequence for that startvalue
# (see https://en.wikipedia.org/wiki/Collatz_conjecture), where
# at each step the value v is replaced by (3*v + 1) / 2 if v was odd and by v/2
# if v was even.  At step i, the content of flag_enc[i % FLAGLEN], which starts
# out as zero, gets xored with a byte from a keystream, but only if this step
# of the Collatz sequence was an odd step. The keystream consists of
# SEQUENCELEN_RANDOM random bytes concatenated with the flag, which has FLAGLEN
# bytes. The idea is thus to use a startvalue where the first
# SEQUENCELEN_RANDOM steps will all be even steps, so that we skip xoring any
# of the random bytes into flag_enc, followed by FLAGLEN odd steps. Then
# flag_enc will be exactly the flag.
# so how do we construct such a startvalue? If v is an integer so that its
# Collatz sequence starts with FLAGLEN odd steps, then we can use
# (2**SEQUENCELEN_RANDOM)*v: the first SEQUENCELEN_RANDOM steps will indeed be
# even, after which we will end up with the value v. So it remains to find an
# integer v such that the first FLAGLEN steps of the Collatz sequence are odd
# steps.

# Before we think about this, let us start with more general theoretical
# considerations (not necessary to find the solution, but helpful). Suppose v
# is a potentially very large integer and we are interested only in whether the
# next n Collatz steps starting with v will be even or odd. Is this predictable
# from only knowing part of v? Indeed it is:

# Claim: The map Z -> {0,1}^n that maps each integer v to (c_1, ..., c_n), with
# c_i being 1 iff the i-th Collatz step starting from v is odd, factors through
# Z/2^n. In other words, to know what the first n Collatz steps of v are we
# only need to know v % (2**n).
# Proof: We prove this by induction. The cases n=0 and n=1 are easy.  So
# suppose we already proved the statement for n >= 1.
# Let v and v' be two integers such that v == v' (mod 2^(n+1)).
# As n >= 1 we can conclude that v will be odd iff v' is odd, which takes care
# of the first Collatz step. Say both are even. Then the remaining n Collatz
# steps (after the first one) of v and v' can also be described as the *first*
# n steps obtained by starting with v/2 and v'/2 instead.  But if v == v' (mod
# 2^(n+1)), then it follows that v/2 == v'/2 (mod 2^n), so that we can apply
# the induction hypothesis. The case in which v and v' are odd is completely
# analogous.

# So now let us get back to the problem of finding a v such that the first n
# Collatz steps are all odd. Let us first consider small examples.
# If n=1, then only the last bit of v is relevant and it is clear that it must
# be 1, so we need to take v=1.
# If n=2, then by the n=1 case we already know that the last bit will be 1, so
# the two options are 0b11 and 0b01. As (3*1 + 1) / 2 = 2 is even, 0b01 won't
# work, but 0b11 works, as (3*3 + 1) / 2 = 5 is odd.
# If n=3, then again by the previous case we know the last two bits must be 1,
# so we need to check 0b111 and 0b011, and it turns out that 0b011 does not
# work but 0b111 does.
# We could actually find our v with this method, by going bit by bit and always
# checking two possibilities.
# But looking at the first couple of examples we might conjecture that 0b1....1
# (with n ones) is the value we need.  We can also easily prove this by
# induction. Suppose that the binary representation of v ends with n ones.
# Then 3*v + 1 = 2*v + v + 1 will be of the following form:
# 0b?...?1...10 + 0b?...?1...1 + 1 = 0b?...?1...1 + 0b?...?1...1
# where the first summand ends with n+1 ones and the second with n ones.  This
# sum will have the form 0b?...?1...10, where the string of ones is n-1 long.
# Dividing this by two, i.e. shifting right by one bit, we obtain a number whose
# binary representation ends with n-1 ones.

# Coming back to the challenge this means that we will get the flag returned if
# we send a number whose binary representation begins (considering it little
# endian) with SEQUENCELEN_RANDOM many zeroes followed by FLAGLEN many ones.

import time
import pwnlib.tubes.process
import pwnlib.tubes.remote

SEQUENCELEN_RANDOM = 131072
FLAGLEN = 64

assert SEQUENCELEN_RANDOM % 8 == 0
assert FLAGLEN % 8 == 0
VALUEBYTES = ((SEQUENCELEN_RANDOM + FLAGLEN) // 8) + 1

remote = pwnlib.tubes.process.process('./cyclechaser')
#remote = pwnlib.tubes.remote.remote('3.123.91.129', 13339)
# First receive seed
print("Waiting for seed")
seed = int(remote.recvline().strip().decode(),16)
print(f'Seed is {seed}')
print("Constructing startvalue")
startvalue = b''
# we want to start with SEQUENCELEN_RANDOM many even steps.
startvalue += b'\0'*(SEQUENCELEN_RANDOM // 8)
# next we want exactly FLAGLEN many odd steps
startvalue += b'\xFF' * (FLAGLEN // 8)
# finish with 0
startvalue += b'\0' * (VALUEBYTES - len(startvalue))
print(f'Sending startvalue of length {len(startvalue)}')
remote.send(startvalue + b'\n')
print('Finished sending')
time_start = time.perf_counter()
data = remote.recvline()
print(data)
flag_enc = data.strip().decode().split(' ')
flag_enc = bytes([int(x, 16) for x in flag_enc])
time_took = time.perf_counter() - time_start
print(f'The remote took {time_took} seconds to compute result')
print(flag_enc)
