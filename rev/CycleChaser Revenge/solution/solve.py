#!/usr/bin/env python3

# Writeup/Solve script for "CycleChaser Revenge" for KalmarCTF 2023
# by shalaamum

# This writeup build on top of the writeup for "CycleChaser", so read that one
# first. For that challenge one had to "invert" Collatz sequences in the sense
# that one had to construct an integer where the first SEQUENCELEN_RANDOM +
# FLAGLEN steps of the Collatz sequence starting with that integer would have
# prescribed type (odd or even). In the "CycleChaser" having SEQUENCELEN_RANDOM
# even steps at the start and then FLAGLEN odd steps was enough, so it was only
# necessary to solve this very special case of the more general problem.
# For this challenge additional restrictions were imposed in order to force the
# player to figure out an efficient solution to the more general problem.  As
# last time we will want the last FLAGLEN steps to be odd in order the have the
# flag be xored into flag_enc. However, we can not avoid xoring bytes from the
# random pool into flag_enc, as each of the random bytes is allowed to occur at
# an even step a maximum of FLAGLEN times, and furthermore each byte of
# flag_enc must have been xored into an odd number of times by *some* random
# byte. At which step which random byte occurs is randomized and different at
# each run, to force players to find an efficient solution that works in the 300
# seconds timeout, but the order is not secret as we provide the seed of the
# random number generator to the player at the start. An additional restriction
# is that the program will abort should any of the intermediate values obtained
# during calculation of the Collatz sequence become too large.  This forces us
# to be careful not to have too many odd steps at the start.

# So there are two main steps to solving this challenge: Figuring out a sequence
# of odd/even that will produce an flac_enc from which the flag can be efficiently
# extracted by locally bruteforcing as few bytes as possible, and then finding
# a start value that will produce a Collatz sequence whose steps are exactly
# of the prescribed type.


import itertools
import time
import pwnlib.tubes.process
import pwnlib.tubes.remote
import ctypes

LIBC = ctypes.CDLL("libc.so.6")

DEBUG = False

if DEBUG:
    SEQUENCELEN_RANDOM = 1024
    FLAGLEN = 32
    RANDOMBYTES = 16
else:
    SEQUENCELEN_RANDOM = 131072
    FLAGLEN = 64
    RANDOMBYTES = 1024


assert SEQUENCELEN_RANDOM % 8 == 0
assert FLAGLEN % 8 == 0
VALUEBYTES = ((SEQUENCELEN_RANDOM + FLAGLEN) // 8) + 1
SEQUENCELEN = SEQUENCELEN_RANDOM + FLAGLEN
MAXVALUE = (1 << (8 * VALUEBYTES)) - 1


####################################################################################################
# Helper functions

# This function corresponds to the "step" function in the challenge, but
# additionally to whether the step was odd we also return the new value
# If the value would overflow in the challenge, then None, None gets returned.
def step(value):
    ret = value % 2 == 1
    if ret:
        value = 3*value + 1
        if value > MAXVALUE:
            return None, None
    value = value // 2
    return ret, value

# The first argument of this function is a list where rand[i] % RANDOMBYTES
# will be the index of the random byte that will be xored into
# flag_enc[i % FLAGLEN] if the i-th step of the Collatz sequence is odd.
# The function goes through the Collatz sequence of length
# SEQUENCELEN_RANDOM + FLAGLEN starting from value and checks whether all of
# the restrictions the challenge imposes are satisfied. It additionally checks
# some properties that we want to hold, such as the flag bytes also being xored
# into flag_enc.
def test_startvalue_works(rand, value):
    # value is an int and we test it does what we want.
    print('Testing startvalue')
    # How often is this random byte a candidate for being xored into flag_enc?
    random_occ_count = [0 for _ in range(RANDOMBYTES)]
    # How often does this random actually get xored into flag_enc?
    random_xor_count = [0 for _ in range(RANDOMBYTES)]
    # flag_enc[i][j] will be True iff random[j] was xored into flag_enc[i] an
    # odd number of times.
    flag_enc = [[False for _ in range(RANDOMBYTES)] for _ in range(FLAGLEN)]
    # SEQUENCELEN = SEQUENCELEN_RANDOM + FLAGLEN
    for i in range(SEQUENCELEN):
        should_xor, value = step(value)
        if value is None:
            print('Overflow at step {i}...')
            return False
        if i < SEQUENCELEN_RANDOM:
            index = rand[i] % RANDOMBYTES
            random_occ_count[index] += 1
            if should_xor:
                random_xor_count[index] += 1
                flag_enc[i % FLAGLEN][index] = not flag_enc[i % FLAGLEN][index]
        else:
            # So this is when the flag gets xored in.
            # We want this to happen each time.
            if not should_xor:
                print(f'Missed xoring in flag[{i % FLAGLEN}]')
                return False
    print('Went through Collatz sequence, now checking parities')
    for flag_index in range(FLAGLEN):
        s = sum([1 if flag_enc[flag_index][rand_index] else 0 for rand_index in range(RANDOMBYTES)])
        if s != 1:
            # We don't want to ultimately xor into a flag_enc byte with more
            # than one random byte, to make things easier when extracting the
            # flag at the end.
            print(f'Flag byte {flag_index} gets xored into by {s} random bytes')
    print(f'Encrypted flag should be as we want.')
    for rand_index in range(RANDOMBYTES):
        if random_xor_count[rand_index] + FLAGLEN < random_occ_count[rand_index]:
            print(f'Did not use random index {rand_index} enough.'
                  + ' Used {random_xor_count[rand_index]} times and occurs {random_occ_count[rand_index]} times')
            return False
    return True


####################################################################################################
# Inverting Collatz sequences

# So given a sequence of n values "odd"/"even", how do we find an integer v
# such that the type of the first n steps of its Collatz sequence will be odd
# or even as prescribed by the sequence?

# The claim in the writeup for "CycleChaser" tells us already that if such an
# integer v exists, we will be able to find one with 0 <= v < 2**n.  This
# suggests as a first solution to just try all 2**n possible v's and see which
# one has the correct Collatz sequence. Unfortunately the runtime for this
# bruteforcing solution explodes so fast that this is not feasible except for
# very small n, and certainly not for n=131136 (which is what n is in the case
# of the challenge). However, as discussed in the writeup for "CycleChaser",
# that claim also tells us that we can construct v bit by bit.  We start by
# figuring out which first bit (the least significant one) would result in the
# correct type of first Collatz step. After we found it, we try out the two
# possibilities for the second bit, having already fixed the first one, and
# check which one will make the first two Collatz steps of the correct type (we
# already know the first one will be), and so on.  When checking bit i, we will
# have to check two choices, and in each of those we will have to evaluate i
# Collatz steps. This results in roughly quadratic runtime in n (here and in
# the following let us ignore that bigger numbers also take longer to add and
# multiply, as that is not super relevant to the discussion). We can improve
# this method a bit by first noting that if the i-th bit is taken to be 0, then
# the number we are checking is the same one as the one we considered in the
# i-1-th step, so by remembering what the i-1--th value in its Collatz sequence
# was, we need only calculate one more step, rather than having to also
# recalculate the i-1 first steps. This will cut runtime roughly in half, but
# runtime is still quadratic.

# We can do better still if we realize that if we remember the value in the
# Collatz sequence after i-1 steps when starting with v, then we can also
# predict the value after i-1 steps when starting with v + 2**(i-1), with only
# a little extra information we need to remember from the first i-1 steps.
# For this, let us take v and consider how the next value in the Collatz
# sequence changes if we replace v by v + a*(2**k), with k>0.
# If v is even (and hence so will be v + a*(2**k)), then the next values will
# be v/2 and (v + a*(2**k))/2 = v/2 + a*(2**(k-1))
# If v is odd, the next values will be
# (3*v + 1) / 2 and
# (3*(v + a*(2**k)) + 1) / 2 = 3*(v+1)/2 + (3*a*(2**k))/2 = 3*(v+1)/2 + 3*a*(2**(k-1))
# The upshot is that the "extra summand" will carry through to a new "extra
# summand" but with the exponent of 2 reduced by 1, and in the odd case we also
# multiply by 3.  So this means that if starting with v we get after i-1 steps
# the value v', then starting with v + 2**(i-1) we will after i-1 steps get
# v' + 3**num_odd instead, where num_odd is the number of odd steps in those
# i-1 Collatz steps. This suggests the algorithm implemented in the following
# function to compute a startvalue for a Collatz sequence where the type of the
# first n steps is prescribed, with linear runtime in n if we ignore that
# arithmetic with larger numbers takes longer.

# When constructing the challenge, I tested all three algorithms suggested here
# (with simple Python implementations) and plotted their runtime.  The pictures
# should be available alongside this writeup. The sequence length of 131136
# (which is 2**17 plus 64 for the flag) was chosen for the challenge to make it
# possible to find a solution with the efficient algorithm described here
# easily in the timeout (i.e. a simple Python solution runs in a few seconds,
# so no need to implement with more efficient programming languages etc.) but
# not with less efficient algorithms, and with sufficient buffer to make it
# very clear to players that so far only found a less efficient algorithm that
# the task is to keep looking for a better algorithm rather than implementing
# it in C or Rust and hiring a big cluster.


# seq encodes which steps should be odd. It is an integer where the i-th bit
# indicates that the i-th step should be an odd one.
def collatz_inverse_fast(seq, width):
    start_value = 0 # Current startvalue at this stage (having considered i steps)
    num_odd = 0 # The number of odd steps after i Collatz sequence steps considered so far
    end_value = 0 # Current value after i steps of the Collatz sequence when starting with start_value
    for i in range(width):
        if seq & (1 << i):
            # Need an odd step.
            if end_value % 2 == 0:
                # End value is even, so need to change start value.
                start_value += 1 << i
                end_value += 3**num_odd # Update the end value after i steps
            end_value = (3*end_value + 1) // 2 # New end value after i+1 steps
            num_odd += 1
        else:
            # Need an even step.
            if end_value % 2 == 1:
                # end value is odd, so need to change start value
                start_value += 1 << i
                end_value += 3**num_odd # Update the end value after i steps
            end_value = end_value // 2 # New end value after i+1 steps
    return start_value


####################################################################################################
# Finding a sequence of odd/even that would pass the challenges restrictions
# and make it easy to get the flag.


# This function will return a dict of dicts result in which result[i][j] is the
# amount of times that random[i] can get xored into flag_enc[j], if the
# relevant step were an odd one.
def get_random_index_flag_index_occurence_num(rand):
    result = {i: {j: 0 for j in range(FLAGLEN)} for i in range(RANDOMBYTES)}
    for i, r in enumerate(rand):
        result[r % RANDOMBYTES][i % FLAGLEN] += 1
    return result


# Not every random byte is available to be xored into every flag_enc byte, as
# the respective indices may just not line up. This function tries to find the
# random byte index that can hit the maximum number of flag_enc bytes.
# rand_index_flag_index_sum is the return value of
# get_random_index_flag_index_occurence_num, so see there.
# rand_indices is a list of indices for the random numbers that we should
# consider, and flag_indices is a list of indices for flag_enc that we should
# consider.
def rand_index_maximizing_flag_hits(rand_index_flag_index_sum, rand_indices, flag_indices):
    result = rand_indices[0]
    result_max = 0
    result_complement_max = 0
    flag_complement_indices = [i for i in range(FLAGLEN) if i not in flag_indices]
    for rand_index in rand_indices:
        s = sum([1 if rand_index_flag_index_sum[rand_index][j] > 0 else 0 for j in flag_indices])
        sc = sum([1 if rand_index_flag_index_sum[rand_index][j] > 0 else 0 for j in flag_complement_indices])
        # As a tie-braker between random_index's which hit the same number of
        # flag_indices we should consider, we look at how many of the flag_enc
        # indices in the complement of flag_indices can be hit, as this will
        # give us the most amount of flexibility in the
        # distribute-things-evenly-step in
        # get_random_index_flag_index_to_be_left_over.
        if (s > result_max) or ((s == result_max) and sc > result_complement_max):
            result = rand_index
            result_max = s
            result_complement_max = sc
    return result


# The argument here is the return value of
# get_random_index_flag_index_occurence_num, so contains how many times each
# random byte could be xored into each flag_enc byte.  Xoring the same random
# value twice into the same byte of flag_enc cancels each other of course, so
# what this function does it will return a dict of dicts result where
# result[i][j] is True iff we want random[i] to be xored into flag_enc[i] an
# odd number of times.
# Note that the solution of always xoring random bytes an even number of times
# into each flag_enc bytes is not possible due to the restrictions the
# challenge imposes.  What would be ideal is if we could have a single of the
# random bytes that gets xored an odd number of times into each of the flag_enc
# bytes, and all other random bytes get xored in an even number of times. Then
# we would only need to guess that single random byte at the end when doing the
# local bruteforce.  But this may not be possible because there just may not be
# any of the random bytes that can be xored into all of the flag_enc bytes.  So
# what this function does is figure out an efficient combination that is
# possible, if necessary for example covering roughly half of the flag_enc
# bytes with one random byte and the rest with another random byte.
def get_random_index_flag_index_to_be_left_over(rand_index_flag_index_sum):
    # This is just to setup result as a nested dict.
    result = {i: {j: False for j in range(FLAGLEN)} for i in range(RANDOMBYTES)}
    # The random indices we still haven't "used up".
    rand_indices_left = list(range(RANDOMBYTES))
    # The number of flag_enc bytes that so far have not been scheduled to be
    # xored an odd number of times with any random byte.
    flag_indices_left = list(range(FLAGLEN))
    rand_indices_used = []
    while len(flag_indices_left) > 0:
        rand_index = rand_index_maximizing_flag_hits(rand_index_flag_index_sum, rand_indices_left, flag_indices_left)
        # rand_index is the index of the random byte that we are going to use
        # to xor into *all* of the flag_enc bytes that we can. We will later
        # remove some of these again if there are overlaps (where multiple
        # random bytes get xored into the same flag_enc byte an odd number of
        # times).
        rand_indices_used.append(rand_index)
        rand_indices_left.remove(rand_index)
        for flag_index in range(FLAGLEN):
            if rand_index_flag_index_sum[rand_index][flag_index] > 0:
                if flag_index in flag_indices_left:
                    flag_indices_left.remove(flag_index)
                result[rand_index][flag_index] = True
    
    # Now we need every flag byte to be only hit once and distribute as evenly
    # as possible among the random bytes. An even distribution is better for
    # the local bruteforce step at the end as it lowers the likelihood of
    # finding more then one possible solution.
    for flag_index in range(FLAGLEN):
        # rand_index_to_survive is the rand index that we want to use to xor
        # into flag_enc[flag_index].
        rand_index_to_survive = None
        rand_index_min_use = FLAGLEN + 1
        for rand_index in rand_indices_used:
            num_used = sum([1 if result[rand_index][j] else 0 for j in range(FLAGLEN)]) 
            # num_used is how often this random byte will be used to xor an odd
            # number of time into a flag_enc byte.
            if (num_used < rand_index_min_use) and result[rand_index][flag_index]:
                # We want to remove this odd-number-xoring from those
                # rand_index which have most other flag_enc bytes that they xor
                # into an odd number of times, so the surviving one should be
                # the one where num_used is minimal.
                rand_index_to_survive = rand_index
                rand_index_min_use = num_used
        if rand_index_to_survive is None:
            raise Exception
        for rand_index in range(RANDOMBYTES):
            if rand_index != rand_index_to_survive:
                result[rand_index][flag_index] = False
        if not result[rand_index_to_survive][flag_index]:
            raise Exception

    for rand_index in rand_indices_used:
        num_used = sum([1 if result[rand_index][j] else 0 for j in range(FLAGLEN)]) 
        print(f'Will use random byte with index {rand_index} to xor into flag, hits {num_used} flag bytes')
    
    return result


# This function takes the seed from the challenge and tries to find a
# startvalue for us to use, also returning to us which random byte will be
# xored an odd number of times into which flag_enc byte at the end. It may fail
# to find a working startvalue.
def generate_startvalue(seed):
    print(f'Generating startvalue for seed {seed}')
    # We use the same libc functions as the challenge to obtain the stream
    # of random numbers used for the index of the random byte from the
    # unknown (to us) buffer of random bytes to be xored into flag_enc.
    # We precompute this and pass it around because we will often need it.
    LIBC.srand(seed)
    rand = [LIBC.rand() % RANDOMBYTES for _ in range(SEQUENCELEN_RANDOM)]
    print(f'Precomputed random indices')
    # We first need to obtain some statistics.
    # rand_index_flag_index_sum contains how many times which random byte can
    # be xored into which byte of flag_enc.
    rand_index_flag_index_sum = get_random_index_flag_index_occurence_num(rand)
    # random_uses_to_be_left_over will for each flag_enc byte and random byte
    # tell us whether we want that random byte to be xored an odd number of
    # times into that flag_enc byte or not.
    random_uses_to_be_left_over = get_random_index_flag_index_to_be_left_over(rand_index_flag_index_sum)
    if random_uses_to_be_left_over is None:
        return None, None
    # This loop here is just to print out some debugging information
    for rand_index in range(RANDOMBYTES):
        num_xors = sum([1 if random_uses_to_be_left_over[rand_index][j] else 0 for j in range(FLAGLEN)])
        flag_indices = [j for j in range(FLAGLEN) if random_uses_to_be_left_over[rand_index][j]]
        if num_xors > 0:
            print(f'Will use random byte with index {rand_index} to xor into flag bytes {flag_indices}')
    # We will go through the Collatz sequence step by step. In the first of
    # these two variables we will count how often we have an odd step in which
    # we do xor a certain random byte into a certain flag_enc byte. In the
    # second variable we also count the even steps, so when the xoring does not
    # actually happen.
    rand_index_flag_index_used = {i: {j: 0 for j in range(FLAGLEN)} for i in range(RANDOMBYTES)}
    rand_index_flag_index_considered = {i: {j: 0 for j in range(FLAGLEN)} for i in range(RANDOMBYTES)}
    # Right now, not having considered a single Collatz sequence step, our target defined by
    # random_uses_to_be_left_over is not reached, as this tells us that some
    # random bytes should be xored an odd number of times into some flag_enc
    # bytes, but so far all do so an even number of times (namely zero times).
    # The following variable will store how many times we still have to xor a
    # specific random byte into *any* flag_enc byte to reach our goal.
    rand_index_outstanding_uses = [
            sum([1 if random_uses_to_be_left_over[rand_index][j] else 0 for j in range(FLAGLEN)])
            for rand_index in range(RANDOMBYTES)]
    #print(rand_index_outstanding_uses)

    # This will contain what type each step in the Collatz sequence should be.
    collatz_sequence_parity_steps = []

    # We go backwards to have odd steps that increase the value *last*
    for index in range(SEQUENCELEN_RANDOM - 1, -1, -1):
        rand_index = rand[index] % RANDOMBYTES
        flag_index = index % FLAGLEN
        rand_index_flag_index_considered[rand_index][flag_index] += 1
        should_xor = False
        # when should we xor? One condition is that we need the parity to be
        # correct in the end, so if it isn't yet, xor.
        parity_we_need = 0
        if random_uses_to_be_left_over[rand_index][flag_index]:
            parity_we_need = 1
        if rand_index_flag_index_used[rand_index][flag_index] % 2 != parity_we_need:
            # Parity is currently wrong, so fix it.
            should_xor = True
            # As we fixed one outstanding xor, we can decrease the remaining
            # number by one.
            rand_index_outstanding_uses[rand_index] -= 1
        # We also should xor if we haven't used the random byte enough and
        # there is at least one more instance of this
        # random-byte-flag-byte-combo available (so that we can fix the parity
        # later if necessary).
        elif (sum([rand_index_flag_index_used[rand_index][j] for j in range(FLAGLEN)])
              + rand_index_outstanding_uses[rand_index] + FLAGLEN
            < sum([rand_index_flag_index_sum[rand_index][j] for j in range(FLAGLEN)])):
            # So we need to use rand_index more. Can we do it in this flag_index?
            if (rand_index_flag_index_considered[rand_index][flag_index]
                < rand_index_flag_index_sum[rand_index][flag_index]):
                # There is at least one more of this combo coming. If parity is
                # wrong now we want to xor anyway, but we already did actually
                # in the other outer if branch. Hence parity is correct now and
                # it will become wrong, but we will still have a chance to
                # correct it.
                should_xor = True
                rand_index_outstanding_uses[rand_index] += 1
        if should_xor:
            rand_index_flag_index_used[rand_index][flag_index] += 1
        collatz_sequence_parity_steps.append(should_xor)
    
    # We went through the steps backwards, so reverse.
    collatz_sequence_parity_steps = collatz_sequence_parity_steps[::-1] 
    # Need to also xor in the flag.
    collatz_sequence_parity_steps += [True] * FLAGLEN
    # Next, convert the list of parity steps to an int.
    collatz_seq_parity_as_int = 0
    for i, b in enumerate(collatz_sequence_parity_steps):
        if b:
            collatz_seq_parity_as_int |= (1 << i)
    print(f'Obtained a parity sequence that hopefully works')
    #print(bin(collatz_seq_parity_as_int))
    # Convert the parity sequence into a startvalue for the Collatz sequence.
    startvalue = collatz_inverse_fast(collatz_seq_parity_as_int, len(collatz_sequence_parity_steps))
    print(f'Obtained a collatz start value as int')
    #print(hex(startvalue))
    # Test the startvalue to make sure.
    if not test_startvalue_works(rand, startvalue):
        print('Unfortunately this startvalue does not work...')
        return None, None
    print('This startvalue should work!')
    startvalue = startvalue.to_bytes(VALUEBYTES, 'little')
    # Finally, we need to know how flag_enc will look like at the end.  We have
    # arranged it so that for example there will be two indices i != j such
    # that flag_enc looks like
    # flag[0] ^ rand[i], flag[1] ^ rand[i], flag[2] ^ rand[j], flag[3] ^ rand[i],...
    # We will then go over all possibilities of rand[i] and rand[j] and check
    # if we obtain a flag that lies in the character ranges we know it must
    # have. For this we need to know which random byte is xored into which slot
    # of flag_enc, so this is what we calculate and return here.
    # In the example, we would return a list [[0,1,3, ...], [2,...]],
    # where the first entry gives the indices into which rand[i] has been xored
    # into (we don't care about i at this point) and the second those indices
    # into which rand[j] has been xored into.
    random_bytes_to_bruteforce = []
    for rand_index in range(RANDOMBYTES):
        list_flag_indices = [j for j in range(FLAGLEN) if random_uses_to_be_left_over[rand_index][j]]
        if len(list_flag_indices) > 0:
            random_bytes_to_bruteforce.append(list_flag_indices)
    return startvalue, random_bytes_to_bruteforce


####################################################################################################
# Interaction with the challenge

num_tries = 0
while True:
    num_tries += 1
    remote = pwnlib.tubes.process.process('./cyclechaser-revenge')
    #remote = pwnlib.tubes.remote.remote('3.123.91.129', 13340)

    # First receive seed
    print("Waiting for seed")
    seed = int(remote.recvline().strip().decode(),16)
    # Generate startvalue
    startvalue, random_bytes_to_bruteforce = generate_startvalue(seed)
    if startvalue is None:
        print(f'Was not able to find a working startvalue for this seed on try {num_tries}, trying again')
        remote.close()
        continue
    print(f'Found a startvalue that should work on try {num_tries}')
    #print(f'Sending startvalue {startvalue} of length {len(startvalue)}')
    remote.send(startvalue + b'\n')
    print('Finished sending')
    time_start = time.perf_counter()
    data = remote.recvline()
    print(data)
    flag_enc = data.strip().decode().split(' ')
    flag_enc = bytes([int(x, 16) for x in flag_enc])
    time_took = time.perf_counter() - time_start
    print(f'The remote took {time_took} seconds to compute result')
    # Now we bruteforce locally by guessing the (usually 2) random bytes that
    # are xored into the flag.
    for guesses in itertools.product(range(256), repeat=len(random_bytes_to_bruteforce)):
        flag = []
        incorrect = False
        for i in range(FLAGLEN):
            for rand_index in range(len(random_bytes_to_bruteforce)):
                if i in random_bytes_to_bruteforce[rand_index]:
                    value = flag_enc[i] ^ guesses[rand_index]
                    if not (0x5f <= value <= 0x7a):
                        # There is an assert in the challenge that tells us
                        # that all characters of the flag lie in this range.
                        # So if that is not the case when decrypting using our
                        # guessed values for the random bytes we bruteforce
                        # over, then the guess must have been wrong.
                        incorrect = True
                    flag.append(value)
                    break
            if incorrect:
                break
        if incorrect:
            continue
        flag = bytes(flag).decode()
        print(flag)
        # It is very unlikely that we get more than one printout here.
    break
