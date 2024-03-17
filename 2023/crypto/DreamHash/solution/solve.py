#!/usr/bin/env python3

# Writeup/Solve script for "DreamHash" challenge at KalmarCTF 2023
# by shalaamum

# Suppose you have a complicated object and a difficult problem to solve on
# that object. One general strategy is to try to decompose that complicated
# object into easier pieces for which the problem can be solved, and then glue
# these solutions together to a solution for the complicated object. One
# instance of this that often appears in crypto challenges is that we want to
# find an element of Z/nZ satisfying some properties, but this is very hard.
# But we can write n as a product, and solving the corresponding problem modulo
# these factors is easier (for example it could be that the problem is easy
# modulo primes, but hard modulo composites). At the end we then use the
# Chinese remainder theorem to glue the solutions together to find that element
# of Z/nZ that we wanted.
#
# In this challenge, the object for which we have a problem is a group. It
# turns out that the problem is very easy to solve for commutative groups, but
# the one we have to deal with is unfortunately not commutative. So we want to
# decompose the group in some way into commutative pieces for which we can
# solve the problem. One easy way to decompose a group, and the most analogous
# to the previous example, would be as a direct product. However a more general
# way is in terms of group extensions
# (see https://en.wikipedia.org/wiki/Group_extension),
# and this is what is required for the solution of this challenge.
# Integers get used a lot in cryptography and most who tried this challenge
# likely know that integers that are the product of small primes are weak for
# many applications in cryptography. The hope was that this challenge might
# introduce one way that some might not have known before in which finite
# groups can also be weak, and make people ask the question "is there a way to
# decompose this object I have not thought of yet?" in more contexts.


import functools
import itertools
import base64
import pwnlib.tubes.process
import pwnlib.tubes.remote
from challenge import * # Assumes the challenge file is named "challenge.py" and in the same dir,
                        # if this is not the case you need to change this line

# First we try to understand the values better.
# We evidently have a set with 216 elements and a binary operation.
# Value(0) is used as padding etc., so is this a neutral element?
zero_neutral = True
for i in range(VALUESIZE):
    if Value(0) + Value(i) != Value(i) or Value(i) + Value(0) != Value(i):
        zero_neutral = False
        break
print(f'Value(0) is neutral element: {zero_neutral}')

# Now let us check associativity
associative = True
# Commented after running it once because it takes a bit, the outcome is that
# the binary operation *is* associative

#n = 0
#for i,j,k in itertools.product(range(VALUESIZE), repeat=3):
#    if (Value(i) + Value(j)) + Value(k) != Value(i) + (Value(j) + Value(k)):
#        associative = False
#        break
#    n += 1
#    if n % 1000 == 0:
#        print(f'\rChecking associativity: {100*(n / (VALUESIZE**3)):.2f}%', end=' '*10)

print(f'\rAssociativity holds: {associative}' + ' '*30)

# Now let us check commutativity
commutative = True
for i,j in itertools.product(range(VALUESIZE), repeat=2):
    if Value(i) + Value(j) != Value(j) + Value(i):
        commutative = False
        break
print(f'Commutativity holds: {commutative}')

# Finally, are there inverses?
inverses = True
for i in range(VALUESIZE):
    inverse_for_i = False
    for j in range(VALUESIZE):
        if Value(i) + Value(j) == Value(0):
            inverse_for_i = True
            break
    if not inverse_for_i:
        inverses = False
        break
print(f'Inverses exist: {inverses}')

# The outcome should be that Value(0) is a neutral element, associativity
# holds, and inverses exist.
# This means that this is a group G, but unfortunately not commutative.  In the
# following, "multiply" will be used for the group operation, even though
# __add__ is used in the implementation, fitting better with the group not
# being commutative.
# Why would it be helpful if G were commutative? Component i of the hash is
# obtained by multiplying together components of the input after folding the
# data into one block. In that product, component i of the input occurs
# exactly once, whereas components other than i occur a multiple of 216 times
# (see the template definition). As g^{|G|} is the neutral element for any
# element g of G, the hash function would thus be the easy to understand
# folding step composed with the identity -- if only G were commutative!
# The next best thing we can do is try to pass to a commutative quotient.
# If N <| G is a normal subgroupp of G, then the hash function on a single
# block, which is a map of sets
# G x ... x G  -->  G x ... x G
# induces a well-defined map of sets
# G/N x ... x G/N  -->  G/N x ... x G/N
# which by the previous argument would be the identity if
# G/N is commutative.
# So if we can find such an N then we will be able to deduce from the hash of
# the secret the residue classes mod N of the secret. How do we continue from
# there?
# As we do not only get the hash of secret, but can add secret componentwise
# with elements of our choice, we can, after obtaining the residue classes mod
# N of secret, replace secret by a tuple where each component is in N. Now note
# that as N is a subgroup, the hash function on a single block restricts to a
# map of sets
# N x ... x N  -->  N x ... x N
# and so we can try to repeat this procedure.
# How do we find N? For G/N to be commutative, N must contain the commutators,
# and we also need N to be normal. Hence we take N to be the smallest normal
# subgroup of G that contains the cummutators. This subgroup is called the
# commutator subgroup, or derived subgroup, denoted by G^(1) = [G, G]. We can
# then iterate this to obtain G^(2) = [G^(1), G^(1)] etc., and get from this
# the derived series of G, which is a sequence
# ... <| G^(n) <| G^(n-1) <| ... <| G^(1) <| G
# of subgroups of G, where each subgroup is a normal subgroup of the next one
# in the sequence, with the quotients G^(i) / G^(i+1) all commutative.
# At the start of the challenge, with no information, we need to find a random
# secret tuple of elements of G=G^(0). With each hash that we are provided from
# our input we will be able to move this problem one step down the sequence. We
# can thus solve the problem with n hashes provided if G^(n) is the trivial
# subgroup.
# A group G is called solvable if there is an n such that G^(n) is the trivial
# subgroup (it could also happen that after some m we have G^(m) = G^(m+1) =
# G^(m+2) = ... and this subgroup is not the trivial one). Luckily, the G we
# are considering here is solvable, and G^(n) = {Value(0)} for n>=4.  So we can
# solve the challenge with 4 hashes provided.
#
# The solution path described above does not require actually identifying the
# group itself, but an alternative route can involve recognizing that __add__
# seems to involve formulas that could be matrix operations and then identify
# this group as ASL_2(F_3). The notation ASL stands for Affine Special Linear
# group, and refers to the semidirect product (F_3)^2 x| SL_2(F_3), with
# SL_2(F_3) acting in the usual way on the vector space (F_3)^2, by
# multiplication from the left.
# If one then looks around, e.g. here:
# https://people.maths.bris.ac.uk/~matyd/GroupNames/193/ASL(2,3).html
# one might see that this group is solvable and think about whether that helps.
# The description of the challenge
# "I fell asleep in my abstract algebra class and dreamt of this weird hash function,
# so I decided to make a challenge with it. Can you solve it?"
# was intended as a little hint, the first sentence with regards to using the
# kind of things one might learn in an abstract algebra class, so that it might
# be helpful to look up / refresh e.g. what kind of properties groups can have
# etc., and the second sentence was a little hint towards the group being
# solvable.

# This function just bruteforces inverses, which is not fast, so we cache it
@functools.cache
def invert(x):
    for y in range(VALUESIZE):
        if Value(y) + Value(x) == Value(0):
            return y
    raise Exception

# We can calculate the derived series and check that G is solvable and
# G^(4)={Value(0)}

# This function calculates the commutator subgroup for a subgroup of G
def commutator_subgroup(group):
    old_subgroup = set()
    subgroup = set()
    for x, y in itertools.product(group, repeat=2):
        subgroup.add((Value(x) + Value(y) + Value(invert(x)) + Value(invert(y))).n)
    while old_subgroup != subgroup:
        old_subgroup = subgroup.copy()
        for x,y in itertools.product(old_subgroup, repeat=2):
            subgroup.add((Value(x) + Value(y)).n)
    return subgroup

# Caclulate the derived series of G and print out the orders
G = {i for i in range(VALUESIZE)}
derived_series = [G]
while len(derived_series[-1]) != 1:
    print(f'|G^({len(derived_series)-1})| = {len(derived_series[-1])}')
    derived_series.append(commutator_subgroup(derived_series[-1]))
print(f'|G^({len(derived_series)-1})| = {len(derived_series[-1])}')
print(f'Length of the derived series is {len(derived_series) - 1}')
# The above should confirm length 4, so that the solution described above
# should work and we need only 4 hashes to figure out the secret

r = pwnlib.tubes.process.process('./challenge.py')
#r = pwnlib.tubes.remote.remote('3.120.132.103', 13341)
inverse_secret = [0]*BLOCKSIZE
for n in range(4):
    r.recvuntil(b'Your values: ')
    r.send(base64.b64encode(bytes(inverse_secret)) + b'\n')
    r.recvuntil(b'Hash: ')
    data = r.recvuntil(b'\n').decode().strip()
    h = base64.b64decode(data)
    print(f'hash: {list(h)}')
    # h is the hash of the componentwise addition of secret and inverse_secret.
    # We have arranged it so that that product is in G^(n).  Thus the residue
    # classes mod G^(n+1) of the components of the hash correspond to those of
    # secret + inverse_secret
    #
    # So in G^(n) / G^(n+1) we will have that
    # Value(h[i]) == Value(secret[i]) + Value(inverse_secret[i])
    # which means that we can get
    # -Value(secret[i]) = Value(inverse_secret[i]) - Value(h[i])
    # still only valid modulo G^(n+1).
    # So we update inverse_secret using this formula, and if before the update
    # inverse_secret was correctly the inverse of secret modulo G^(n), then the
    # new value will be correct modulo G^(n+1).
    inverse_secret_new = []
    secret = []
    for i in range(BLOCKSIZE):
        inverse_secret_new.append(
                (Value(inverse_secret[i]) + Value(invert(h[i]))).n )
        secret.append(invert(inverse_secret_new[-1]))
    inverse_secret = inverse_secret_new
    print(f'Current value of secret: {secret}')

# inverse_secret will now be correct modulo G^(4), but as G^(4), this is
# actually exactly the inverse of the secret that the remote has, hence secret
# is the secret the server has.
r.recvuntil(b'Your guess at secret: ')
r.send(base64.b64encode(bytes(secret)) + b'\n')
flag = r.recvuntil(b'\n').decode().strip()
print(flag)
