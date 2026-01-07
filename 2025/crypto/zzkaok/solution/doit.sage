from intarg import *

from server import NUMBER

import fractions

def decomp(n):
    vecs = []
    for p in PRIMES:
        try:
            e = (n.numerator() * inverse_mod(n.denominator(), p)) % p
        except ZeroDivisionError:
            e = 0 # if it fails, try a different value here
        vecs.append(e)
    return vecs

class BadCom(Merkle):
    def __init__(self, n):
        self.n = n
        self.cord = decomp(n)
        super().__init__([str(n) for n in self.cord])

    def eval(self):
        return self.n

class BadProver:
    def __init__(self, statement):
        self.tx = Transcript(statement)
        self.coms = []
        self.open = []
        self.vals = []

    def equal(self, expr, value):
        pass

    def com(self, n):
        com = BadCom(n)
        self.coms.append(com)
        self.tx.com(com)
        return com

    def value(self, value):
        assert value.denominator() == 1
        value = int(value)
        self.tx.value(value)
        self.vals.append(int(value))
        return value

    def combine(self):
        expr = Mul(self.tx.challenge(), self.coms[0])
        for com in self.coms[1:]:
            expr = Add(expr, Mul(self.tx.challenge(), com))
        return expr

    def finalize(self):
        cmb = self.combine()
        value = self.value(cmb.eval())
        self.equal(cmb, value)

        # opening proofs
        positions = [self.tx.challenge() % len(PRIMES) for _ in range(QUERIES)]
        return {
            'root': [com.root for com in self.coms],
            'vals': self.vals,
            'open': [[com.open(pos) for pos in positions] for com in self.coms],
            'poss': positions
        }

from fractions import Fraction

def frac_four_squares(n):
    v1, v2, v3, v4 = four_squares(n.numerator() * n.denominator())
    v1 = v1 / n.denominator()
    v2 = v2 / n.denominator()
    v3 = v3 / n.denominator()
    v4 = v4 / n.denominator()
    assert v1*v1 + v2*v2 + v3*v3 + v4*v4 == n
    return v1, v2, v3, v4

f = 2
p = 1/f * NUMBER
q = f

assert p*q == NUMBER

a = p**2 - 4
b = q**2 - 4

a1, a2, a3, a4 = frac_four_squares(a)
b1, b2, b3, b4 = frac_four_squares(b)

prv = BadProver(NUMBER)

p = prv.com(p)
q = prv.com(q)

a1 = prv.com(a1)
a2 = prv.com(a2)
a3 = prv.com(a3)
a4 = prv.com(a4)

b1 = prv.com(b1)
b2 = prv.com(b2)
b3 = prv.com(b3)
b4 = prv.com(b4)

rel_factor(
    prv,
    p, a1, a2, a3, a4,
    q, b1, b2, b3, b4,
    NUMBER
)

pf = prv.finalize()

msg = {
    'pf': pf,
    'N': NUMBER,
}

import json

from server import check_proof

assert check_proof(msg) == NUMBER

open('pf.json', 'w').write(json.dumps(msg))
