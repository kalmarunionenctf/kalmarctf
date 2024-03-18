from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

from os import urandom

FLAG = b'kalmar{???}'

def connectingIdeal(O1, O2):
    I = O1*O2
    I *= I.norm().denominator()
    return I

def gram_matrix(basis):
    M = []
    for a in basis:
        M.append([a.pair(b) for b in basis])
    return Matrix(QQ, M)

def ReducedBasis(I):
    B = I.basis()
    G = gram_matrix(I.basis())
    U = G.LLL_gram().transpose()
    return [sum(c*beta for c, beta in zip(row, B)) for row in U]

def invariant(O):
    return [b.reduced_norm() for b in ReducedBasis(O)]


def reduceHeight(O):
    B = O.quaternion_algebra()
    O0 = B.maximal_order()
    I_conn = connectingIdeal(O0, O)
    alpha = ReducedBasis(I_conn)[0]
    O_reduced = B.quaternion_order([alpha * b * alpha^(-1) for b in O.basis()])
    return O_reduced, alpha 

def isIsomorphic(O1, O2):
    I = connectingIdeal(O1, O2)
    for alpha in ReducedBasis(I):
        if alpha.reduced_norm() == I.norm():
            return True
    return False

def GroupAction(O_oriented, es_in, ells, gens):
    O, omega = O_oriented
    
    es = es_in.copy()
    O_i = O
    while not all([e == 0 for e in es]):
        frak_l = O_i*1
        for i in range(len(es)):
            if es[i] != 0:
                if es[i] > 0:
                    gen = (gens[i] + omega)
                    es[i] -= 1
                else:
                    gen = (gens[i] - omega)
                    es[i] += 1
                frak_l = frak_l.intersection(O_i*gen + O_i*ells[i])

        O_i = frak_l.right_order()

        O_i, beta = reduceHeight(O_i)
        omega = beta*omega*beta^(-1)

    return O_i, omega

def encrypt_flag(shared_secret):
    key = SHA256.new(data=str(shared_secret).encode()).digest()[:128]
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(FLAG, 16))
    return iv.hex(), ct.hex()

if __name__=="__main__":
    p = next_prime(2**512)
    B = QuaternionAlgebra(-1, -p)
    i, j, k = B.gens()
    O0 = B.maximal_order()

    omega = 820*i + 362*j + 153*k
    d = -ZZ(omega**2)

    assert is_prime(d)
    assert omega in O0
    assert (1 + omega)/2 not in O0

    O0_oriented = (O0, omega)

    ells = [ell for ell in Primes()[:150] if kronecker(-d, ell) == 1]
    gens = [ZZ(mod(-d, ell).sqrt()) for ell in ells]

    alice_secret = [randint(-3, 3) for _ in range(len(ells))]
    bob_secret = [randint(-3, 3) for _ in range(len(ells))]
    
    O_A = GroupAction(O0_oriented, alice_secret, ells, gens)
    O_B = GroupAction(O0_oriented, bob_secret, ells, gens)

    assert O_A[1] in O_A[0]
    assert O_B[1] in O_B[0]

    print("Alice's public key:")
    print(f"O_A = {O_A[0].basis()}\nomega_a = {O_A[1]}")
    print("\n\nBob's public key:")
    print(f"O_B = {O_B[0].basis()}\nomega_b = {O_B[1]}")

    O_BA = GroupAction(O_B, alice_secret, ells, gens)
    O_AB = GroupAction(O_A, bob_secret, ells, gens)

    assert invariant(O_BA[0]) == invariant(O_BA[0])

    shared_secret = invariant(O_BA[0])
    iv, ct = encrypt_flag(shared_secret)
    print(f"\n\nEncrypted flag: iv = {iv}, ct = {ct}")

    



