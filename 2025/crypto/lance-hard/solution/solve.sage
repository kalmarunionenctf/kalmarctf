#!/usr/bin/env sage

from Crypto.Util.strxor import strxor
from hashlib import shake_128
from itertools import chain
from multiprocessing import Pool
from tqdm import tqdm
from functools import partial

from multipoint import multi_point_tree

# I feel like there should be a much better solution based on trying to find the algebraic variety
# given its principle divisors.

a_list = []
o_list = []

with open('output.txt', 'r') as f:
    data = f.readlines()
    p, a, b = [ZZ(x) for x in data[0].split(' ')]

    samples = len(data) - 2
    for i in range(samples):
        ai, oi = [ZZ(x) for x in data[1 + i].split(' ')]
        a_list.append(ai)
        o_list.append(oi)
    ctxt = bytes.fromhex(data[-1])

F = GF(p)
E = EllipticCurve(F, [a,b])
order = E.cardinality()
assert order.is_prime()

# Find short linear combination of a's that adds to zero.
def get_shortest_ortho(a_list, num_vecs):
    l = len(a_list)

    a0_inv = inverse_mod(a_list[0], order)
    A = [[order] + [(-a0_inv * a_list[i]) % order for i in range(1, l)]]
    for i in range(1, l):
        A.append([0] * i + [1] + [0] * (l - 1 - i))

    A = matrix(A).transpose()
    short_vecs = A.BKZ(block_size=l)[:num_vecs]
    output = []
    for sv in short_vecs:
        assert sum(x * y for x, y in zip(a_list, sv)) % order == 0
        if 0 in sv:
            continue
        deg = int(sv.norm()^2) * 2^(l - 2)
        cost = int(sv.norm()^2) * 2^(2*l - 3)
        output.append((cost, deg, sv))

    return output

print("Finding linear combinations")
def find_eqns(eqns_needed, subsets):
    best_n = []
    for subset in subsets:
        a_list_i = [a_list[j] for j in subset]
        best_n += [(cost, deg, sv, subset) for cost, deg, sv in get_shortest_ortho(a_list_i, 1)]
        best_n.sort()
        best_n = best_n[:eqns_needed]
    return best_n

with Pool() as pool:
    tries = 4000000 # It's worth it to spend some time trying to find a good set of equations for later.
    samples_to_use = 9
    eqns_needed = 2

    set_random_seed(0) # Easier testing
    subsets = Subsets(range(samples), samples_to_use)

    chunk_size = 5000
    try_subsets_chunks = ([subsets.random_element() for j in range(i, min(i + chunk_size, tries))] for i in range(0, tries, chunk_size))
    best_n = list(chain.from_iterable(tqdm(
        pool.imap_unordered(partial(find_eqns, eqns_needed), try_subsets_chunks),
        total = float(tries / chunk_size))))
    best_n.sort()
    best_n = best_n[:eqns_needed]

    print([(u[0], u[1], u[0].bit_length(), u[1].bit_length()) for u in best_n])
    print(best_n)

#nonsquare = 2
#while True:
#    if jacobi_symbol(nonsquare, p) == -1:
#        break
#    nonsquare += 1
#nonsquare_inv = F(nonsquare).inverse()
#nonsquare_sqrt = F(nonsquare).sqrt()
#F2 = nonsquare_sqrt.parent()

R.<r> = F['r']

def compute_powers(a, max_deg):
    out = [1, a]
    while len(out) <= max_deg:
        out.append(out[-1] * a)
    return out

from sage.combinat import gray_codes
gray_code = list(gray_codes.product([2] * (samples_to_use - 1)))

# Define functions before the Pool to avoid issues with pickling.

# Find values of r to interpolate through that do not require any field extensions to get points on
# the curve. Sage's field extension arithmetic seems to be enough slower than Fp for this to be
# worthwhile.
def find_r(o_list_subset, chunk_size, num_r_points, j_start):
    j_end = min(j_start + chunk_size, num_r_points)
    out = []
    for j in range(j_start, j_end):
        #rj = F.random_element()
        rj = F(1000000000 * j)
        while True:
            for o in o_list_subset:
                xij = -rj + o
                if not (xij^3 + a*xij + b).is_square():
                    break
            else:
                out.append(rj)
                break
            rj += 1
    return out

def eval_scalar_mult(pair):
    c, o = pair

    mult_map = E.multiplication_by_m(c, x_only=True)
    map_x = mult_map.numerator()
    map_z = mult_map.denominator()

    x_list = r_tree.evaluate(map_x(-r + o))
    if map_z == 1:
        z_list = [map_z] * r_tree.n_points
    else:
        z_list = r_tree.evaluate(map_z(-r + o))

    return x_list, z_list


def calc_interp_constraints(gray_code, xz_lists):
    x_lists, z_lists = xz_lists
    samples_to_use = len(x_lists[0])
    x_deg = samples_to_use // 2
    z_deg = (samples_to_use + 1) // 2

    interp_con = []
    for x_samples, z_samples in zip(x_lists, z_lists):
        rows = []
        for i in range(samples_to_use):
            xij = x_samples[i]
            zij = z_samples[i]
            xij_pows = compute_powers(xij, max(x_deg, 3))
            zij_pows = compute_powers(zij, max(z_deg, 4))

            yzsqij = xij_pows[3] * zij + a*xij*zij_pows[3] + b*zij_pows[4]
            #if yzsqij.is_square():
            #    yzij = yzsqij.sqrt(extend=False)
            #else:
            #    yzij = (yzsqij * nonsquare_inv).sqrt(extend=False) * nonsquare_sqrt
            yzij = yzsqij.sqrt(extend=False)

            row = [xij_pows[i] * zij_pows[z_deg - i] for i in range(x_deg + 1)]
            row += [yzij * xij_pows[i] * zij_pows[z_deg - 2 - i] for i in range(z_deg - 2 + 1)]
            rows.append(row)

        orig_mat = matrix(rows)
        det = orig_mat.determinant()
        inv_mat = orig_mat.inverse()

        det_prod = det

        # Compute all determinants of subsets of the ys negated, using the Sherman-Morrison formula
        # for rank 1 updates. Last y is never negated, as negating it is equivalent to negating all
        # of the others (and possibly negating the result).
        for row_i, change in gray_code:
            # u = [0] * row_i + [-2 * change] + [0] * (samples_to_use - row_i - 1)
            v = orig_mat.row(row_i)
            for i in range(x_deg + 1):
                v[i] = 0

            inv_mat_u = (-2 * change) * inv_mat.column(row_i)
            det_update = 1 + v.inner_product(inv_mat_u)
            v_inv_mat = v * inv_mat

            inv_mat -= inv_mat_u.outer_product(v_inv_mat) / det_update
            det *= det_update

            det_prod *= det

        #det_prod = F(det_prod)

        # Remove excess factors of the Vandermonde determinant
        v_det = prod(x_samples[l] * z_samples[k] - x_samples[k] * z_samples[l] for k in range(samples_to_use - 1) for l in range(k + 1, samples_to_use))
        if samples_to_use % 2 == 1:
            # We have extra multiples of z in each det, because we used y*z instead of y.
            v_det *= prod(zi for zi in z_samples)
        interp_con.append(det_prod / v_det^(2^(samples_to_use - 2)))

    return interp_con

constraints = []
for cost, deg, sv, subset in best_n:
    print("Finding r points that don't require field extension.")
    o_list_subset = [o_list[j] for j in subset]
    num_r_points = deg + 2
    chunk_size = 1000
    with Pool() as pool:
        r_points = list(chain.from_iterable(tqdm(
            pool.imap_unordered(partial(find_r, o_list_subset, chunk_size, num_r_points),
                                range(0, num_r_points, chunk_size)),
            total = float(num_r_points / chunk_size))))

    # Hopefully we didn't get any collisions by accident
    assert(len(set(r_points)) == len(r_points))

    global r_tree # Avoid pickling
    r_tree = multi_point_tree(r, list(r_points))

    print("Evaluating scalar multiplications")
    #with Pool(2) as pool: # Multi-threading this uses too much memory for my puny laptop
    #    xz_lists = list(tqdm(
    #        pool.imap(eval_scalar_mult, zip(sv, o_list_subset)),
    #        total = len(sv)))
    xz_lists = list(tqdm((eval_scalar_mult(pair) for pair in zip(sv, o_list_subset)), total = len(sv)))

    x_lists = [[xz[0][j] for xz in xz_lists] for j in range(num_r_points)]
    z_lists = [[xz[1][j] for xz in xz_lists] for j in range(num_r_points)]
    del xz_lists

    print("Evaluating constraint")
    chunk_size = 200
    interp_con_input_lists = [(x_lists[j:j+chunk_size], z_lists[j:j+chunk_size]) for j in range(0, num_r_points, chunk_size)]
    with Pool() as pool:
        interp_con = list(chain.from_iterable(tqdm(
            pool.imap(partial(calc_interp_constraints, gray_code), interp_con_input_lists),
            total = float(num_r_points / chunk_size))))

    print("Interpolating constraint")
    r_tree.calculate_derivatives()
    constraint = r_tree.interpolate(interp_con)
    print(constraint.degree(), deg)
    constraints.append(constraint)

print("Finding GCD")
combined_constraints = gcd(constraints)
print(combined_constraints.degree())
print(combined_constraints)
for ri, mul in combined_constraints.roots():
    try:
        Kx = (inverse_mod(a_list[0], order) * E.lift_x(-ri + o_list[0])).x()

        # Try decrypting:
        keystream = shake_128(str((Kx, ri)).encode()).digest(len(ctxt))
        flag = strxor(keystream, ctxt)
        print(flag)
    except ValueError as e:
        print(e)
