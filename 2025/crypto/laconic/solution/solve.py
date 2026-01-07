from sage.all import *
import json
import sys
import zlib

import socket

from pks import *
from ab_lfe import *

if len(sys.argv) != 3:
    print("Usage: sage client.py HOST PORT")
else:
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])

def recv_loop(conn, buf = b''):
    while b'\n' not in buf and len(buf) < 1000000:
        new_data = conn.recv(1000)
        if len(new_data) == 0:
            raise RuntimeError("Server Disconnected")
        buf += new_data
    return buf

cmd = b"cat flag.txt"

scale = q // (4 * cbd_nu)

def attack_circuit(comments, target = None):
    if target != None:
        add_target = public_key.const(-target)
    else:
        add_target = ciphertext()

    return sum((comments[i] * Rx(2**i) for i in range(len(comment_inputs))), add_target)

def gadget_inv_bits(u):
    if u.parent() == Rx or u.parent() == Zqx:
        inv_elems = [gadget_inv_bits(ui) for ui in u.list()]
        return vector([u.parent()([inv_elems[j][i] for j in range(N)]) for i in range(len(comment_inputs))])

    u = Zq(u).lift()
    digits = u.digits(2)
    digits += (len(comment_inputs) - len(digits)) * [0]
    return vector(digits)

target_pk = scale * (command_input.mat - matrix(Rx, encode_bytes(cmd) * gadget))[0,0]
attack_pk = attack_circuit(comment_inputs, target_pk).mat[0,0]
comment_chunks = list(gadget_inv_bits(attack_pk))

comment = b''
for chunk in comment_chunks:
    chunk_bits = [int(c.lift()) for c in chunk.lift().list()]
    chunk_bits += [0] * (N - len(chunk_bits))
    comment += bytes(sum(chunk_bits[8 * i + j] << j for j in range(8)) for i in range(N // 8))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    buf = recv_loop(s)
    msg, buf = buf.split(b'\n', 1)
    print(msg.decode())

    print(cmd)
    s.sendall(cmd + b'\n')

    buf = recv_loop(s, buf)
    msg, buf = buf.split(b'\n', 1)
    print(msg.decode())

    print(comment.hex())
    s.sendall(comment.hex().encode() + b'\n')

    buf = recv_loop(s, buf)
    msg, buf = buf.split(b'\n', 1)
    print(msg.decode())

    # Receive the final ciphertext
    while True:
        new_data = s.recv(1000)
        if len(new_data) == 0:
            break
        buf += new_data

    ctxt_object = json.loads(zlib.decompress(buf))
    input_ctxts = [vector(Rx, [deserialize_Rx(u) for u in ctxt]) for ctxt in ctxt_object['input_ctxts']]
    t = deserialize_Rx(ctxt_object['t'])
    msg_ctxt = deserialize_Rx(ctxt_object['msg_ctxt'])

    input_pks = [command_input]
    input_pks += comment_inputs[:len(input_ctxts)-1]

    input_ctxts = [ciphertext(pk, v, ct) for pk, v, ct in zip(input_pks, [encode_bytes(cmd)] + comment_chunks, input_ctxts)]

print("Decrypting...")

# Should give an RLWE sample under public matrix target_pk
attack_rlwe_sample = attack_circuit(input_ctxts[1:]).rlwe_sample[0]

scaled_noise = scale * input_ctxts[0].rlwe_sample[0] - attack_rlwe_sample
noise = [(u + (scale // 2)).lift() // scale for u in scaled_noise.lift().list()]
print(noise)
noise = [u if u < 4 * cbd_nu - u else u - 4 * cbd_nu for u in noise]
print(noise)

# Remove the noise and recover the secret
secret = (input_ctxts[0].rlwe_sample[0] - Rx(noise)) / (command_input.mat[0,0] - encode_bytes(cmd))

noisy_msg = msg_ctxt - secret * (predicate_pk.mat * gadget_inv_elem(t))[0]

msg_bits = [1 if (q <= 4 * m.lift() < 3 * q) else 0 for m in noisy_msg.lift().list()]
msg_bits += [0] * (N - len(msg_bits))

msg = bytes(sum(msg_bits[8 * i + j] << j for j in range(8)) for i in range(len(msg_bits) // 8))
print("Message:")
try:
    print(msg.decode())
except:
    print(msg)
