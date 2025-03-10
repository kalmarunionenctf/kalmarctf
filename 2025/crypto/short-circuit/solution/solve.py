from pwn import *

with open("words.txt", "r") as f:
    words = [w.strip() for w in f.readlines()]
assert len(words) == 2048

print("Loading table...")
table = {}
with open("table.txt", "r") as f:
    for l in f:
        if not l.strip():
            continue
        letters, indexes = l.strip().split(":")
        indexes = [int(x) for x in indexes.split(",")]
        table[letters] = indexes

print("Connecting...")
while True:
    with remote("short-circuit.chal-kalmarc.tf", 1337) as io:
        io.recvuntil(b"(hint: ")
        hint_line = io.recvline().decode()
        hint_letters = "".join(w[0] for w in hint_line.split(" ")[:5])
        if hint_letters not in table:
            continue
        answer = " ".join(words[i] for i in table[hint_letters])
        print(hint_letters, answer)
        io.recvuntil(b"> ")
        io.sendline(answer.encode())
        resp = io.recvline()
        if resp != b"Nope!\n":
            print(resp)
            break
