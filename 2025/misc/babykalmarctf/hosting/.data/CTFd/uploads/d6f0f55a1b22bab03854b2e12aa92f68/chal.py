

def collatz(x):
    if x % 2:
        return x//2
    else:
        return 3*x + 1


with open("flag.txt", "rb") as f:
    flag = f.read()

flag = int.from_bytes(flag, 'big')

# Good luck!
with open("collatz_counterexample", "r") as f:
    collatz_counter = int(f.read())

assert collatz_counter >= 3

collatz_cycle = collatz_counter
for _ in range(collatz_cycle):
    collatz_cycle = collatz(collatz_cycle)

# This is probably impossible right?
assert collatz_cycle == collatz_counter

masked_flag = (flag * collatz_cycle) % 2**2048

with open("output.txt", "w") as f:
    f.write(masked_flag)