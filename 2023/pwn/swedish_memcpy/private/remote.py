#!/usr/bin/env python3
import os
from base64 import b64decode
import subprocess
try:
    s = input("Please give base64 encoded main.bin: ")
except EOFError:
    print("eof")
    exit()

try:
    data = b64decode(s)
    assert len(data) <= 0x2000
except Exception:
    print("Invalid data")
    print("Read:", s)
    exit()

p = subprocess.Popen(["./run.sh"], stdin=subprocess.PIPE)
p.stdin.write(data)
p.stdin.close()
p.wait()

