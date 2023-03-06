#!/usr/bin/env python3

import fileinput

for l in fileinput.input():
  l = l.rstrip('\n')
  while len(l)>0:
    sl = l[0:7]
    l = l[7:]
    print(chr(int(sl,2)), end='')

print()
