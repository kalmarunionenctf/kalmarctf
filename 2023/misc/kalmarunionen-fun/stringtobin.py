#!/usr/bin/env python3

import sys

st = sys.argv[1]

print(''.join(format(ord(x), 'b').zfill(7) for x in st))
