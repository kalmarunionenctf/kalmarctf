#!/usr/bin/env python3
from sandbox import check_source, safe_globals
from fastformat import format

print("Please give your input. End with \"EOF\"")
source_code = ""
try:
    while (s := input()) != 'EOF':
        source_code += s + '\n'
except EOFError:
    pass

if check_source(source_code):
    byte_code = compile(source_code, '<inline>', 'exec')
    exec(byte_code, safe_globals, {'format': format})
else:
    print("Invalid source")

