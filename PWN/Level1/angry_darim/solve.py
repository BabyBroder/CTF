#!/usr/bin/python3

from pwn import *
import time

JOKER = "\x5f\x75\x43\x30\x6e\x5f"

context.binary = exe = ELF('./darim',checksec=False)

token = int(time.time())

pwd = JOKER + '_' + str(token)

p = process(['./darim',pwd])
print(pwd)

p.interactive()