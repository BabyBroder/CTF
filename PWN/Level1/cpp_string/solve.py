from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./cpp_string', checksec=False)

r = process(exe.path)