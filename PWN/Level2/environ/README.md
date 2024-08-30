![checksec](images/checksec.png)

Stack:    Executable -> Execute shellcode in stack

Environ ptr: point to stack 
Leak stdout -> libc -> environ

![offset](images/environ_offset.png)

![vmmap](images/environ_vmmap.png)