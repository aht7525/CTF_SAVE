t=bytearray(open('Encrypted_1.exe').read())
for i in range(len(t)):
	tmp=t[i]
	tmp+=0x19
	tmp^=0x95
	tmp^=0x1
	tmp-=0x12
	t[i]=tmp&0xff
open('fix.exe','w+b').write(t)