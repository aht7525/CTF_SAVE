from pwn import *
import ast

r=remote('218.158.141.182',52387)
for i in range(1,101):
	r.recvuntil('Step :  '+str(i)+'\n')
	r.recvuntil('\n')
	key=r.recvuntil('\n').replace('\n','')
	r.recvuntil('height = ')
	height=int(r.recvuntil('\n').replace('\n',''))
	r.recvuntil('table :  ')
	table=r.recvuntil('}')
	table=ast.literal_eval(table)
	real_table={v: k for k, v in table.iteritems()}
	output=''
	output2=''
	for i in range(len(key)):
		output+=key[i]
		if(key[i] == '1'):
			output2+=real_table[output]
			output=''
		if(len(output) == (height-1)):
			output2+=real_table[output]
			output=''
	r.sendlineafter('Input :',output2)
	output2=''
r.interactive()