from z3 import *

s=Solver()
xs=[BitVec("x%d" % i, 32) for i in range(2)]
s.add(xs[0]<100000)
s.add(xs[1]<100000)
s.add(((xs[0]-1)*xs[1]-((xs[1]>>1)+(xs[1]>>1)*2)+(xs[0]))^0xaaefeae == 0x1b008da0)
s.add(xs[0]<47000)
s.add(xs[0]>46000)
s.add(xs[1]<99000)
s.add(xs[1]>98000)
r=s.check()
if r == sat:
	m=s.model()
	print(m)