key=[3,3,1,0,1,1,1,0,0,0,0,1,0,3,3,1,1,0,0,0,1,0,0,1,1,0,3,3,1,0,1,1,0,1,1,0,0,0,0,3,3,1,1,0,0,0,0,0,1,0,1,1,3,3,1,1,0,1,0,0,0,1,1,0,0,3,3,1,1,0,0,0,1,0,1,0,0,1,3,1,0,1,0,0,1,0,1,1,1,1,0,3,3,1,1,0,0,0,0,0,1,0,1,0,3,3,1,1,0,0,1,1,0,1,1,0,0,3,3,1,0,1,1,0,1,1,1,0,1,0,3,1,0,1,0,0,1,0,1,1,1,1,0,3,3,1,1,0,0,1,1,1,1,0,0,0,3,3,1,0,1,1,0,1,1,1,0,1,0,3,3,1,0,1,1,0,1,0,1,1,1,1,3,1,0,1,0,0,1,0,1,0,1,0,1]
key2=[3,1,0,1,0,0,1,0,1,1,1,1,0,3,3,1,1,0,1,1,1,0,0,1,1,1,3,3,1,1,0,1,1,0,1,0,0,1,1,3,3,1,0,1,1,0,1,0,0,1,0,0,3,3,1,1,0,0,0,0,1,1,1,0,1,3,3,1,0,1,1,0,1,1,1,0,1,0,3,3,1,1,0,0,1,1,1,0,1,1,1,3,3,1,1,0,1,1,1,0,0,1,0,1,3,3,1,1,0,1,0,0,0,1,1,0,1,3,3,1,0,1,1,0,1,1,1,0,1,0,3,3,1,1,0,1,1,1,0,1,1,1,1,3,1,0,1,0,0,1,1,0,0,0,0,0,3,3,1,1,0,1,1,1,0,0,1,0,1,3,3,1,1,0,0,1,1,1,0,1,1,1,3,3,1,1,0,1,0,0,0,0,0,0,0]
flag=[]
def gen_flag():
    dst=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    v14=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    v13 = [_ for _ in range(256)]
    for i in range(256):
        v13[i] = 0
    for i in range(15):
        v3 = 1
        for j in range(12,-1,-1):
            if(key[13*i+j]!=3):
                dst[i]+=v3*key[13*i+j]
                v3 = v3*2
    for k in range(15):
        v4 = 1000
        for l in range(4):
            v13[4*k+l] = dst[k]/v4
            dst[k] %= v4
            v4 = v4/10
    for m in range(15):
        v13[4*m]+=3
    for n in range(15):
        for ii in range(4):
            v13[4*n+ii]^=5
        v5=1
        for jj in range(3,-1,-1):
            v13[4*n+jj]*=v5
            v14[n]+=(v13[4*n+jj])
            v5*=4
    return v14
def gen_flag2():
    dst=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    v14=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    v13 = [_ for _ in range(256)]
    for i in range(256):
        v13[i] = 0
    for i in range(15):
        v3 = 1
        for j in range(12,-1,-1):
            if(key2[13*i+j]!=3):
                dst[i]+=v3*key2[13*i+j]
                v3 = v3*2
    for k in range(15):
        v4 = 1000
        for l in range(4):
            v13[4*k+l] = dst[k]/v4
            dst[k] %= v4
            v4 = v4/10
    for m in range(15):
        v13[4*m]+=3
    for n in range(15):
        for ii in range(4):
            v13[4*n+ii]^=5
        v5=1
        for jj in range(3,-1,-1):
            v13[4*n+jj]*=v5
            v14[n]+=(v13[4*n+jj])
            v5*=4
    return v14
for t in range(15):
    flag.append(gen_flag()[t])
for t in range(15):
    flag.append(gen_flag2()[t])
print(flag)
real_flag = ""
for i in range(len(flag)):
    real_flag+=chr(flag[i])
print(real_flag)