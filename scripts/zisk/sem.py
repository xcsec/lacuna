M=(1<<64)-1
def s64(x):
    x&=M
    return x-(1<<64) if x>>63 else x
def s32(x):
    x&=0xffffffff
    return x-(1<<32) if x>>31 else x
def sext32(x): return s32(x)&M
def rv(op,a,b):
    a&=M; b&=M
    if op=="add": return (a+b)&M
    if op=="sub": return (a-b)&M
    if op=="xor": return a^b
    if op=="and": return a&b
    if op=="or":  return a|b
    if op=="sll": return (a<<(b&63))&M
    if op=="srl": return (a>>(b&63))
    if op=="sra": return (s64(a)>>(b&63))&M
    if op=="slt": return 1 if s64(a)<s64(b) else 0
    if op=="sltu":return 1 if a<b else 0
    if op=="mul": return (a*b)&M
    if op=="mulh":return ((s64(a)*s64(b))>>64)&M
    if op=="mulhu":return ((a*b)>>64)&M
    if op=="div":
        if b==0: return M
        q=abs(s64(a))//abs(s64(b)); 
        if (s64(a)<0)!=(s64(b)<0): q=-q
        return q&M
    if op=="divu":
        if b==0: return M
        return (a//b)&M
    if op=="rem":
        if b==0: return a
        r=abs(s64(a))%abs(s64(b))
        if s64(a)<0: r=-r
        return r&M
    if op=="remu":
        if b==0: return a
        return (a%b)&M
    if op=="addw": return sext32((a+b)&0xffffffff)
    if op=="subw": return sext32((a-b)&0xffffffff)
    if op=="mulw": return sext32((a*b)&0xffffffff)
    raise ValueError(op)
# opcode table: name -> selector
OPS=[("add",0),("sub",1),("xor",2),("and",3),("or",4),("sll",5),("srl",6),("sra",7),
     ("mul",10),("mulh",11),("mulhu",12),("div",13),("divu",14),("rem",15),("remu",16),
     ("addw",17),("subw",18),("mulw",19)]
A=0x0123456789ABCDEF
B=0x1122334455667788
if __name__=="__main__":
    for n,s in OPS:
        print(f"{n}\tsel={s}\texp=0x{rv(n,A,B):016x}")
