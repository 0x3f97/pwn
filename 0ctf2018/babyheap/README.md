# Baby Heap 2018

**Points:** 183
**Solves:** 50

>[babyheap](babyheap)

程序主要功能有四个：1. alloc 2. update 3. delete 4. view，update 存在 `off-by-one` 溢出，看了下 alloc 限制了
`0x58` 大小的 `calloc` 内存分配，就没往 fastbin attack 想（赛后发现这题应该是用 fastbin 做的。。），找 
`/dev/urandom` 随机数预测相关的文章，想获取 mmap 地址使用 `unlink` 技术获取任意地址读写，搞不出来搁置了一段
时间突然想到 `house of orange`，就用 `IO_FILE` 技术搞出来了，而 `glibc-2.24` 版本对 `vtable` 新增了 `IO_vtable_check`
([`libio/vtables.c`](https://code.woboq.org/userspace/glibc/libio/vtables.c.html#39))，不过可以使用 `IO_str_jumps`
绕过，对其 overflow 函数 `IO_str_overflow` 函数的代码 [`/libio/strops.c`](https://code.woboq.org/userspace/glibc/libio/strops.c.html#_IO_str_overflow) 进行分析，可进行以下构造：

```
_flags = 0
_IO_buf_base = 0
_IO_write_ptr = 0x7fffffffffffffff
_IO_write_base = 0
_IO_buf_end = (bin_sh_addr-0x64)/2
_IO_buf_base = 0
```

`_IO_str_overflow` 填在 `0xe0` 偏移处，`system` 地址填在它后面
