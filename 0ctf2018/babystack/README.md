# Baby Stack 2018

**Points:** 132
**Solves:** 73

>[babystack](babystack)


使用 return-to-dl-resolve 技术解决这题，分析程序，只开启了 `NX` 没有 `PIE` 和 `stack canary`，继续分析，程序
功能非常简单，发现在 `0x804843b` 处的函数存在 `0x18` 字节的溢出，可以构造 rop。

程序的 `plt` 没有 `system` 函数可以调用，而在无法泄露 libc 的情况下就需要用到 `_dl_runtime_resolve` 函数对 `system`
函数进行绑定，由于延迟绑定机制，程序在执行的过程中，对没有调用过的函数先不进行绑定，等到要调用该函数时再对其
进行绑定。

`_dl_runtime_resolve` 调用了 `_dl_fixup` 进行重定位处理，相关代码在
[`elf/dl-runtime.c`](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/dl-runtime.c#l61)，可以调用 `plt[0]`
位置处的代码来调用 `_dl_runtime_resolve`。

`_dl_fixup` 函数从 `link_map` 中找到对应的 `symtab` 和 `strtab`，再根据传入的 `reloc_arg` 参数找到需要重定位
的函数在 `.rel.plt` 重定位节上对应的条目，再根据重定位条目的 `r_info` 找到 `symtab` 表中符号字符串在 `strtab`
表中的偏移，找到 `strtab` 中的字符串后查找对应的函数地址填写到 `r_offset` 地址处，即完成了函数重定位。

根据重定位处理逻辑构造相应的 rop，攻击思路：
1. 控制 `eip` 为 `.plt` 地址，传递 `reloc_arg` 参数
2. 控制 `reloc_arg` 的值，使 `reloc` 落在可控范围内
3. 伪造 `reloc` 的内容，使 `sym` 落在可控范围内
4. 伪造 `sym` 的内容，使 `name` 落在可控范围内
5. 伪造 `name` 为 `system`

验证秘钥稍微跑一下就可以了，而输入输出都被重定向了想不到什么办法把它重定向回来，就直接把输出重定向到一台服务
器上接收。。
