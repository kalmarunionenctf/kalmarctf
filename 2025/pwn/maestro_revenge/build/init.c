#define _GNU_SOURCE
#include <stdint.h>

#include "shellcode.h"

char *const argv[] = { "/bin/sh", "--login", NULL };
char *const envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/home/ctf", NULL };

void _start() { 
    write(1, "\e[1;1H\e[2J", 10);
    
    mount("procfs", "/proc", "procfs", 0, NULL);
    
    chmod("/", 0755);
    chown("/home/ctf", 1000, 1000);
    sethostname("maestro", 7);
    
    // Read exploit
    mknod("/dev/sda", S_IFBLK | 0660, makedev(8, 0));
    int blkfd = open("/dev/sda", O_RDONLY|O_CLOEXEC);
    int outfd = open("/home/ctf/exploit", O_WRONLY|O_CREAT|O_CLOEXEC, 0775);

    ssize_t count;
    char buf[512];
    while ((count = read(blkfd, buf, sizeof(buf))) > 0) {
        write(outfd, buf, count);
    }
    close(outfd);
    close(blkfd);
    chown("/home/ctf/exploit", 1000, 1000);

    int modfd = open("/lib/modules/maestro-0.1.0/default/libserial.so", O_RDONLY|O_CLOEXEC);
    finit_module(modfd, NULL, 0);

    int pid = fork();
    if (pid == 0) {
        chdir("/home/ctf");
        setuid(1000);
        setgid(1000);
        execve("/bin/sh", argv, envp);
        exit(1);
    }
	waitpid(pid, NULL, 0);
    reboot(0xde145e83, 0x40367d6e, 1, NULL);
}
