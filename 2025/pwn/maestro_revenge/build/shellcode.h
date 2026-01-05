#ifndef _SHELLCODE_H
#define _SHELLCODE_H
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sched.h>
#include <string.h>
#include <poll.h>
#include <mqueue.h>
#include <utime.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/timex.h>
#include <sys/timerfd.h>
#include <sys/sem.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/times.h>
#include <sys/sysinfo.h>
#include <sys/msg.h>
#include <sys/utsname.h>
#include <linux/openat2.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/aio_abi.h>
#include <linux/capability.h>
#include <asm/ldt.h>

#define NOALIGN __attribute__ ((aligned (1)))
#define INLINE __attribute__((always_inline)) static inline
#define PARENS ()
#define EXPAND(...) EXPAND2(EXPAND2(EXPAND2(EXPAND2(__VA_ARGS__))))
#define EXPAND2(...) EXPAND1(EXPAND1(EXPAND1(EXPAND1(__VA_ARGS__))))
#define EXPAND1(...) __VA_ARGS__

#define NARGS(...) NARGS_(__VA_ARGS__, 7, 6, 5, 4, 3, 2, 1, 0)
#define NARGS_(_7, _6, _5, _4, _3, _2, _1, N, ...) N

#define CONC(A, B) CONC_(A, B)
#define CONC_(A, B) A##B

#define syscall(...) CONC(_syscall, NARGS(__VA_ARGS__))(__VA_ARGS__)

// Syscall define helper
#define SYSCALL_DEFINE_VOID(rettype, name) \
    INLINE rettype name (void) { return (rettype) syscall(__NR_##name); }

#define SYSCALL_DEFINE(rettype, name, ...) \
  INLINE rettype name ( \
  __VA_OPT__(EXPAND2(SYSCALL_DEFINE_HELPER1(__VA_ARGS__))) \
  ) { \
    return (rettype) syscall(__NR_##name , \
    __VA_OPT__(EXPAND2(SYSCALL_DEFINE_HELPER2(__VA_ARGS__))) \
    ); \
  }
#define SYSCALL_DEFINE_HELPER1(typename, varname, ...) \
    typename varname __VA_OPT__(,) \
  __VA_OPT__(SYSCALL_DEFINE_AGAIN1 PARENS (__VA_ARGS__))
#define SYSCALL_DEFINE_AGAIN1() SYSCALL_DEFINE_HELPER1

#define SYSCALL_DEFINE_HELPER2(typename, varname, ...) \
    (int64_t) varname __VA_OPT__(,) \
  __VA_OPT__(SYSCALL_DEFINE_AGAIN2 PARENS (__VA_ARGS__))
#define SYSCALL_DEFINE_AGAIN2() SYSCALL_DEFINE_HELPER2



#define read(...) sys_read(__VA_ARGS__)
#define write(...) sys_write(__VA_ARGS__)
#define open(...) CONC(__open, NARGS(__VA_ARGS__))(__VA_ARGS__)
#define close(...) sys_close(__VA_ARGS__)
#define stat(...) sys_stat(__VA_ARGS__)
#define fstat(...) sys_fstat(__VA_ARGS__)
#define lstat(...) sys_lstat(__VA_ARGS__)
#define poll(...) sys_poll(__VA_ARGS__)
#define lseek(...) sys_lseek(__VA_ARGS__)
#define mmap(...) sys_mmap(__VA_ARGS__)
#define mprotect(...) sys_mprotect(__VA_ARGS__)
#define munmap(...) sys_munmap(__VA_ARGS__)
#define brk(...) sys_brk(__VA_ARGS__)
// rt_sigaction
#define rt_sigprocmask(...) sys_rt_sigprocmask(__VA_ARGS__)
// rt_sigreturn
#define ioctl(...) syscall(__NR_ioctl, __VA_ARGS__)
#define pread64(...) sys_pread64(__VA_ARGS__)
#define pwrite64(...) sys_pwrite64(__VA_ARGS__)
#define readv(...) sys_readv(__VA_ARGS__)
#define writev(...) sys_writev(__VA_ARGS__)
#define access(...) sys_access(__VA_ARGS__)
#define pipe(...) sys_pipe(__VA_ARGS__)
#define select(...) sys_select(__VA_ARGS__)
#define sched_yield(...) sys_sched_yield(__VA_ARGS__)
#define mremap(...) CONC(__mremap, NARGS(__VA_ARGS__))(__VA_ARGS__)
#define msync(...) sys_msync(__VA_ARGS__)
#define mincore(...) sys_mincore(__VA_ARGS__)
#define madvise(...) sys_madvise(__VA_ARGS__)
#define shmget(...) sys_shmget(__VA_ARGS__)
#define shmat(...) sys_shmat(__VA_ARGS__)
#define shmctl(...) sys_shmctl(__VA_ARGS__)
#define dup(...) sys_dup(__VA_ARGS__)
#define dup2(...) sys_dup2(__VA_ARGS__)
#define pause(...) sys_pause(__VA_ARGS__)
#define nanosleep(...) sys_nanosleep(__VA_ARGS__)
#define getitimer(...) sys_getitimer(__VA_ARGS__)
#define alarm(...) sys_alarm(__VA_ARGS__)
#define setitimer(...) sys_setitimer(__VA_ARGS__)
#define getpid(...) sys_getpid(__VA_ARGS__)
#define sendfile(...) sys_sendfile(__VA_ARGS__)
#define socket(...) sys_socket(__VA_ARGS__)
#define connect(...) sys_connect(__VA_ARGS__)
#define accept(...) sys_accept(__VA_ARGS__)
#define sendto(...) sys_sendto(__VA_ARGS__)
#define recvfrom(...) sys_recvfrom(__VA_ARGS__)
#define sendmsg(...) sys_sendmsg(__VA_ARGS__)
#define recvmsg(...) sys_recvmsg(__VA_ARGS__)
#define shutdown(...) sys_shutdown(__VA_ARGS__)
#define bind(...) sys_bind(__VA_ARGS__)
#define listen(...) sys_listen(__VA_ARGS__)
#define getsockname(...) sys_getsockname(__VA_ARGS__)
#define getpeername(...) sys_getpeername(__VA_ARGS__)
#define socketpair(...) sys_socketpair(__VA_ARGS__)
#define setsockopt(...) sys_setsockopt(__VA_ARGS__)
#define getsockopt(...) sys_getsockopt(__VA_ARGS__)
#define clone(...) sys_clone(__VA_ARGS__)
#define fork(...) sys_fork(__VA_ARGS__)
#define vfork(...) sys_vfork(__VA_ARGS__)
#define execve(...) sys_execve(__VA_ARGS__)
#define exit(...) sys_exit(__VA_ARGS__)
#define wait4(...) sys_wait4(__VA_ARGS__)
#define kill(...) sys_kill(__VA_ARGS__)
#define uname(...) sys_uname(__VA_ARGS__)
#define semget(...) sys_semget(__VA_ARGS__)
#define semop(...) sys_semop(__VA_ARGS__)
#define semctl(...) syscall(__NR_semctl, __VA_ARGS__)
#define shmdt(...) sys_shmdt(__VA_ARGS__)
#define msgget(...) sys_msgget(__VA_ARGS__)
#define msgsnd(...) sys_msgsnd(__VA_ARGS__)
#define msgrcv(...) sys_msgrcv(__VA_ARGS__)
#define msgctl(...) sys_msgctl(__VA_ARGS__)
#define fcntl(...) syscall(__NR_fcntl, __VA_ARGS__)
#define flock(...) sys_flock(__VA_ARGS__)
#define fsync(...) sys_fsync(__VA_ARGS__)
#define fdatasync(...) sys_fdatasync(__VA_ARGS__)
#define truncate(...) sys_truncate(__VA_ARGS__)
#define ftruncate(...) sys_ftruncate(__VA_ARGS__)
#define getdents(...) sys_getdents(__VA_ARGS__)
#define getcwd(...) sys_getcwd(__VA_ARGS__)
#define chdir(...) sys_chdir(__VA_ARGS__)
#define fchdir(...) sys_fchdir(__VA_ARGS__)
#define rename(...) sys_rename(__VA_ARGS__)
#define mkdir(...) sys_mkdir(__VA_ARGS__)
#define rmdir(...) sys_rmdir(__VA_ARGS__)
#define creat(...) sys_creat(__VA_ARGS__)
#define link(...) sys_link(__VA_ARGS__)
#define unlink(...) sys_unlink(__VA_ARGS__)
#define symlink(...) sys_symlink(__VA_ARGS__)
#define readlink(...) sys_readlink(__VA_ARGS__)
#define chmod(...) sys_chmod(__VA_ARGS__)
#define fchmod(...) sys_fchmod(__VA_ARGS__)
#define chown(...) sys_chown(__VA_ARGS__)
#define fchown(...) sys_fchown(__VA_ARGS__)
#define lchown(...) sys_lchown(__VA_ARGS__)
#define umask(...) sys_umask(__VA_ARGS__)
#define gettimeofday(...) sys_gettimeofday(__VA_ARGS__)
#define getrlimit(...) sys_getrlimit(__VA_ARGS__)
#define getrusage(...) sys_getrusage(__VA_ARGS__)
#define sysinfo(...) sys_sysinfo(__VA_ARGS__)
#define times(...) sys_times(__VA_ARGS__)
#define ptrace(...) sys_ptrace(__VA_ARGS__)
#define getuid(...) sys_getuid(__VA_ARGS__)
#define syslog(...) sys_syslog(__VA_ARGS__)
#define getgid(...) sys_getgid(__VA_ARGS__)
#define setuid(...) sys_setuid(__VA_ARGS__)
#define setgid(...) sys_setgid(__VA_ARGS__)
#define geteuid(...) sys_geteuid(__VA_ARGS__)
#define getegid(...) sys_getegid(__VA_ARGS__)
#define setpgid(...) sys_setpgid(__VA_ARGS__)
#define getppid(...) sys_getppid(__VA_ARGS__)
#define getpgrp(...) sys_getpgrp(__VA_ARGS__)
#define setsid(...) sys_setsid(__VA_ARGS__)
#define setreuid(...) sys_setreuid(__VA_ARGS__)
#define setregid(...) sys_setregid(__VA_ARGS__)
#define getgroups(...) sys_getgroups(__VA_ARGS__)
#define setgroups(...) sys_setgroups(__VA_ARGS__)
#define setresuid(...) sys_setresuid(__VA_ARGS__)
#define getresuid(...) sys_getresuid(__VA_ARGS__)
#define setresgid(...) sys_setresgid(__VA_ARGS__)
#define getresgid(...) sys_getresgid(__VA_ARGS__)
#define getpgid(...) sys_getpgid(__VA_ARGS__)
// setfsuid
// setfsgid
#define getsid(...) sys_getsid(__VA_ARGS__)
#define capget(...) sys_capget(__VA_ARGS__)
#define capset(...) sys_capset(__VA_ARGS__)
// rt_sigpending
// rt_sigtimedwait
#define rt_sigqueueinfo(...) sys_rt_sigqueueinfo(__VA_ARGS__)
// rt_sigsuspend
#define sigaltstack(...) sys_sigaltstack(__VA_ARGS__)
#define utime(...) sys_utime(__VA_ARGS__)
#define mknod(...) sys_mknod(__VA_ARGS__)
// uselib
#define personality(...) sys_personality(__VA_ARGS__)
// ustat
#define statfs(...) sys_statfs(__VA_ARGS__)
#define fstatfs(...) sys_fstatfs(__VA_ARGS__)
// sysfs
#define getpriority(...) sys_getpriority(__VA_ARGS__)
#define setpriority(...) sys_setpriority(__VA_ARGS__)
#define sched_setparam(...) sys_sched_setparam(__VA_ARGS__)
#define sched_getparam(...) sys_sched_getparam(__VA_ARGS__)
#define sched_setscheduler(...) sys_sched_setscheduler(__VA_ARGS__)
#define sched_getscheduler(...) sys_sched_getscheduler(__VA_ARGS__)
#define sched_get_priority_max(...) sys_sched_get_priority_max(__VA_ARGS__)
#define sched_get_priority_min(...) sys_sched_get_priority_min(__VA_ARGS__)
#define sched_rr_get_interval(...) sys_sched_rr_get_interval(__VA_ARGS__)
#define mlock(...) sys_mlock(__VA_ARGS__)
#define munlock(...) sys_munlock(__VA_ARGS__)
#define mlockall(...) sys_mlockall(__VA_ARGS__)
#define munlockall(...) sys_munlockall(__VA_ARGS__)
#define vhangup(...) sys_vhangup(__VA_ARGS__)
#define modify_ldt(...) sys_modify_ldt(__VA_ARGS__)
#define pivot_root(...) sys_pivot_root(__VA_ARGS__)
#define _sysctl(...) sys__sysctl(__VA_ARGS__)
#define prctl(...) syscall(__NR_prctl, __VA_ARGS__)
#define arch_prctl(...) sys_arch_prctl(__VA_ARGS__)
#define adjtimex(...) sys_adjtimex(__VA_ARGS__)
#define setrlimit(...) sys_setrlimit(__VA_ARGS__)
#define chroot(...) sys_chroot(__VA_ARGS__)
#define sync(...) sys_sync(__VA_ARGS__)
#define acct(...) sys_acct(__VA_ARGS__)
#define settimeofday(...) sys_settimeofday(__VA_ARGS__)
#define mount(...) sys_mount(__VA_ARGS__)
#define umount2(...) sys_umount2(__VA_ARGS__)
#define swapon(...) sys_swapon(__VA_ARGS__)
#define swapoff(...) sys_swapoff(__VA_ARGS__)
#define reboot(...) sys_reboot(__VA_ARGS__)
#define sethostname(...) sys_sethostname(__VA_ARGS__)
#define setdomainname(...) sys_setdomainname(__VA_ARGS__)
// iopl
#define ioperm(...) sys_ioperm(__VA_ARGS__)
// create_module
#define init_module(...) sys_init_module(__VA_ARGS__)
#define delete_module(...) sys_delete_module(__VA_ARGS__)
// get_kernel_syms
// query_module
#define quotactl(...) sys_quotactl(__VA_ARGS__)
#define nfsservctl(...) sys_nfsservctl(__VA_ARGS__)
// getpmsg
// putpmsg
// afs_syscall
// tuxcall
// security
#define gettid(...) sys_gettid(__VA_ARGS__)
#define readahead(...) sys_readahead(__VA_ARGS__)
#define setxattr(...) sys_setxattr(__VA_ARGS__)
#define lsetxattr(...) sys_lsetxattr(__VA_ARGS__)
#define fsetxattr(...) sys_fsetxattr(__VA_ARGS__)
#define getxattr(...) sys_getxattr(__VA_ARGS__)
#define lgetxattr(...) sys_lgetxattr(__VA_ARGS__)
#define fgetxattr(...) sys_fgetxattr(__VA_ARGS__)
#define listxattr(...) sys_listxattr(__VA_ARGS__)
#define llistxattr(...) sys_llistxattr(__VA_ARGS__)
#define flistxattr(...) sys_flistxattr(__VA_ARGS__)
#define removexattr(...) sys_removexattr(__VA_ARGS__)
#define lremovexattr(...) sys_lremovexattr(__VA_ARGS__)
#define fremovexattr(...) sys_fremovexattr(__VA_ARGS__)
// tkill
#define time(...) sys_time(__VA_ARGS__)
#define futex(...) sys_futex(__VA_ARGS__)
#define sched_setaffinity(...) sys_sched_setaffinity(__VA_ARGS__)
#define sched_getaffinity(...) sys_sched_getaffinity(__VA_ARGS__)
#define set_thread_area(...) sys_set_thread_area(__VA_ARGS__)
#define io_setup(...) sys_io_setup(__VA_ARGS__)
#define io_destroy(...) sys_io_destroy(__VA_ARGS__)
#define io_getevents(...) sys_io_getevents(__VA_ARGS__)
#define io_submit(...) sys_io_submit(__VA_ARGS__)
#define io_cancel(...) sys_io_cancel(__VA_ARGS__)
#define get_thread_area(...) sys_get_thread_area(__VA_ARGS__)
#define lookup_dcookie(...) sys_lookup_dcookie(__VA_ARGS__)
#define epoll_create(...) sys_epoll_create(__VA_ARGS__)
// remap_file_pages
#define getdents64(...) sys_getdents64(__VA_ARGS__)
#define set_tid_address(...) sys_set_tid_address(__VA_ARGS__)
#define restart_syscall(...) sys_restart_syscall(__VA_ARGS__)
#define semtimedop(...) sys_semtimedop(__VA_ARGS__)
#define fadvise64(...) sys_fadvise64(__VA_ARGS__)
#define timer_create(...) sys_timer_create(__VA_ARGS__)
#define timer_settime(...) sys_timer_settime(__VA_ARGS__)
#define timer_gettime(...) sys_timer_gettime(__VA_ARGS__)
#define timer_getoverrun(...) sys_timer_getoverrun(__VA_ARGS__)
#define timer_delete(...) sys_timer_delete(__VA_ARGS__)
#define clock_settime(...) sys_clock_settime(__VA_ARGS__)
#define clock_gettime(...) sys_clock_gettime(__VA_ARGS__)
#define clock_getres(...) sys_clock_getres(__VA_ARGS__)
#define clock_nanosleep(...) sys_clock_nanosleep(__VA_ARGS__)
#define exit_group(...) sys_exit_group(__VA_ARGS__)
#define epoll_wait(...) sys_epoll_wait(__VA_ARGS__)
#define epoll_ctl(...) sys_epoll_ctl(__VA_ARGS__)
#define tgkill(...) sys_tgkill(__VA_ARGS__)
#define utimes(...) sys_utimes(__VA_ARGS__)
// vserver
// mbind
#define set_mempolicy(...) sys_set_mempolicy(__VA_ARGS__)
// get_mempolicy
#define mq_open(...) sys_mq_open(__VA_ARGS__)
#define mq_unlink(...) sys_mq_unlink(__VA_ARGS__)
#define mq_timedsend(...) sys_mq_timedsend(__VA_ARGS__)
#define mq_timedreceive(...) sys_mq_timedreceive(__VA_ARGS__)
#define mq_notify(...) sys_mq_notify(__VA_ARGS__)
#define mq_getsetattr(...) sys_mq_getsetattr(__VA_ARGS__)
#define kexec_load(...) sys_kexec_load(__VA_ARGS__)
#define waitid(...) sys_waitid(__VA_ARGS__)
#define add_key(...) sys_add_key(__VA_ARGS__)
#define request_key(...) sys_request_key(__VA_ARGS__)
#define keyctl(...) sys_keyctl(__VA_ARGS__)
#define ioprio_set(...) sys_ioprio_set(__VA_ARGS__)
#define ioprio_get(...) sys_ioprio_get(__VA_ARGS__)
#define inotify_init(...) sys_inotify_init(__VA_ARGS__)
#define inotify_add_watch(...) sys_inotify_add_watch(__VA_ARGS__)
#define inotify_rm_watch(...) sys_inotify_rm_watch(__VA_ARGS__)
#define migrate_pages(...) sys_migrate_pages(__VA_ARGS__)
#define openat(...) CONC(__openat, NARGS(__VA_ARGS__))(__VA_ARGS__)
#define mkdirat(...) sys_mkdirat(__VA_ARGS__)
#define mknodat(...) sys_mknodat(__VA_ARGS__)
#define fchownat(...) sys_fchownat(__VA_ARGS__)
// futimesat
// newfstatat
#define unlinkat(...) sys_unlinkat(__VA_ARGS__)
#define renameat(...) sys_renameat(__VA_ARGS__)
#define linkat(...) sys_linkat(__VA_ARGS__)
#define symlinkat(...) sys_symlinkat(__VA_ARGS__)
#define readlinkat(...) sys_readlinkat(__VA_ARGS__)
#define fchmodat(...) sys_fchmodat(__VA_ARGS__)
#define faccessat(...) sys_faccessat(__VA_ARGS__)
// pselect6
#define ppoll(...) sys_ppoll(__VA_ARGS__)
#define unshare(...) sys_unshare(__VA_ARGS__)
// set_robust_list
#define get_robust_list(...) sys_get_robust_list(__VA_ARGS__)
#define splice(...) sys_splice(__VA_ARGS__)
#define tee(...) sys_tee(__VA_ARGS__)
#define sync_file_range(...) sys_sync_file_range(__VA_ARGS__)
#define vmsplice(...) sys_vmsplice(__VA_ARGS__)
#define move_pages(...) sys_move_pages(__VA_ARGS__)
#define utimensat(...) sys_utimensat(__VA_ARGS__)
#define epoll_pwait(...) sys_epoll_pwait(__VA_ARGS__)
#define signalfd(...) sys_signalfd(__VA_ARGS__)
#define timerfd_create(...) sys_timerfd_create(__VA_ARGS__)
#define eventfd(...) sys_eventfd(__VA_ARGS__)
#define fallocate(...) sys_fallocate(__VA_ARGS__)
#define timerfd_settime(...) sys_timerfd_settime(__VA_ARGS__)
#define timerfd_gettime(...) sys_timerfd_gettime(__VA_ARGS__)
#define accept4(...) sys_accept4(__VA_ARGS__)
// signalfd4
// eventfd2
#define epoll_create1(...) sys_epoll_create1(__VA_ARGS__)
#define dup3(...) sys_dup3(__VA_ARGS__)
#define pipe2(...) sys_pipe2(__VA_ARGS__)
#define inotify_init1(...) sys_inotify_init1(__VA_ARGS__)
#define preadv(...) sys_preadv(__VA_ARGS__)
#define pwritev(...) sys_pwritev(__VA_ARGS__)
#define rt_tgsigqueueinfo(...) sys_rt_tgsigqueueinfo(__VA_ARGS__)
#define perf_event_open(...) sys_perf_event_open(__VA_ARGS__)
#define recvmmsg(...) sys_recvmmsg(__VA_ARGS__)
#define fanotify_init(...) sys_fanotify_init(__VA_ARGS__)
#define fanotify_mark(...) sys_fanotify_mark(__VA_ARGS__)
#define prlimit64(...) sys_prlimit64(__VA_ARGS__)
#define name_to_handle_at(...) sys_name_to_handle_at(__VA_ARGS__)
#define open_by_handle_at(...) sys_open_by_handle_at(__VA_ARGS__)
#define clock_adjtime(...) sys_clock_adjtime(__VA_ARGS__)
#define syncfs(...) sys_syncfs(__VA_ARGS__)
#define sendmmsg(...) sys_sendmmsg(__VA_ARGS__)
#define setns(...) sys_setns(__VA_ARGS__)
#define getcpu(...) sys_getcpu(__VA_ARGS__)
#define process_vm_readv(...) sys_process_vm_readv(__VA_ARGS__)
#define process_vm_writev(...) sys_process_vm_writev(__VA_ARGS__)
#define kcmp(...) sys_kcmp(__VA_ARGS__)
#define finit_module(...) sys_finit_module(__VA_ARGS__)
#define sched_setattr(...) sys_sched_setattr(__VA_ARGS__)
#define sched_getattr(...) sys_sched_getattr(__VA_ARGS__)
#define renameat2(...) sys_renameat2(__VA_ARGS__)
#define seccomp(...) sys_seccomp(__VA_ARGS__)
#define getrandom(...) sys_getrandom(__VA_ARGS__)
#define memfd_create(...) sys_memfd_create(__VA_ARGS__)
#define kexec_file_load(...) sys_kexec_file_load(__VA_ARGS__)
#define bpf(...) sys_bpf(__VA_ARGS__)
#define execveat(...) sys_execveat(__VA_ARGS__)
#define userfaultfd(...) sys_userfaultfd(__VA_ARGS__)
#define membarrier(...) sys_membarrier(__VA_ARGS__)
#define mlock2(...) sys_mlock2(__VA_ARGS__)
#define copy_file_range(...) sys_copy_file_range(__VA_ARGS__)
#define preadv2(...) sys_preadv2(__VA_ARGS__)
#define pwritev2(...) sys_pwritev2(__VA_ARGS__)
#define pkey_mprotect(...) sys_pkey_mprotect(__VA_ARGS__)
#define pkey_alloc(...) sys_pkey_alloc(__VA_ARGS__)
#define pkey_free(...) sys_pkey_free(__VA_ARGS__)
#define statx(...) sys_statx(__VA_ARGS__)
#define pidfd_send_signal(...) sys_pidfd_send_signal(__VA_ARGS__)
#define pidfd_open(...) sys_pidfd_open(__VA_ARGS__)
#define clone3(...) sys_clone3(__VA_ARGS__)
#define close_range(...) sys_close_range(__VA_ARGS__)
#define openat2(...) sys_openat2(__VA_ARGS__)
#define pidfd_getfd(...) sys_pidfd_getfd(__VA_ARGS__)
// faccessat2
#define process_madvise(...) sys_process_madvise(__VA_ARGS__)
#define epoll_pwait2(...) sys_epoll_pwait2(__VA_ARGS__)
#define mount_setattr(...) sys_mount_setattr(__VA_ARGS__)
// landlock_create_ruleset
// landlock_add_rule
// landlock_restrict_self
#define memfd_secret(...) sys_memfd_secret(__VA_ARGS__)






INLINE int64_t _syscall1(long __sysno)
{
    int64_t result;

    asm volatile (
        "syscall"
        : "=a"(result)
        : "a"(__sysno)
        : "memory", "rcx", "r11"
    );

    return result;
}

INLINE int64_t _syscall2(long __sysno, int64_t arg1)
{
    int64_t result;

    asm volatile (
        "syscall"
        : "=a"(result)
        : "a"(__sysno),
          "D"(arg1)
        : "memory", "rcx", "r11"
    );

    return result;
}

INLINE int64_t _syscall3(long __sysno, int64_t arg1, int64_t arg2)
{
    int64_t result;

    asm volatile (
        "syscall"
        : "=a"(result)
        : "a"(__sysno),
          "D"(arg1),
          "S"(arg2)
        : "memory", "rcx", "r11"
    );

    return result;
}

INLINE int64_t _syscall4(long __sysno, int64_t arg1, int64_t arg2, int64_t arg3)
{
    int64_t result;

    asm volatile (
        "syscall"
        : "=a"(result)
        : "a"(__sysno),
          "D"(arg1),
          "S"(arg2),
          "d"(arg3)
        : "memory", "rcx", "r11"
    );

    return result;
}

INLINE int64_t _syscall5(long __sysno, int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4)
{
    int64_t result;

    register int64_t r10 asm("r10") = arg4;

    asm volatile (
        "syscall"
        : "=a"(result)
        : "a"(__sysno),
          "D"(arg1),
          "S"(arg2),
          "d"(arg3),
          "r"(r10)
        : "memory", "rcx", "r11"
    );

    return result;
}

INLINE int64_t _syscall6(long __sysno, int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5)
{
    int64_t result;

    register int64_t r10 asm("r10") = arg4;
    register int64_t r8 asm("r8") = arg5;

    asm volatile (
        "syscall"
        : "=a"(result)
        : "a"(__sysno),
          "D"(arg1),
          "S"(arg2),
          "d"(arg3),
          "r"(r10),
          "r"(r8)
        : "memory", "rcx", "r11"
    );

    return result;
}

INLINE int64_t _syscall7(long __sysno, int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6)
{
    int64_t result;

    register int64_t r10 asm("r10") = arg4;
    register int64_t r8 asm("r8") = arg5;
    register int64_t r9 asm("r9") = arg6;

    asm volatile (
        "syscall"
        : "=a"(result)
        : "a"(__sysno),
          "D"(arg1),
          "S"(arg2),
          "d"(arg3),
          "r"(r10),
          "r"(r8),
          "r"(r9)
        : "memory", "rcx", "r11"
    );

    return result;
}

INLINE int __open2(const char *pathname, int flags) {
    return syscall(__NR_open, (int64_t)pathname, (int64_t)flags);
}
INLINE int __open3(const char *pathname, int flags, mode_t mode) {
    return syscall(__NR_open, (int64_t)pathname, (int64_t)flags, (int64_t)mode);
}

INLINE int __openat3(int dirfd, const char *pathname, int flags) {
    return syscall(__NR_openat, dirfd, (int64_t)pathname, (int64_t)flags);
}
INLINE int __openat4(int dirfd, const char *pathname, int flags, mode_t mode) {
    return syscall(__NR_openat, dirfd, (int64_t)pathname, (int64_t)flags, (int64_t)mode);
}
INLINE int __mremap4(void *old_address, size_t old_size, size_t new_size, int flags) {
    return syscall(__NR_mremap, (int64_t)old_address, old_size, new_size, flags);
}
INLINE int __mremap5(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address) {
    return syscall(__NR_mremap, (int64_t)old_address, old_size, new_size, flags, (int64_t)new_address);
}

SYSCALL_DEFINE(ssize_t, read, int, fd, void *, buf, size_t, count)
SYSCALL_DEFINE(ssize_t, write, int, fd, const void *, buf, size_t, count)
// open
SYSCALL_DEFINE(int, close, int, fd)
SYSCALL_DEFINE(int, stat, const char *restrict, pathname, struct stat *restrict, statbuf)
SYSCALL_DEFINE(int, fstat, int, fd, struct stat *, statbuf)
SYSCALL_DEFINE(int, lstat, const char *restrict, pathname, struct stat *restrict, statbuf)
SYSCALL_DEFINE(int, poll, struct pollfd *, fds, nfds_t, nfds, int, timeout)
SYSCALL_DEFINE(off_t, lseek, int, fd, off_t, offset, int, whence)
SYSCALL_DEFINE(void *, mmap, void *, addr, size_t, length, int, prot, int, flags, int, fd, off_t, offset)
SYSCALL_DEFINE(int, mprotect, void *, addr, size_t, len, int, prot)
SYSCALL_DEFINE(int, munmap, void *, addr, size_t, length)
SYSCALL_DEFINE(int, brk, void *, addr)
//  rt_sigaction
SYSCALL_DEFINE(int, rt_sigprocmask, int, how, const sigset_t *, set, sigset_t *, oldset, size_t, sigsetsize)
//  rt_sigreturn
// ioctl
SYSCALL_DEFINE(ssize_t, pread64, int, fd, void *, buf, size_t, count, off_t, offset)
SYSCALL_DEFINE(ssize_t, pwrite64, int, fd, const void *, buf, size_t, count, off_t, offset)
SYSCALL_DEFINE(ssize_t, readv, int, fd, const struct iovec *, iov, int, iovcnt)
SYSCALL_DEFINE(ssize_t, writev, int, fd, const struct iovec *, iov, int, iovcnt)
SYSCALL_DEFINE(int, access, const char *, pathname, int, mode)
SYSCALL_DEFINE(int, pipe, int *, pipefd)
SYSCALL_DEFINE(int, select, int, nfds, fd_set * restrict, readfds, fd_set * restrict, writefds, fd_set * restrict, exceptfds, struct timeval * restrict, timeout)
SYSCALL_DEFINE_VOID(int, sched_yield)
// mremap
SYSCALL_DEFINE(int, msync, void *, addr, size_t, length, int, flags)
SYSCALL_DEFINE(int, mincore, void *, addr, size_t, length, unsigned char *, vec)
SYSCALL_DEFINE(int, madvise, void *, addr, size_t, length, int, advice)
SYSCALL_DEFINE(int, shmget, key_t, key, size_t, size, int, shmflg)
SYSCALL_DEFINE(void *, shmat, int, shmid, const void *, shmaddr, int, shmflg)
SYSCALL_DEFINE(int, shmctl, int, shmid, int, op, struct shmid_ds *, buf)
SYSCALL_DEFINE(int, dup, int, oldfd)
SYSCALL_DEFINE(int, dup2, int, oldfd, int, newfd)
SYSCALL_DEFINE_VOID(int, pause)
SYSCALL_DEFINE(int, nanosleep, const struct timespec *, duration, struct timespec *, rem)
SYSCALL_DEFINE(int, getitimer, int, which, struct itimerval *, curr_value)
SYSCALL_DEFINE(unsigned int, alarm, unsigned int, seconds)
SYSCALL_DEFINE(int, setitimer, int, which, const struct itimerval *restrict, new_value, struct itimerval * restrict, old_value)
SYSCALL_DEFINE_VOID(pid_t, getpid)
SYSCALL_DEFINE(ssize_t, sendfile, int, out_fd, int, in_fd, off_t *, offset, size_t, count)
SYSCALL_DEFINE(int, socket, int, domain, int, type, int, protocol)
SYSCALL_DEFINE(int, connect, int, sockfd, const struct sockaddr *, addr, socklen_t, addrlen)
SYSCALL_DEFINE(int, accept, int, sockfd, struct sockaddr * restrict, addr, socklen_t * restrict, addrlen)
SYSCALL_DEFINE(ssize_t, sendto, int, sockfd, const void *, buf, size_t, len, int, flags, const struct sockaddr *, dest_addr, socklen_t, addrlen)
SYSCALL_DEFINE(ssize_t, recvfrom, int, sockfd, void *, buf, size_t, len, int, flags, struct sockaddr * restrict, src_addr, socklen_t * restrict, addrlen)
SYSCALL_DEFINE(ssize_t, sendmsg, int, sockfd, const struct msghdr *, msg, int, flags)
SYSCALL_DEFINE(ssize_t, recvmsg, int, sockfd, struct msghdr *, msg, int, flags)
SYSCALL_DEFINE(int, shutdown, int, sockfd, int, how)
SYSCALL_DEFINE(int, bind, int, sockfd, const struct sockaddr *, addr, socklen_t, addrlen)
SYSCALL_DEFINE(int, listen, int, sockfd, int, backlog)
SYSCALL_DEFINE(int, getsockname, int, sockfd, struct sockaddr *restrict, addr, socklen_t *restrict, addrlen)
SYSCALL_DEFINE(int, getpeername, int, sockfd, struct sockaddr *restrict, addr, socklen_t *restrict, addrlen)
SYSCALL_DEFINE(int, socketpair, int, domain, int, type, int, protocol, int *, sv)
SYSCALL_DEFINE(int, setsockopt, int, sockfd, int, level, int, optname, const void *, optval, socklen_t, optlen)
SYSCALL_DEFINE(int, getsockopt, int, sockfd, int, level, int, optname, void *, optval, socklen_t *restrict, optlen)
SYSCALL_DEFINE(long, clone, unsigned long, flags, void *, stack, int *, parent_tid, int *, child_tid, unsigned long, tls)
SYSCALL_DEFINE_VOID(pid_t, fork)
SYSCALL_DEFINE_VOID(pid_t, vfork)
SYSCALL_DEFINE(int, execve, const char *, pathname, char *const  *, argv, char *const  *, envp)
SYSCALL_DEFINE(void, exit, int, status)
SYSCALL_DEFINE(pid_t, wait4, pid_t, pid, int *, wstatus, int, options, struct rusage *, rusage)
SYSCALL_DEFINE(int, kill, pid_t, pid, int, sig)
SYSCALL_DEFINE(int, uname, struct utsname *, buf)
SYSCALL_DEFINE(int, semget, key_t, key, int, nsems, int, semflg)
SYSCALL_DEFINE(int, semop, int, semid, struct sembuf *, sops, size_t, nsops)
// semctl
SYSCALL_DEFINE(int, shmdt, const void *, shmaddr)
SYSCALL_DEFINE(int, msgget, key_t, key, int, msgflg)
SYSCALL_DEFINE(int, msgsnd, int, msqid, const void *, msgp, size_t, msgsz, int, msgflg)
SYSCALL_DEFINE(ssize_t, msgrcv, int, msqid, void *, msgp, size_t, msgsz, long, msgtyp, int, msgflg)
SYSCALL_DEFINE(int, msgctl, int, msqid, int, op, struct msqid_ds *, buf)
// fcntl
SYSCALL_DEFINE(int, flock, int, fd, int, op)
SYSCALL_DEFINE(int, fsync, int, fd)
SYSCALL_DEFINE(int, fdatasync, int, fd)
SYSCALL_DEFINE(int, truncate, const char *, path, off_t, length)
SYSCALL_DEFINE(int, ftruncate, int, fd, off_t, length)
SYSCALL_DEFINE(long, getdents, unsigned int, fd, struct dirent *, dirp, unsigned int, count)
SYSCALL_DEFINE(char *, getcwd, char *, buf, size_t, size)
SYSCALL_DEFINE(int, chdir, const char *, path)
SYSCALL_DEFINE(int, fchdir, int, fd)
SYSCALL_DEFINE(int, rename, const char *, oldpath, const char *, newpath)
SYSCALL_DEFINE(int, mkdir, const char *, pathname, mode_t, mode)
SYSCALL_DEFINE(int, rmdir, const char *, pathname)
SYSCALL_DEFINE(int, creat, const char *, pathname, mode_t, mode)
SYSCALL_DEFINE(int, link, const char *, oldpath, const char *, newpath)
SYSCALL_DEFINE(int, unlink, const char *, pathname)
SYSCALL_DEFINE(int, symlink, const char *, target, const char *, linkpath)
SYSCALL_DEFINE(ssize_t, readlink, const char *restrict, pathname, char *restrict, buf, size_t, bufsiz)
SYSCALL_DEFINE(int, chmod, const char *, pathname, mode_t, mode)
SYSCALL_DEFINE(int, fchmod, int, fd, mode_t, mode)
SYSCALL_DEFINE(int, chown, const char *, pathname, uid_t, owner, gid_t, group)
SYSCALL_DEFINE(int, fchown, int, fd, uid_t, owner, gid_t, group)
SYSCALL_DEFINE(int, lchown, const char *, pathname, uid_t, owner, gid_t, group)
SYSCALL_DEFINE(mode_t, umask, mode_t, mask)
SYSCALL_DEFINE(int, gettimeofday, struct timeval *restrict, tv, struct timezone * restrict, tz)
SYSCALL_DEFINE(int, getrlimit, int, resource, struct rlimit *, rlim)
SYSCALL_DEFINE(int, getrusage, int, who, struct rusage *, usage)
SYSCALL_DEFINE(int, sysinfo, struct sysinfo *, info)
SYSCALL_DEFINE(clock_t, times, struct tms *, buf)
SYSCALL_DEFINE(long, ptrace, enum __ptrace_request, op, pid_t, pid, void *, addr, void *, data)
SYSCALL_DEFINE_VOID(uid_t, getuid)
SYSCALL_DEFINE(int, syslog, int, type, char *, bufp, int, len)
SYSCALL_DEFINE_VOID(gid_t, getgid)
SYSCALL_DEFINE(int, setuid, uid_t, uid)
SYSCALL_DEFINE(int, setgid, gid_t, gid)
SYSCALL_DEFINE_VOID(uid_t, geteuid)
SYSCALL_DEFINE_VOID(gid_t, getegid)
SYSCALL_DEFINE(int, setpgid, pid_t, pid, pid_t, pgid)
SYSCALL_DEFINE_VOID(pid_t, getppid)
SYSCALL_DEFINE_VOID(pid_t, getpgrp)
SYSCALL_DEFINE_VOID(pid_t, setsid)
SYSCALL_DEFINE(int, setreuid, uid_t, ruid, uid_t, euid)
SYSCALL_DEFINE(int, setregid, gid_t, rgid, gid_t, egid)
SYSCALL_DEFINE(int, getgroups, int, size, gid_t *, list)
SYSCALL_DEFINE(int, setgroups, size_t, size, const gid_t *, list)
SYSCALL_DEFINE(int, setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)
SYSCALL_DEFINE(int, getresuid, uid_t *, ruid, uid_t *, euid, uid_t *, suid)
SYSCALL_DEFINE(int, setresgid, gid_t, rgid, gid_t, egid, gid_t, sgid)
SYSCALL_DEFINE(int, getresgid, gid_t *, rgid, gid_t *, egid, gid_t *, sgid)
SYSCALL_DEFINE(pid_t, getpgid, pid_t, pid)
//  setfsuid
//  setfsgid
SYSCALL_DEFINE(pid_t, getsid, pid_t, pid)
SYSCALL_DEFINE(int, capget, cap_user_header_t, hdrp, cap_user_data_t, datap)
SYSCALL_DEFINE(int, capset, cap_user_header_t, hdrp, const cap_user_data_t, datap)
//  rt_sigpending
//  rt_sigtimedwait
SYSCALL_DEFINE(int, rt_sigqueueinfo, pid_t, tgid, int, sig, siginfo_t *, info)
//  rt_sigsuspend
SYSCALL_DEFINE(int, sigaltstack, const stack_t * restrict, ss, stack_t * restrict, old_ss)
SYSCALL_DEFINE(int, utime, const char *, filename, const struct utimbuf *, times)
SYSCALL_DEFINE(int, mknod, const char *, pathname, mode_t, mode, dev_t, dev)
//  uselib
SYSCALL_DEFINE(int, personality, unsigned long, persona)
//  ustat
SYSCALL_DEFINE(int, statfs, const char *, path, struct statfs *, buf)
SYSCALL_DEFINE(int, fstatfs, int, fd, struct statfs *, buf)
//  sysfs
SYSCALL_DEFINE(int, getpriority, int, which, id_t, who)
SYSCALL_DEFINE(int, setpriority, int, which, id_t, who, int, prio)
SYSCALL_DEFINE(int, sched_setparam, pid_t, pid, const struct sched_param *, param)
SYSCALL_DEFINE(int, sched_getparam, pid_t, pid, struct sched_param *, param)
SYSCALL_DEFINE(int, sched_setscheduler, pid_t, pid, int, policy, const struct sched_param *, param)
SYSCALL_DEFINE(int, sched_getscheduler, pid_t, pid)
SYSCALL_DEFINE(int, sched_get_priority_max, int, policy)
SYSCALL_DEFINE(int, sched_get_priority_min, int, policy)
SYSCALL_DEFINE(int, sched_rr_get_interval, pid_t, pid, struct timespec *, tp)
SYSCALL_DEFINE(int, mlock, const void *, addr, size_t, len)
SYSCALL_DEFINE(int, munlock, const void *, addr, size_t, len)
SYSCALL_DEFINE(int, mlockall, int, flags)
SYSCALL_DEFINE_VOID(int, munlockall)
SYSCALL_DEFINE_VOID(int, vhangup)
SYSCALL_DEFINE(int, modify_ldt, int, func, void *, ptr, unsigned long, bytecount)
SYSCALL_DEFINE(int, pivot_root, const char *, new_root, const char *, put_old)
// sysctl
// prctl
SYSCALL_DEFINE(int, arch_prctl, int, op, unsigned long, addr)
SYSCALL_DEFINE(int, adjtimex, struct timex *, buf)
SYSCALL_DEFINE(int, setrlimit, int, resource, const struct rlimit *, rlim)
SYSCALL_DEFINE(int, chroot, const char *, path)
SYSCALL_DEFINE_VOID(void, sync)
SYSCALL_DEFINE(int, acct, const char *, filename)
SYSCALL_DEFINE(int, settimeofday, const struct timeval *, tv, const struct timezone *, tz)
SYSCALL_DEFINE(int, mount, const char *, source, const char *, target, const char *, filesystemtype, unsigned long, mountflags, const void *, data)
SYSCALL_DEFINE(int, umount2, const char *, target, int, flags)
SYSCALL_DEFINE(int, swapon, const char *, path, int, swapflags)
SYSCALL_DEFINE(int, swapoff, const char *, path)
SYSCALL_DEFINE(int, reboot, int, magic, int, magic2, int, op, void *, arg)
SYSCALL_DEFINE(int, sethostname, const char *, name, size_t, len)
SYSCALL_DEFINE(int, setdomainname, const char *, name, size_t, len)
SYSCALL_DEFINE(int, iopl, int, level)
SYSCALL_DEFINE(int, ioperm, unsigned long, from, unsigned long, num, int, turn_on)
// create_module
SYSCALL_DEFINE(int, init_module, void *, module_image, unsigned long, len, const char *, param_values)
SYSCALL_DEFINE(int, delete_module, const char *, name, unsigned int, flags)
// get_kernel_syms
// query_module
SYSCALL_DEFINE(int, quotactl, int, op, const char *, special, int, id, caddr_t, addr)
// nfsservctl
// getpmsg
// putpmsg
// afs_syscall
// tuxcall
// security
SYSCALL_DEFINE_VOID(pid_t, gettid)
SYSCALL_DEFINE(ssize_t, readahead, int, fd, off_t, offset, size_t, count)
SYSCALL_DEFINE(int, setxattr, const char *, path, const char *, name, const void *, value, size_t, size, int, flags)
SYSCALL_DEFINE(int, lsetxattr, const char *, path, const char *, name, const void *, value, size_t, size, int, flags)
SYSCALL_DEFINE(int, fsetxattr, int, fd, const char *, name, const void *, value, size_t, size, int, flags)
SYSCALL_DEFINE(ssize_t, getxattr, const char *, path, const char *, name, void *, value, size_t, size)
SYSCALL_DEFINE(ssize_t, lgetxattr, const char *, path, const char *, name, void *, value, size_t, size)
SYSCALL_DEFINE(ssize_t, fgetxattr, int, fd, const char *, name, void *, value, size_t, size)
SYSCALL_DEFINE(ssize_t, listxattr, const char *, path, char *, list, size_t, size)
SYSCALL_DEFINE(ssize_t, llistxattr, const char *, path, char *, list, size_t, size)
SYSCALL_DEFINE(ssize_t, flistxattr, int, fd, char *, list, size_t, size)
SYSCALL_DEFINE(int, removexattr, const char *, path, const char *, name)
SYSCALL_DEFINE(int, lremovexattr, const char *, path, const char *, name)
SYSCALL_DEFINE(int, fremovexattr, int, fd, const char *, name)
// tkill
SYSCALL_DEFINE(time_t, time, time_t *, tloc)
SYSCALL_DEFINE(long, futex, uint32_t *, uaddr, int, futex_op, uint32_t, val, const struct timespec *, timeout, uint32_t *, uaddr2, uint32_t, val3)
SYSCALL_DEFINE(int, sched_setaffinity, pid_t, pid, size_t, cpusetsize, const cpu_set_t *, mask)
SYSCALL_DEFINE(int, sched_getaffinity, pid_t, pid, size_t, cpusetsize, cpu_set_t *, mask)
SYSCALL_DEFINE(int, set_thread_area, struct user_desc *, u_info)
SYSCALL_DEFINE(long, io_setup, unsigned int, nr_events, aio_context_t *, ctx_idp)
SYSCALL_DEFINE(int, io_destroy, aio_context_t, ctx_id)
SYSCALL_DEFINE(int, io_getevents, aio_context_t, ctx_id, long, min_nr, long, nr, struct io_event *, events, struct timespec *, timeout)
SYSCALL_DEFINE(int, io_submit, aio_context_t, ctx_id, long, nr, struct iocb **, iocbpp)
SYSCALL_DEFINE(int, io_cancel, aio_context_t, ctx_id, struct iocb *, iocb, struct io_event *, result)
SYSCALL_DEFINE(int, get_thread_area, struct user_desc *, u_info)
SYSCALL_DEFINE(int, lookup_dcookie, uint64_t, cookie, char *, buffer, size_t, len)
SYSCALL_DEFINE(int, epoll_create, int, size)
// remap_file_pages
SYSCALL_DEFINE(ssize_t, getdents64, int, fd, void *, dirp, size_t, count)
SYSCALL_DEFINE(pid_t, set_tid_address, int *, tidptr)
SYSCALL_DEFINE_VOID(long, restart_syscall)
SYSCALL_DEFINE(int, semtimedop, int, semid, struct sembuf *, sops, size_t, nsops, const struct timespec *, timeout)
SYSCALL_DEFINE(int, fadvise64, int, fd, off_t, offset, off_t, len, int, advice)
SYSCALL_DEFINE(int, timer_create, clockid_t, clockid, struct sigevent * restrict, sevp, timer_t *restrict, timerid)
SYSCALL_DEFINE(int, timer_settime, timer_t, timerid, int, flags, const struct itimerspec *restrict, new_value, struct itimerspec * restrict, old_value)
SYSCALL_DEFINE(int, timer_gettime, timer_t, timerid, struct itimerspec *, curr_value)
SYSCALL_DEFINE(int, timer_getoverrun, timer_t, timerid)
SYSCALL_DEFINE(int, timer_delete, timer_t, timerid)
SYSCALL_DEFINE(int, clock_settime, clockid_t, clockid, const struct timespec *, tp)
SYSCALL_DEFINE(int, clock_gettime, clockid_t, clockid, struct timespec *, tp)
SYSCALL_DEFINE(int, clock_getres, clockid_t, clockid, struct timespec *, res)
SYSCALL_DEFINE(int, clock_nanosleep, clockid_t, clockid, int, flags, const struct timespec *, t, struct timespec *, remain)
SYSCALL_DEFINE(void, exit_group, int, status)
SYSCALL_DEFINE(int, epoll_wait, int, epfd, struct epoll_event *, events, int, maxevents, int, timeout)
SYSCALL_DEFINE(int, epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event *, event)
SYSCALL_DEFINE(int, tgkill, pid_t, tgid, pid_t, tid, int, sig)
SYSCALL_DEFINE(int, utimes, const char *, filename, const struct timeval *, times)
// vserver
// mbind
SYSCALL_DEFINE(long, set_mempolicy, int, mode, const unsigned long *, nodemask, unsigned long, maxnode)
// get_mempolicy
SYSCALL_DEFINE(mqd_t, mq_open, const char *, name, int, oflag)
SYSCALL_DEFINE(int, mq_unlink, const char *, name)
SYSCALL_DEFINE(int, mq_timedsend, mqd_t, mqdes, const char *, msg_ptr, size_t, msg_len, unsigned int, msg_prio, const struct timespec *, abs_timeout)
SYSCALL_DEFINE(ssize_t, mq_timedreceive, mqd_t, mqdes, char *restrict *, msg_ptr, size_t, msg_len, unsigned int *restrict, msg_prio, const struct timespec *restrict, abs_timeout)
SYSCALL_DEFINE(int, mq_notify, mqd_t, mqdes, const struct sigevent *, sevp)
SYSCALL_DEFINE(int, mq_getsetattr, mqd_t, mqdes, const struct mq_attr *, newattr, struct mq_attr *, oldattr)
//SYSCALL_DEFINE(long, kexec_load, unsigned long, entry, unsigned long, nr_segments, struct kexec_segment *, segments, unsigned long, flags)
SYSCALL_DEFINE(int, waitid, idtype_t, idtype, id_t, id, siginfo_t *, infop, int, options)
//SYSCALL_DEFINE(key_serial_t, add_key, const char *, type, const char *, description, const void *, payload, size_t, plen, key_serial_t, keyring)
//SYSCALL_DEFINE(key_serial_t, request_key, const char *, type, const char *, description, const char *, callout_info, key_serial_t, dest_keyring)
SYSCALL_DEFINE(long, keyctl, int, operation, unsigned long, arg2, unsigned long, arg3, unsigned long, arg4, unsigned long, arg5)
SYSCALL_DEFINE(int, ioprio_set, int, which, int, who, int, ioprio)
SYSCALL_DEFINE(int, ioprio_get, int, which, int, who)
SYSCALL_DEFINE_VOID(int, inotify_init)
SYSCALL_DEFINE(int, inotify_add_watch, int, fd, const char *, pathname, uint32_t, mask)
SYSCALL_DEFINE(int, inotify_rm_watch, int, fd, int, wd)
SYSCALL_DEFINE(long, migrate_pages, int, pid, unsigned long, maxnode, const unsigned long *, old_nodes, const unsigned long *, new_nodes)
// openat
SYSCALL_DEFINE(int, mkdirat, int, dirfd, const char *, pathname, mode_t, mode)
SYSCALL_DEFINE(int, mknodat, int, dirfd, const char *, pathname, mode_t, mode, dev_t, dev)
SYSCALL_DEFINE(int, fchownat, int, dirfd, const char *, pathname, uid_t, owner, gid_t, group, int, flags)
//  futimesat
//  newfstatat
SYSCALL_DEFINE(int, unlinkat, int, dirfd, const char *, pathname, int, flags)
SYSCALL_DEFINE(int, renameat, int, olddirfd, const char *, oldpath, int, newdirfd, const char *, newpath)
SYSCALL_DEFINE(int, linkat, int, olddirfd, const char *, oldpath, int, newdirfd, const char *, newpath, int, flags)
SYSCALL_DEFINE(int, symlinkat, const char *, target, int, newdirfd, const char *, linkpath)
SYSCALL_DEFINE(ssize_t, readlinkat, int, dirfd, const char *restrict, pathname, char *restrict, buf, size_t, bufsiz)
SYSCALL_DEFINE(int, fchmodat, int, dirfd, const char *, pathname, mode_t, mode, int, flags)
SYSCALL_DEFINE(int, faccessat, int, dirfd, const char *, pathname, int, mode, int, flags)
//  pselect6
SYSCALL_DEFINE(int, ppoll, struct pollfd *, fds, nfds_t, nfds, const struct timespec *, tmo_p, const sigset_t *, sigmask)
SYSCALL_DEFINE(int, unshare, int, flags)
//  set_robust_list
//SYSCALL_DEFINE(long, get_robust_list, int, pid, struct robust_list_head **, head_ptr, size_t *, len_ptr)
SYSCALL_DEFINE(ssize_t, splice, int, fd_in, off_t *, off_in, int, fd_out, off_t *, off_out, size_t, len, unsigned int, flags)
SYSCALL_DEFINE(ssize_t, tee, int, fd_in, int, fd_out, size_t, len, unsigned int, flags)
SYSCALL_DEFINE(int, sync_file_range, int, fd, off_t, offset, off_t, nbytes, unsigned int, flags)
SYSCALL_DEFINE(ssize_t, vmsplice, int, fd, const struct iovec *, iov, size_t, nr_segs, unsigned int, flags)
SYSCALL_DEFINE(long, move_pages, int, pid, unsigned long, count, void * *, pages, const int *, nodes, int *, status, int, flags)
SYSCALL_DEFINE(int, utimensat, int, dirfd, const char *, pathname, const struct timespec *, times, int, flags)
SYSCALL_DEFINE(int, epoll_pwait, int, epfd, struct epoll_event *, events, int, maxevents, int, timeout, const sigset_t *, sigmask)
SYSCALL_DEFINE(int, signalfd, int, fd, const sigset_t *, mask, int, flags)
SYSCALL_DEFINE(int, timerfd_create, int, clockid, int, flags)
SYSCALL_DEFINE(int, eventfd, unsigned int, initval, int, flags)
SYSCALL_DEFINE(int, fallocate, int, fd, int, mode, off_t, offset, off_t, len)
SYSCALL_DEFINE(int, timerfd_settime, int, fd, int, flags, const struct itimerspec *, new_value, struct itimerspec *, old_value)
SYSCALL_DEFINE(int, timerfd_gettime, int, fd, struct itimerspec *, curr_value)
SYSCALL_DEFINE(int, accept4, int, sockfd, struct sockaddr * restrict, addr, socklen_t * restrict, addrlen, int, flags)
//  signalfd4
//  eventfd2
SYSCALL_DEFINE(int, epoll_create1, int, flags)
SYSCALL_DEFINE(int, dup3, int, oldfd, int, newfd, int, flags)
SYSCALL_DEFINE(int, pipe2, int *, pipefd, int, flags)
SYSCALL_DEFINE(int, inotify_init1, int, flags)
SYSCALL_DEFINE(ssize_t, preadv, int, fd, const struct iovec *, iov, int, iovcnt, off_t, offset)
SYSCALL_DEFINE(ssize_t, pwritev, int, fd, const struct iovec *, iov, int, iovcnt, off_t, offset)
SYSCALL_DEFINE(int, rt_tgsigqueueinfo, pid_t, tgid, pid_t, tid, int, sig, siginfo_t *, info)
//SYSCALL_DEFINE(int, perf_event_open, struct perf_event_attr *, attr, pid_t, pid, int, cpu, int, group_fd, unsigned long, flags)
//SYSCALL_DEFINE(int, recvmmsg, int, sockfd, struct mmsghdr *, msgvec, unsigned int, vlen, int, flags, struct timespec *, timeout)
SYSCALL_DEFINE(int, fanotify_init, unsigned int, flags, unsigned int, event_f_flags)
SYSCALL_DEFINE(int, fanotify_mark, int, fanotify_fd, unsigned int, flags, uint64_t, mask, int, dirfd, const char *, pathname)
SYSCALL_DEFINE(int, prlimit64, pid_t, pid, int, resource, const struct rlimit *, new_limit, struct rlimit *, old_limit)
#ifdef _GNU_SOURCE
SYSCALL_DEFINE(int, name_to_handle_at, int, dirfd, const char *, pathname, struct file_handle *, handle, int *, mount_id, int, flags)
SYSCALL_DEFINE(int, open_by_handle_at, int, mount_fd, struct file_handle *, handle, int, flags)
#endif
SYSCALL_DEFINE(int, clock_adjtime, clockid_t, clk_id, struct timex *, buf)
SYSCALL_DEFINE(int, syncfs, int, fd)
//SYSCALL_DEFINE(int, sendmmsg, int, sockfd, struct mmsghdr *, msgvec, unsigned int, vlen, int, flags)
SYSCALL_DEFINE(int, setns, int, fd, int, nstype)
SYSCALL_DEFINE(int, getcpu, unsigned int *, cpu, unsigned int *, node)
SYSCALL_DEFINE(ssize_t, process_vm_readv, pid_t, pid, const struct iovec *, local_iov, unsigned long, liovcnt, const struct iovec *, remote_iov, unsigned long, riovcnt, unsigned long, flags)
SYSCALL_DEFINE(ssize_t, process_vm_writev, pid_t, pid, const struct iovec *, local_iov, unsigned long, liovcnt, const struct iovec *, remote_iov, unsigned long, riovcnt, unsigned long, flags)
SYSCALL_DEFINE(int, kcmp, pid_t, pid1, pid_t, pid2, int, type, unsigned long, idx1, unsigned long, idx2)
SYSCALL_DEFINE(int, finit_module, int, fd, const char *, param_values, int, flags)
//SYSCALL_DEFINE(int, sched_setattr, pid_t, pid, struct sched_attr *, attr, unsigned int, flags)
//SYSCALL_DEFINE(int, sched_getattr, pid_t, pid, struct sched_attr *, attr, unsigned int, size, unsigned int, flags)
SYSCALL_DEFINE(int, renameat2, int, olddirfd, const char *, oldpath, int, newdirfd, const char *, newpath, unsigned int, flags)
SYSCALL_DEFINE(int, seccomp, unsigned int, operation, unsigned int, flags, void *, args)
SYSCALL_DEFINE(ssize_t, getrandom, void *, buf, size_t, buflen, unsigned int, flags)
SYSCALL_DEFINE(int, memfd_create, const char *, name, unsigned int, flags)
SYSCALL_DEFINE(long, kexec_file_load, int, kernel_fd, int, initrd_fd, unsigned long, cmdline_len, const char *, cmdline, unsigned long, flags)
SYSCALL_DEFINE(int, bpf, int, cmd, union bpf_attr *, attr, unsigned int, size)
SYSCALL_DEFINE(int, execveat, int, dirfd, const char *, pathname, char *const  *, argv, char *const  *, envp, int, flags)
SYSCALL_DEFINE(int, userfaultfd, int, flags)
SYSCALL_DEFINE(int, membarrier, int, cmd, unsigned int, flags, int, cpu_id)
SYSCALL_DEFINE(int, mlock2, const void *, addr, size_t, len, unsigned int, flags)
SYSCALL_DEFINE(ssize_t, copy_file_range, int, fd_in, off_t *, off_in, int, fd_out, off_t *, off_out, size_t, len, unsigned int, flags)
SYSCALL_DEFINE(ssize_t, preadv2, int, fd, const struct iovec *, iov, int, iovcnt, off_t, offset, int, flags)
SYSCALL_DEFINE(ssize_t, pwritev2, int, fd, const struct iovec *, iov, int, iovcnt, off_t, offset, int, flags)
SYSCALL_DEFINE(int, pkey_mprotect, void *, addr, size_t, len, int, prot, int, pkey)
SYSCALL_DEFINE(int, pkey_alloc, unsigned int, flags, unsigned int, access_rights)
SYSCALL_DEFINE(int, pkey_free, int, pkey)
//SYSCALL_DEFINE(int, statx, int, dirfd, const char *restrict, pathname, int, flags, unsigned int, mask, struct statx *restrict, statxbuf)
SYSCALL_DEFINE(int, pidfd_send_signal, int, pidfd, int, sig, siginfo_t *, info, unsigned int, flags)
SYSCALL_DEFINE(int, pidfd_open, pid_t, pid, unsigned int, flags)
SYSCALL_DEFINE(long, clone3, struct clone_args *, cl_args, size_t, size)
SYSCALL_DEFINE(int, close_range, unsigned int, first, unsigned int, last, int, flags)
SYSCALL_DEFINE(long, openat2, int, dirfd, const char *, pathname, struct open_how *, how, size_t, size)
SYSCALL_DEFINE(int, pidfd_getfd, int, pidfd, int, targetfd, unsigned int, flags)
//  faccessat2
SYSCALL_DEFINE(ssize_t, process_madvise, int, pidfd, const struct iovec *, iovec, size_t, n, int, advice, unsigned int, flags)
SYSCALL_DEFINE(int, epoll_pwait2, int, epfd, struct epoll_event *, events, int, maxevents, const struct timespec *, timeout, const sigset_t *, sigmask)
// SYSCALL_DEFINE(int, mount_setattr, int, dirfd, const char *, pathname, unsigned int, flags, struct mount_attr *, attr, size_t, size)
// landlock_create_ruleset
// landlock_add_rule
// landlock_restrict_self
SYSCALL_DEFINE(int, memfd_secret, unsigned int, flags)


// HELPERS
#define makedev(x,y) ( \
        (((x)&0xfffff000ULL) << 32) | \
	(((x)&0x00000fffULL) << 8) | \
        (((y)&0xffffff00ULL) << 12) | \
	(((y)&0x000000ffULL)) )


#define sleep(...) _sleep(__VA_ARGS__)
static unsigned int _sleep(unsigned seconds) {
    struct timespec tv = { .tv_sec = seconds, .tv_nsec = 0 };
    return nanosleep(&tv, &tv) ? tv.tv_sec : 0;
}
#define waitpid(...) _waitpid(__VA_ARGS__)
static pid_t _waitpid(pid_t pid, int *status, int options) {
    return wait4(pid, status, options, NULL);
}

#endif /* shellcode.h */
