
#include <linux/types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <uapi/asm-generic/unistd.h>
#include <stdbool.h>
#include "./kmemmanager.h"
#include "./kernel_symbol.h"

#define MODULE_TAG "debugtool:sys_call_info"

extern struct util_kernel_symbol kernel_sym;

typedef char *(*t_get_syscall_info)(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret);
struct sys_call_info {
    t_get_syscall_info get_syscall_info;
    char *sys_name;
    int sys_number;
};

const char *get_syscall_name(int scno);
char *get_syscall_info_null(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret);
char *get_syscall_info_default(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret);
char *get_getdents64_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret);
char *get_statfs_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret);
char *get_close_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret);
char *get_mmap_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret);
char *get_fstat_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret);
char *get_fstatat_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret);
char *get_openat_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret);
char *get_faccessat_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret);
char *get_read_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret);

struct sys_call_info sys_call_table_info[__NR_syscalls + 1] = {0};

struct sys_call_info p_sys_call_info[] = { 
    {get_syscall_info_default, (char *)"__NR_io_setup", 0},
    {get_syscall_info_default, (char *)"__NR_io_destroy", 1},
    {get_syscall_info_default, (char *)"__NR_io_submit", 2},
    {get_syscall_info_default, (char *)"__NR_io_cancel", 3},
    {get_syscall_info_default, (char *)"__NR_io_getevents", 4},
    {get_syscall_info_default, (char *)"__NR_setxattr", 5},
    {get_syscall_info_default, (char *)"__NR_lsetxattr", 6},
    {get_syscall_info_default, (char *)"__NR_fsetxattr", 7},
    {get_syscall_info_default, (char *)"__NR_getxattr", 8},
    {get_syscall_info_default, (char *)"__NR_lgetxattr", 9},
    {get_syscall_info_default, (char *)"__NR_fgetxattr", 10},
    {get_syscall_info_default, (char *)"__NR_listxattr", 11},
    {get_syscall_info_default, (char *)"__NR_llistxattr", 12},
    {get_syscall_info_default, (char *)"__NR_flistxattr", 13},
    {get_syscall_info_default, (char *)"__NR_removexattr", 14},
    {get_syscall_info_default, (char *)"__NR_lremovexattr", 15},
    {get_syscall_info_default, (char *)"__NR_fremovexattr", 16},
    {get_syscall_info_default, (char *)"__NR_getcwd", 17},
    {get_syscall_info_default, (char *)"__NR_lookup_dcookie", 18},
    {get_syscall_info_default, (char *)"__NR_eventfd2", 19},
    {get_syscall_info_default, (char *)"__NR_epoll_create1", 20},
    {get_syscall_info_default, (char *)"__NR_epoll_ctl", 21},
    {get_syscall_info_default, (char *)"__NR_epoll_pwait", 22},
    {get_syscall_info_default, (char *)"__NR_dup", 23},
    {get_syscall_info_default, (char *)"__NR_dup3", 24},
    {get_syscall_info_default, (char *)"__NR3264_fcntl", 25},
    {get_syscall_info_default, (char *)"__NR_inotify_init1", 26},
    {get_syscall_info_default, (char *)"__NR_inotify_add_watch", 27},
    {get_syscall_info_default, (char *)"__NR_inotify_rm_watch", 28},
    {get_syscall_info_default, (char *)"__NR_ioctl", 29},
    {get_syscall_info_default, (char *)"__NR_ioprio_set", 30},
    {get_syscall_info_default, (char *)"__NR_ioprio_get", 31},
    {get_syscall_info_default, (char *)"__NR_flock", 32},
    {get_syscall_info_default, (char *)"__NR_mknodat", 33},
    {get_syscall_info_default, (char *)"__NR_mkdirat", 34},
    {get_syscall_info_default, (char *)"__NR_unlinkat", 35},
    {get_syscall_info_default, (char *)"__NR_symlinkat", 36},
    {get_syscall_info_default, (char *)"__NR_linkat", 37},
    {get_syscall_info_default, (char *)"__NR_renameat", 38},
    {get_syscall_info_default, (char *)"__NR_umount2", 39},
    {get_syscall_info_default, (char *)"__NR_mount", 40},
    {get_syscall_info_default, (char *)"__NR_pivot_root", 41},
    {get_syscall_info_default, (char *)"__NR_nfsservctl", 42},
    {get_statfs_syscall_info, (char *)"__NR3264_statfs", 43},
    {get_syscall_info_default, (char *)"__NR3264_fstatfs", 44},
    {get_syscall_info_default, (char *)"__NR3264_truncate", 45},
    {get_syscall_info_default, (char *)"__NR3264_ftruncate", 46},
    {get_syscall_info_default, (char *)"__NR_fallocate", 47},
    {get_faccessat_syscall_info, (char *)"__NR_faccessat", 48},
    {get_syscall_info_default, (char *)"__NR_chdir", 49},
    {get_syscall_info_default, (char *)"__NR_fchdir", 50},
    {get_syscall_info_default, (char *)"__NR_chroot", 51},
    {get_syscall_info_default, (char *)"__NR_fchmod", 52},
    {get_syscall_info_default, (char *)"__NR_fchmodat", 53},
    {get_syscall_info_default, (char *)"__NR_fchownat", 54},
    {get_syscall_info_default, (char *)"__NR_fchown", 55},
    {get_openat_syscall_info, (char *)"__NR_openat", 56},
    {get_close_syscall_info, (char *)"__NR_close", 57},
    {get_syscall_info_default, (char *)"__NR_vhangup", 58},
    {get_syscall_info_default, (char *)"__NR_pipe2", 59},
    {get_syscall_info_default, (char *)"__NR_quotactl", 60},
    {get_getdents64_syscall_info, (char *)"__NR_getdents64", 61},
    {get_syscall_info_default, (char *)"__NR3264_lseek", 62},
    {get_read_syscall_info, (char *)"__NR_read", 63},
    {get_read_syscall_info, (char *)"__NR_write", 64},
    {get_syscall_info_default, (char *)"__NR_readv", 65},
    {get_syscall_info_default, (char *)"__NR_writev", 66},
    {get_syscall_info_default, (char *)"__NR_pread64", 67},
    {get_syscall_info_default, (char *)"__NR_pwrite64", 68},
    {get_syscall_info_default, (char *)"__NR_preadv", 69},
    {get_syscall_info_default, (char *)"__NR_pwritev", 70},
    {get_syscall_info_default, (char *)"__NR3264_sendfile", 71},
    {get_syscall_info_default, (char *)"__NR_pselect6", 72},
    {get_syscall_info_default, (char *)"__NR_ppoll", 73},
    {get_syscall_info_default, (char *)"__NR_signalfd4", 74},
    {get_syscall_info_default, (char *)"__NR_vmsplice", 75},
    {get_syscall_info_default, (char *)"__NR_splice", 76},
    {get_syscall_info_default, (char *)"__NR_tee", 77},
    {get_fstatat_syscall_info, (char *)"__NR_readlinkat", 78},
    {get_fstatat_syscall_info, (char *)"__NR3264_fstatat", 79},
    {get_fstat_syscall_info, (char *)"__NR3264_fstat", 80},
    {get_syscall_info_default, (char *)"__NR_sync", 81},
    {get_syscall_info_default, (char *)"__NR_fsync", 82},
    {get_syscall_info_default, (char *)"__NR_fdatasync", 83},
    {get_syscall_info_default, (char *)"__NR_sync_file_range", 84},
    {get_syscall_info_default, (char *)"__NR_timerfd_create", 85},
    {get_syscall_info_default, (char *)"__NR_timerfd_settime", 86},
    {get_syscall_info_default, (char *)"__NR_timerfd_gettime", 87},
    {get_syscall_info_default, (char *)"__NR_utimensat", 88},
    {get_syscall_info_default, (char *)"__NR_acct", 89},
    {get_syscall_info_default, (char *)"__NR_capget", 90},
    {get_syscall_info_default, (char *)"__NR_capset", 91},
    {get_syscall_info_default, (char *)"__NR_personality", 92},
    {get_syscall_info_default, (char *)"__NR_exit", 93},
    {get_syscall_info_default, (char *)"__NR_exit_group", 94},
    {get_syscall_info_default, (char *)"__NR_waitid", 95},
    {get_syscall_info_default, (char *)"__NR_set_tid_address", 96},
    {get_syscall_info_default, (char *)"__NR_unshare", 97},
    {get_syscall_info_default, (char *)"__NR_futex", 98},
    {get_syscall_info_default, (char *)"__NR_set_robust_list", 99},
    {get_syscall_info_default, (char *)"__NR_get_robust_list", 100},
    {get_syscall_info_default, (char *)"__NR_nanosleep", 101},
    {get_syscall_info_default, (char *)"__NR_getitimer", 102},
    {get_syscall_info_default, (char *)"__NR_setitimer", 103},
    {get_syscall_info_default, (char *)"__NR_kexec_load", 104},
    {get_syscall_info_default, (char *)"__NR_init_module", 105},
    {get_syscall_info_default, (char *)"__NR_delete_module", 106},
    {get_syscall_info_default, (char *)"__NR_timer_create", 107},
    {get_syscall_info_default, (char *)"__NR_timer_gettime", 108},
    {get_syscall_info_default, (char *)"__NR_timer_getoverrun", 109},
    {get_syscall_info_default, (char *)"__NR_timer_settime", 110},
    {get_syscall_info_default, (char *)"__NR_timer_delete", 111},
    {get_syscall_info_default, (char *)"__NR_clock_settime", 112},
    {get_syscall_info_default, (char *)"__NR_clock_gettime", 113},
    {get_syscall_info_default, (char *)"__NR_clock_getres", 114},
    {get_syscall_info_default, (char *)"__NR_clock_nanosleep", 115},
    {get_syscall_info_default, (char *)"__NR_syslog", 116},
    {get_syscall_info_default, (char *)"__NR_ptrace", 117},
    {get_syscall_info_default, (char *)"__NR_sched_setparam", 118},
    {get_syscall_info_default, (char *)"__NR_sched_setscheduler", 119},
    {get_syscall_info_default, (char *)"__NR_sched_getscheduler", 120},
    {get_syscall_info_default, (char *)"__NR_sched_getparam", 121},
    {get_syscall_info_default, (char *)"__NR_sched_setaffinity", 122},
    {get_syscall_info_default, (char *)"__NR_sched_getaffinity", 123},
    {get_syscall_info_default, (char *)"__NR_sched_yield", 124},
    {get_syscall_info_default, (char *)"__NR_sched_get_priority_max", 125},
    {get_syscall_info_default, (char *)"__NR_sched_get_priority_min", 126},
    {get_syscall_info_default, (char *)"__NR_sched_rr_get_interval", 127},
    {get_syscall_info_default, (char *)"__NR_restart_syscall", 128},
    {get_syscall_info_default, (char *)"__NR_kill", 129},
    {get_syscall_info_default, (char *)"__NR_tkill", 130},
    {get_syscall_info_default, (char *)"__NR_tgkill", 131},
    {get_syscall_info_default, (char *)"__NR_sigaltstack", 132},
    {get_syscall_info_default, (char *)"__NR_rt_sigsuspend", 133},
    {get_syscall_info_default, (char *)"__NR_rt_sigaction", 134},
    {get_syscall_info_default, (char *)"__NR_rt_sigprocmask", 135},
    {get_syscall_info_default, (char *)"__NR_rt_sigpending", 136},
    {get_syscall_info_default, (char *)"__NR_rt_sigtimedwait", 137},
    {get_syscall_info_default, (char *)"__NR_rt_sigqueueinfo", 138},
    {get_syscall_info_default, (char *)"__NR_rt_sigreturn", 139},
    {get_syscall_info_default, (char *)"__NR_setpriority", 140},
    {get_syscall_info_default, (char *)"__NR_getpriority", 141},
    {get_syscall_info_default, (char *)"__NR_reboot", 142},
    {get_syscall_info_default, (char *)"__NR_setregid", 143},
    {get_syscall_info_default, (char *)"__NR_setgid", 144},
    {get_syscall_info_default, (char *)"__NR_setreuid", 145},
    {get_syscall_info_default, (char *)"__NR_setuid", 146},
    {get_syscall_info_default, (char *)"__NR_setresuid", 147},
    {get_syscall_info_default, (char *)"__NR_getresuid", 148},
    {get_syscall_info_default, (char *)"__NR_setresgid", 149},
    {get_syscall_info_default, (char *)"__NR_getresgid", 150},
    {get_syscall_info_default, (char *)"__NR_setfsuid", 151},
    {get_syscall_info_default, (char *)"__NR_setfsgid", 152},
    {get_syscall_info_default, (char *)"__NR_times", 153},
    {get_syscall_info_default, (char *)"__NR_setpgid", 154},
    {get_syscall_info_default, (char *)"__NR_getpgid", 155},
    {get_syscall_info_default, (char *)"__NR_getsid", 156},
    {get_syscall_info_default, (char *)"__NR_setsid", 157},
    {get_syscall_info_default, (char *)"__NR_getgroups", 158},
    {get_syscall_info_default, (char *)"__NR_setgroups", 159},
    {get_syscall_info_default, (char *)"__NR_uname", 160},
    {get_syscall_info_default, (char *)"__NR_sethostname", 161},
    {get_syscall_info_default, (char *)"__NR_setdomainname", 162},
    {get_syscall_info_default, (char *)"__NR_getrlimit", 163},
    {get_syscall_info_default, (char *)"__NR_setrlimit", 164},
    {get_syscall_info_default, (char *)"__NR_getrusage", 165},
    {get_syscall_info_default, (char *)"__NR_umask", 166},
    {get_syscall_info_default, (char *)"__NR_prctl", 167},
    {get_syscall_info_default, (char *)"__NR_getcpu", 168},
    {get_syscall_info_default, (char *)"__NR_gettimeofday", 169},
    {get_syscall_info_default, (char *)"__NR_settimeofday", 170},
    {get_syscall_info_default, (char *)"__NR_adjtimex", 171},
    {get_syscall_info_default, (char *)"__NR_getpid", 172},
    {get_syscall_info_default, (char *)"__NR_getppid", 173},
    {get_syscall_info_default, (char *)"__NR_getuid", 174},
    {get_syscall_info_default, (char *)"__NR_geteuid", 175},
    {get_syscall_info_default, (char *)"__NR_getgid", 176},
    {get_syscall_info_default, (char *)"__NR_getegid", 177},
    {get_syscall_info_default, (char *)"__NR_gettid", 178},
    {get_syscall_info_default, (char *)"__NR_sysinfo", 179},
    {get_syscall_info_default, (char *)"__NR_mq_open", 180},
    {get_syscall_info_default, (char *)"__NR_mq_unlink", 181},
    {get_syscall_info_default, (char *)"__NR_mq_timedsend", 182},
    {get_syscall_info_default, (char *)"__NR_mq_timedreceive", 183},
    {get_syscall_info_default, (char *)"__NR_mq_notify", 184},
    {get_syscall_info_default, (char *)"__NR_mq_getsetattr", 185},
    {get_syscall_info_default, (char *)"__NR_msgget", 186},
    {get_syscall_info_default, (char *)"__NR_msgctl", 187},
    {get_syscall_info_default, (char *)"__NR_msgrcv", 188},
    {get_syscall_info_default, (char *)"__NR_msgsnd", 189},
    {get_syscall_info_default, (char *)"__NR_semget", 190},
    {get_syscall_info_default, (char *)"__NR_semctl", 191},
    {get_syscall_info_default, (char *)"__NR_semtimedop", 192},
    {get_syscall_info_default, (char *)"__NR_semop", 193},
    {get_syscall_info_default, (char *)"__NR_shmget", 194},
    {get_syscall_info_default, (char *)"__NR_shmctl", 195},
    {get_syscall_info_default, (char *)"__NR_shmat", 196},
    {get_syscall_info_default, (char *)"__NR_shmdt", 197},
    {get_syscall_info_default, (char *)"__NR_socket", 198},
    {get_syscall_info_default, (char *)"__NR_socketpair", 199},
    {get_syscall_info_default, (char *)"__NR_bind", 200},
    {get_syscall_info_default, (char *)"__NR_listen", 201},
    {get_syscall_info_default, (char *)"__NR_accept", 202},
    {get_syscall_info_default, (char *)"__NR_connect", 203},
    {get_syscall_info_default, (char *)"__NR_getsockname", 204},
    {get_syscall_info_default, (char *)"__NR_getpeername", 205},
    {get_syscall_info_default, (char *)"__NR_sendto", 206},
    {get_syscall_info_default, (char *)"__NR_recvfrom", 207},
    {get_syscall_info_default, (char *)"__NR_setsockopt", 208},
    {get_syscall_info_default, (char *)"__NR_getsockopt", 209},
    {get_syscall_info_default, (char *)"__NR_shutdown", 210},
    {get_syscall_info_default, (char *)"__NR_sendmsg", 211},
    {get_syscall_info_default, (char *)"__NR_recvmsg", 212},
    {get_syscall_info_default, (char *)"__NR_readahead", 213},
    {get_syscall_info_default, (char *)"__NR_brk", 214},
    {get_syscall_info_default, (char *)"__NR_munmap", 215},
    {get_syscall_info_default, (char *)"__NR_mremap", 216},
    {get_syscall_info_default, (char *)"__NR_add_key", 217},
    {get_syscall_info_default, (char *)"__NR_request_key", 218},
    {get_syscall_info_default, (char *)"__NR_keyctl", 219},
    {get_syscall_info_default, (char *)"__NR_clone", 220},
    {get_syscall_info_default, (char *)"__NR_execve", 221},
    {get_mmap_syscall_info, (char *)"__NR3264_mmap", 222},
    {get_syscall_info_default, (char *)"__NR3264_fadvise64", 223},
    {get_syscall_info_default, (char *)"__NR_swapon", 224},
    {get_syscall_info_default, (char *)"__NR_swapoff", 225},
    {get_syscall_info_default, (char *)"__NR_mprotect", 226},
    {get_syscall_info_default, (char *)"__NR_msync", 227},
    {get_syscall_info_default, (char *)"__NR_mlock", 228},
    {get_syscall_info_default, (char *)"__NR_munlock", 229},
    {get_syscall_info_default, (char *)"__NR_mlockall", 230},
    {get_syscall_info_default, (char *)"__NR_munlockall", 231},
    {get_syscall_info_default, (char *)"__NR_mincore", 232},
    {get_syscall_info_default, (char *)"__NR_madvise", 233},
    {get_syscall_info_default, (char *)"__NR_remap_file_pages", 234},
    {get_syscall_info_default, (char *)"__NR_mbind", 235},
    {get_syscall_info_default, (char *)"__NR_get_mempolicy", 236},
    {get_syscall_info_default, (char *)"__NR_set_mempolicy", 237},
    {get_syscall_info_default, (char *)"__NR_migrate_pages", 238},
    {get_syscall_info_default, (char *)"__NR_move_pages", 239},
    {get_syscall_info_default, (char *)"__NR_rt_tgsigqueueinfo", 240},
    {get_syscall_info_default, (char *)"__NR_perf_event_open", 241},
    {get_syscall_info_default, (char *)"__NR_accept4", 242},
    {get_syscall_info_default, (char *)"__NR_recvmmsg", 243},
    {get_syscall_info_default, (char *)"__NR_arch_specific_syscall", 244},
    {get_syscall_info_default, (char *)"__NR_wait4", 260},
    {get_syscall_info_default, (char *)"__NR_prlimit64", 261},
    {get_syscall_info_default, (char *)"__NR_fanotify_init", 262},
    {get_syscall_info_default, (char *)"__NR_fanotify_mark", 263},
    {get_syscall_info_default, (char *)"__NR_name_to_handle_at", 264},
    {get_syscall_info_default, (char *)"__NR_open_by_handle_at", 265},
    {get_syscall_info_default, (char *)"__NR_clock_adjtime", 266},
    {get_syscall_info_default, (char *)"__NR_syncfs", 267},
    {get_syscall_info_default, (char *)"__NR_setns", 268},
    {get_syscall_info_default, (char *)"__NR_sendmmsg", 269},
    {get_syscall_info_default, (char *)"__NR_process_vm_readv", 270},
    {get_syscall_info_default, (char *)"__NR_process_vm_writev", 271},
    {get_syscall_info_default, (char *)"__NR_kcmp", 272},
    {get_syscall_info_default, (char *)"__NR_finit_module", 273},
    {get_syscall_info_default, (char *)"__NR_sched_setattr", 274},
    {get_syscall_info_default, (char *)"__NR_sched_getattr", 275},
    {get_syscall_info_default, (char *)"__NR_renameat2", 276},
    {get_syscall_info_default, (char *)"__NR_seccomp", 277},
    {get_syscall_info_default, (char *)"__NR_getrandom", 278},
    {get_syscall_info_default, (char *)"__NR_memfd_create", 279},
    {get_syscall_info_default, (char *)"__NR_bpf", 280},
    {get_syscall_info_default, (char *)"__NR_execveat", 281},
    {get_syscall_info_default, (char *)"__NR_userfaultfd", 282},
    {get_syscall_info_default, (char *)"__NR_membarrier", 283},
    {get_syscall_info_default, (char *)"__NR_mlock2", 284},
    {get_syscall_info_default, (char *)"__NR_copy_file_range", 285},
    {get_syscall_info_default, (char *)"__NR_preadv2", 286},
    {get_syscall_info_default, (char *)"__NR_pwritev2", 287},
    {get_syscall_info_default, (char *)"__NR_pkey_mprotect", 288},
    {get_syscall_info_default, (char *)"__NR_pkey_alloc", 289},
    {get_syscall_info_default, (char *)"__NR_pkey_free", 290},
    {get_syscall_info_default, (char *)"__NR_statx", 291},
    {get_syscall_info_default, (char *)"__NR_io_pgetevents", 292},
    {get_syscall_info_default, (char *)"__NR_rseq", 293},
    {get_syscall_info_default, (char *)"__NR_kexec_file_load", 294},
    {get_syscall_info_default, (char *)"__NR_clock_gettime64", 403},
    {get_syscall_info_default, (char *)"__NR_clock_settime64", 404},
    {get_syscall_info_default, (char *)"__NR_clock_adjtime64", 405},
    {get_syscall_info_default, (char *)"__NR_clock_getres_time64", 406},
    {get_syscall_info_default, (char *)"__NR_clock_nanosleep_time64", 407},
    {get_syscall_info_default, (char *)"__NR_timer_gettime64", 408},
    {get_syscall_info_default, (char *)"__NR_timer_settime64", 409},
    {get_syscall_info_default, (char *)"__NR_timerfd_gettime64", 410},
    {get_syscall_info_default, (char *)"__NR_timerfd_settime64", 411},
    {get_syscall_info_default, (char *)"__NR_utimensat_time64", 412},
    {get_syscall_info_default, (char *)"__NR_pselect6_time64", 413},
    {get_syscall_info_default, (char *)"__NR_ppoll_time64", 414},
    {get_syscall_info_default, (char *)"__NR_io_pgetevents_time64", 416},
    {get_syscall_info_default, (char *)"__NR_recvmmsg_time64", 417},
    {get_syscall_info_default, (char *)"__NR_mq_timedsend_time64", 418},
    {get_syscall_info_default, (char *)"__NR_mq_timedreceive_time64", 419},
    {get_syscall_info_default, (char *)"__NR_semtimedop_time64", 420},
    {get_syscall_info_default, (char *)"__NR_rt_sigtimedwait_time64", 421},
    {get_syscall_info_default, (char *)"__NR_futex_time64", 422},
    {get_syscall_info_default, (char *)"__NR_sched_rr_get_interval_time64", 423},
    {get_syscall_info_default, (char *)"__NR_pidfd_send_signal", 424},
    {get_syscall_info_default, (char *)"__NR_io_uring_setup", 425},
    {get_syscall_info_default, (char *)"__NR_io_uring_enter", 426},
    {get_syscall_info_default, (char *)"__NR_io_uring_register", 427},
    {get_syscall_info_default, (char *)"__NR_open_tree", 428},
    {get_syscall_info_default, (char *)"__NR_move_mount", 429},
    {get_syscall_info_default, (char *)"__NR_fsopen", 430},
    {get_syscall_info_default, (char *)"__NR_fsconfig", 431},
    {get_syscall_info_default, (char *)"__NR_fsmount", 432},
    {get_syscall_info_default, (char *)"__NR_fspick", 433},
    {get_syscall_info_default, (char *)"__NR_pidfd_open", 434},
    {get_syscall_info_default, (char *)"__NR_clone3", 435},
    {get_syscall_info_default, (char *)"__NR_close_range", 436},
    {get_syscall_info_default, (char *)"__NR_openat2", 437},
    {get_syscall_info_default, (char *)"__NR_pidfd_getfd", 438},
    {get_syscall_info_default, (char *)"__NR_faccessat2", 439},
    {get_syscall_info_default, (char *)"__NR_process_madvise", 440},
    {get_syscall_info_default, (char *)"__NR_epoll_pwait2", 441},
    {get_syscall_info_default, NULL, -1},
};

const char *null_sys_call = "null_sys_call";

char *get_syscall_info_null(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret)
{
    *out = 0;
    return out;
}

char *get_syscall_info_default(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret)
{
    unsigned char comm[sizeof(((struct task_struct*)0)->comm)];

    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    pid_t threadid = __task_pid_nr_ns(current, PIDTYPE_PID, NULL);
    get_task_comm(comm, current);
    snprintf(out, max_size - 1, "%d\t%s\t%s\tret:%lx X0:%llx X1:%llx X2:%llx X3:%llx X4:%llx X5:%llx LR:%llx\n",
        threadid, comm, get_syscall_name(scno), ret,
        kregs->regs[0], kregs->regs[1], kregs->regs[2], kregs->regs[3], kregs->regs[4], kregs->regs[5], uregs->regs[30]);
    return out;
}

char *get_faccessat_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret)
{
    struct filename *tmp;
    unsigned char comm[sizeof(((struct task_struct*)0)->comm)];

    int fd = (int)kregs->regs[0];
    char __user *fname = (char __user *)kregs->regs[1];

    if (fd != AT_FDCWD && fd != 0) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    tmp = kernel_sym.file_util.getname(fname);
    if (IS_ERR(tmp)) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }
    if (NULL == tmp->name) {
        kernel_sym.file_util.putname(tmp);
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    pid_t threadid = __task_pid_nr_ns(current, PIDTYPE_PID, NULL);
    get_task_comm(comm, current);
    snprintf(out, max_size - 1, "%d\t%s\t%s\tret:%lx X0:%llx X1:%s X2:%llx LR:%llx\n",
        threadid, comm, get_syscall_name(scno), ret,
        kregs->regs[0], tmp->name, kregs->regs[2], uregs->regs[30]);

    kernel_sym.file_util.putname(tmp);
    return out;
}

char *get_openat_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret)
{
    struct filename *tmp;
    unsigned char comm[sizeof(((struct task_struct*)0)->comm)];

    int fd = (int)kregs->regs[0];
    char __user *fname = (char __user *)kregs->regs[1];

    if (fd != AT_FDCWD && fd != 0) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    tmp = kernel_sym.file_util.getname(fname);
    if (IS_ERR(tmp)) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }
    if (NULL == tmp->name) {
        kernel_sym.file_util.putname(tmp);
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    pid_t threadid = __task_pid_nr_ns(current, PIDTYPE_PID, NULL);
    get_task_comm(comm, current);
    snprintf(out, max_size - 1, "%d\t%s\t%s\tret:%lx X0:%llx X1:%s X2:%llx LR:%llx\n",
        threadid, comm, get_syscall_name(scno), ret,
        kregs->regs[0], tmp->name, kregs->regs[2], uregs->regs[30]);

    kernel_sym.file_util.putname(tmp);
    return out;
}

char *get_fstat_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret)
{
    struct file *f = NULL;
    char *dir = "/", *pathname;
    unsigned char comm[sizeof(((struct task_struct*)0)->comm)];

    int dfd = (int)kregs->regs[0];

    f = fget(dfd);
    if (NULL == f) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    pathname = dt_kmalloc_fast_path();
    if (NULL == pathname) {
        if (f) {fput(f);}
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    dir = file_path(f, pathname, dt_get_kmalloc_fast_size());
    if (IS_ERR_OR_NULL(dir)) {
        dt_kfree_fast_path(pathname);
        if (f) {fput(f);}
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    pid_t threadid = __task_pid_nr_ns(current, PIDTYPE_PID, NULL);
    get_task_comm(comm, current);
    snprintf(out, max_size - 1, "%d\t%s\t%s\tret:%lx X0:%s X1:%llx LR:%llx\n",
        threadid, comm, get_syscall_name(scno), ret,
        dir, kregs->regs[1], uregs->regs[30]);

    dt_kfree_fast_path(pathname);
    if (f) {fput(f);}
    return out;
}

char *get_mmap_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret)
{
    struct file *f = NULL;
    char *dir = "/", *pathname;
    unsigned char comm[sizeof(((struct task_struct*)0)->comm)];

    int dfd = (int)kregs->regs[4];

    if (-1 == dfd) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    f = fget(dfd);
    if (NULL == f) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    pathname = dt_kmalloc_fast_path();
    if (NULL == pathname) {
        if (f) {fput(f);}
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    dir = file_path(f, pathname, dt_get_kmalloc_fast_size());
    if (IS_ERR_OR_NULL(dir)) {
        dt_kfree_fast_path(pathname);
        if (f) {fput(f);}
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    pid_t threadid = __task_pid_nr_ns(current, PIDTYPE_PID, NULL);
    get_task_comm(comm, current);
    snprintf(out, max_size - 1, "%d\t%s\t%s\tret:%lx X0:%llx X1:%llx X2:%llx X3:%llx X4:%s X5:%llx LR:%llx\n",
        threadid, comm, get_syscall_name(scno), ret,
        kregs->regs[0], kregs->regs[1], kregs->regs[2], kregs->regs[3], dir, kregs->regs[5], uregs->regs[30]);

    dt_kfree_fast_path(pathname);
    if (f) {fput(f);}
    return out;
}

char *get_close_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret)
{
    struct file *f = NULL;
    char *dir = "/", *pathname;
    unsigned char comm[sizeof(((struct task_struct*)0)->comm)];

    int dfd = (int)kregs->regs[0];

    if (-1 == dfd) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    f = fget(dfd);
    if (NULL == f) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    pathname = dt_kmalloc_fast_path();
    if (NULL == pathname) {
        if (f) {fput(f);}
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    dir = file_path(f, pathname, dt_get_kmalloc_fast_size());
    if (IS_ERR_OR_NULL(dir)) {
        dt_kfree_fast_path(pathname);
        if (f) {fput(f);}
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    pid_t threadid = __task_pid_nr_ns(current, PIDTYPE_PID, NULL);
    get_task_comm(comm, current);
    snprintf(out, max_size - 1, "%d\t%s\t%s\tret:%lx X0:%s LR:%llx\n",
        threadid, comm, get_syscall_name(scno), ret,
        dir, uregs->regs[30]);

    dt_kfree_fast_path(pathname);
    if (f) {fput(f);}
    return out;
}

char *get_statfs_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret)
{
    struct filename *tmp;
    unsigned char comm[sizeof(((struct task_struct*)0)->comm)];

    char __user *fname = (char __user *)kregs->regs[0];

    tmp = kernel_sym.file_util.getname(fname);
    if (IS_ERR(tmp)) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }
    if (NULL == tmp->name) {
        kernel_sym.file_util.putname(tmp);
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    pid_t threadid = __task_pid_nr_ns(current, PIDTYPE_PID, NULL);
    get_task_comm(comm, current);
    snprintf(out, max_size - 1, "%d\t%s\t%s\tret:%lx X0:%s X1:%llx LR:%llx\n",
        threadid, comm, get_syscall_name(scno), ret,
        tmp->name, kregs->regs[1], uregs->regs[30]);

    kernel_sym.file_util.putname(tmp);
    return out;
}

char *get_fstatat_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret)
{
    struct filename *tmp;
    unsigned char comm[sizeof(((struct task_struct*)0)->comm)];

    int fd = (int)kregs->regs[0];
    char __user *fname = (char __user *)kregs->regs[1];

    if (fd != AT_FDCWD) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    tmp = kernel_sym.file_util.getname(fname);
    if (IS_ERR(tmp)) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }
    if (NULL == tmp->name) {
        kernel_sym.file_util.putname(tmp);
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    pid_t threadid = __task_pid_nr_ns(current, PIDTYPE_PID, NULL);
    get_task_comm(comm, current);
    snprintf(out, max_size - 1, "%d\t%s\t%s\tret:%lx X0:%llx X1:%s X2:%llx X3:%llx X4:%llx LR:%llx\n",
        threadid, comm, get_syscall_name(scno), ret,
        kregs->regs[0], tmp->name, kregs->regs[2], kregs->regs[3], kregs->regs[4], uregs->regs[30]);

    kernel_sym.file_util.putname(tmp);
    return out;
}

char *get_getdents64_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret)
{
    struct file *f = NULL;
    char *dir = "/", *pathname;
    unsigned char comm[sizeof(((struct task_struct*)0)->comm)];

    int dfd = (int)kregs->regs[0];

    if (-1 == dfd) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    f = fget(dfd);
    if (NULL == f) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    pathname = dt_kmalloc_fast_path();
    if (NULL == pathname) {
        if (f) {fput(f);}
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    dir = file_path(f, pathname, dt_get_kmalloc_fast_size());
    if (IS_ERR_OR_NULL(dir)) {
        dt_kfree_fast_path(pathname);
        if (f) {fput(f);}
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    pid_t threadid = __task_pid_nr_ns(current, PIDTYPE_PID, NULL);
    get_task_comm(comm, current);
    snprintf(out, max_size - 1, "%d\t%s\t%s\tret:%lx X0:%s X1:%llx X2:%llx LR:%llx\n",
        threadid, comm, get_syscall_name(scno), ret,
        dir, kregs->regs[1], kregs->regs[2], uregs->regs[30]);

    dt_kfree_fast_path(pathname);
    if (f) {fput(f);}
    return out;

}

char *get_read_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret)
{
    struct file *f = NULL;
    char *dir = "/", *pathname;
    int dfd = (int)kregs->regs[0];
    unsigned char comm[sizeof(((struct task_struct*)0)->comm)];

    if (-1 == dfd) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    f = fget(dfd);
    if (NULL == f) {
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    pathname = dt_kmalloc_fast_path();
    if (NULL == pathname) {
        if (f) {fput(f);}
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    dir = file_path(f, pathname, dt_get_kmalloc_fast_size());
    if (IS_ERR_OR_NULL(dir)) {
        dt_kfree_fast_path(pathname);
        if (f) {fput(f);}
        return get_syscall_info_default(out, max_size, scno, kregs, ret);
    }

    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    pid_t threadid = __task_pid_nr_ns(current, PIDTYPE_PID, NULL);
    get_task_comm(comm, current);
    snprintf(out, max_size - 1, "%d\t%s\t%s\tret:%lx X0:%s X1:%llx X2:%llx LR:%llx\n",
        threadid, comm, get_syscall_name(scno), ret,
        dir, kregs->regs[1], kregs->regs[2], uregs->regs[30]);

    dt_kfree_fast_path(pathname);
    if (f) {fput(f);}
    return out;
}

char *get_syscall_info(char *out, int max_size, int scno, struct pt_regs *kregs, unsigned long ret)
{
    if (scno < 0 || scno >= __NR_syscalls) {
        return "";
    }

    return sys_call_table_info[scno].get_syscall_info(out, max_size, scno, kregs, ret);
}

void init_sys_call_table_info()
{
    for (int i = 0; i < __NR_syscalls + 1; i++) {
        sys_call_table_info[i].get_syscall_info = get_syscall_info_default;
        sys_call_table_info[i].sys_name = (char *)null_sys_call;
        sys_call_table_info[i].sys_number = i;
    }

    for (struct sys_call_info *p = p_sys_call_info; NULL != p->sys_name; p++) {
        sys_call_table_info[p->sys_number].sys_name = p->sys_name;
        sys_call_table_info[p->sys_number].get_syscall_info = p->get_syscall_info;
    }
}

const char *get_syscall_name(int scno)
{
    if (scno < 0 || scno >= __NR_syscalls) {
        return "over_sys_call";
    }

    return sys_call_table_info[scno].sys_name;
}

