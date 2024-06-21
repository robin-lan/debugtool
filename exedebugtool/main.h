
#ifndef EXE_MAIN_H
#define EXE_MAIN_H

#define IOCTL_ADD           0
#define IOCTL_DEL           1
#define IOCTL_CLEAN         2

#define IOCTL_OPENAT        1340
#define IOCTL_KPRINT        1341
#define IOCTL_NEWFSTATAT    1342
#define IOCTL_GETDENTS64    1343
#define IOCTL_STATFS        1344
#define IOCTL_DUMP_LOGER    1345
#define IOCTL_ECHO_PROCESS  1346
#define IOCTL_FSTAT         1347
#define IOCTL_READ          1348
#define IOCTL_DUMP_MEMORY   1349
#define IOCTL_MMAP          1350
#define IOCTL_HOOKSYSCALLROOT        1351
#define IOCTL_UNAME         1352
#define IOCTL_FACCESSAT     1353
#define IOCTL_PTRACE        1354

#define MAX_PATH_LEN 256


#ifdef USER_INCLUDE
#include <dirent.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

struct linux_dirent64 {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[0];
};
#else
#include <linux/stat.h>
#include <linux/dirent.h>
#include <asm/statfs.h>
#endif


typedef struct {
    int ioctl_type;
    int type;
    char *outbuff;
    int outbuff_size;
} common_parameters;

typedef struct {
    common_parameters common;
    char *src_file;
    int src_file_len;
    char *replace_file;
    int replace_file_len;
    char *hide_file;
    int hide_file_len;
    char *stop_file;
    int stop_file_len;
    char *noperm_file;
    int noperm_file_len;
} openat_parameters;

typedef struct {
    common_parameters common;
    char *sym;
    int sym_len;
    unsigned long addr;
    int type;
    int unit;
    int count;
} kprint_parameters;

typedef struct {
    char magic[8];
    unsigned long size;
    unsigned long addr;
}kprint_dis_hex;

#define DIS_HEX_MAGIK "turtssid"

#define init_kprint_dis_hex(in_dis_hex) \
            in_dis_hex.magic[0] = 't'; \
            in_dis_hex.magic[1] = 'u'; \
            in_dis_hex.magic[2] = 'r'; \
            in_dis_hex.magic[3] = 't'; \
            in_dis_hex.magic[4] = 's'; \
            in_dis_hex.magic[5] = 's'; \
            in_dis_hex.magic[6] = 'i'; \
            in_dis_hex.magic[7] = 'd'; \
            in_dis_hex.size = 0;


typedef struct {
    common_parameters common;
    char *src_file;
    int src_file_len;
    char *replace_file;
    int replace_file_len;
    struct stat replace_file_stat;
} newfstatat_parameters;

typedef struct {
    common_parameters common;
    char *dir;
    int dir_len;
    char *add_file;
    int add_file_len;
    struct linux_dirent64 add_file_dirent;
    char nop[128];
    char *hide_file;
    int hide_file_len;
} getdents64_parameters;

typedef struct {
    common_parameters common;
    char *add_file;
    int add_file_len;
    struct statfs add_file_stat;
} statfs_parameters;

typedef struct {
    common_parameters common;
    char *file;
    int file_len;
} dump_loger_parameters;

typedef struct {
    common_parameters common;
    char *cmdline;
    int cmdline_len;
} echo_process_parameters;

typedef struct {
    common_parameters common;
    int cmd_hook;
} read_parameters;

typedef struct {
    common_parameters common;
    int pid;
    unsigned long start;
    unsigned long end;
    char *dump_path;
    int dump_path_len;
} dump_memory_parameters;

typedef struct {
    common_parameters common;
} mmap_parameters;

typedef struct {
    common_parameters common;
} hooksyscallroot_parameters;

typedef struct {
    common_parameters common;
    char *add_file;
    int add_file_len;
} faccessat_parameters;

#endif
