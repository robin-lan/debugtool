
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "main.h"
#include "./handle_openat.h"
#include "./handle_kprint.h"
#include "./handle_newfstatat.h"
#include "./handle_getdents64.h"
#include "./handle_adddir.h"
#include "./handle_statfs.h"
#include "./handle_extr.h"
#include "./handle_dump_loger.h"
#include "./handle_echo_process.h"
#include "./handle_read.h"
#include "./handle_dump_memory.h"
#include "./handle_mmap.h"
#include "./handle_hooksyscallroot.h"

#define DEVICE_NAME "/dev/debugtools"

#define DEBUGTOOL_HELP ADDDIR_HELP KPRINT_HELP OPENAT_HELP NEWFSTATAT_HELP GETDENTS64_HELP STATFS_HELP EXTR_HELP DUMP_LOGER_HELP ECHO_PROCESS_HELP READ_HELP DUMP_MEMORY_HELP MMAP_HELP HOOKSYSCALLROOT_HELP

struct handle_function{
    char *function;
    void (*handle)(int fd, int argc, char **argv);
};

struct handle_function do_functions[] = {
    {"openat", handle_openat},
    {"kprint", handle_kprint},
    {"newfstatat", handle_newfstatat},
    {"getdents64", handle_getdents64},
    {"adddir", handle_adddir},
    {"statfs", handle_statfs},
    {"extr", handle_extr},
    {"dump_loger", handle_dump_loger},
    {"echo_process", handle_echo_process},
    {"read", handle_read},
    {"dump_memory", handle_dump_memory},
    {"mmap", handle_mmap},
    {"hooksyscallroot", handle_hooksyscallroot},
    {NULL, NULL}
};

static const char *opt_param = "hf:";

static const struct option long_option[] = {
    {"help", no_argument, NULL, 'h'},
    {"function", required_argument, NULL, 'f'},
    {0, 0, 0, 0}
};

extern int optind, ipterr, optopt;

int main(int argc, char **argv)
{
    int opt, i;
    bool print_help = false;
    char function[MAX_PATH_LEN];
    int long_index = 0;
    char *backup = (char *)malloc(sizeof(void *) * argc + 1);
    memset(backup, 0, sizeof(void *) * argc + 1);
    memcpy(backup, argv, sizeof(void *) * argc);

    opterr = 0;
    while ((opt = getopt_long(argc, argv, opt_param, long_option, &long_index)) != -1) {
        if ('f' == opt) {
            strcpy(function, optarg);
        }
        if ('h' == opt) {
            print_help  = true;
        }
    }
    if (0 == strlen(function) || true == print_help) {
        printf("%s\n", DEBUGTOOL_HELP);
        return 0;
    }

    int fd = open(DEVICE_NAME, 0);
//    if (fd < 0) {
//        if (NULL == strstr(function, "extr")) {
//            printf("\n");
//            printf("Can't open device file: %s\n", DEVICE_NAME);
//            printf("\n");
//            return -1;
//        }
//    }

    argv = (char **)backup;
    for (i = 0; -1 != i; i++) {
        if (NULL == do_functions[i].function) {
            break;
        }
        if (0 == strcmp(do_functions[i].function, function)) {
            do_functions[i].handle(fd, argc, argv);
            break;
        }
    }

    close(fd);
    return 0;
}
