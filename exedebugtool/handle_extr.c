
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <string.h>
#include <sys/syscall.h>
#include "main.h"

static const char *opt_param = "t:s:d:";

static const struct option long_option[] = {
    {"type", required_argument, NULL, 't'},
    {"file", required_argument, NULL, 's'},
    {"des", required_argument, NULL, 'd'},
    {0, 0, 0, 0}
};

extern int optind, ipterr, optopt;

void get_statfs(char *src_file, char *bin)
{
    int ret;
    struct statfs stat;

    FILE* output_file = fopen(bin, "wb+");
    if (!output_file) {
        printf("fopen %s error.\n", bin);
        return;
    }

    memset(&stat, 0, sizeof(struct statfs));
    ret = syscall(SYS_statfs, src_file, &stat);
    if (0 != ret) {
        printf("get statfs %s error.\n", src_file);
        fclose(output_file);
        return;
    }

    fwrite(&stat, 1, sizeof(struct statfs), output_file);
    fclose(output_file);
}

void handle_extr(int fd, int argc, char **argv)
{
    int opt;
    int long_index = 0;
    char function[MAX_PATH_LEN] = {0};
    char src_file[MAX_PATH_LEN] = {0};
    char des_file[MAX_PATH_LEN] = {0};

    optind = 1;
    while ((opt = getopt_long(argc, argv, opt_param, long_option, &long_index)) != -1) {
        if (NULL == optarg) {
            continue;
        }
        switch (opt) {
            case 't':
                strcpy(function, optarg);
                break;
            case 's':
                strcpy(src_file, optarg);
                break;
            case 'd':
                strcpy(des_file, optarg);
                break;
            default:
                continue;
        }
    }
    if (0 == strlen(function)) {
        return;
    }
    if (0 == strcmp(function, "get_statfs")) {
        get_statfs(src_file, des_file);
    }

    return;
}
