
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "main.h"

static const char *opt_param = "t:s:r:";

static const struct option long_option[] = {
    {"type", required_argument, NULL, 't'},
    {"src", required_argument, NULL, 's'},
    {"replace", required_argument, NULL, 'r'},
    {0, 0, 0, 0}
};

extern int optind, ipterr, optopt;

int set_replace_file_stat(char *file, struct stat *buff)
{
    int ret = syscall(SYS_newfstatat, AT_FDCWD, file, buff, AT_SYMLINK_NOFOLLOW);
    if (ret != 0) {
        return -1;
    }
    return 0;
}

static int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        return -1;
    }
    return S_ISDIR(st.st_mode);
}

void handle_newfstatat_(int fd, int type, char *src_file, char *replace_file)
{
    if (NULL == src_file || NULL == replace_file) {
        printf("src_file or replace_file is null.");
        return;
    }

    newfstatat_parameters param;
    memset(&param, 0, sizeof(newfstatat_parameters));

    if (is_directory(replace_file) > 0
            && '/' != src_file[strlen(src_file) - 1]
            && '/' != replace_file[strlen(replace_file) - 1]) {
        char *append_src_file = (char *)malloc(strlen(src_file) + 0x10);
        strcpy(append_src_file, src_file);
        strcat(append_src_file, "/");
        char *append_replace_file = (char *)malloc(strlen(replace_file) + 0x10);
        strcpy(append_replace_file, replace_file);
        strcat(append_replace_file, "/");
        param.common.ioctl_type = IOCTL_NEWFSTATAT;
        param.common.type = type;

        param.src_file = append_src_file;
        param.src_file_len = strlen(append_src_file);
        param.replace_file = append_replace_file;
        param.replace_file_len = strlen(append_replace_file);

        int ret = set_replace_file_stat(param.replace_file, &param.replace_file_stat);
        if (0 != ret) {
            printf("set add file's dirent error. set_getdents64 error. file:%s\n", param.replace_file);
            free(append_src_file);
            free(append_replace_file);
            return;
        }
        printf("set_newfstatat: type:%d src:%s replace:%s.\n\n",
                param.common.type,
                NULL != param.src_file ? param.src_file : "",
                NULL != param.replace_file ? param.replace_file : "");

        ioctl(fd, IOCTL_NEWFSTATAT, (void*)&param);
        free(append_src_file);
        free(append_replace_file);
    }
    memset(&param, 0, sizeof(newfstatat_parameters));
    param.common.ioctl_type = IOCTL_NEWFSTATAT;
    param.common.type = type;
    param.src_file = src_file;
    param.src_file_len = strlen(src_file);
    param.replace_file = replace_file;
    param.replace_file_len = strlen(replace_file);

    int ret = set_replace_file_stat(param.replace_file, &param.replace_file_stat);
    if (0 != ret) {
        printf("set add file's dirent error. set_getdents64 error. file:%s\n", param.replace_file);
        return;
    }
    printf("set_newfstatat: type:%d src:%s replace:%s.\n\n",
            param.common.type,
            NULL != param.src_file ? param.src_file : "",
            NULL != param.replace_file ? param.replace_file : "");

    ioctl(fd, IOCTL_NEWFSTATAT, (void*)&param);
}

void handle_newfstatat(int fd, int argc, char **argv)
{
    int opt, ret;
    int long_index = 0;
    newfstatat_parameters param;
    memset(&param, 0, sizeof(newfstatat_parameters));
    param.common.ioctl_type = IOCTL_NEWFSTATAT;

    optind = 1;
    while ((opt = getopt_long(argc, argv, opt_param, long_option, &long_index)) != -1) {
        if (NULL == optarg) {
            continue;
        }
        switch (opt) {
            case 't':
                param.common.type = atoi(optarg);
                break;
            case 's':
                param.src_file = optarg;
                param.src_file_len = strlen(optarg);
                break;
            case 'r':
                param.replace_file = optarg;
                param.replace_file_len = strlen(optarg);
                break;
            default:
                continue;
        }
    }
    if (0 == param.common.type || 1 == param.common.type) {
        if (NULL == param.src_file || 0 == strlen(param.src_file)) {
            printf("the src file does not set.\n");
            return;
        }
        if (NULL == param.replace_file || 0 == strlen(param.replace_file)) {
            printf("the replace file does not set.\n");
            return;
        }
    }
    ret = set_replace_file_stat(param.replace_file, &param.replace_file_stat);
    if (0 != ret) {
        printf("set add file's dirent error. set_getdents64 error.\n");
        return;
    }
    printf("set_newfstatat: type:%d src:%s replace:%s.\n\n",
            param.common.type,
            NULL != param.src_file ? param.src_file : "",
            NULL != param.replace_file ? param.replace_file : "");

    ioctl(fd, IOCTL_NEWFSTATAT, (void*)&param);
    return;
}
