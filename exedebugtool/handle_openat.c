
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include "main.h"

static const char *opt_param = "t:s:r:d:c:";

static const struct option long_option[] = {
    {"type", required_argument, NULL, 't'},
    {"src", required_argument, NULL, 's'},
    {"replace", required_argument, NULL, 'r'},
    {"hide", required_argument, NULL, 'd'},
    {0, 0, 0, 0}
};

static int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        return -1;
    }
    return S_ISDIR(st.st_mode);
}

extern int optind, ipterr, optopt;

void handle_openat_(int fd, int type, char *src_file, char *replace_file, char *hide_file)
{
    openat_parameters param;
    memset(&param, 0, sizeof(openat_parameters));
    param.common.ioctl_type = IOCTL_OPENAT;
    param.common.type = type;

    if (NULL != src_file && NULL != replace_file
            && is_directory(replace_file) > 0
            && '/' != src_file[strlen(src_file) - 1]
            && '/' != replace_file[strlen(replace_file) - 1]) {
        char *append_src_file = (char *)malloc(strlen(src_file) + 0x10);
        strcpy(append_src_file, src_file);
        strcat(append_src_file, "/");
        char *append_replace_file = (char *)malloc(strlen(replace_file) + 0x10);
        strcpy(append_replace_file, replace_file);
        strcat(append_replace_file, "/");

        param.src_file = append_src_file;
        param.src_file_len = strlen(append_src_file);
        param.replace_file = append_replace_file;
        param.replace_file_len = strlen(append_replace_file);
        printf("set_openat: type:%d src:%s replace:%s hide:%s.\n\n",
                param.common.type,
                NULL != param.src_file ? param.src_file : "",
                NULL != param.replace_file ? param.replace_file : "",
                NULL != param.hide_file ? param.hide_file : "");

        ioctl(fd, IOCTL_OPENAT, (void*)&param);
        free(append_src_file);
        free(append_replace_file);
    }

    param.src_file = src_file;
    if (NULL != src_file) {
        param.src_file_len = strlen(src_file);
    }
    param.replace_file = replace_file;
    if (NULL != replace_file) {
        param.replace_file_len = strlen(replace_file);
    }
    param.hide_file = hide_file;
    if (NULL != hide_file) {
        param.hide_file_len = strlen(hide_file);
    }

    printf("set_openat: type:%d src:%s replace:%s hide:%s.\n\n",
            param.common.type,
            NULL != param.src_file ? param.src_file : "",
            NULL != param.replace_file ? param.replace_file : "",
            NULL != param.hide_file ? param.hide_file : "");

    ioctl(fd, IOCTL_OPENAT, (void*)&param);
}

void handle_openat(int fd, int argc, char **argv)
{
    int opt;
    int long_index = 0;
    openat_parameters param;
    memset(&param, 0, sizeof(openat_parameters));
    param.common.ioctl_type = IOCTL_OPENAT;

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
            case 'd':
                param.hide_file = optarg;
                param.hide_file_len = strlen(optarg);
                break;
            default:
                continue;
        }
    }

    printf("set_openat: type:%d src:%s replace:%s hide:%s.\n\n",
            param.common.type,
            NULL != param.src_file ? param.src_file : "",
            NULL != param.replace_file ? param.replace_file : "",
            NULL != param.hide_file ? param.hide_file : "");

    ioctl(fd, IOCTL_OPENAT, (void*)&param);
    return;
}
