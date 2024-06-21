
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include "main.h"

static const char *opt_param = "t:a:b:";

static const struct option long_option[] = {
    {"type", required_argument, NULL, 't'},
    {"add", required_argument, NULL, 'a'},
    {"bin_file", required_argument, NULL, 'b'},
    {0, 0, 0, 0}
};

extern int optind, ipterr, optopt;

bool read_statfs(char *statfs_bin, struct statfs *bin)
{
    FILE* in_file = fopen(statfs_bin, "rb");
    if (!in_file) {
        printf("fopen %s error.\n", statfs_bin);
        return false;
    }

    struct stat sb;
    if (stat(statfs_bin, &sb) == -1) {
        printf("stat %s error.\n", statfs_bin);
        return false;
    }
    if (sb.st_size != sizeof(struct statfs)) {
        printf("the size of %s is not equal to sizeof(struct statfs).\n", statfs_bin);
        return false;
    }

    fread(bin, sb.st_size, 1, in_file);
    fclose(in_file);

    return true;
}


void handle_statfs_(int fd, int type, char *add_file, char *statfs_bin)
{
    bool status;

    statfs_parameters param;
    memset(&param, 0, sizeof(statfs_parameters));
    param.common.ioctl_type = IOCTL_STATFS;
    param.common.type = type;
    param.add_file = add_file;
    if (NULL != add_file) {
        param.add_file_len = strlen(add_file);
    }
    status = read_statfs(statfs_bin, &param.add_file_stat);
    if (false == status) {
        return;
    }

    printf("set_statfs: type:%d add:%s statfs:%s.\n\n",
            param.common.type,
            NULL != param.add_file ? param.add_file : "",
            NULL != statfs_bin ? statfs_bin : "");

    ioctl(fd, IOCTL_STATFS, (void*)&param);
}

void handle_statfs(int fd, int argc, char **argv)
{
    int opt;
    int long_index = 0;
    bool status; 
    statfs_parameters param;
    memset(&param, 0, sizeof(statfs_parameters));
    param.common.ioctl_type = IOCTL_STATFS;
    char *statfs_bin = NULL;

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
                param.add_file = optarg;
                param.add_file_len = strlen(optarg);
                break;
            case 'b':
                statfs_bin = optarg;
                break;
            default:
                continue;
        }
    }
    status = read_statfs(statfs_bin, &param.add_file_stat);
    if (false == status) {
        return;
    }
    printf("set_statfs: type:%d add:%s statfs:%s.\n\n",
            param.common.type,
            NULL != param.add_file ? param.add_file : "",
            NULL != statfs_bin ? statfs_bin : "");

    ioctl(fd, IOCTL_STATFS, (void*)&param);
    return;
}
