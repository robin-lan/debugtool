
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include "main.h"

static const char *opt_param = "t:";

static const struct option long_option[] = {
    {"type", required_argument, NULL, 't'},
    {0, 0, 0, 0}
};

void handle_mmap(int fd, int argc, char **argv)
{
    int opt;
    int long_index = 0;
    mmap_parameters param;
    memset(&param, 0, sizeof(mmap_parameters));
    param.common.ioctl_type = IOCTL_MMAP;

    optind = 1;
    while ((opt = getopt_long(argc, argv, opt_param, long_option, &long_index)) != -1) {
        if (NULL == optarg) {
            continue;
        }
        switch (opt) {
            case 't':
                param.common.type = atoi(optarg);
                break;
                break;
            default:
                continue;
        }
    }

    printf("set_mmap: type:%d.\n\n",
            param.common.type);

    ioctl(fd, IOCTL_MMAP, (void*)&param);
    return;
}
