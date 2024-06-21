
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include "main.h"

static const char *opt_param = "t:s:";

static const struct option long_option[] = {
    {"type", required_argument, NULL, 't'},
    {"src", required_argument, NULL, 's'},
    {0, 0, 0, 0}
};

void handle_read(int fd, int argc, char **argv)
{
    int opt;
    int long_index = 0;
    read_parameters param;
    memset(&param, 0, sizeof(read_parameters));
    param.common.ioctl_type = IOCTL_READ;

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
                param.cmd_hook = atoi(optarg);
                break;
            default:
                continue;
        }
    }

    printf("set_read: type:%d hook:%d.\n\n",
            param.common.type,
            param.cmd_hook);

    ioctl(fd, IOCTL_READ, (void*)&param);
    return;
}
