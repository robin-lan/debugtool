
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include "main.h"

static const char *opt_param = "s:d:";

static const struct option long_option[] = {
    {"file", required_argument, NULL, 's'},
    {0, 0, 0, 0}
};

extern int optind, ipterr, optopt;

void handle_dump_loger(int fd, int argc, char **argv)
{
    int opt;
    int long_index = 0;
    dump_loger_parameters param;
    memset(&param, 0, sizeof(dump_loger_parameters));
    param.common.ioctl_type = IOCTL_DUMP_LOGER;

    optind = 1;
    while ((opt = getopt_long(argc, argv, opt_param, long_option, &long_index)) != -1) {
        if (NULL == optarg) {
            continue;
        }
        switch (opt) {
            case 's':
                param.file = optarg;
                param.file_len = strlen(optarg);
                break;
            default:
                continue;
        }
    }

    printf("set_dump_loger: file:%s.\n\n",
            NULL != param.file ? param.file : "");

    ioctl(fd, IOCTL_DUMP_LOGER, (void*)&param);
    return;
}
