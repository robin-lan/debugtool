
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include "main.h"

static const char *opt_param = "t:c:";

static const struct option long_option[] = {
    {"type", required_argument, NULL, 't'},
    {"cmdline", required_argument, NULL, 'c'},
    {0, 0, 0, 0}
};

extern int optind, ipterr, optopt;

void handle_echo_process(int fd, int argc, char **argv)
{
    int opt;
    int long_index = 0;
    echo_process_parameters param;
    memset(&param, 0, sizeof(echo_process_parameters));
    param.common.ioctl_type = IOCTL_ECHO_PROCESS;

    optind = 1;
    while ((opt = getopt_long(argc, argv, opt_param, long_option, &long_index)) != -1) {
        if (NULL == optarg) {
            continue;
        }
        switch (opt) {
            case 'c':
                param.cmdline = optarg;
                param.cmdline_len = strlen(optarg);
                break;
            case 't':
                param.common.type = atoi(optarg);
                break;
            default:
                continue;
        }
    }

    printf("set_echo_process: cmdline:%s type:%d.\n\n",
            NULL != param.cmdline ? param.cmdline: "",
            param.common.type);

    ioctl(fd, IOCTL_ECHO_PROCESS, (void*)&param);
    return;
}
