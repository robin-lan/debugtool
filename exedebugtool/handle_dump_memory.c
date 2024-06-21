
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include "main.h"

static const char *opt_param = "p:s:e:d:";

static const struct option long_option[] = {
    {"pid", required_argument, NULL, 'p'},
    {"start", required_argument, NULL, 's'},
    {"end", required_argument, NULL, 'e'},
    {"file", required_argument, NULL, 'd'},
    {0, 0, 0, 0}
};

void handle_dump_memory(int fd, int argc, char **argv)
{
    char *point;
    int opt;
    int long_index = 0;
    dump_memory_parameters param;
    memset(&param, 0, sizeof(dump_memory_parameters));
    param.common.ioctl_type = IOCTL_DUMP_MEMORY;

    optind = 1;
    while ((opt = getopt_long(argc, argv, opt_param, long_option, &long_index)) != -1) {
        if (NULL == optarg) {
            continue;
        }
        switch (opt) {
            case 'p':
                param.pid = atoi(optarg);
                break;
            case 's':
                param.start = strtol(optarg, &point, 0);
                break;
            case 'e':
                param.end = strtol(optarg, &point, 0);
                break;
            case 'd':
                param.dump_path = optarg;
                param.dump_path_len = strlen(optarg);
                break;
            default:
                continue;
        }
    }

    printf("dump_memory: pid:%d start::%010lx end:%010lx dump_path:%s.\n\n",
            param.pid, param.start, param.end,
            NULL != param.dump_path ? param.dump_path : "");

    ioctl(fd, IOCTL_DUMP_MEMORY, (void*)&param);
    return;
}
