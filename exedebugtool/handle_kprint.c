
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <string.h>
#include <sys/ioctl.h>
#include "main.h"
#include "./mem_print.h"

static const char *opt_param = "s:a:t:u:l:";

static const struct option long_option[] = {
    {"sym", required_argument, NULL, 's'},
    {"addr", required_argument, NULL, 'a'},
    {"type", required_argument, NULL, 't'},
    {"unit", required_argument, NULL, 'u'},
    {"line", required_argument, NULL, 'l'},
    {0, 0, 0, 0}
};

extern int optind, ipterr, optopt;

void handle_kprint(int fd, int argc, char **argv)
{
    kprint_dis_hex dis_hex;
    char *ptr = NULL, *point;
    int opt = 0;
    int long_index = 0;
    kprint_parameters param;
    memset(&param, 0, sizeof(kprint_parameters));
    param.common.ioctl_type = IOCTL_KPRINT;

    optind = 1;
    while ((opt = getopt_long(argc, argv, opt_param, long_option, &long_index)) != -1) {
        if (NULL == optarg) {
            continue;
        }
        switch (opt) {
            case 's':
                param.sym = optarg;
                param.sym_len = strlen(optarg);
                break;
            case 'a':
//                param.addr= strtol(optarg, &point, 0);
                sscanf(optarg, "0x%lx", &param.addr);
                break;
            case 't':
                param.type = *(char *)optarg;
                break;
            case 'u':
                param.unit = *(char *)optarg;
                break;
            case 'l':
                param.count = atoi(optarg);
                break;
            default:
                continue;
        }
    }

    printf("set_kprint: sym:%s addr:0x%lx type:%c unit:%c line:%d.\n\n",
            NULL != param.sym ? param.sym : "",
            param.addr,
            0 != param.type ? param.type : ' ',
            0 != param.unit ? param.unit : ' ',
            param.count);

#define BUFFER_SIZE 14000

    param.common.outbuff = (char *)malloc(BUFFER_SIZE);
    memset(param.common.outbuff, 0, BUFFER_SIZE);
    param.common.outbuff_size = BUFFER_SIZE;

    ioctl(fd, IOCTL_KPRINT, (void*)&param);

    ptr = strstr(param.common.outbuff, DIS_HEX_MAGIK);
    if (NULL == ptr) {
        printf("%s", param.common.outbuff);
        free(param.common.outbuff);
        return;
    }

    *ptr = 0;
    printf("%s\n", param.common.outbuff);

    memcpy(&dis_hex, ptr, sizeof(dis_hex));
    ptr = ptr + sizeof(dis_hex);

    char *print_buffer = (char *)malloc(BUFFER_SIZE);
    *(unsigned long *)print_buffer = dis_hex.addr;
    int unit_size = 0;
    if (param.unit == 'c') {
        unit_size = 1;
    } else if (param.unit == 's') {
        unit_size = 2;
    } else if (param.unit == 'g') {
        unit_size = 8;
    } else {
        unit_size = 4;
    }
    mem_print(print_buffer, BUFFER_SIZE, ptr, dis_hex.size, param.type, unit_size);
    printf("%s\n", print_buffer);
    free(print_buffer);

    free(param.common.outbuff);
    return;
}
