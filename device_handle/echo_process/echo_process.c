
#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/string.h>
#include <asm/ptrace.h>
#include <linux/mman.h>
#include <asm/uaccess.h>
#include <stdbool.h>

#include "./cmd_echo_process.h"

#define MODULE_TAG "debugtool:echo_process"

bool init_echo_process()
{
    init_echo_process_filter_list();
    return true;
}

bool release_echo_process()
{
    clean_echo_process_filter_list();
    return true;
}

int open_echo_process()
{
    return 0;
}

int close_echo_process()
{
    return 0;
}

int cmd_echo_process(unsigned long arg)
{
    operate_echo_process_cmd(arg);
    return 0;
}
