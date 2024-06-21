
#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/string.h>
#include <asm/ptrace.h>
#include <linux/mman.h>
#include <asm/uaccess.h>
#include <stdbool.h>

#include "./cmd_dump_loger.h"

#define MODULE_TAG "debugtool:dump_loger"

bool init_dump_loger()
{
    return true;
}

bool release_dump_loger()
{
    return true;
}

int open_dump_loger()
{
    return 0;
}

int close_dump_loger()
{
    return 0;
}

int cmd_dump_loger(unsigned long arg)
{
    operate_dump_loger_cmd(arg);
    return 0;
}
