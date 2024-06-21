
#include <linux/types.h>
#include <linux/linkage.h>
#include <stdbool.h>
#include "./cmd_kprint.h"

#define MODULE_TAG "debugtool_kprint"

bool init_kprint()
{
    return true;
}

bool release_kprint()
{
    return true;
}

int open_kprint()
{
    return 0;
}

int close_kprint()
{
    return 0;
}

int cmd_kprint(unsigned long arg)
{
    operate_kprint_cmd(arg);
    return 0;
}
