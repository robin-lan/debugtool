
#include <linux/types.h>
#include <stdbool.h>
#include "./cmd_dump_memory.h"

#define MODULE_TAG "debugtool:dump_memory"

bool init_dump_memory()
{
    return true;
}

bool release_dump_memory()
{
    return true;
}

int open_dump_memory()
{
    return 0;
}

int close_dump_memory()
{
    return 0;
}

int cmd_dump_memory(unsigned long arg)
{
    operate_dump_memory_cmd(arg);
    return 0;
}

