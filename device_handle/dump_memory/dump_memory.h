
#ifndef DEBUG_TOOL_DUMP_MEMORY_H
#define DEBUG_TOOL_DUMP_MEMORY_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_dump_memory();
bool release_dump_memory();
int open_dump_memory();
int close_dump_memory();

int cmd_dump_memory(unsigned long arg);

struct base_control controls_dump_memory = {
    IOCTL_DUMP_MEMORY,cmd_dump_memory 
};

#endif
