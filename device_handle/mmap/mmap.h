
#ifndef DEBUG_TOOL_MMAP_H
#define DEBUG_TOOL_MMAP_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_mmap();
bool release_mmap();
int open_mmap();
int close_mmap();

int cmd_mmap(unsigned long arg);

struct base_control controls_mmap = {
    IOCTL_MMAP,cmd_mmap 
};

#endif
