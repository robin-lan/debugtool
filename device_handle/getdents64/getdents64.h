
#ifndef DEBUG_TOOL_GETDENTS64_H
#define DEBUG_TOOL_GETDENTS64_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_getdents64();
bool release_getdents64();
int open_getdents64();
int close_getdents64();

int cmd_getdents64(unsigned long arg);

struct base_control controls_getdents64 = {
    IOCTL_GETDENTS64,cmd_getdents64 
};

#endif
