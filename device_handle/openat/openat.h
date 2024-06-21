
#ifndef DEBUG_TOOL_OPENAT_H
#define DEBUG_TOOL_OPENAT_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_openat();
bool release_openat();
int open_openat();
int close_openat();

int cmd_openat(unsigned long arg);

struct base_control controls_openat = {
    IOCTL_OPENAT,cmd_openat 
};

#endif
