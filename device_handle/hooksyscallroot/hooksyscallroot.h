
#ifndef DEBUG_TOOL_HOOKSYSCALLROOT_H
#define DEBUG_TOOL_HOOKSYSCALLROOT_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_hooksyscallroot();
bool release_hooksyscallroot();
int open_hooksyscallroot();
int close_hooksyscallroot();

int cmd_hooksyscallroot(unsigned long arg);

struct base_control controls_hooksyscallroot = {
    IOCTL_HOOKSYSCALLROOT, cmd_hooksyscallroot 
};

#endif
