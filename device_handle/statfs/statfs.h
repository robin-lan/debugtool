
#ifndef DEBUG_TOOL_STATFS_H
#define DEBUG_TOOL_STATFS_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_statfs();
bool release_statfs();
int open_statfs();
int close_statfs();

int cmd_statfs(unsigned long arg);

struct base_control controls_statfs = {
    IOCTL_STATFS,cmd_statfs 
};

#endif
