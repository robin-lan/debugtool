
#ifndef DEBUG_TOOL_FSTAT_H
#define DEBUG_TOOL_FSTAT_H

#include "../../../handle.h"
#include "../../../exedebugtool/main.h"

bool init_fstat();
bool release_fstat();
int open_fstat();
int close_fstat();

int cmd_fstat(unsigned long arg);

struct base_control controls_fstat = {
    IOCTL_FSTAT,cmd_fstat 
};

#endif
