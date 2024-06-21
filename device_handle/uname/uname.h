
#ifndef DEBUG_TOOL_UNAME_H
#define DEBUG_TOOL_UNAME_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_uname();
bool release_uname();
int open_uname();
int close_uname();

int cmd_uname(unsigned long arg);

struct base_control controls_uname = {
    IOCTL_UNAME,cmd_uname 
};

#endif
