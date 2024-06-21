
#ifndef DEBUG_TOOL_READ_H
#define DEBUG_TOOL_READ_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_read();
bool release_read();
int open_read();
int close_read();

int cmd_read(unsigned long arg);

struct base_control controls_read = {
    IOCTL_READ,cmd_read 
};

#endif
