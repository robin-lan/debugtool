
#ifndef DEBUG_TOOL_KPRINT_H
#define DEBUG_TOOL_KPRINT_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_kprint();
bool release_kprint();
int open_kprint();
int close_kprint();

int cmd_kprint(unsigned long arg);

struct base_control controls_kprint = {
    IOCTL_KPRINT,cmd_kprint 
};

#endif
