
#ifndef DEBUG_TOOL_NEWFSTATAT_H
#define DEBUG_TOOL_NEWFSTATAT_H

#include "../../../handle.h"
#include "../../../exedebugtool/main.h"

bool init_newfstatat();
bool release_newfstatat();
int open_newfstatat();
int close_newfstatat();

int cmd_newfstatat(unsigned long arg);

struct base_control controls_newfstatat = {
    IOCTL_NEWFSTATAT,cmd_newfstatat 
};

#endif
