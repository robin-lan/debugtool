
#ifndef DEBUG_TOOL_DUMP_LOGER_H
#define DEBUG_TOOL_DUMP_LOGER_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_dump_loger();
bool release_dump_loger();
int open_dump_loger();
int close_dump_loger();

int cmd_dump_loger(unsigned long arg);

struct base_control controls_dump_loger = {
    IOCTL_DUMP_LOGER, cmd_dump_loger 
};

#endif
