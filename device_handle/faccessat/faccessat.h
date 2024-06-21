
#ifndef DEBUG_TOOL_FACCESSAT_H
#define DEBUG_TOOL_FACCESSAT_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_faccessat();
bool release_faccessat();
int open_faccessat();
int close_faccessat();

int cmd_faccessat(unsigned long arg);

struct base_control controls_faccessat = {
    IOCTL_FACCESSAT,cmd_faccessat 
};

#endif
