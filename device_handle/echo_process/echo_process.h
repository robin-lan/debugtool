
#ifndef DEBUG_TOOL_ECHO_PROCESS_H
#define DEBUG_TOOL_ECHO_PROCESS_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_echo_process();
bool release_echo_process();
int open_echo_process();
int close_echo_process();

int cmd_echo_process(unsigned long arg);

struct base_control controls_echo_process = {
    IOCTL_ECHO_PROCESS,cmd_echo_process 
};

#endif
