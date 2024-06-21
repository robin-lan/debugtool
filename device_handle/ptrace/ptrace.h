
#ifndef DEBUG_TOOL_PTRACE_H
#define DEBUG_TOOL_PTRACE_H

#include "../../handle.h"
#include "../../exedebugtool/main.h"

bool init_ptrace();
bool release_ptrace();
int open_ptrace();
int close_ptrace();

int cmd_ptrace(unsigned long arg);

struct base_control controls_ptrace = {
    IOCTL_PTRACE,cmd_ptrace 
};

#endif
