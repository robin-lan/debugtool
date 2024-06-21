
#ifndef EXE_DEBUG_TOOL_HANDLE_HOOKSYSCALLROOT_H
#define EXE_DEBUG_TOOL_HANDLE_HOOKSYSCALLROOT_H

void handle_hooksyscallroot(int fd, int argc, char **argv);

#define HOOKSYSCALLROOT_HELP "hooksyscallroot:\n  \
\t-f hooksyscallroot -t [0|1]\n\
hooksyscallroot usage:\t!! !!! !!!! !!!!! !!!!!! !!!!!!!$if hook, must unhook!$\n\
\t-f hooksyscallroot -t [0|1]\t\t\t0:hook\t1:unhook. use dump_loger to dump\n\n"

#endif
