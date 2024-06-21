
#ifndef EXE_DEBUG_TOOL_HANDLE_MMAP_H
#define EXE_DEBUG_TOOL_HANDLE_MMAP_H

void handle_mmap(int fd, int argc, char **argv);

#define MMAP_HELP "mmap:\n  \
\t-f mmap -t [0|1]\n\
mmap usage:\n\
\t-f mmap -t [0|1] \t\t\t\t0:hook\t1:unhook.\n\n"

#endif
