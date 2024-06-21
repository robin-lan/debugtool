
#ifndef EXE_DEBUG_TOOL_HANDLE_ADDDIR_H
#define EXE_DEBUG_TOOL_HANDLE_ADDDIR_H

void handle_adddir(int fd, int argc, char **argv);

#define ADDDIR_HELP "adddir:\n  \
\t-f adddir -t [0|1|2]\t\t\t\t0:enable, 1:disable, 2:disable all.\n\
adddir usage:\n\
\t-f adddir -t [0|1] -a src -d des\t\tadd files in src to des dir.\n\n"

#endif
