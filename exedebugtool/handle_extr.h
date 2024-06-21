
#ifndef EXE_DEBUG_TOOL_HANDLE_EXTR_H
#define EXE_DEBUG_TOOL_HANDLE_EXTR_H

void handle_extr(int fd, int argc, char **argv);

#define EXTR_HELP "extr:\n  \
\t-f extr -t [get_statfs]\t\t\t\n\
extr usage:\n\
\t-f extr -t [get_statfs] -s file -d statfs_bin\tget file's statfs to bin file.\n\n"

#endif
