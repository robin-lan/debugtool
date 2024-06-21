
#ifndef EXE_DEBUG_TOOL_HANDLE_STATFS_H
#define EXE_DEBUG_TOOL_HANDLE_STATFS_H

void handle_statfs(int fd, int argc, char **argv);
void handle_statfs_(int fd, int type, char *add_file, char *statfs_bin);

#define STATFS_HELP "statfs:\n  \
\t-f statfs -t [0|1]\t\t\t\t0:enable, 1:disable.\n\
statfs usage:\n\
\t-f statfs -t [0|1] -a add file -b statfs.bin \tset add file's statfs with statfs.bin.\n\n"

#endif
