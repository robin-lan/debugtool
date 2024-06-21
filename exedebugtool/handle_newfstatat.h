
#ifndef EXE_DEBUG_TOOL_HANDLE_NEWFSTATAT_H
#define EXE_DEBUG_TOOL_HANDLE_NEWFSTATAT_H

void handle_newfstatat(int fd, int argc, char **argv);
void handle_newfstatat_(int fd, int type, char *src_file, char *replace_file);

#define NEWFSTATAT_HELP "newfstatat:\n  \
\t-f newfstatat -t [0|1|2]\t\t\t0:enable, 1:disable, 2:disable all.\n\
newfstatat usage:\n\
\t-f newfstatat -t [0|1] -s src -r dst\t\treplace src to dst.\n\n"

#endif
