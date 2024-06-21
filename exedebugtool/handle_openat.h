
#ifndef EXE_DEBUG_TOOL_HANDLE_OPENAT_H
#define EXE_DEBUG_TOOL_HANDLE_OPENAT_H

void handle_openat(int fd, int argc, char **argv);
void handle_openat_(int fd, int type, char *src_file, char *replace_file, char *hide_file);

#define OPENAT_HELP "openat:\n  \
\t-f openat -t [0|1|2]\t\t\t\t0:enable, 1:disable, 2:disable all.\n\
openat usage:\n\
\t-f openat -t [0|1] -s src -r dst\t\treplace src to dst.\n \
\t-f openat -t [0|1] -d hide\t\t\thide file.\n\n"

#endif
