
#ifndef EXE_DEBUG_TOOL_HANDLE_GETDENTS64_H
#define EXE_DEBUG_TOOL_HANDLE_GETDENTS64_H

void handle_getdents64(int fd, int argc, char **argv);
void handle_getdents64_(int fd, int type, char *add_file, char *hide_file, char *dir, char *raw_dir);

#define GETDENTS64_HELP "getdents64:\n  \
\t-f getdents64 -t [0|1|2]\t\t\t0:enable, 1:disable, 2:disable all.\n\
getdents64 usage:\n\
\t-f getdents64 -t [0|1] -a file -p parent dir -i src parent dir\tadd file in parent dir.\n \
\t-f getdents64 -t [0|1] -d file -p parent dir\t\t\thide file in parent dir.\n\n"

#endif
