
#ifndef EXE_DEBUG_TOOL_HANDLE_READ_H
#define EXE_DEBUG_TOOL_HANDLE_READ_H

void handle_read(int fd, int argc, char **argv);
void handle_read_(int fd, int type, char *src_file, char *replace_file, char *hide_file);

#define READ_HELP "read:\n  \
\t-f read -t [0|1]\n\
read usage:\n\
\t-f read -t [0|1] -s file \t\t\t0:hook\t1:unhook.\n\n"

#endif
