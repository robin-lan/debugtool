
#ifndef EXE_DEBUG_TOOL_HANDLE_ECHO_PROCESS_H
#define EXE_DEBUG_TOOL_HANDLE_ECHO_PROCESS_H

void handle_echo_process(int fd, int argc, char **argv);

#define ECHO_PROCESS_HELP "echo_process:\n  \
echo_process usage:\n\
\t-f echo_process -c cmdline -t [0|1]\t\tfocus special process.\n\n"

#endif
