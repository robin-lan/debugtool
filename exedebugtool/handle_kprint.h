
#ifndef EXE_DEBUG_TOOL_HANDLE_KPRINT_H
#define EXE_DEBUG_TOOL_HANDLE_KPRINT_H

void handle_kprint(int fd, int argc, char **argv);

#define KPRINT_HELP "kprint:\n  \
\t-f kprint -s sym\t\t\t\tprint kernel symbol.\n \
\t-f kprint -a addr\t\t\t\tprint kernel address,e.g. 0x010203.\n\
\t-f kprint -t [xd]\t\t\t\tprint hex or disassemble.\n \
\t-f kprint -u [csdg]\t\t\t\tfor -t x. print unit size.\n \
\t-f kprint -l count/line\t\t\t\tcount for -t x. line for -t d.\n\
kprint usage:\n\
\t-f kprint -[s|a] ... -t [xd] -u [csdg] -l ...\n\n"

#endif
