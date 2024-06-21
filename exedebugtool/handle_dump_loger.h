
#ifndef EXE_DEBUG_TOOL_HANDLE_DUMP_LOGER_H
#define EXE_DEBUG_TOOL_HANDLE_DUMP_LOGER_H

void handle_dump_loger(int fd, int argc, char **argv);

#define DUMP_LOGER_HELP "dump_loger:\n  \
dump_loger usage:\n\
\t-f dump_loger -s file\t\t\t\tdump log to file.\n\n"

#endif
