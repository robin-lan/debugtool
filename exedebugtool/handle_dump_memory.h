
#ifndef EXE_DEBUG_TOOL_HANDLE_DUMP_MEMORY_H
#define EXE_DEBUG_TOOL_HANDLE_DUMP_MEMORY_H

void handle_dump_memory(int fd, int argc, char **argv);

#define DUMP_MEMORY_HELP "dump_memory:\n  \
\t-f dump_memory -p pid -s start -e end -d dump_path\thide file.\n\n"

#endif
