
#ifndef DEBUG_TOOL_DUMP_USER_CONTENT_H
#define DEBUG_TOOL_DUMP_USER_CONTENT_H

void dump_user_regs(char *dir);
void dump_user_stack(char *dir);
void dump_user_pc_mem_range(char *dir);
void dump_user_maps(int target_pid, char *dir);
void dump_pid_mem(int target_pid, unsigned long addr, char *dir);
void dump_pid_mem_range(int target_pid, unsigned long start, unsigned long end, char *dir);

void dump_user_content(char *dir);
#endif
