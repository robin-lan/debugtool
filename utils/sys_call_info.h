
#ifndef DEBUG_TOOL_SYS_CALL_INFO_H
#define DEBUG_TOOL_SYS_CALL_INFO_H

void init_sys_call_table_info();
char *get_syscall_info(char *out, int max_size, int scno, struct pt_regs *uregs, unsigned long ret);

#endif
