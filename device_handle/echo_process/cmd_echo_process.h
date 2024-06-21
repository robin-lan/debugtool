
#ifndef DEBUG_TOOL_CMD_ECHO_PROCESS_H
#define DEBUG_TOOL_CMD_ECHO_PROCESS_H

void echo_process(const char *tag, const char *msg);
void operate_echo_process_cmd(unsigned long arg);
void init_echo_process_filter_list();
void clean_echo_process_filter_list();

#endif

