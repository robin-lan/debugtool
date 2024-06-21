
#ifndef DEBUG_TOOL_CMD_NEWFSTATAT_H
#define DEBUG_TOOL_CMD_NEWFSTATAT_H

void init_newfstatat_filter_list();
void clean_newfstatat_filter_list();

void operate_newfstatat_cmd(unsigned long arg);

char __user *replace_newfstatat_src_file(const char __user *ufrom, const char *kfrom, size_t *malloc_len);

#define NEWFSTATAT_MAX_USER_FILE_PATH 128

#endif

