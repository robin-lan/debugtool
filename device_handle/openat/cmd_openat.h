
#ifndef DEBUG_TOOL_CMD_OPENAT_H
#define DEBUG_TOOL_CMD_OPENAT_H

void init_openat_filter_list();
void clean_openat_filter_list();

bool filter_hide_files(const char *file_name);
bool filter_enoent_files(const char *file_name);
bool filter_eacces_files(const char *file_name);
char __user * replace_openat_src_file(const char __user *ufrom, const char *kfrom, long *malloc_len);

void operate_openat_cmd(unsigned long arg);

#endif

