
#ifndef DEBUG_TOOL_CMD_STATFS_H
#define DEBUG_TOOL_CMD_STATFS_H

void init_statfs_filter_list();
void clean_statfs_filter_list();
void operate_statfs_cmd(unsigned long arg);

int statfs_get_flag(const char *dir);
long statfs_add_statfs(char *dir, char __user * user_statfs);

#endif

