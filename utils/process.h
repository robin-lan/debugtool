
#ifndef DEBUG_TOOL_PROCESS_H
#define DEBUG_TOOL_PROCESS_H

#include <linux/sched.h>

void wakeup_process(void);
struct task_struct *get_target_pid_task(int target_pid);
int get_cmdline(struct task_struct *task, char *buffer, int buflen);

char *get_abpath(const char *file_name);
bool get_cwd(char *cwd, int size, char **out);
//char *get_abpath_fd(unsigned int dfd, const char __user *filename_user, char *abpath, int ab_size);
bool get_absolute_path(const char *dir, const char *path, char *abpath, int abpath_size);

#endif
