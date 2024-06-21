
#include <linux/linkage.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include "./kmemmanager.h"
#include "./kernel_symbol.h"
#include "./kmem.h"
#include "../exedebugtool/main.h"

#define MODULE_TAG "debugtool:process"

extern struct util_kernel_symbol kernel_sym;

/**
 * get_cmdline() - copy the cmdline value to a buffer.
 * @task:     the task whose cmdline value to copy.
 * @buffer:   the buffer to copy to.
 * @buflen:   the length of the buffer. Larger cmdline values are truncated
 *            to this length.
 * Returns the size of the cmdline field copied. Note that the copy does
 * not guarantee an ending NULL byte.
 */
int get_cmdline(struct task_struct *task, char *buffer, int buflen)
{
    int res = 0;
    unsigned int len;
    struct mm_struct *mm;
    unsigned long arg_start, arg_end, env_start, env_end;

    if (!task) {
        goto out;
    }
    mm = get_task_mm(task);
    if (!mm)
        goto out;
    if (!mm->arg_end)
        goto out_mm; /* Shh! No looking before we're done */

    down_read(&mm->mmap_lock);
    arg_start = mm->arg_start;
    arg_end = mm->arg_end;
    env_start = mm->env_start;
    env_end = mm->env_end;
    up_read(&mm->mmap_lock);

    len = arg_end - arg_start;

    if (len > buflen)
        len = buflen;

    res = access_process_vm(task, arg_start, buffer, len, FOLL_FORCE);

    /*
     * If the nul at the end of args has been overwritten, then
     * assume application is using setproctitle(3).
     */
    if (res > 0 && buffer[res - 1] != '\0' && len < buflen) {
        len = strnlen(buffer, res);
        if (len < res) {
            res = len;
        } else {
            len = env_end - env_start;
            if (len > buflen - res)
                len = buflen - res;
            res += access_process_vm(task, env_start, buffer + res, len,
                    FOLL_FORCE);
            res = strnlen(buffer, res);
        }
    }
out_mm:
    mmput(mm);
out:
    return res;
}

void wakeup_process(void)
{
    struct task_struct *p;
    rcu_read_lock();
    for_each_process(p) { wake_up_process(p); }
    rcu_read_unlock();
}

struct task_struct *get_target_pid_task(int target_pid)
{
    struct task_struct *task = NULL;

    struct pid *kpid = find_get_pid(target_pid);
    if (!kpid) {
        printk(KERN_WARNING "%s find_get_pid error.\n", MODULE_TAG);
        return NULL;
    }

    task = pid_task(kpid, PIDTYPE_PID);
    put_pid(kpid);
    if (!task) {
        printk(KERN_WARNING "%s pid_task error.\n", MODULE_TAG);
        return NULL;
    }

    return task;
}

typedef asmlinkage long (*T_getcwd)(struct pt_regs *param);

bool get_cwd(char *cwd, int size, char **out)
{
    struct pt_regs param;

    if (size < 0x10 || NULL == kernel_sym.hook_util.sys_call_table) {
        return false;
    }

    T_getcwd getcwd = (T_getcwd)(kernel_sym.hook_util.sys_call_table)[__NR_getcwd];

    char __user *buf = kmalloc_user_memory(size);
    param.regs[0] = (u64)buf;
    param.regs[1] = size - 1;
    int len = getcwd(&param);
    if (len < 0) {
        kfree_user_memory(buf, size);
        return false;
    }

    int status = strncpy_from_user(cwd, buf, size);
    kfree_user_memory(buf, size);
    if (status < 0) {
        return false;
    }
    *out = cwd;

    return true;
}

bool parent_dir(char *path, char *cur)
{
    char *point = NULL;
    cur = cur - 1;
    if (cur <= path) {
        return false;
    }
    if ('/' == *cur) {
        cur = cur -1;
    }
    for(point = cur; point > path; point--) {
        if ('/' == *point) {
            point[1] = 0;
            return true;
        }
    }

    return false;
}

bool get_absolute_path(const char *dir, const char *path, char *abpath, int abpath_size)
{
    int i, ret;
    char *tmp_dir = (char *)dir;

    if (NULL == tmp_dir &&  NULL == path) {
        return false;
    }
    memset(abpath, 0, abpath_size);

    if ('/' == path[0] || NULL == tmp_dir || strlen(tmp_dir) == 0) {
        if (strlen(path) >= abpath_size - 1) {
            return false;
        }
        strcpy(abpath, path);
        return true;
    }

    if ('/' != tmp_dir[0]) {
        abpath[0] = '/';
    }
    if (0 != strlen(tmp_dir)) {
        if (strlen(tmp_dir) + 2 >= abpath_size) {
            return false;
        }
        strcat(abpath, tmp_dir);
    }
    if ('/' != abpath[strlen(abpath) - 1]) {
        strcat(abpath, "/");
    }

    for (i = 0; i < strlen(path); i++) {
        if ('/' == path[i]) {
            if ('/' == abpath[strlen(abpath) - 1]) {
                continue;
            }
            if (strlen(abpath) >= abpath_size - 1) {
                return false;
            }
            strcat(abpath, "/");
            continue;
        }
        if ('.' == path[i] && '.' == path[i + 1]) {
            if ('/' != path[i + 2]) {
                return false;
            }
            ret = parent_dir(abpath, abpath + strlen(abpath));
            if (false == ret) {
                return false;
            }
            i = i + 2;
            continue;
        }
        if ('.' == path[i] && '/' == path[i + 1]) {
            i = i + 1;
            continue;
        }
        if (strlen(abpath) >= abpath_size - 1) {
            return false;
        }
        abpath[strlen(abpath) + 1] = 0;
        abpath[strlen(abpath)] = path[i];
    }

    return true;
}

char *get_abpath(const char *file_name)
{
    bool state;
    char *dir, *abpath;
    char *cwd_buff = dt_kmalloc(MAX_PATH_LEN * 2);
    if (NULL == cwd_buff) {
        return NULL;
    }

    state = get_cwd(cwd_buff, MAX_PATH_LEN * 2 - 1, &dir);
    if (false == state) {
        dt_kfree(cwd_buff);
        return NULL;
    }

    abpath = dt_kmalloc(MAX_PATH_LEN * 2);
    if (NULL == abpath) {
        dt_kfree(cwd_buff);
        return NULL;
    }
    state = get_absolute_path(dir, file_name, abpath, MAX_PATH_LEN * 2 - 1);
    if (false == state) {
        dt_kfree(cwd_buff);
        dt_kfree(abpath);
        return NULL;
    }
    dt_kfree(cwd_buff);

    return abpath;
}

char *get_abpath_fd(int dfd, const char __user *filename_user, char *abpath, int ab_size)
{
    int status;
    char *filename_kernel, *pathname;
    char *dir = "/";
    bool state;
    struct file *f = NULL;

    pathname = dt_kmalloc_fast_path();
    if (NULL == pathname){
        return NULL;
    }

    if (AT_FDCWD != dfd) {
        f = fget(dfd);
        if (NULL == f) {
            dt_kfree_fast_path(pathname);
            return NULL;
        }
        dir = file_path(f, pathname, dt_get_kmalloc_fast_size() - 1);
        if (IS_ERR_OR_NULL(dir)) {
            if (f) {fput(f);}
            dt_kfree_fast_path(pathname);
            return NULL;
        }
    }
    if (AT_FDCWD == dfd) {
        state = get_cwd(pathname, dt_get_kmalloc_fast_size() -1, &dir);
        if (false == state) {
            if(f) {fput(f);}
            dt_kfree_fast_path(pathname);
            return NULL;
        }
    }

    filename_kernel = dt_kmalloc_fast_path();
    if (NULL == filename_kernel) {
        if(f) {fput(f);}
        dt_kfree_fast_path(pathname);
        return NULL;
    }
    status = strncpy_from_user(filename_kernel, filename_user, dt_get_kmalloc_fast_size() - 1);
    if (status <= 0) {
        if(f) {fput(f);}
        dt_kfree_fast_path(filename_kernel);
        dt_kfree_fast_path(pathname);
        return NULL;
    }

    state = get_absolute_path(dir, filename_kernel, abpath, ab_size);
    dt_kfree_fast_path(filename_kernel);
    if(f) {fput(f);}
    dt_kfree_fast_path(pathname);
    if (false == state) {
        return NULL;
    }

    return abpath;
}

