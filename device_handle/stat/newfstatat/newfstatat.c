
#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <stdbool.h>
#include "../../../utils/hook_systable.h"
#include "../../../utils/kmem.h"
#include "../../../utils/kmemmanager.h"
#include "../../../utils/process.h"
#include "../../../utils/kernel_symbol.h"
#include "../../../exedebugtool/main.h"
#include "../../filter_process.h"
#include "./cmd_newfstatat.h"
#include "../../echo_process/cmd_echo_process.h"
#include "../../static_var/static_newfstatat.h"

#define MODULE_TAG "debugtool:newfstatat"

extern struct util_kernel_symbol kernel_sym;

extern atomic_t runhook_count;

asmlinkage unsigned long (*raw_newfstatat)(struct pt_regs *param);

unsigned long set_static_newfstatat(unsigned long ret, const char *dir, char __user *user_buffer)
{
    size_t count[[gnu::unused]];

    for (int i = 0; i < sizeof(fake_stats) / sizeof(struct fake_stat); i++) {
        if (NULL == fake_stats[i].dir) {
            return ret;
        }

        if (0 == strcmp(dir, fake_stats[i].dir)) {
            count = copy_to_user(user_buffer, fake_stats[i].stat, fake_stats[i].count);
            return 0;
        }
    }

    return ret;
}

long new_newfstatat_func_(struct pt_regs *param, const char *kfrom)
{
    long ret = 0;
    size_t malloc_len = 0;
    struct filename *tmp;
    int fd = (int)param->regs[0];
    char __user *filename_user = (char __user *)param->regs[1];
    char __user *stat_buff = (char __user *)param->regs[2];

    char __user *filename_user_new = replace_newfstatat_src_file(filename_user, kfrom, &malloc_len);

    param->regs[1] = (unsigned long)filename_user_new;
    ret = raw_newfstatat(param);
    if ((0 != malloc_len)
            && (filename_user != filename_user_new)) {
        kfree_user_memory(filename_user_new, malloc_len);
    }
    param->regs[1] = (unsigned long)filename_user;

    if (AT_FDCWD == fd) {
        tmp = kernel_sym.file_util.getname(filename_user);
        if (IS_ERR(tmp)) {
            return ret;
        }
        if (NULL == tmp->name) {
            kernel_sym.file_util.putname(tmp);
            return ret;
        }
        ret = set_static_newfstatat(ret, tmp->name, stat_buff);
        kernel_sym.file_util.putname(tmp);
    }
    return ret;
}

asmlinkage unsigned long new_newfstatat_func(struct pt_regs *param)
{
    CRITICAL_COUNT_INHOOK

    unsigned long status;
    struct filename *tmp;

    unsigned int dfd = (unsigned int)param->regs[0];
    char __user *filename_user = (char __user *)param->regs[1];

    if (false == filter_process()) {
        return raw_newfstatat(param);
    }

    if (AT_FDCWD == dfd) {
        tmp = kernel_sym.file_util.getname(filename_user);
        if (IS_ERR(tmp)) {
            return raw_newfstatat(param);
        }
        if ((NULL == tmp->name)) {
            kernel_sym.file_util.putname(tmp);
            return raw_newfstatat(param);
        }

        echo_process(MODULE_TAG, tmp->name);

        status = new_newfstatat_func_(param, tmp->name);

        kernel_sym.file_util.putname(tmp);
        return status;
    }

    return raw_newfstatat(param);
}

bool init_newfstatat()
{
    init_newfstatat_filter_list();
    if (0 != hook_syscall(__NR_newfstatat, (ptr_t)new_newfstatat_func,
                          (ptr_t *)&raw_newfstatat)) {
        printk(KERN_ALERT "[%s] hook newfstatat error.\n", MODULE_TAG);
        return false;
    }
    return true;
}

bool release_newfstatat()
{
    unhook_syscall(__NR_newfstatat, raw_newfstatat);
    clean_newfstatat_filter_list();
    return true;
}

int open_newfstatat()
{
    return 0;
}

int close_newfstatat()
{
    return 0;
}

int cmd_newfstatat(unsigned long arg)
{
    operate_newfstatat_cmd(arg);
    return 0;
}
