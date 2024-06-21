
#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/string.h>
#include <asm/ptrace.h>
#include <linux/mman.h>
#include <asm/uaccess.h>
#include <stdbool.h>
#include "../../utils/kernel_symbol.h"
#include "../../utils/hook_systable.h"
#include "../../utils/kmem.h"
#include "../../utils/kmemmanager.h"
#include "../../utils/process.h"
#include "../../exedebugtool/main.h"
#include "../filter_process.h"
#include "./cmd_statfs.h"
#include "../echo_process/cmd_echo_process.h"

#define MODULE_TAG "debugtool:statfs"

extern struct util_kernel_symbol kernel_sym;

extern atomic_t runhook_count;

asmlinkage unsigned long (*raw_statfs)(struct pt_regs *param);

asmlinkage unsigned long new_statfs_func(struct pt_regs *param)
{
    struct filename *tmp;
    const char __user *fname = (const char __user *)param->regs[0];

    CRITICAL_COUNT_INHOOK

    if (false == filter_process()) {
        return raw_statfs(param);
    }

    tmp = kernel_sym.file_util.getname(fname);
    if (IS_ERR(tmp)) {
        return raw_statfs(param);
    }
    if (NULL == tmp->name) {
        kernel_sym.file_util.putname(tmp);
        return raw_statfs(param);
    }

    echo_process(MODULE_TAG, tmp->name);

    kernel_sym.file_util.putname(tmp);
    return raw_statfs(param);
}

bool init_statfs()
{
    init_statfs_filter_list();
    if (0 != hook_syscall(__NR_statfs, (ptr_t)new_statfs_func,
                          (ptr_t *)&raw_statfs)) {
        printk(KERN_ALERT "[%s] hook statfs error.\n", MODULE_TAG);
        return false;
    }
    return true;
}

bool release_statfs()
{
    unhook_syscall(__NR_statfs, raw_statfs);
    clean_statfs_filter_list();
    return true;
}

int open_statfs()
{
    return 0;
}

int close_statfs()
{
    return 0;
}

int cmd_statfs(unsigned long arg)
{
    operate_statfs_cmd(arg);
    return 0;
}
