
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
#include "../../echo_process/cmd_echo_process.h"

#define MODULE_TAG "debugtool:fstat"

extern atomic_t runhook_count;

asmlinkage unsigned long (*raw_fstat)(struct pt_regs *param);

asmlinkage unsigned long long new_fstat_func(struct pt_regs *param)
{
    CRITICAL_COUNT_INHOOK
    char tmp[0x10];
    char *dir = "/", *pathname;
    struct file *f = NULL;
    int dfd = (int)param->regs[0];

    if (false == filter_process()) {
        return raw_fstat(param);
    }

    f = fget(dfd);
    if (NULL == f) {
        snprintf(tmp, sizeof(tmp), "dfd:%d", dfd);
        echo_process(MODULE_TAG, tmp);
        return raw_fstat(param);
    }

    pathname = dt_kmalloc_fast_path();
    if (NULL == pathname) {
        if (f) {fput(f);}
        return raw_fstat(param);
    }

    dir = file_path(f, pathname, dt_get_kmalloc_fast_size());
    if (IS_ERR_OR_NULL(dir)) {
        dt_kfree_fast_path(pathname);
        if (f) {fput(f);}
        return raw_fstat(param);
    }

    echo_process(MODULE_TAG, dir);

    dt_kfree_fast_path(pathname);
    if (f) {fput(f);}
    return raw_fstat(param);
}

bool init_fstat()
{
    if (0 != hook_syscall(__NR_fstat, (ptr_t)new_fstat_func,
                          (ptr_t *)&raw_fstat)) {
        printk(KERN_ALERT "[%s] hook fstat error.\n", MODULE_TAG);
        return false;
    }
    return true;
}

bool release_fstat()
{
    unhook_syscall(__NR_fstat, raw_fstat);
    return true;
}

int open_fstat()
{
    return 0;
}

int close_fstat()
{
    return 0;
}

int cmd_fstat(unsigned long arg)
{
    return 0;
}
