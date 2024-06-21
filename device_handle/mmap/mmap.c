
#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/file.h>
#include <stdbool.h>
#include "../../utils/hook_systable.h"
#include "../../utils/loger.h"
#include "../echo_process/cmd_echo_process.h"
#include "../../utils/kmemmanager.h"
#include "../../utils/kernel_symbol.h"
#include "../filter_process.h"
#include "../../exedebugtool/main.h"

#define MODULE_TAG "debugtool:mmap"


atomic_t mmaphook_count = ATOMIC_INIT(0);

asmlinkage unsigned long (*raw_mmap)(struct pt_regs *param) = NULL;

asmlinkage unsigned long new_mmap_func(struct pt_regs *param)
{
    atomic_t *p_runhook_count
    __attribute__((__cleanup__(dec_runhook_count))) = &mmaphook_count;

    atomic_inc(&mmaphook_count);

    char tmp[0x10];
    struct file * f = NULL;
    int dfd = (int)param->regs[4];
    unsigned long addr = (unsigned int)param->regs[0];
    //unsigned long len = (unsigned int)param->regs[1];

    if (false == filter_process()) {
        return raw_mmap(param);
    }

    if (0 != addr) {
        return raw_mmap(param);
    }

    f = fget(dfd);
    if (NULL == f) {
        snprintf(tmp, sizeof(tmp), "dfd:%d", dfd);
        echo_process(MODULE_TAG, tmp);
        return raw_mmap(param);
    }

    char *pathname = dt_kmalloc_fast_path();
    if (NULL == pathname) {
        if (f) {fput(f);}
        return raw_mmap(param);
    }

    char *dir = file_path(f, pathname, dt_get_kmalloc_fast_size());
    if (IS_ERR_OR_NULL(dir)) {
        dt_kfree_fast_path(pathname);
        if (f) {fput(f);}
        return raw_mmap(param);
    }

    echo_process(MODULE_TAG, dir);

    unsigned long ret = raw_mmap(param);
    if (0 == ret) {
        dt_kfree_fast_path(pathname);
        if (f) {fput(f);}
        return ret;
    }

    dt_kfree_fast_path(pathname);
    if (f) {fput(f);}
    return ret;
}

bool init_mmap()
{
    return true;
}

bool release_mmap()
{
    if (raw_mmap) {
        unhook_syscall_count(__NR_mmap, raw_mmap, &mmaphook_count);
    }
    return true;
}

int open_mmap()
{
    return 0;
}

int close_mmap()
{
    return 0;
}

int cmd_mmap(unsigned long arg)
{
    mmap_parameters parameters;
    int status = copy_from_user((void *)&parameters, (void *)arg, sizeof(mmap_parameters));
    if (0 != status) {
        printk(KERN_ALERT "[%s]  copy param error.\n", MODULE_TAG);
        return 0;
    }
    switch (parameters.common.type) {
        case 0:
            if (0 != hook_syscall_count(__NR_mmap, (ptr_t)new_mmap_func,
                                  (ptr_t *)&raw_mmap, &mmaphook_count)) {
                printk(KERN_ALERT "[%s] hook mmap error.\n", MODULE_TAG);
                return 0;
            }
            break;
        case 1:
            unhook_syscall_count(__NR_mmap, raw_mmap, &mmaphook_count);
            break;
        default:
            break;
    }

    return 0;
}
