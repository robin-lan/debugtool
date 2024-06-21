
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
#include "./cmd_faccessat.h"
#include "../echo_process/cmd_echo_process.h"

#define MODULE_TAG "debugtool:faccessat"

extern struct util_kernel_symbol kernel_sym;

extern atomic_t runhook_count;

asmlinkage unsigned long (*raw_faccessat)(struct pt_regs *param);

const char *filter_faccessat_files[11] = {
    "/sys/block/loop0/loop/backing_file",
    "/sys/block/loop1/loop/backing_file",
    "/sys/block/loop2/loop/backing_file",
    "/sys/block/loop3/loop/backing_file",
    "/sys/block/loop4/loop/backing_file",
    "/sys/block/loop5/loop/backing_file",
    "/sys/block/loop6/loop/backing_file",
    "/sys/block/loop7/loop/backing_file",
    "/sys/block/loop8/loop/backing_file",
    "/sys/block/loop9/loop/backing_file",
    NULL
};
unsigned long set_static_faccessat(unsigned long status, const char *file) {
    if (NULL == file) {
        return status;
    }

    for (int i = 0; i < sizeof(filter_faccessat_files) / sizeof(char *); i++) {
        if (NULL == filter_faccessat_files[i]) {
            break;
        }
        if (0 == strcmp(filter_faccessat_files[i], file)) {
            return -1;
        }
    }
    return status;
}

asmlinkage unsigned long new_faccessat_func(struct pt_regs *param)
{
    int status;
    struct filename *tmp;
    int dfd = (int)param->regs[0];
    const char __user *fname = (const char __user *)param->regs[1];

    CRITICAL_COUNT_INHOOK

    if (false == filter_process()) {
        return raw_faccessat(param);
    }

    if (false == filter_thread()) {
        return raw_faccessat(param);
    }
    if (dfd != AT_FDCWD && dfd != 0) {
        return raw_faccessat(param);
    }

    tmp = kernel_sym.file_util.getname(fname);
    if (IS_ERR(tmp)) {
        return raw_faccessat(param);
    }
    if (NULL == tmp->name) {
        kernel_sym.file_util.putname(tmp);
        return raw_faccessat(param);
    }

    echo_process(MODULE_TAG, tmp->name);

    status = raw_faccessat(param);
    status = set_static_faccessat(status, tmp->name);

    kernel_sym.file_util.putname(tmp);
    return status;
}

bool init_faccessat()
{
    init_faccessat_filter_list();
    if (0 != hook_syscall(__NR_faccessat, (ptr_t)new_faccessat_func,
                          (ptr_t *)&raw_faccessat)) {
        printk(KERN_ALERT "[%s] hook faccessat error.\n", MODULE_TAG);
        return false;
    }
    return true;
}

bool release_faccessat()
{
    unhook_syscall(__NR_faccessat, raw_faccessat);
    clean_faccessat_filter_list();
    return true;
}

int open_faccessat()
{
    return 0;
}

int close_faccessat()
{
    return 0;
}

int cmd_faccessat(unsigned long arg)
{
    operate_faccessat_cmd(arg);
    return 0;
}
