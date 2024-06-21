
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
#include "../../utils/dump_user_content.h"
#include "../../exedebugtool/main.h"
#include "../filter_process.h"
#include "./cmd_openat.h"
#include "../echo_process/cmd_echo_process.h"

#define MODULE_TAG "debugtool:openat"

extern struct util_kernel_symbol kernel_sym;

extern atomic_t runhook_count;

asmlinkage unsigned long (*raw_openat)(struct pt_regs *param);

asmlinkage unsigned long new_openat_func(struct pt_regs *param)
{
    bool status;
    struct filename *tmp;
    unsigned long value;
    long malloc_len;
    char __user *user_file, *fname = (char __user *)param->regs[1];

    CRITICAL_COUNT_INHOOK

    if (false == filter_process()) {
        return raw_openat(param);
    }

    if (false == filter_thread()) {
        return raw_openat(param);
    }

    tmp = kernel_sym.file_util.getname(fname);
    if (IS_ERR(tmp)) {
        return raw_openat(param);
    }
    if (NULL == tmp->name) {
        kernel_sym.file_util.putname(tmp);
        return raw_openat(param);
    }

    echo_process(MODULE_TAG, tmp->name);

    status = filter_hide_files(tmp->name);
    if (true == status) {
        kernel_sym.file_util.putname(tmp);
        return -ENOENT;
    }

    status = filter_eacces_files(tmp->name);
    if (true == status) {
        kernel_sym.file_util.putname(tmp);
        return -EACCES;
    }

    user_file = replace_openat_src_file(fname, tmp->name, &malloc_len);
    param->regs[1] = (u64)user_file;
    kernel_sym.file_util.putname(tmp);

    value = raw_openat(param);

    if (malloc_len) {
        kfree_user_memory(user_file, malloc_len);
    }

    param->regs[1] = (u64)fname;
    return value;
}

bool init_openat()
{
    init_openat_filter_list();
    if (0 != hook_syscall(__NR_openat, (ptr_t)new_openat_func,
                          (ptr_t *)&raw_openat)) {
        printk(KERN_ALERT "[%s] hook openat error.\n", MODULE_TAG);
        return false;
    }
    return true;
}

bool release_openat()
{
    unhook_syscall(__NR_openat, raw_openat);
    clean_openat_filter_list();
    return true;
}

int open_openat()
{
    return 0;
}

int close_openat()
{
    return 0;
}

int cmd_openat(unsigned long arg)
{
    operate_openat_cmd(arg);
    return 0;
}

