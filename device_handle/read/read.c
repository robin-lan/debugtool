
#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/string.h>
#include <linux/file.h>
#include <asm/ptrace.h>
#include <linux/mman.h>
#include <asm/uaccess.h>
#include <stdbool.h>
#include "../../utils/hook_systable.h"
#include "../../utils/kmem.h"
#include "../../utils/kmemmanager.h"
#include "../../utils/process.h"
#include "../filter_process.h"
#include "../echo_process/cmd_echo_process.h"
#include "../../exedebugtool/main.h"

#define MODULE_TAG "debugtool:read"

atomic_t readhook_count = ATOMIC_INIT(0);

asmlinkage unsigned long (*raw_read)(struct pt_regs *param) = NULL;

asmlinkage unsigned long new_read_func(struct pt_regs *param)
{
    atomic_t *p_runhook_count
    __attribute__((__cleanup__(dec_runhook_count))) = &readhook_count;

    atomic_inc(&readhook_count);

    char tmp[0x10];
    struct file *f = NULL;
    int dfd = (int)param->regs[0];

    if (false == filter_process()) {
        return raw_read(param);
    }

    f = fget(dfd);
    if (NULL == f) {
        snprintf(tmp, sizeof(tmp), "dfd:%d", dfd);
        echo_process(MODULE_TAG, tmp);
        return raw_read(param);
    }

    char *pathname = dt_kmalloc_fast_path();
    if (NULL == pathname) {
        if (f) {fput(f);}
        return raw_read(param);
    }

    char *dir = file_path(f, pathname, dt_get_kmalloc_fast_size());
    if (IS_ERR_OR_NULL(dir)) {
        dt_kfree_fast_path(pathname);
        if (f) {fput(f);}
        return raw_read(param);
    }

    unsigned long ret = raw_read(param);
    if (0 == ret) {
        echo_process(MODULE_TAG, dir);
    }

    dt_kfree_fast_path(pathname);
    if (f) {fput(f);}
    return ret;
}

bool init_read()
{
    return true;
}

bool release_read()
{
    if (raw_read) {
        unhook_syscall_count(__NR_read, raw_read, &readhook_count);
    }
    return true;
}

int open_read()
{
    return 0;
}

int close_read()
{
    return 0;
}

int cmd_read(unsigned long arg)
{
    read_parameters parameters;
    int status = copy_from_user((void *)&parameters, (void *)arg, sizeof(read_parameters));
    if (0 != status) {
        printk(KERN_ALERT "[%s]  copy param error.\n", MODULE_TAG);
        return 0;
    }
    if (1 == parameters.cmd_hook) {
        if (0 != hook_syscall_count(__NR_read, (ptr_t)new_read_func,
                              (ptr_t *)&raw_read, &readhook_count)) {
            printk(KERN_ALERT "[%s] hook read error.\n", MODULE_TAG);
            return 0;
        }
        printk(KERN_ALERT "[%s]  hook param ok.\n", MODULE_TAG);
    }
    if (2 == parameters.cmd_hook) {
        unhook_syscall_count(__NR_read, raw_read, &readhook_count);
        printk(KERN_ALERT "[%s]  unhook param ok.\n", MODULE_TAG);
    }

    return 0;
}
