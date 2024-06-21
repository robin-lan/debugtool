
#include <linux/delay.h>
#include <linux/stop_machine.h>
#include "../utils/kmem.h"
#include "../utils/process.h"
#include "../utils/kernel_symbol.h"

#define MODULE_TAG "debugtool:hook_systable"

atomic_t runhook_count = ATOMIC_INIT(0);

extern struct util_kernel_symbol kernel_sym;

struct sys_hook_param {
    int sys_call_number;
    void *old_fn;
    void *new_fn;
};

int _hook_syscall(void *arg)
{
    struct sys_hook_param *p_param = (struct sys_hook_param *)arg;

    if (p_param->new_fn) {
        if (0 != write_ro_memory(kernel_sym.hook_util.sys_call_table + p_param->sys_call_number,
                        (void *)&p_param->new_fn, sizeof(ptr_t))) {
            printk(KERN_ALERT "[%s] hook_syscall error. sys_call_number:%d.\n", MODULE_TAG, p_param->sys_call_number);
                        }
    } else {
        if (0 != write_ro_memory(kernel_sym.hook_util.sys_call_table + p_param->sys_call_number,
                        (void *)&p_param->old_fn, sizeof(ptr_t))) {
            printk(KERN_ALERT "[%s] hook_syscall error. sys_call_number:%d.\n", MODULE_TAG, p_param->sys_call_number);
                        }
    }
    return 0;
}

int hook_syscall(int call_num, ptr_t new_fn, ptr_t *old_fn)
{
    struct sys_hook_param param;
    param.sys_call_number = call_num;
    param.old_fn = NULL;
    param.new_fn = new_fn;

    if ((kernel_sym.hook_util.sys_call_table)[call_num] == new_fn) {
        return 0;
    }

    *old_fn = kernel_sym.hook_util.sys_call_table[call_num];
    stop_machine(_hook_syscall, (void *)&param, 0);

    while (atomic_read(&runhook_count) > 0) {
        wakeup_process();
        msleep_interruptible(500);
        printk(KERN_INFO "[%s] waiting for hook.\n", MODULE_TAG);
    }
    msleep_interruptible(300);
    return 0;
}

void unhook_syscall(int call_num, ptr_t old_fn)
{
    struct sys_hook_param param;
    param.sys_call_number = call_num;
    param.old_fn = old_fn;
    param.new_fn = NULL;

    if (0 == old_fn) {
        return;
    }
    if (kernel_sym.hook_util.sys_call_table[call_num] == old_fn) {
        return;
    }

    stop_machine(_hook_syscall, (void *)&param, 0);
    while (atomic_read(&runhook_count) > 0) {
        wakeup_process();
        msleep_interruptible(500);
//        printk(KERN_INFO "[%s] waiting for unhook.\n", MODULE_TAG);
    }
    msleep_interruptible(300);
}

void *get_syscall(int call_num)
{
    return kernel_sym.hook_util.sys_call_table[call_num];
}

void dec_runhook_count(atomic_t **count) { atomic_dec(*count); }


int hook_syscall_count(int call_num, ptr_t new_fn, ptr_t *old_fn, atomic_t *count)
{
    struct sys_hook_param param;
    param.sys_call_number = call_num;
    param.old_fn = NULL;
    param.new_fn = new_fn;

    if ((kernel_sym.hook_util.sys_call_table)[call_num] == new_fn) {
        return 0;
    }

    *old_fn = kernel_sym.hook_util.sys_call_table[call_num];
    stop_machine(_hook_syscall, (void *)&param, 0);

    while (atomic_read(count) > 0) {
        wakeup_process();
        msleep_interruptible(500);
        printk(KERN_INFO "[%s] waiting for hook.\n", MODULE_TAG);
    }
    msleep_interruptible(300);
    return 0;
}

void unhook_syscall_count(int call_num, ptr_t old_fn, atomic_t *count)
{
    struct sys_hook_param param;
    param.sys_call_number = call_num;
    param.old_fn = old_fn;
    param.new_fn = NULL;

    if (0 == old_fn) {
        return;
    }
    if (kernel_sym.hook_util.sys_call_table[call_num] == old_fn) {
        return;
    }

    stop_machine(_hook_syscall, (void *)&param, 0);
    while (atomic_read(count) > 0) {
        wakeup_process();
        msleep_interruptible(500);
//        printk(KERN_INFO "[%s] waiting for unhook.\n", MODULE_TAG);
    }
    msleep_interruptible(300);
}
