
#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/stop_machine.h>
#include <stdbool.h>
#include "../../utils/hook_systable.h"
#include "../../utils/loger.h"
#include "../../utils/kmemmanager.h"
#include "../../utils/kmem.h"
#include "../../utils/kernel_symbol.h"
#include "../../utils/sys_call_info.h"
#include "../filter_process.h"
#include "../../exedebugtool/main.h"

#define MODULE_TAG "debugtool:hooksyscallroot"

typedef long (*syscall_fn_t)(const struct pt_regs *regs);

extern struct util_kernel_symbol kernel_sym;

bool init_back = false;
ptr_t sys_call_table_back[__NR_syscalls];
ptr_t sys_call_table_cover[__NR_syscalls];

bool init_hooksyscallroot()
{
    memset(sys_call_table_back, 0, sizeof(sys_call_table_back));
    return true;
}

bool release_hooksyscallroot()
{
    return true;
}

int open_hooksyscallroot()
{
    return 0;
}

int close_hooksyscallroot()
{
    return 0;
}

void init_sys_call_table_back()
{
    for (int i = 0; i < __NR_syscalls; i++ ) {
        sys_call_table_back[i] = kernel_sym.hook_util.sys_call_table[i];
    }
}

asmlinkage unsigned long sys_call_table_entry(struct pt_regs *regs)
{
    char *tmp;
    unsigned long ret;
    syscall_fn_t sys_call_fn;

    int scno = regs->syscallno;
    sys_call_fn = sys_call_table_back[scno];
    ret = sys_call_fn(regs);

    if (false == filter_process()) {
        return ret;
    }

    tmp = dt_kmalloc_fast_path();
    if (NULL == tmp) {
        return ret;
    }
    tmp = get_syscall_info(tmp, dt_get_kmalloc_fast_size(), scno, regs, ret);
    if (strlen(tmp) <= 0) {
        dt_kfree_fast_path(tmp);
        return ret;
    }

    loger("%s", tmp);
    dt_kfree_fast_path(tmp);

    return ret;
}

void init_sys_call_table_cover()
{
    for (int i = 0; i < __NR_syscalls; i++) {
        sys_call_table_cover[i] = sys_call_table_entry;
    }
}

int _hook_sys_call_table(void *arg)
{
    int ret, less;
    unsigned long start, from, count, next, npage, page = 0xFFF;
    if (true == init_back) {
        return 0;
    }
    init_back = true;

    init_sys_call_table_back();
    init_sys_call_table_cover();
    
    from = (unsigned long)sys_call_table_cover;
    start = (unsigned long)kernel_sym.hook_util.sys_call_table;
    less = sizeof(ptr_t) * __NR_syscalls;
    while (less > 0) {
        count = less;
        next = start + less;
        npage = (start + 0x1000) & (~page);
        if (next > npage) {
            count = npage - start;
        }
        ret = write_ro_memory((void *)start, (void *)from, count);
        if (ret != 0) {
            printk(KERN_ALERT "[%s] hook sys_call_table error.n", MODULE_TAG);
        }
        less = less - count;
        start = start + count;
        from = from + count;
    }

    for (int i = 0; i < __NR_syscalls; i++) {
        if (kernel_sym.hook_util.sys_call_table[i] != sys_call_table_cover[i]) {
            printk(KERN_ALERT "[%s] hook sys_call_table scon:%d error.\n", MODULE_TAG, i);
        }
    }

    return 0;
}

void hook_sys_call_table()
{
    stop_machine(_hook_sys_call_table, NULL, 0);
}

int _unhook_sys_call_table(void *arg)
{
    int ret, less;
    unsigned long start, from, count, next, npage, page = 0xFFF;

    if (false == init_back) {
        return 0;
    }
    init_back = false;

    from = (unsigned long)sys_call_table_back;
    start = (unsigned long)kernel_sym.hook_util.sys_call_table;
    less = sizeof(ptr_t) * __NR_syscalls;
    while (less > 0) {
        count = less;
        next = start + less;
        npage = (start + 0x1000) & (~page);
        if (next > npage) {
            count = npage - start;
        }
        ret = write_ro_memory((void *)start, (void *)from, count);
        if (ret != 0) {
            printk(KERN_ALERT "[%s] hook sys_call_table error.n", MODULE_TAG);
        }
        less = less - count;
        start = start + count;
        from = from + count;
    }

    for (int i = 0; i < __NR_syscalls; i++) {
        if (kernel_sym.hook_util.sys_call_table[i] != sys_call_table_back[i]) {
            printk(KERN_ALERT "[%s] unhook sys_call_table scon:%d error.\n", MODULE_TAG, i);
        }
    }
    return 0;
}

void unhook_sys_call_table()
{
    stop_machine(_unhook_sys_call_table, NULL, 0);
}

int cmd_hooksyscallroot(unsigned long arg)
{
    hooksyscallroot_parameters parameters;
    int status = copy_from_user((void *)&parameters, (void *)arg, sizeof(hooksyscallroot_parameters));
    if (0 != status) {
        printk(KERN_ALERT "[%s]  copy param error.\n", MODULE_TAG);
        return 0;
    }
    switch (parameters.common.type) {
        case 0:
            printk(KERN_ALERT "[%s]  hook_sys_call_table.\n", MODULE_TAG);
            hook_sys_call_table();
            break;
        case 1:
            printk(KERN_ALERT "[%s]  unhook_sys_call_table.\n", MODULE_TAG);
            unhook_sys_call_table();
            break;
        default:
            break;
    }

    return 0;
}
