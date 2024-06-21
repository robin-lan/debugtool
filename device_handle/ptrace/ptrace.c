
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

#define MODULE_TAG "debugtool:ptrace"

extern atomic_t runhook_count;

asmlinkage unsigned long (*raw_ptrace)(struct pt_regs *param) = NULL;

asmlinkage unsigned long new_ptrace_func(struct pt_regs *param)
{
    CRITICAL_COUNT_INHOOK

    long request = param->regs[0];

    if (false == filter_process()) {
        return raw_ptrace(param);
    }
    if (16 == request || 7 == request) {
        return raw_ptrace(param);
    }

    return -EPERM;
}

bool init_ptrace()
{
    if (0 != hook_syscall(__NR_ptrace, (ptr_t)new_ptrace_func,
                          (ptr_t *)&raw_ptrace)) {
        printk(KERN_ALERT "[%s] hook ptrace error.\n", MODULE_TAG);
        return false;
    }
    return true;
}

bool release_ptrace()
{
    unhook_syscall(__NR_ptrace, raw_ptrace);
    return true;
}

int open_ptrace()
{
    return 0;
}

int close_ptrace()
{
    return 0;
}

int cmd_ptrace(unsigned long arg)
{
    return 0;
}
