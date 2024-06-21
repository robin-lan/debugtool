
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
#include "../static_var/static_uname.h"

#define MODULE_TAG "debugtool:uname"

extern atomic_t runhook_count;


asmlinkage unsigned long (*raw_uname)(struct pt_regs *param) = NULL;

asmlinkage unsigned long new_uname_func(struct pt_regs *param)
{
    CRITICAL_COUNT_INHOOK

    size_t count[[gnu::unused]];
    char __user *buff = (char __user *)param->regs[0];

    if (false == filter_process()) {
        return raw_uname(param);
    }

    if (true == filter_thread()) {
        return raw_uname(param);
    }


    count = copy_to_user(buff, uname, sizeof(uname));
    return 0;
}

bool init_uname()
{
    if (0 != hook_syscall(__NR_uname, (ptr_t)new_uname_func,
                          (ptr_t *)&raw_uname)) {
        printk(KERN_ALERT "[%s] hook uname error.\n", MODULE_TAG);
        return false;
    }
    return true;
}

bool release_uname()
{
    unhook_syscall(__NR_uname, raw_uname);
    return true;
}

int open_uname()
{
    return 0;
}

int close_uname()
{
    return 0;
}

int cmd_uname(unsigned long arg)
{
    return 0;
}
