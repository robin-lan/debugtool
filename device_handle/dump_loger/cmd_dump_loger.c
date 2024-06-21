
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <stdbool.h>
#include "../../exedebugtool/main.h"
#include "../../utils/loger.h"
#include "../../utils/kmem.h"
#include "../../utils/kmemmanager.h"

#define MODULE_TAG "debugtool:cmd_dump_loger"

static void parser_param(unsigned long arg, dump_loger_parameters *parameters)
{
    unsigned long status;

    status = copy_from_user((void *)parameters, (void *)arg,
            sizeof(dump_loger_parameters));
    if (0 != status) {
        printk(KERN_ALERT "[%s]  copy param error.\n", MODULE_TAG);
        return;
    }
    copy_userchar2kmalloc(&parameters->file, &parameters->file_len);
}

static void operate_param(dump_loger_parameters *parameters)
{
    if (0 == parameters->file_len || NULL == parameters->file) {
        return;
    }
    write_log_file(parameters->file);
}

void operate_dump_loger_cmd(unsigned long arg)
{
    dump_loger_parameters parameters;

    parser_param(arg, &parameters);
    operate_param(&parameters);

    dt_kfree(parameters.file);
}
