
#include <linux/types.h>
#include <linux/mman.h>
#include <asm/uaccess.h>
#include <stdbool.h>
#include "../../exedebugtool/main.h"
#include "../../utils/kmemmanager.h"
#include "../../utils/kmem.h"
#include "../../utils/dump_user_content.h"
#include "../../utils/userfile.h"

#define MODULE_TAG "debugtool:cmd_dump_memory"

static void parser_param(unsigned long arg, dump_memory_parameters *parameters)
{
    unsigned long status;

    status = copy_from_user((void *)parameters, (void *)arg, sizeof(dump_memory_parameters));
    if (0 != status) {
        printk(KERN_ALERT "[%s]  copy param error.\n", MODULE_TAG);
        return;
    }
    copy_userchar2kmalloc(&parameters->dump_path, &parameters->dump_path_len);
}

static void operate_param(dump_memory_parameters *parameters)
{
    dump_pid_mem_range(parameters->pid, parameters->start, parameters->end, parameters->dump_path);
}

void operate_dump_memory_cmd(unsigned long arg)
{
    dump_memory_parameters parameters;

    parser_param(arg, &parameters);
    operate_param(&parameters);

    dt_kfree(parameters.dump_path);
}
