
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
#include "../../utils/process.h"

#define MODULE_TAG "debugtool:cmd_echo_process"

struct filter_list{
    struct list_head list;
    char *cmdline;
};

static DEFINE_RWLOCK(filter_rwlock);
static struct filter_list filters = {{NULL, NULL}, NULL};

static void safe_free_pos(struct filter_list *pos)
{
    dt_kfree(pos->cmdline);
    list_del(&pos->list);
    dt_kfree(pos);
}

void init_echo_process_filter_list()
{
    INIT_LIST_HEAD(&filters.list);
}

void clean_echo_process_filter_list()
{
    struct filter_list *pos;
    struct filter_list *temp;

    write_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list)
    {
        safe_free_pos(pos);
    }
    write_unlock(&filter_rwlock);
}

bool echo_process_cmdline(char *cmdline)
{
    bool ret = false;
    struct filter_list *pos;
    struct filter_list *temp;

    if (NULL == cmdline) {
        return ret;
    }

    read_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list) {
        if (pos->cmdline && (0 != strstr(cmdline, pos->cmdline))) {
            ret = true;
            break;
        }
    }
    read_unlock(&filter_rwlock);
    return ret;
}

void echo_process(const char *tag, const char *msg)
{
    pid_t threadid, processid = 0;

    char *cmdline = dt_kmalloc_fast_path();
    if (NULL == cmdline) {
        return;
    }
    get_cmdline(current, cmdline, dt_get_kmalloc_fast_size());

    if (false == echo_process_cmdline(cmdline)) {
        dt_kfree_fast_path(cmdline);
        return;
    }

    threadid = __task_pid_nr_ns(current, PIDTYPE_PID, NULL);
    processid= __task_pid_nr_ns(current, PIDTYPE_TGID, NULL);

    if (tag && msg) {
        int ret = loger("[%s]  cmdline:%s threadid:%d processid:%d msg:%s\n", tag, cmdline, (int)threadid, (int)processid, msg);
        if (0 == ret) {
            printk(KERN_ALERT "[%s]  unloger cmdline:%s msg:%s\n", MODULE_TAG, cmdline, msg);
        }
    }
    dt_kfree_fast_path(cmdline);
}

static void add_param(struct list_head *new, struct list_head *head)
{
    write_lock(&filter_rwlock);
    list_add_tail(new, head);
    write_unlock(&filter_rwlock);
}

static bool copy2malloc(char **to, char *src, int len)
{
    *to =  dt_kmalloc (len + 1);
    if (NULL == *to) {
        printk(KERN_ALERT "[%s] dt_kmalloc error.\n", MODULE_TAG);
        return false;
    }
    memcpy(*to, src, len);

    return true;
}

static void insert_process(echo_process_parameters *param)
{
    bool ret = false;
    echo_process_parameters *parameters = (echo_process_parameters *)(param);
    if (0 == parameters->cmdline_len || NULL == parameters->cmdline) {
        return;
    }

    struct filter_list *insert_param =
        (struct filter_list *)dt_kmalloc(sizeof(struct filter_list));
    ret = copy2malloc(&insert_param->cmdline, parameters->cmdline, parameters->cmdline_len + 1);
    if (false == ret) {
        return;
    }
    add_param(&insert_param->list, &filters.list);
}

static void del_process(echo_process_parameters *param)
{
    struct filter_list *pos;
    struct filter_list *temp;

    echo_process_parameters *parameters = (echo_process_parameters *)(param);
    if (NULL == parameters->cmdline) {
        return;
    }
    write_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list)
    {
        if (NULL == pos || NULL == pos->cmdline) {
            continue;
        }
        if (0 == strcmp(parameters->cmdline, pos->cmdline)) {
            safe_free_pos(pos);
        }
    }
    write_unlock(&filter_rwlock);
}

static void parser_param(unsigned long arg, echo_process_parameters *parameters)
{
    unsigned long status;

    status = copy_from_user((void *)parameters, (void *)arg,
            sizeof(echo_process_parameters));
    if (0 != status) {
        printk(KERN_ALERT "[%s]  copy param error.\n", MODULE_TAG);
        return;
    }
    copy_userchar2kmalloc(&parameters->cmdline, &parameters->cmdline_len);
}


static void operate_param(echo_process_parameters *parameters)
{
    if (0 == parameters->cmdline_len || NULL == parameters->cmdline) {
        return;
    }
    if (0 == parameters->common.type) {
        insert_process(parameters);
    }
    if (1 == parameters->common.type) {
        del_process(parameters);
    }
}

void operate_echo_process_cmd(unsigned long arg)
{
    echo_process_parameters parameters;

    parser_param(arg, &parameters);
    operate_param(&parameters);

    dt_kfree(parameters.cmdline);
}
