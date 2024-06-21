
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <stdbool.h>
#include "../../exedebugtool/main.h"
#include "../../utils/kmemprint.h"
#include "../../utils/kmemmanager.h"
#include "../../utils/kmem.h"

#define MODULE_TAG "debugtool:cmd_faccessat"

struct filter_list{
    struct list_head list;
    char *add_file;
};

static DEFINE_RWLOCK(filter_rwlock);
static struct filter_list filters = {{NULL, NULL}, NULL};

static void safe_free_pos(struct filter_list *pos)
{
    dt_kfree(pos->add_file);
    list_del(&pos->list);
    dt_kfree(pos);
}

void init_faccessat_filter_list()
{
    INIT_LIST_HEAD(&filters.list);
}

void clean_faccessat_filter_list()
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

#define faccessatInsert    (1<<0)
#define faccessatDel       (1<<1)
#define faccessatClean     (1<<2)
#define faccessatAdd       (1<<3)

static void insert_add(faccessat_parameters *parameters);
static void del_add(faccessat_parameters *parameters);
static void clean_filter(faccessat_parameters *parameters);

struct handleS {
    int type;
    void (*handle)(faccessat_parameters *param);
};

static struct handleS handle_cmd[] = {
    {faccessatInsert | faccessatAdd,  insert_add},
    {faccessatDel | faccessatAdd,     del_add},
    {faccessatClean,               clean_filter},
    {0,   NULL},
};

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

static void add_param(struct list_head *new, struct list_head *head)
{
    write_lock(&filter_rwlock);
    list_add_tail(new, head);
    write_unlock(&filter_rwlock);
}

static void insert_add(faccessat_parameters *param)
{
    bool ret = false;
    faccessat_parameters *parameters = (faccessat_parameters *)(param);
    if (NULL == parameters->add_file) {
        return;
    }

    struct filter_list *insert_param =
        (struct filter_list *)dt_kmalloc(sizeof(struct filter_list));
    ret = copy2malloc(&insert_param->add_file, parameters->add_file, parameters->add_file_len + 1);
    if (false == ret) {
        return;
    }
    add_param(&insert_param->list, &filters.list);
}

static void del_add(faccessat_parameters *param)
{
    struct filter_list *pos;
    struct filter_list *temp;

    faccessat_parameters *parameters = (faccessat_parameters *)(param);
    if (NULL == parameters->add_file) {
        return;
    }
    write_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list)
    {
        if (NULL == parameters->add_file || NULL == pos->add_file ) {
            continue;
        }
        if (0 == strcmp(parameters->add_file, pos->add_file)) {
            safe_free_pos(pos);
        }
    }
    write_unlock(&filter_rwlock);
}

static void clean_filter(faccessat_parameters *param)
{
    clean_faccessat_filter_list();
}

static void parser_param(unsigned long arg, faccessat_parameters *parameters)
{
    unsigned long status;

    status = copy_from_user((void *)parameters, (void *)arg,
            sizeof(faccessat_parameters));
    if (0 != status) {
        printk(KERN_ALERT "[%s]  copy param error.\n", MODULE_TAG);
        return;
    }
    copy_userchar2kmalloc(&parameters->add_file, &parameters->add_file_len);
}

static void operate_param_(int type, faccessat_parameters *param)
{
    for (int i = 0; -1 != i; i++) {
        if (NULL == handle_cmd[i].handle) {
            break;
        }
        if (handle_cmd[i].type == (type & handle_cmd[i].type)) {
            handle_cmd[i].handle(param);
        }
    }
}

static void operate_param(faccessat_parameters *parameters)
{
    int handle_type = 0;

    if (0 == parameters->common.type) {
        handle_type |= faccessatInsert;
    }
    if (1 == parameters->common.type) {
        handle_type |= faccessatDel;
    }
    if (2 == parameters->common.type) {
        handle_type |= faccessatClean;
    }

    if (parameters->add_file_len && parameters->add_file) {
        handle_type |= faccessatAdd;
    }
    operate_param_(handle_type, parameters);
}

void operate_faccessat_cmd(unsigned long arg)
{
    faccessat_parameters parameters;

    parser_param(arg, &parameters);
    operate_param(&parameters);

    dt_kfree(parameters.add_file);
}
