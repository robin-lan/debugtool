
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <stdbool.h>
#include "../../../exedebugtool/main.h"
#include "../../../utils/kmemprint.h"
#include "../../../utils/kmemmanager.h"
#include "../../../utils/kmem.h"

#define MODULE_TAG "debugtool:cmd_newfstatat"

struct filter_list{
    struct list_head list;
    char *src_file;
    char *replace_file;
    struct stat replace_file_stat;
};

static DEFINE_RWLOCK(filter_rwlock);
static struct filter_list filters = {{NULL, NULL}, NULL, NULL, {0}};

char __user *replace_newfstatat_src_file(const char __user *ufrom, char *kfrom, size_t *malloc_len)
{
    int status;
    struct filter_list *pos;
    struct filter_list *temp;
    char __user *replace_file = (char __user *)ufrom;

    *malloc_len = 0;
    read_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list) {
        if (pos->src_file && (0 == strcmp(kfrom, pos->src_file)) && pos->replace_file) {
            *malloc_len = strlen(pos->replace_file) + 1;
            replace_file = kmalloc_user_memory(*malloc_len);
            status = copy_to_user(replace_file, pos->replace_file, *malloc_len);
            if (0 != status) {
                printk(KERN_ALERT "[%s] %s copy_to_user error %d.\n", MODULE_TAG, __FUNCTION__, status);
                kfree_user_memory(replace_file, *malloc_len);
                *malloc_len = 0;
                replace_file = (char  __user *)ufrom;
                break;
            }
            printk(KERN_INFO "[%s] %s from:%s to:%s.\n", MODULE_TAG, __FUNCTION__, pos->src_file, pos->replace_file);
            break;
        }
    }
    read_unlock(&filter_rwlock);

    return replace_file;
}

static void safe_free_pos(struct filter_list *pos)
{
    if (NULL == pos) {
        return;
    }
    dt_kfree(pos->src_file);
    dt_kfree(pos->replace_file);
    list_del(&pos->list);
    dt_kfree(pos);
}

void init_newfstatat_filter_list()
{
    INIT_LIST_HEAD(&filters.list);
}

void clean_newfstatat_filter_list()
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

#define newfstatatInsert    (1<<0)
#define newfstatatDel       (1<<1)
#define newfstatatClean     (1<<2)
#define newfstatatReplace   (1<<3)

static void insert_replace(newfstatat_parameters *parameters);
static void del_replace(newfstatat_parameters *parameters);
static void clean_filter(newfstatat_parameters *parameters);

struct handleS {
    int type;
    void (*handle)(newfstatat_parameters *param);
};

static struct handleS handle_cmd[] = {
    {newfstatatInsert | newfstatatReplace,      insert_replace},
    {newfstatatDel | newfstatatReplace,         del_replace},
    {newfstatatClean,                           clean_filter},
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

static void insert_replace(newfstatat_parameters *param)
{
    bool ret = false;
    newfstatat_parameters *parameters = (newfstatat_parameters *)(param);
    if (NULL == parameters->src_file || NULL == parameters->replace_file) {
        return;
    }

    struct filter_list *insert_param =
        (struct filter_list *)dt_kmalloc(sizeof(struct filter_list));
    ret = copy2malloc(&insert_param->src_file, parameters->src_file, parameters->src_file_len + 1);
    if (false == ret) {
        return;
    }
    ret = copy2malloc(&insert_param->replace_file, parameters->replace_file, parameters->replace_file_len + 1);
    if (false == ret) {
        return;
    }
    memcpy(&(insert_param->replace_file_stat), &(param->replace_file_stat), sizeof(struct stat));
    add_param(&insert_param->list, &filters.list);
}

static void del_replace(newfstatat_parameters *param)
{
    struct filter_list *pos;
    struct filter_list *temp;

    newfstatat_parameters *parameters = (newfstatat_parameters *)(param);
    if (NULL == parameters->src_file || NULL == parameters->replace_file) {
        return;
    }
    write_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list)
    {
        if (NULL == parameters->src_file || NULL == pos->src_file
                || NULL == parameters->replace_file || NULL == pos->replace_file) {
            continue;
        }
        if ((0 == strcmp(parameters->src_file, pos->src_file)) &&
            (0 == strcmp(parameters->replace_file, pos->replace_file))) {
            safe_free_pos(pos);
        }
    }
    write_unlock(&filter_rwlock);
}

static void clean_filter(newfstatat_parameters *param)
{
    clean_newfstatat_filter_list();
}

static void parser_param(unsigned long arg, newfstatat_parameters *parameters)
{
    unsigned long status;

    status = copy_from_user((void *)parameters, (void *)arg,
            sizeof(newfstatat_parameters));
    if (0 != status) {
        printk(KERN_ALERT "[%s] copy param error.\n", MODULE_TAG);
        return;
    }
    copy_userchar2kmalloc(&parameters->src_file, &parameters->src_file_len);
    copy_userchar2kmalloc(&parameters->replace_file, &parameters->replace_file_len);
}

static void operate_param_(int type, newfstatat_parameters *param)
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

static void operate_param(newfstatat_parameters *parameters)
{
    int handle_type = 0;
    if (0 == parameters->common.type) {
        handle_type |= newfstatatInsert;
    }
    if (1 == parameters->common.type) {
        handle_type |= newfstatatDel;
    }
    if (2 == parameters->common.type) {
        handle_type |= newfstatatClean;
    }

    if (parameters->src_file_len && parameters->src_file &&
            parameters->replace_file_len && parameters->replace_file) {
        handle_type |= newfstatatReplace;
    }

    operate_param_(handle_type, parameters);
}

void operate_newfstatat_cmd(unsigned long arg)
{
    newfstatat_parameters parameters;

    parser_param(arg, &parameters);
    operate_param(&parameters);

    dt_kfree(parameters.src_file);
    dt_kfree(parameters.replace_file);
}
