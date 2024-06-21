
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
#include "../../utils/process.h"
#include "../static_var/static_openat.h"

#define MODULE_TAG "debugtool:cmd_openat"

struct filter_list{
    struct list_head list;
    char *src_file;
    char *replace_file;
    char *hide_file;
    char *noperm_file;
};

static DEFINE_RWLOCK(filter_rwlock);
static struct filter_list filters = {{NULL, NULL}, NULL, NULL, NULL, NULL};

static void safe_free_pos(struct filter_list *pos)
{
    dt_kfree(pos->src_file);
    dt_kfree(pos->replace_file);
    dt_kfree(pos->hide_file);
    dt_kfree(pos->noperm_file);
    list_del(&pos->list);
    dt_kfree(pos);
}

void init_openat_filter_list()
{
    INIT_LIST_HEAD(&filters.list);
}

void clean_openat_filter_list()
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

bool hide_openat_files(const char *filename)
{
    bool ret = false;
    struct filter_list *pos;
    struct filter_list *temp;

    if (NULL == filename) {
        return ret;
    }

    for (int i = 0; i < sizeof(enoent_files) / sizeof(char *); i++) {
        if (NULL == enoent_files[i]) {
            break;
        }
        if (0 == strcmp(enoent_files[i], filename)) {
            return true;
        }
    }

    read_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list) {
        if (pos->hide_file && (0 == strcmp(filename, pos->hide_file))) {
            ret = true;
            break;
        }
    }
    read_unlock(&filter_rwlock);
    return ret;
}

bool filter_hide_files(const char *file_name)
{
    bool ret;
    ret = hide_openat_files(file_name);
    if (true == ret) {
        return true;
    }

    return false;
}

bool eacces_openat_files(const char *filename)
{
    bool ret = false;
    struct filter_list *pos;
    struct filter_list *temp;

    if (NULL == filename) {
        return ret;
    }

    for (int i = 0; i < sizeof(eacces_files) / sizeof(char *); i++) {
        if (NULL == eacces_files[i]) {
            break;
        }
        if (0 == strcmp(eacces_files[i], filename)) {
            return true;
        }
    }

    read_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list) {
        if (pos->noperm_file && (0 == strcmp(filename, pos->noperm_file))) {
            ret = true;
            break;
        }
    }
    read_unlock(&filter_rwlock);
    return ret;
}

bool filter_eacces_files(const char *file_name)
{
    bool ret;
    ret = eacces_openat_files(file_name);
    if (true == ret) {
        return true;
    }

    return false;
}

char __user *replace_openat_src_file(const char __user *ufrom, const char *kfrom, long *malloc_len)
{
    int status;
    struct filter_list *pos;
    struct filter_list *temp;
    char __user *replace_file = (char  __user *)ufrom;

    if (NULL == ufrom || NULL == kfrom) {
        return replace_file;
    }
    *malloc_len = 0;

    for (int i = 0; i < sizeof(replace2_files) / sizeof(struct replace2_file); i++) {
        if (NULL == replace2_files[i].from) {
            break;
        }
        if (0 == strcmp(replace2_files[i].from, kfrom)) {
            *malloc_len = strlen(replace2_files[i].to) + 1;
            replace_file = kmalloc_user_memory(*malloc_len);
            status = copy_to_user(replace_file, replace2_files[i].to, *malloc_len);
            if (0 != status) {
                printk(KERN_ALERT "[%s] %s copy_to_user error %d.\n", MODULE_TAG, __FUNCTION__, status);
                kfree_user_memory(replace_file, *malloc_len);
                *malloc_len = 0;
                replace_file = (char  __user *)ufrom;
                break;
            }
            printk(KERN_INFO "[%s] %s from %s to %s.\n", MODULE_TAG,__FUNCTION__, kfrom, replace2_files[i].to);
            return replace_file;
        }
    }

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
            printk(KERN_INFO "[%s] %s from %s to %s.\n", MODULE_TAG,__FUNCTION__, kfrom, pos->replace_file);
            break;
        }
    }
    read_unlock(&filter_rwlock);

    return replace_file;
}

#define openatInsert    (1<<0)
#define openatDel       (1<<1)
#define openatClean     (1<<2)
#define openatReplace   (1<<3)
#define openatHide      (1<<4)

static void insert_replace(openat_parameters *parameters);
static void insert_hide(openat_parameters *parameters);
static void del_replace(openat_parameters *parameters);
static void del_hide(openat_parameters *parameters);
static void clean_filter(openat_parameters *parameters);

struct handleS {
    int type;
    void (*handle)(openat_parameters *param);
};

static struct handleS handle_cmd[] = {
    {openatInsert | openatReplace,     insert_replace},
    {openatInsert | openatHide,        insert_hide},
    {openatDel | openatReplace,     del_replace},
    {openatDel | openatHide,        del_hide},
    {openatClean,                   clean_filter},
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

#define add_param2filter2(to, src, content0, content0_len, content1, content1_len)      \
    bool ret = false;                                                                   \
    openat_parameters *parameters = (openat_parameters *)(src);                         \
    struct filter_list *insert_param =                                                  \
        (struct filter_list *)dt_kmalloc(sizeof(struct filter_list));                   \
    ret = copy2malloc(&insert_param->content0, parameters->content0,                    \
            parameters->content0_len + 1);                                              \
    if (false == ret) {                                                                 \
        return;                                                                         \
    }                                                                                   \
    ret = copy2malloc(&insert_param->content1, parameters->content1,                    \
            parameters->content1_len + 1);                                              \
    if (false == ret) {                                                                 \
        return;                                                                         \
    }                                                                                   \
    add_param(&insert_param->list, &to.list);

#define add_param2filter1(to, src, content0, content0_len)                              \
    bool ret = false;                                                                   \
    openat_parameters *parameters = (openat_parameters *)(src);                         \
    struct filter_list *insert_param =                                                  \
        (struct filter_list *)dt_kmalloc(sizeof(struct filter_list));                   \
    ret = copy2malloc(&insert_param->content0, parameters->content0,                    \
            parameters->content0_len + 1);                                              \
    if (false == ret) {                                                                 \
        return;                                                                         \
    }                                                                                   \
    add_param(&insert_param->list, &to.list);

static void insert_replace(openat_parameters *param)
{
    if (NULL == param->src_file || NULL == param->replace_file) {
        return;
    }
    add_param2filter2(filters, param, src_file, src_file_len, replace_file, replace_file_len);
    printk(KERN_INFO "[%s] add file src:%s  replace:%s to openat.\n", MODULE_TAG,
            insert_param->src_file, insert_param->replace_file);
}

static void insert_hide(openat_parameters *param)
{
    if (NULL == param->hide_file) {
        return;
    }
    add_param2filter1(filters, param, hide_file, hide_file_len);
    printk(KERN_INFO "[%s] insert hide file :%s  in openat.\n", MODULE_TAG,
            parameters->hide_file);
}

#define del_paramInfilter2(from, byparam, content0, content1)               \
    struct filter_list *pos;                                                \
    struct filter_list *temp;                                               \
    openat_parameters *parameters = (openat_parameters *)byparam;           \
    write_lock(&filter_rwlock);                                             \
    list_for_each_entry_safe(pos, temp, &from.list, list)                   \
    {                                                                       \
        if (NULL == parameters->content0 || NULL == pos->content0 ||        \
                NULL == parameters->content1 || NULL == pos->content1) {    \
            continue;                                                       \
        }                                                                   \
        if ((0 == strcmp(parameters->content0, pos->content0)) &&           \
            (0 == strcmp(parameters->content1, pos->content1))) {           \
            safe_free_pos(pos);                                             \
        }                                                                   \
    }                                                                       \
    write_unlock(&filter_rwlock);

#define del_paramInfilter1(from, byparam, content0)                         \
    struct filter_list *pos;                                                \
    struct filter_list *temp;                                               \
    openat_parameters *parameters = (openat_parameters *)byparam;           \
    write_lock(&filter_rwlock);                                             \
    list_for_each_entry_safe(pos, temp, &from.list, list)                   \
    {                                                                       \
        if (NULL == parameters->content0 || NULL == pos->content0) {        \
            continue;                                                       \
        }                                                                   \
        if (0 == strcmp(parameters->content0, pos->content0)) {             \
            safe_free_pos(pos);                                             \
        }                                                                   \
    }                                                                       \
    write_unlock(&filter_rwlock);

static void del_replace(openat_parameters *param)
{
    del_paramInfilter2(filters, param, src_file, replace_file);
    printk(KERN_INFO "[%s]  delete replace file :%s  in openat.\n", MODULE_TAG,
            parameters->src_file);
}

static void del_hide(openat_parameters *param)
{
    del_paramInfilter1(filters, param, hide_file);
    printk(KERN_INFO "[%s]  delete hide file :%s  in openat.\n", MODULE_TAG,
            parameters->hide_file);
}

static void clean_filter(openat_parameters *param)
{
    clean_openat_filter_list();
}

static void parser_param(unsigned long arg, openat_parameters *parameters)
{
    unsigned long status;

    status = copy_from_user((void *)parameters, (void *)arg,
            sizeof(openat_parameters));
    if (0 != status) {
        printk(KERN_ALERT "[%s]  copy param error.\n", MODULE_TAG);
        return;
    }
    copy_userchar2kmalloc(&parameters->src_file, &parameters->src_file_len);
    copy_userchar2kmalloc(&parameters->replace_file, &parameters->replace_file_len);
    copy_userchar2kmalloc(&parameters->hide_file, &parameters->hide_file_len);
    copy_userchar2kmalloc(&parameters->noperm_file, &parameters->noperm_file_len);

}

static void operate_param_(int type, openat_parameters *param)
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

static void operate_param(openat_parameters *parameters)
{
    int handle_type = 0;

    if (0 == parameters->common.type) {
        handle_type |= openatInsert;
    }
    if (1 == parameters->common.type) {
        handle_type |= openatDel;
    }
    if (2 == parameters->common.type) {
        handle_type |= openatClean;
    }

    if (parameters->src_file_len && parameters->src_file &&
            parameters->replace_file_len && parameters->replace_file) {
        handle_type |= openatReplace;
    }
    if (parameters->hide_file_len && parameters->hide_file) {
        handle_type |= openatHide;
    }
    operate_param_(handle_type, parameters);
}

void operate_openat_cmd(unsigned long arg)
{
    openat_parameters parameters;

    parser_param(arg, &parameters);
    operate_param(&parameters);

    dt_kfree(parameters.src_file);
    dt_kfree(parameters.replace_file);
    dt_kfree(parameters.hide_file);
    dt_kfree(parameters.noperm_file);
}
