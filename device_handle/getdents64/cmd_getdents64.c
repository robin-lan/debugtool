
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

#define MODULE_TAG "debugtool:cmd_getdents64"

struct filter_list{
    struct list_head list;
    char *dir;
    char *add_file;
    char *hide_file;
    struct linux_dirent64 add_file_dirent;
    char nop[128];
};

static DEFINE_RWLOCK(filter_rwlock);
static struct filter_list filters = {{NULL, NULL}, NULL, NULL, NULL, {0}, {0}};

int getdents64_get_flag(const char *dir)
{
    int flag = 0;
    struct filter_list *pos;
    struct filter_list *temp;

    if (NULL == dir) {
        return flag;
    }

    read_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list)
    {
        if (NULL == pos->dir ||  
            (NULL == pos->add_file && NULL == pos->hide_file)) {
            continue;
        }
        if (0 == strcmp(dir, pos->dir) && NULL != pos->add_file) {
            flag = flag | 1;
            break;
        }
        if (0 == strcmp(dir, pos->dir) && NULL != pos->hide_file) {
            flag = flag | 2;
            break;
        }
    }
    read_unlock(&filter_rwlock);

    return flag;
}

bool is_exist(char *target_file, struct linux_dirent64 *dirent, long value)
{
    struct linux_dirent64 *d = NULL;
    int bpos;

    for (bpos = 0; bpos < value; ) {
        d = (struct linux_dirent64 *)((char *)dirent + bpos);
        if (0 == d->d_reclen) {
            break;
        }
        if (strcmp(d->d_name, target_file) == 0) {
            return true;
        }
        bpos = bpos + d->d_reclen;
    }

    return false;
}

long getdents64_add_file_(struct linux_dirent64 *add_file_dirent, char __user * user_buffer, long value, unsigned int count)
{
    unsigned long status;
    struct linux_dirent64 *dirent = NULL;

    if (NULL == add_file_dirent || add_file_dirent->d_reclen + value > count) {
        return value;
    }

    dirent = (struct linux_dirent64 *)dt_kmalloc(count);
    status = copy_from_user(dirent, user_buffer, value);
    if (0 != status) {
        dt_kfree((void *)dirent);
        return value;
    }
    if (is_exist(add_file_dirent->d_name, dirent, value)) {
        dt_kfree((void *)dirent);
        return value;
    }

    memcpy((char *)dirent + value, add_file_dirent, add_file_dirent->d_reclen);
    value = value + add_file_dirent->d_reclen;

    status = copy_to_user(user_buffer, dirent, value); 
    dt_kfree((void *)dirent);

    return value;
}

long getdents64_hide_file_(char *hide_file, char __user * user_buffer, long value, unsigned int count)
{
    unsigned long status;
    struct linux_dirent64 *dirent = NULL;
    struct linux_dirent64 *d = NULL;
    int bpos;

    dirent = (struct linux_dirent64 *)dt_kmalloc(count);
    status = copy_from_user(dirent, user_buffer, value);
    if (0 != status) {
        dt_kfree((void *)dirent);
        return value;
    }
    if (false == is_exist(hide_file, dirent, value)) {
        dt_kfree((void *)dirent);
        return value;
    }

    for (bpos = 0; bpos < value; ) {
        d = (struct linux_dirent64 *)((char *)dirent + bpos);
        if (0 == d->d_reclen) {
            break;
        }
        if (strcmp(d->d_name, hide_file) == 0) {
            memmove(d, (char *)d + d->d_reclen, value - bpos - d->d_reclen);
            value = value - d->d_reclen;
            break;
        }
        bpos = bpos + d->d_reclen;
    }

    status = copy_to_user(user_buffer, dirent, value);
    dt_kfree((void *)dirent);
    return value;
}

long getdents64_add_file(char *dir, char __user * user_buffer, long value, unsigned int count)
{
    struct filter_list *pos;
    struct filter_list *temp;

    if (NULL == dir) {
        return value;
    }

    read_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list)
    {
        if (NULL == pos->dir || NULL == pos->add_file) {
            continue;
        }
        if (0 == strcmp(dir, pos->dir) && NULL != pos->add_file) {
            value = getdents64_add_file_(&(pos->add_file_dirent), user_buffer, value, count);
        }
    }
    read_unlock(&filter_rwlock);

    return value;
}

long getdents64_hide_file(char *dir, char __user * user_buffer, long value, unsigned int count)
{
    struct filter_list *pos;
    struct filter_list *temp;

    if (NULL == dir) {
        return value;
    }

    read_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list)
    {
        if (NULL == pos->dir || NULL == pos->hide_file) {
            continue;
        }
        if (0 == strcmp(dir, pos->dir) && NULL != pos->hide_file) {
            value = getdents64_hide_file_(pos->hide_file, user_buffer, value, count);
        }
    }
    read_unlock(&filter_rwlock);

    return value;
}

static void safe_free_pos(struct filter_list *pos)
{
    if (NULL == pos) {
        return;
    }
    dt_kfree(pos->dir);
    dt_kfree(pos->add_file);
    dt_kfree(pos->hide_file);
    list_del(&pos->list);
    dt_kfree(pos);
}

void init_getdents64_filter_list()
{
    INIT_LIST_HEAD(&filters.list);
}

void clean_getdents64_filter_list()
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

#define getdents64Insert    (1<<0)
#define getdents64Del       (1<<1)
#define getdents64Clean     (1<<2)
#define getdents64Add       (1<<3)
#define getdents64Hide      (1<<4)

static void insert_add(getdents64_parameters *parameters);
static void del_add(getdents64_parameters *parameters);
static void insert_hide(getdents64_parameters *parameters);
static void del_hide(getdents64_parameters *parameters);
static void clean_filter(getdents64_parameters *parameters);

struct handleS {
    int type;
    void (*handle)(getdents64_parameters *param);
};

static struct handleS handle_cmd[] = {
    {getdents64Insert| getdents64Add,   insert_add},
    {getdents64Del   | getdents64Add,   del_add},
    {getdents64Insert| getdents64Hide,  insert_hide},
    {getdents64Del   | getdents64Hide,  del_hide},
    {getdents64Clean,                   clean_filter},
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

static void insert_add(getdents64_parameters *param)
{
    bool ret = false;
    getdents64_parameters *parameters = (getdents64_parameters *)(param);
    if (NULL == parameters->dir || NULL == parameters->add_file) {
        return;
    }

    struct filter_list *insert_param =
        (struct filter_list *)dt_kmalloc(sizeof(struct filter_list));
    ret = copy2malloc(&insert_param->dir, parameters->dir, parameters->dir_len + 1);
    if (false == ret) {
        return;
    }
    ret = copy2malloc(&insert_param->add_file, parameters->add_file, parameters->add_file_len + 1);
    if (false == ret) {
        return;
    }
    memcpy(&(insert_param->add_file_dirent), &(param->add_file_dirent), param->add_file_dirent.d_reclen);

    add_param(&insert_param->list, &filters.list);
}

static void del_add(getdents64_parameters *param)
{
    struct filter_list *pos;
    struct filter_list *temp;

    getdents64_parameters *parameters = (getdents64_parameters *)(param);
    if (NULL == parameters->dir || NULL == parameters->add_file) {
        return;
    }
    write_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list)
    {
        if (NULL == parameters->dir || NULL == pos->dir
                || NULL == parameters->add_file || pos->add_file) {
            continue;
        }
        if ((0 == strcmp(parameters->dir, pos->dir)) &&
            (0 == strcmp(parameters->add_file, pos->add_file))) {
            safe_free_pos(pos);
        }
    }
    write_unlock(&filter_rwlock);
}

static void insert_hide(getdents64_parameters *param)
{
    bool ret = false;
    getdents64_parameters *parameters = (getdents64_parameters *)(param);
    if (NULL == parameters->dir || NULL == parameters->hide_file) {
        return;
    }

    struct filter_list *insert_param =
        (struct filter_list *)dt_kmalloc(sizeof(struct filter_list));
    ret = copy2malloc(&insert_param->dir, parameters->dir, parameters->dir_len + 1);
    if (false == ret) {
        return;
    }
    ret = copy2malloc(&insert_param->hide_file, parameters->hide_file, parameters->hide_file_len + 1);
    if (false == ret) {
        return;
    }
    add_param(&insert_param->list, &filters.list);
}

static void del_hide(getdents64_parameters *param)
{
    struct filter_list *pos;
    struct filter_list *temp;

    getdents64_parameters *parameters = (getdents64_parameters *)(param);
    if (!parameters->dir || !parameters->hide_file) {
        return;
    }
    write_lock(&filter_rwlock);
    list_for_each_entry_safe(pos, temp, &filters.list, list)
    {
        if (NULL == parameters->dir || NULL == pos->dir
                || NULL == parameters->hide_file || NULL == pos->hide_file) {
            continue;
        }
        if ((0 == strcmp(parameters->dir, pos->dir)) &&
            (0 == strcmp(parameters->hide_file, pos->hide_file))) {
            safe_free_pos(pos);
        }
    }
    write_unlock(&filter_rwlock);
}

static void clean_filter(getdents64_parameters *param)
{
    clean_getdents64_filter_list();
}

static void parser_param(unsigned long arg, getdents64_parameters *parameters)
{
    unsigned long status;

    status = copy_from_user((void *)parameters, (void *)arg,
            sizeof(getdents64_parameters));
    if (0 != status) {
        printk(KERN_ALERT "[%s] copy param error.\n", MODULE_TAG);
        return;
    }
    copy_userchar2kmalloc(&parameters->dir, &parameters->dir_len);
    copy_userchar2kmalloc(&parameters->add_file, &parameters->add_file_len);
    copy_userchar2kmalloc(&parameters->hide_file, &parameters->hide_file_len);
}

static void operate_param_(int type, getdents64_parameters *param)
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

static void operate_param(getdents64_parameters *parameters)
{
    int handle_type = 0;
    if (0 == parameters->common.type) {
        handle_type |= getdents64Insert;
    }
    if (1 == parameters->common.type) {
        handle_type |= getdents64Del;
    }
    if (2 == parameters->common.type) {
        handle_type |= getdents64Clean;
    }

    if (parameters->dir_len && parameters->dir &&
            parameters->add_file_len && parameters->add_file) {
        handle_type |= getdents64Add;
    }
    if (parameters->dir_len && parameters->dir &&
            parameters->hide_file_len && parameters->hide_file) {
        handle_type |= getdents64Hide;
    }

    operate_param_(handle_type, parameters);
}

void operate_getdents64_cmd(unsigned long arg)
{
    getdents64_parameters parameters;

    parser_param(arg, &parameters);
    operate_param(&parameters);

    dt_kfree(parameters.dir);
    dt_kfree(parameters.add_file);
    dt_kfree(parameters.hide_file);
}
