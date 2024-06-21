

#include <linux/kernel.h>
#include <linux/mman.h>
#include "./userfile.h"
#include "./kmemmanager.h"
#include "../exedebugtool/main.h"

#define MODULE_TAG "loger"


#define LOG_CACHE 0x8000

struct log_list{
    struct list_head list;
    char *log;
    char *logpos;
    char *logend;
};

static char *log_file = NULL;
static DEFINE_RWLOCK(loger_rwlock);
static struct log_list logs = {{NULL, NULL}, NULL, NULL, NULL};

void init_loger()
{
    INIT_LIST_HEAD(&logs.list);
}

static void safe_free_pos(struct log_list *pos)
{
    if (!pos) {
        return;
    }

    if (NULL != pos->log) {
        dt_kfree(pos->log);
    }

    list_del(&pos->list);
    dt_kfree(pos);
}

void release_loger()
{
    struct log_list *pos, *temp;

    write_lock(&loger_rwlock);
    list_for_each_entry_safe(pos, temp, &logs.list, list)
    {
        safe_free_pos(pos);
    }

    dt_kfree(log_file);
    log_file = NULL;
    write_unlock(&loger_rwlock);
}

int log_func(const char *fmt, va_list args)
{
    bool added = false;
    struct log_list *pos, *temp;
    struct log_list *plog = NULL;
    char *textbuff = dt_kmalloc_fast_path();
    char *text = textbuff;

    if(NULL == textbuff) {
        return 0;
    }

    size_t text_len = vscnprintf(text, dt_get_kmalloc_fast_size() - 1, fmt, args);
    if (0 == text_len) {
        dt_kfree_fast_path(textbuff);
        return 0;
    }

    text_len = strlen(textbuff);

    if(!write_trylock(&loger_rwlock)) {
        dt_kfree_fast_path(textbuff);
        return 0;
    }
    list_for_each_entry_safe(pos, temp, &logs.list, list)
    {
        if (pos && pos->log
                && (pos->logpos + text_len + 2) < pos->logend) {
            strcpy(pos->logpos, textbuff);
            pos->logpos = pos->logpos + text_len;
            added = true;
            break;
        }
    }
    if (false == added) {
        plog = (struct log_list *)dt_kmalloc(sizeof(struct log_list));
        if (NULL == plog) {
            write_unlock(&loger_rwlock);
            dt_kfree_fast_path(textbuff);
            return 0;
        }

        plog->log = (char *)dt_kmalloc(LOG_CACHE);
        if (NULL == plog->log) {
            write_unlock(&loger_rwlock);
            dt_kfree(plog);
            dt_kfree_fast_path(textbuff);
            return 0;
        }
        memset(plog->log, 0, LOG_CACHE);
        plog->logpos = plog->log;
        plog->logend = plog->log + LOG_CACHE;

        strcpy(plog->logpos, textbuff);
        plog->logpos = plog->logpos + text_len;

        list_add_tail(&plog->list, &logs.list);
    }
    write_unlock(&loger_rwlock);
    dt_kfree_fast_path(textbuff);
    return text_len;
}

int loger(const char *fmt, ...)
{
    va_list args;
    int r;

    va_start(args, fmt);
    r = log_func(fmt, args);
    va_end(args);

    return r;
}

void write_log_file(const char *file)
{
    int len = 0;
    struct log_list *pos, *temp;

    if (NULL == file) {
        printk(KERN_ALERT "[%s] log file is null.\n", MODULE_TAG);
        return;
    }

    len = strlen(file);

    write_lock(&loger_rwlock);
    if (log_file) {
        dt_kfree(log_file);
        log_file = NULL;
    }
    log_file = dt_kmalloc(len + 0x10);
    if (NULL == log_file) {
        printk(KERN_ALERT "[%s] log file dt_kmalloc error.\n", MODULE_TAG);
        return;
    }
    strcpy(log_file, file);
    write_unlock(&loger_rwlock);

    read_lock(&loger_rwlock);
    list_for_each_entry_safe(pos, temp, &logs.list, list)
    {
        if (NULL == pos || NULL == pos->log) {
            continue;
        }
        printk(KERN_ALERT "[%s] write_file %p.\n", MODULE_TAG, pos);
        write_file(log_file, pos->log, pos->logpos - pos->log, O_CREAT|O_RDWR|O_APPEND, 0644);
    }
    read_unlock(&loger_rwlock);

    release_loger();
}
