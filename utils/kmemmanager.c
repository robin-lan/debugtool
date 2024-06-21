
#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/vmalloc.h>
#include "./kmemmanager.h"
#include "../exedebugtool/main.h"

#define MODULE_TAG "debugtool:kmemmanager"

enum alloc_type {
    KNONE_TYPE,
    KMALLOC_TYPE,
    VMALLOC_TYPE
};

struct kmem_list{
    struct list_head list;
    void *ptr;
    size_t size;
    int type;
};

static DEFINE_RWLOCK(kmem_rwlock);
static struct kmem_list kmems = {{NULL, NULL}, NULL, 0, KNONE_TYPE};
struct kmem_cache *fast_chache = NULL;

void init_kmemmanger()
{
    INIT_LIST_HEAD(&kmems.list);
    fast_chache = kmem_cache_create("fast_cache", MAX_PATH_LEN, 0, SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);
}

static void safe_free_pos(struct kmem_list *pos)
{
    if (pos && KMALLOC_TYPE == pos->type && NULL != pos->ptr) {
        kfree(pos->ptr);
    }
    if (pos && VMALLOC_TYPE == pos->type && NULL != pos->ptr) {
        vfree(pos->ptr);
    }
    list_del(&pos->list);
    kfree(pos);
}

void release_kmemmanger()
{
    struct kmem_list *pos;
    struct kmem_list *temp;

    write_lock(&kmem_rwlock);
    list_for_each_entry_safe(pos, temp, &kmems.list, list)
    {
        safe_free_pos(pos);
    }
    write_unlock(&kmem_rwlock);
    if (fast_chache) {
        kmem_cache_destroy(fast_chache);
    }
    fast_chache = NULL;
}

void dt_kfree(void *ptr)
{
    if (NULL == ptr) {
        return;
    }
    struct kmem_list *pos;
    struct kmem_list *temp;

    write_lock(&kmem_rwlock);
    list_for_each_entry_safe(pos, temp, &kmems.list, list)
    {
        if (pos->ptr == ptr) {
            safe_free_pos(pos);
        }
    }
    write_unlock(&kmem_rwlock);
}

void read_ptr_mem(void *ptr, struct kmem_list *mem)
{
    struct kmem_list *pos;
    struct kmem_list *temp;

    read_lock(&kmem_rwlock);
    list_for_each_entry_safe(pos, temp, &kmems.list, list)
    {
        if (pos->ptr == ptr) {
            *mem = *pos;
        }
    }
    read_unlock(&kmem_rwlock);
}

struct kmem_list *malloc_kmem_list(void *ptr, size_t size, enum alloc_type type)
{
    struct kmem_list *pkmem = NULL;

    memset(ptr, 0, size);

    pkmem = (struct kmem_list *)kzalloc(sizeof(struct kmem_list), GFP_KERNEL);
    if (NULL == pkmem) {
        printk(KERN_ALERT "[%s] kernel alloc error.\n", MODULE_TAG);
        return NULL;
    }
    pkmem->ptr = ptr;
    pkmem->size = size;
    pkmem->type = type;

    return pkmem;
}

void *dt_kmalloc_fast_path()
{
    if (NULL == fast_chache) {
        return NULL;
    }
    void *ret = kmem_cache_alloc(fast_chache, GFP_KERNEL);
    if (NULL != ret) {
        memset(ret, 0, dt_get_kmalloc_fast_size());
    }

    return ret;
}

int dt_get_kmalloc_fast_size()
{
    return MAX_PATH_LEN;
}


void dt_kfree_fast_path(void *ptr)
{
    if (NULL == fast_chache || NULL == ptr) {
        return;
    }
    kmem_cache_free(fast_chache, ptr);
}

void *dt_kmalloc(size_t size)
{
    void *ptr = NULL;
    struct kmem_list *pkmem = NULL;

    if (size <= 0) {
        return NULL;
    }

    if (size < 14000) {
        ptr= kmalloc(size, GFP_KERNEL);   
        if (NULL == ptr) {
            printk(KERN_ALERT "[%s] kmalloc size:%ld error.\n", MODULE_TAG, size);
            return NULL;
        }
        pkmem = malloc_kmem_list(ptr, size, KMALLOC_TYPE);
    } 
    if (size >= 14000) {
        ptr= vmalloc(size);
        if (NULL == ptr) {
            printk(KERN_ALERT "[%s] vmalloc size:%ld error.\n", MODULE_TAG, size);
            return NULL;
        }
        pkmem = malloc_kmem_list(ptr, size, VMALLOC_TYPE);
    }
    write_lock(&kmem_rwlock);
    list_add_tail(&pkmem->list, &kmems.list);
    write_unlock(&kmem_rwlock);

    memset(ptr, 0, size);
    return ptr;
}

void *dt_kcalloc(size_t nmemb, size_t size)
{
    size_t len = nmemb * size;
    if (len <= 0) {
        return NULL;
    }
    return dt_kmalloc(len);
}

void *dt_krealloc(void *ptr, size_t size)
{
    struct kmem_list old;
    if (NULL == ptr) {
        return NULL;
    }
    read_ptr_mem(ptr, &old);
    if (ptr != old.ptr) {
        return NULL;
    }
    void *new_ptr = dt_kmalloc(size);
    if (NULL == new_ptr) {
        return NULL;
    }
    memcpy(new_ptr, ptr, old.size < size ? old.size : size);

    dt_kfree(ptr);

    return new_ptr;
}
