
#ifndef DEBUG_TOOL_KMEMMANAGER_H
#define DEBUG_TOOL_KMEMMANAGER_H

#include <linux/types.h>
#include <stdbool.h>

void init_kmemmanger();
void release_kmemmanger();

void *dt_kmalloc_fast_path();
int dt_get_kmalloc_fast_size();
void dt_kfree_fast_path(void *ptr);
void *dt_kmalloc(size_t size);
void *dt_kcalloc(size_t nmemb, size_t size);
void *dt_krealloc(void *ptr, size_t size);
void dt_kfree(void *ptr);

#endif
