
#ifndef DEBUG_TOOL_KMEM_H
#define DEBUG_TOOL_KMEM_H

#include <linux/types.h>
#include <stdbool.h>

char __user * kmalloc_user_memory(unsigned long size);

bool kfree_user_memory(void __user *buf, size_t size);

void copy_userchar2kmalloc(char **str, int *len);

long write_ro_memory(void *addr, void *source, int size);

bool addr_valid(unsigned long addr, size_t size);

#endif
