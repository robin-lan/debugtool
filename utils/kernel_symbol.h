
#ifndef DEBUG_TOOL_KERNEL_SYM_H
#define DEBUG_TOOL_KERNEL_SYM_H

#include <linux/mm.h>

typedef void *ptr_t;

struct hook_kernel {
    ptr_t *sys_call_table;
    struct mm_struct *init_mm;
    void (*__sync_icache_dcache)(pte_t pte);
};

struct kernel_mem {
    int (*do_munmap)(struct mm_struct *mm, unsigned long start, size_t len, struct list_head *uf);
    unsigned long(* do_mmap)(struct file *file, unsigned long addr, unsigned long len,
            unsigned long prot, unsigned long flags, unsigned long pgoff, unsigned long *populate, struct list_head *uf);
};

struct kernel_file {
    struct filename *(* getname)(const char __user * filename);
    void (* putname)(struct filename *name);
    struct file *(* pick_file)(struct files_struct *files, unsigned fd);
};

struct kernel_info {
    int (*lookup_symbol_name)(unsigned long addr, char *symname);
};

struct util_kernel_symbol {
    struct hook_kernel hook_util;
    struct kernel_mem mem_util;
    struct kernel_info info_util;
    struct kernel_file file_util;
};

bool init_kernel_symbol();

bool get_sym(ptr_t *fn, const char *fn_name);

#endif
