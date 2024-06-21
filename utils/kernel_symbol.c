
#include <linux/kprobes.h>
#include "./kernel_symbol.h"

#define MODULE_TAG "debugtool:kernel_symbol"

struct util_kernel_symbol kernel_sym;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t pkallsyms_lookup_name = NULL;

void init_syms_look_up()
{
    static struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};

    int status = register_kprobe(&kp);
    if (status < 0) {
        printk(KERN_ALERT "[%s] kprobe kallsyms_lookup_name_ error.\n", MODULE_TAG);
        return;
    }
    pkallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    if (NULL == pkallsyms_lookup_name) {
        printk(KERN_ALERT "[%s] kprobe kallsyms_lookup_name_ error.\n", MODULE_TAG);
    }
}

unsigned long kallsyms_lookup_name_(const char *name)
{
    if (!pkallsyms_lookup_name) {
        printk(KERN_ALERT "[%s] kallsyms_lookup_name is NULL.\n", MODULE_TAG);
        return 0;
    }
    return pkallsyms_lookup_name(name);
}

bool get_sym(ptr_t *fn, const char *fn_name)
{
    if (NULL == fn_name || NULL == fn) {
        return false;
    }

    *fn = (ptr_t)kallsyms_lookup_name_(fn_name);
    if (NULL == *fn) {
        printk(KERN_ALERT "[%s] lookup %s sym error.\n", MODULE_TAG, fn_name);
        return false;
    }

    return true;
}

unsigned long get_adrl(char *fn, int off)
{
    ptr_t *fn_addr;
    bool ret = get_sym((ptr_t *)&fn_addr, fn);
    if (false == ret) {
        return ret;
    }

    uint32_t msb     = 8u;
    uint32_t lsb     = 5u;

    unsigned long ld_addr = (unsigned long)((char *)fn_addr+ off);
    unsigned int ins = *(unsigned int *)ld_addr;
    unsigned int lsb_bytes     = (unsigned int)(ins << 1u) >> 30u;
    unsigned long absolute_addr = (ld_addr & ~0xfffll) + (((((unsigned int)(ins << msb) >> (msb + lsb - 2u)) & ~3u) | lsb_bytes) << 12);

    ins = *(unsigned int *)(ld_addr + 4);
    int flag = ins & 0x400000;
    int imm12 = ins & 0x3FFC00;
    if (flag == 0x000000) {
        imm12 = imm12 >> 10;
    } else {
        imm12 = imm12 >> 10;
        imm12 = imm12 << 12;
    }
    absolute_addr = absolute_addr + imm12;

    return absolute_addr;
}

bool init_hook_kernel_syms()
{
    bool ret = true;

//    kernel_sym.hook_util.sys_call_table = (ptr_t)get_adrl("do_el0_svc", 0x60);
//    kernel_sym.hook_util.init_mm = (ptr_t)get_adrl("copy_init_mm", 0x08);

    ret = get_sym((ptr_t *)&kernel_sym.hook_util.sys_call_table, "sys_call_table");
    if (false == ret) {
        return ret;
    }
    ret = get_sym((ptr_t *)&kernel_sym.hook_util.init_mm, "init_mm");
    if (false == ret) {
        return ret;
    }
    ret = get_sym((ptr_t *)&kernel_sym.hook_util.__sync_icache_dcache, "__sync_icache_dcache");
    if (false == ret) {
        return ret;
    }
    
    return ret;
}

bool init_kernel_mem_sym()
{
    bool ret = true;

    ret = get_sym((ptr_t *)&kernel_sym.mem_util.do_munmap, "do_munmap");
    if (false == ret) {
        return ret;
    }

    ret = get_sym((ptr_t *)&kernel_sym.mem_util.do_mmap, "do_mmap");
    if (false == ret) {
        return ret;
    }

    return ret;
}

bool init_kernel_info_sym()
{
    bool ret = true;
    ret = get_sym((ptr_t *)&kernel_sym.info_util.lookup_symbol_name, "lookup_symbol_name");
    if (false == ret) {
        return ret;
    }

    return ret;
}

bool init_kernel_file_sym()
{
    bool ret = true;
    ret = get_sym((ptr_t *)&kernel_sym.file_util.getname, "getname");
    if (false == ret) {
        return ret;
    }
    ret = get_sym((ptr_t *)&kernel_sym.file_util.putname, "putname");
    if (false == ret) {
        return ret;
    }

    ret = get_sym((ptr_t *)&kernel_sym.file_util.pick_file, "pick_file");
    if (false == ret) {
        return ret;
    }

    return ret;
}

bool init_kernel_symbol()
{
    bool ret = true;

    init_syms_look_up();

    ret = init_hook_kernel_syms();
    if (false == ret) {
        return ret;
    }

    ret = init_kernel_mem_sym();
    if (false == ret) {
        return ret;
    }

    ret = init_kernel_info_sym();
    if (false == ret) {
        return ret;
    }

    ret = init_kernel_file_sym();
    if (false == ret) {
        return ret;
    }

    return ret;
}
