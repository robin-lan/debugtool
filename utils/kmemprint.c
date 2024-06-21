
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include "./kernel_symbol.h"
#include "./kmem.h"
#include "./kmemmanager.h"
#include "./../exedebugtool/main.h"

#define MODULE_TAG "debugtool:kmemprint"

extern struct util_kernel_symbol kernel_sym;

char *smemcopy(char *output, int max_size, const char *src, int size, int *less_size)
{
    if (NULL == output) {
        return NULL;
    }

    if (size >= max_size) {
        return NULL;
    }

    memcpy(output, src, size);
    *less_size = max_size - size;
    return output + size;
}

char *sstrcopy(char *output, int max_size, const char *src, int *less_size)
{
    int len;
    
    if (NULL == output) {
        return NULL;
    }

    len = strlen(src);
    if (len >= max_size) {
        return NULL;
    }
    strcpy(output, src);
    *less_size = max_size - len;
    return output + len;
}

char *mem_print_addr(char *output, int max_size, const char *addr, int *less_size)
{
    char tmp[0x20 + KSYM_NAME_LEN];
    char *ret = NULL;
    char symname[KSYM_NAME_LEN];

    if (NULL == output) {
        return NULL;
    }
    memset(symname, 0, sizeof(symname));
    kernel_sym.info_util.lookup_symbol_name((unsigned long)addr, symname);
    sprintf(tmp, "0x%016lx: %s\t", (unsigned long)addr, strlen(symname) > 0 ? symname : "");
    ret = sstrcopy(output, max_size, tmp, less_size);

    return ret;
}

void mem_print_c(char *output, int max_size, const char *addr, int size)
{
    char tmp[0x20];
    char *next = NULL;
    int less_size = max_size;

    next = mem_print_addr(output, less_size, addr, &less_size);
    for (int i = 0; i < size; i++) {
        memset(tmp, 0, sizeof(tmp));
        sprintf(tmp, "%c ", *(addr + i));
        next = sstrcopy(next, less_size, tmp, &less_size);
        if (i + 1 >= size) {
            break;
        }
        if ((0 == (i + 1) % 16) && (0 != i)) {
            next = sstrcopy(next, less_size, "\n", &less_size);
            next = mem_print_addr(next, less_size, addr + (i + 1) * 1, &less_size);
        }
    }

    next = sstrcopy(next, less_size, "\n", &less_size);
}

void mem_print_x_1(char *output, int max_size, const char *addr, int size)
{
    char tmp[0x20];
    char *next = NULL;
    int less_size = max_size;

    next = mem_print_addr(output, less_size, addr, &less_size);
    for (int i = 0; i < size; i++) {
        memset(tmp, 0, sizeof(tmp));
        sprintf(tmp, "0x%02x ", *(addr + i));
        next = sstrcopy(next, less_size, tmp, &less_size);
        if (i + 1 >= size) {
            break;
        }
        if ((0 == (i + 1) % 16) && (0 != i)) {
            next = sstrcopy(next, less_size, "\n", &less_size);
            next = mem_print_addr(next, less_size, addr + (i + 1) * 1, &less_size);
        }
    }
    next = sstrcopy(next, less_size, "\n", &less_size);
}

void mem_print_x_2(char *output, int max_size, const char *addr, int size)
{
    char tmp[0x20];
    char *next = NULL;
    int less_size = max_size;

    next = mem_print_addr(output, less_size, addr, &less_size);
    for (int i = 0; i < size; i++) {
        memset(tmp, 0, sizeof(tmp));
        sprintf(tmp, "0x%04x ", *(unsigned short *)(addr + i * 2));
        next = sstrcopy(next, less_size, tmp, &less_size);
        if (i + 1 >= size) {
            break;
        }
        if ((0 == (i + 1) % 8) && (0 != i)) {
            next = sstrcopy(next, less_size, "\n", &less_size);
            next = mem_print_addr(next, less_size, addr + (i + 1) * 2, &less_size);
        }
    }

    next = sstrcopy(next, less_size, "\n", &less_size);
}

void mem_print_x_4(char *output, int max_size, const char *addr, int size)
{
    char tmp[0x20];
    char *next = NULL;
    int less_size = max_size;

    next = mem_print_addr(output, less_size, addr, &less_size);
    for (int i = 0; i < size; i++) {
        memset(tmp, 0, sizeof(tmp));
        sprintf(tmp, "0x%08x ", *(unsigned int*)(addr + i * 4));
        next = sstrcopy(next, less_size, tmp, &less_size);
        if (i + 1 >= size) {
            break;
        }
        if ((0 == (i + 1) % 4) && (0 != i)) {
            next = sstrcopy(next, less_size, "\n", &less_size);
            next = mem_print_addr(next, less_size, addr + (i + 1) * 4, &less_size);
        }
    }

    next = sstrcopy(next, less_size, "\n", &less_size);
}

void mem_print_x_8(char *output, int max_size, const char *addr, int size)
{
    char tmp[0x20];
    char *next = NULL;
    int less_size = max_size;

    next = mem_print_addr(output, less_size, addr, &less_size);
    for (int i = 0; i < size; i++) {
        memset(tmp, 0, sizeof(tmp));
        sprintf(tmp, "0x%016lx ", *(unsigned long *)(addr + i * 8));
        next = sstrcopy(next, less_size, tmp, &less_size);
        if (i + 1 >= size) {
            break;
        }

        if ((0 == (i + 1) % 2) && (0 != i)) {
            next = sstrcopy(next, less_size, "\n", &less_size);
            next = mem_print_addr(next, less_size, addr + (i + 1) * 8, &less_size);
        }
    }

    next = sstrcopy(next, less_size, "\n", &less_size);
}

void mem_print_x(char *output, int max_size, const char *addr, int size, int content_len)
{
    switch (content_len) {
        case 1:
            mem_print_x_1(output, max_size, addr, size / content_len);
            break;
        case 2:
            mem_print_x_2(output, max_size, addr, size / content_len);
            break;
        case 4:
            mem_print_x_4(output, max_size, addr, size / content_len);
            break;
        case 8:
            mem_print_x_8(output, max_size, addr, size / content_len);
            break;
        default:
            break;
    }
}

void mem_print_d(char *output, int max_size, const char *addr, int size, int content_len)
{
    char *next = output;
    int less_size = max_size;
    int copy_content_len;
    kprint_dis_hex dis_hex;
    init_kprint_dis_hex(dis_hex);

    copy_content_len = (max_size - sizeof(kprint_dis_hex)) / content_len;
    copy_content_len = copy_content_len < (size / content_len) ? copy_content_len : (size / content_len);

    dis_hex.size = copy_content_len * content_len;
    dis_hex.addr = (unsigned long)addr;

    next = smemcopy(next, less_size, (const char *)&dis_hex, sizeof(dis_hex), &less_size);
    next = smemcopy(next, less_size, addr, dis_hex.size, &less_size);
}

void mem_print(char *output, int max_size, const char *addr, int size, int type, int content_len)
{
    bool ret = addr_valid((unsigned long)addr, size);
    if (false == ret) {
        printk(KERN_ALERT "[%s] addr_valid %016lx is invalid.\n", MODULE_TAG, (unsigned long)addr);
        return;
    }

    switch (type) {
        case 'c':
            mem_print_c(output, max_size, addr, size);
            break;
        case 'x':
            mem_print_x(output, max_size, addr, size, content_len);
            break;
        case 'd':
            mem_print_d(output, max_size, addr, size, content_len);
            break;
        default:
            break;
    }
}
