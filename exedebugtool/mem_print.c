

#include <string.h>
#include "./capstone/capstone.h"
#define MODULE_TAG "debugtool:memprint"


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
    char tmp[0x30];
    char *ret = NULL;

    if (NULL == output) {
        return NULL;
    }
    sprintf(tmp, "0x%016lx:\t", (unsigned long)addr);
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
    csh handle;
    int j = 0;
    int count = 0;
    cs_insn *insn;
    cs_opt_mem opt_mem;

    char tmp[0x200];
    unsigned long virt_addr = *(unsigned long *)((unsigned long *)output);
    char *next = output;
    int less_size = max_size;

    opt_mem.malloc = malloc;
    opt_mem.calloc = calloc;
    opt_mem.realloc = realloc;
    opt_mem.free = free;
    opt_mem.vsnprintf = vsnprintf;

    cs_option(handle, CS_OPT_MEM, (size_t)&opt_mem);

    cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle);
    if (err) {
        printf("Failed on cs_open() with error returned: %u\n", err);
        return;
    }

    count = cs_disasm(handle, addr, size, virt_addr, 0, &insn);
    if (0 == count) {
        cs_close(&handle);
        printf("ERROR: Failed to disasm given code!\n");
        return;
    }

    for (j = 0; j < count; j++) {
        memset(tmp, 0, sizeof(tmp));
        sprintf(tmp, "0x%llx:\t %02x %02x %02x %02x\t%s\t%s\n",
                insn[j].address,
                *(unsigned char *)((char *)addr + 4 * j + 0),
                *(unsigned char *)((char *)addr + 4 * j + 1),
                *(unsigned char *)((char *)addr + 4 * j + 2),
                *(unsigned char *)((char *)addr + 4 * j + 3),
                insn[j].mnemonic, insn[j].op_str);
        next = sstrcopy(next, less_size, tmp, &less_size);
    }

    cs_free(insn, count);
    cs_close(&handle);
}

void mem_print(char *output, int max_size, const char *addr, int size, int type, int content_len)
{
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
