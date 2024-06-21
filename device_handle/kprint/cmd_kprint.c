
#include <linux/slab.h>
#include <linux/mman.h>
#include "../../utils/kmem.h"
#include "../../utils/kernel_symbol.h"
#include "../../utils/kmemprint.h"
#include "../../utils/kmemmanager.h"
#include "../../exedebugtool/main.h"

#define MODULE_TAG "debugtool:cmd_kprint"

struct handleS {
    int type;
    void (*handle)(kprint_parameters *param);
};

int get_unit_size(int unit)
{
    switch (unit) {
        case 'c':
            return 1;
        case 's':
            return 2;
        case 'd':
            return 4;
        case 'g':
            return 8;
        default:
            return 0;
    }
    return 0;
}

void print_sym_hex(kprint_parameters *param)
{
    bool ret = false;
    ptr_t sym_addr = NULL;
    char *buffer, *next;
    int less_size = 0;

    int content_len = get_unit_size(param->unit);

    ret = get_sym(&sym_addr, param->sym);
    if (false == ret) {
        return;
    }

    less_size = param->common.outbuff_size - 1;
    buffer = (char *)dt_kmalloc(param->common.outbuff_size);
    if (NULL == buffer) {
        printk(KERN_ALERT "[%s] dt_kmalloc error.\n", MODULE_TAG);
        return;
    }
    next = buffer;

    next = mem_print_addr(next, less_size, sym_addr, &less_size);
    next = sstrcopy(next, less_size, param->sym, &less_size);
    next = sstrcopy(next, less_size, "\n", &less_size);
    mem_print(next, less_size, sym_addr, param->count * content_len, 'x', content_len);

    ret = copy_to_user(param->common.outbuff, buffer, strlen(buffer));
    if (0 != ret) {
        printk(KERN_ALERT "[%s] copy sym to user error.\n", MODULE_TAG);
    }
    dt_kfree(buffer);
}

void print_addr_hex(kprint_parameters *param)
{
    bool ret = false;
    ptr_t sym_addr = NULL;
    char *buffer, *next;
    int less_size = 0;

    int content_len = get_unit_size(param->unit);
    sym_addr = (void *)param->addr;

    less_size = param->common.outbuff_size - 1;
    buffer = dt_kmalloc(param->common.outbuff_size);
    if (NULL == buffer) {
        printk(KERN_ALERT "[%s] dt_kmalloc error.\n", MODULE_TAG);
        return;
    }
    next = buffer;

    next = mem_print_addr(next, less_size, sym_addr, &less_size);
    next = sstrcopy(next, less_size, "\n", &less_size);
    mem_print(next, less_size, sym_addr, param->count * content_len, 'x', content_len);

    ret = copy_to_user(param->common.outbuff, buffer, strlen(buffer));
    if (0 != ret) {
        printk(KERN_ALERT "[%s] copy sym to user error.\n", MODULE_TAG);
    }
    dt_kfree(buffer);
}

void print_sym_dis(kprint_parameters *param)
{
    kprint_dis_hex dis_hex;
    bool ret = false;
    ptr_t sym_addr = NULL;
    char *buffer, *next;
    int less_size = 0;
    int total_size = 0;

    int content_len = get_unit_size(param->unit);
    ret = get_sym(&sym_addr, param->sym);
    if (false == ret) {
        return;
    }

    less_size = param->common.outbuff_size - 1;
    buffer = dt_kmalloc(param->common.outbuff_size);
    if (NULL == buffer) {
        printk(KERN_ALERT "[%s] dt_kmalloc error.\n", MODULE_TAG);
        return;
    }
    next = buffer;

    next = mem_print_addr(next, less_size, sym_addr, &less_size);
    next = sstrcopy(next, less_size, param->sym, &less_size);
    next = sstrcopy(next, less_size, "\n", &less_size);

    mem_print(next, less_size, sym_addr, param->count * content_len, 'd', content_len);
    next = strstr(buffer, DIS_HEX_MAGIK);
    if (NULL == next) {
        dt_kfree(buffer);
        printk(KERN_ALERT "[%s] can not find DIS_HEX_MAGIK error.\n", MODULE_TAG);
        return;
    }
    memcpy(&dis_hex, next, sizeof(dis_hex));
    total_size = next - buffer + sizeof(dis_hex) + dis_hex.size;

    ret = copy_to_user(param->common.outbuff, buffer, total_size);
    if (0 != ret) {
        printk(KERN_ALERT "[%s] copy sym to user error.\n", MODULE_TAG);
    }
    dt_kfree(buffer);
}

void print_addr_dis(kprint_parameters *param)
{
    kprint_dis_hex dis_hex;
    bool ret = false;
    ptr_t sym_addr = NULL;
    char *buffer, *next;
    int less_size = 0;
    int total_size = 0;

    int content_len = get_unit_size(param->unit);
    sym_addr = (void *)param->addr;

    less_size = param->common.outbuff_size - 1;
    buffer = dt_kmalloc(param->common.outbuff_size);
    if (NULL == buffer) {
        printk(KERN_ALERT "[%s] dt_kmalloc error.\n", MODULE_TAG);
        return;
    }
    next = buffer;

    next = mem_print_addr(next, less_size, sym_addr, &less_size);
    next = sstrcopy(next, less_size, "\n", &less_size);

    mem_print(next, less_size, sym_addr, param->count * content_len, 'd', content_len);
    next = strstr(buffer, DIS_HEX_MAGIK);
    if (NULL == next) {
        dt_kfree(buffer);
        printk(KERN_ALERT "[%s] can not find DIS_HEX_MAGIK error.\n", MODULE_TAG);
        return;
    }
    memcpy(&dis_hex, next, sizeof(dis_hex));
    total_size = next - buffer + sizeof(dis_hex) + dis_hex.size;

    ret = copy_to_user(param->common.outbuff, buffer, total_size);
    if (0 != ret) {
        printk(KERN_ALERT "[%s] copy sym to user error.\n", MODULE_TAG);
    }
    dt_kfree(buffer);
}


#define kprintSym       (1<<0)
#define kprintAddr      (1<<1)
#define kprintHex       (1<<2)
#define kprintDis       (1<<3)

static struct handleS handle_cmd[] = {
    {kprintSym  | kprintHex,    print_sym_hex},
    {kprintSym  | kprintDis,    print_sym_dis},
    {kprintAddr | kprintHex,    print_addr_hex},
    {kprintAddr | kprintDis,    print_addr_dis},
    {0,   NULL},
};

static void parser_param(unsigned long arg, kprint_parameters *parameters)
{
    unsigned long status;

    status = copy_from_user((void *)parameters, (void *)arg,
            sizeof(kprint_parameters));
    if (0 != status) {
        printk(KERN_ALERT "[%s] copy param error.\n", MODULE_TAG);
        return;
    }
    copy_userchar2kmalloc(&parameters->sym, &parameters->sym_len);
}

static void operate_param_(int type, kprint_parameters *param)
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

static void operate_param(kprint_parameters *parameters)
{
    int handle_type = 0;

    if (parameters->common.outbuff_size <= 0x10) {
        printk(KERN_ALERT "[%s] outbuff_siz must larger than 0x10.\n", MODULE_TAG);
        return;
    }

    if (parameters->sym_len && parameters->sym) {
        handle_type |= kprintSym;
    }
    if (0 != parameters->addr) {
        handle_type |= kprintAddr;
    }
    if ('x' == parameters->type && parameters->unit && parameters->count) {
        handle_type |= kprintHex;
    }
    if ('d' == parameters->type && parameters->count) {
        handle_type |= kprintDis;
        parameters->unit = 'd';
    }
    operate_param_(handle_type, parameters);
}

void operate_kprint_cmd(unsigned long arg)
{
    kprint_parameters parameters;

    parser_param(arg, &parameters);
    operate_param(&parameters);

    dt_kfree(parameters.sym);
}
