
#include <linux/printk.h>
#include <stddef.h>
#include "./handle.h"

#include "./utils/util.h"
#include "./device_handle/openat/openat.h"
#include "./device_handle/kprint/kprint.h"
#include "./device_handle/stat/newfstatat/newfstatat.h"
#include "./device_handle/stat/fstat/fstat.h"
#include "./device_handle/getdents64/getdents64.h"
#include "./device_handle/statfs/statfs.h"
#include "./device_handle/dump_loger/dump_loger.h"
#include "./device_handle/echo_process/echo_process.h"
#include "./device_handle/read/read.h"
#include "./device_handle/dump_memory/dump_memory.h"
#include "./device_handle/mmap/mmap.h"
#include "./device_handle/hooksyscallroot/hooksyscallroot.h"
#include "./device_handle/uname/uname.h"
#include "./device_handle/ptrace/ptrace.h"
#include "./device_handle/faccessat/faccessat.h"

#define MODULE_TAG "debugtool:handle"

#define GENERIC_TOOL(tag, name)                     \
{                                                   \
    #tag, init_##name, release_##name,              \
    open_##name, close_##name, &controls_##name      \
}

//    GENERIC_TOOL(tag_read, read),
//    GENERIC_TOOL(tag_mmap, mmap),
//    GENERIC_TOOL(tag_fstat, fstat),
//    GENERIC_TOOL(tag_statfs, statfs),

struct base_tool g_tools[] = {
    GENERIC_TOOL(tag_util, util),
    GENERIC_TOOL(tag_kprint, kprint),
    GENERIC_TOOL(tag_dump_memory, dump_memory),
    GENERIC_TOOL(tag_dump_loger, dump_loger),
    GENERIC_TOOL(tag_echo_process, echo_process),
    GENERIC_TOOL(tag_hooksyscallroot, hooksyscallroot),
    GENERIC_TOOL(tag_openat, openat),
    GENERIC_TOOL(tag_getdents64, getdents64),
    GENERIC_TOOL(tag_uname, uname),
    GENERIC_TOOL(tag_faccessat, faccessat),
    GENERIC_TOOL(tag_newfstatat, newfstatat),
    GENERIC_TOOL(tag_ptrace, ptrace),
    {NULL, NULL, NULL, NULL, NULL, NULL}
};

bool do_init()
{
    bool ret = true;
    for (int i = 0; -1 != i; i++) {
        if (NULL == g_tools[i].tag) {
            break;
        }
        if (NULL != g_tools[i].init) {
            ret = g_tools[i].init();
        }
        if (true != ret) {
            printk(KERN_ALERT "[%s] Call init %s error.\n", MODULE_TAG, g_tools[i].tag);
            break;
        }
    }

    return ret;
}

bool do_release()
{
    bool ret = true;
    int i = 0; 

    for (i = 0; -1 != i; i++) {
        if (NULL == g_tools[i].tag) {
            break;
        }
    }
    for (i = i - 1; i >= 0; i--) {
        if (NULL != g_tools[i].release) {
            ret = g_tools[i].release();
        }
        if (true != ret) {
            printk(KERN_ALERT "[%s] Call release %s error.\n", MODULE_TAG, g_tools[i].tag);
            break;
        }
    }

    return ret;
}
