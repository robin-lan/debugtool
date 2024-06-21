#include <linux/printk.h>
#include "device_handler.h"
#include "./handle.h"

#define MODULE_TAG "debugtool:device_handler"

extern struct base_tool g_tools[];

int device_open(struct inode *inode, struct file *file)
{
    long status = 0;
    for (int i = 0; i != -1; i++) {
        if (NULL == g_tools[i].tag) {
            break;
        }
        if (NULL != g_tools[i].open) {
            status = g_tools[i].open();
        }
        if (0 != status) {
            printk(KERN_ALERT "[%s] Call open %s error.\n", MODULE_TAG, g_tools[i].tag);
            break;
        }
    }
    return status;
}

int device_close(struct inode *inode, struct file *file)
{
    long status = 0;
    for (int i = 0; i != -1; i++) {
        if (NULL == g_tools[i].tag) {
            break;
        }
        if (NULL != g_tools[i].close) {
            status = g_tools[i].close();
        }
        if (0 != status) {
            printk(KERN_ALERT "[%s] Call close %s error.\n", MODULE_TAG, g_tools[i].tag);
            break;
        }
    }
    return status;
}

long device_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    long status = 0;

    for (int i = 0; i != -1; i++) {
        if (NULL == g_tools[i].tag) {
            break;
        }
        if (NULL == g_tools[i].control
          || cmd != g_tools[i].control->type) {
            continue;
        }
        printk(KERN_INFO "[%s] Call ioctl %s type:%d.\n", MODULE_TAG, g_tools[i].tag, g_tools[i].control->type);
        status = g_tools[i].control->handle(arg);
        if (0 != status) {
            printk(KERN_ALERT "[%s] Call ioctl %s error.\n", MODULE_TAG, g_tools[i].tag);
            break;
        }
    }

    return status;
}
