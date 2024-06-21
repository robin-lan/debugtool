
#ifndef DEBUG_TOOL_DEVICE_HANDLERS_H
#define DEBUG_TOOL_DEVICE_HANDLERS_H

#include <linux/fs.h>
#include <linux/ioctl.h>

int device_open(struct inode *inode, struct file *file);
int device_close(struct inode *inode, struct file *file);
long device_ioctl(struct file *f, unsigned int cmd, unsigned long arg);

#endif
