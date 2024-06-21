#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/module.h>
#include <linux/version.h>

#include "./device_handler.h"
#include "./handle.h"

#define MODULE_TAG "debugtool:main"

#define MAYJOR_NUMBER 510
#define DEVICE_NAME "debugtools"


MODULE_LICENSE("GPL");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Robin");

struct file_operations fops = {
    .unlocked_ioctl = device_ioctl,
    .open = device_open,
    .release = device_close,
};

dev_t g_first_device;
struct cdev g_cdev;
struct class *g_cl;

static int driver_initialization(void)
{
    int ret_val;
    g_first_device = MKDEV(MAYJOR_NUMBER, 0);
    ret_val = register_chrdev_region(g_first_device, 1, DEVICE_NAME);
    if (0 > ret_val) {
        printk(KERN_ALERT "[%s] Device Registration failed.\n", MODULE_TAG);
        return -1;
    }
    if ((g_cl = class_create(THIS_MODULE, "chardev")) == NULL) {
        printk(KERN_ALERT "[%s] Class creation failed.\n", MODULE_TAG);
        goto failed_cla_create;
    }

    if (device_create(g_cl, NULL, g_first_device, NULL, DEVICE_NAME) == NULL) {
        printk(KERN_ALERT "[%s] Device creation failed.\n", MODULE_TAG);
        goto failed_dev_create;
    }

    cdev_init(&g_cdev, &fops);

    if (cdev_add(&g_cdev, g_first_device, 1) == -1) {
        printk(KERN_ALERT "[%s] Device addition failed.\n", MODULE_TAG);
        goto failed_add;
    }

    if (false == do_init()) {
        printk(KERN_ALERT "[%s] do init failed.\n", MODULE_TAG);
        goto failed_do_init;
    }

    printk(KERN_INFO "[%s] driver initialize.\n", MODULE_TAG);
    return 0;

failed_do_init:
    cdev_del(&g_cdev);
failed_add:
    device_destroy(g_cl, g_first_device);
failed_dev_create:
    class_destroy(g_cl);
failed_cla_create:
    unregister_chrdev_region(g_first_device, 1);
    return -1;
}

static void driver_exit(void)
{
    do_release();

    cdev_del(&g_cdev);
    device_destroy(g_cl, g_first_device);
    class_destroy(g_cl);
    unregister_chrdev_region(g_first_device, 1);
    printk(KERN_INFO "[%s] driver unregistered\n", MODULE_TAG);
}

module_init(driver_initialization);
module_exit(driver_exit);
