

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/mman.h>

#define MODULE_TAG "userfile"

// flag: O_CREAT|O_RDWR|O_APPEND
// mode: 0644
int write_file(const char *file_w, const char *buff, int size, int flag, int mode)
{
    int ret = 0;
	struct file *file_write = NULL;
    mm_segment_t old_fs;

	file_write = filp_open(file_w, flag, mode);
	if (IS_ERR_OR_NULL(file_write)) {
        printk(KERN_WARNING "%s filp_open file:%s error.\n", MODULE_TAG, file_w);
		return 0;
	}

    old_fs = force_uaccess_begin();

    ret = kernel_write(file_write, buff, size, &file_write->f_pos);
    if (ret < 0) {
        printk(KERN_WARNING "%s vfs_write file:%s error:%d.\n", MODULE_TAG, file_w, ret);
    }

    force_uaccess_end(old_fs);

	filp_close(file_write, NULL);
    return ret;
}

int read_file(const char *file_r, char *buff, int size)
{
    int len, ret = 0;
    loff_t pos = 0;
    struct file *file_maps = NULL;
    struct kstat stat;
    mm_segment_t old_fs;

    file_maps = filp_open(file_r, O_RDONLY, 0);
    if (IS_ERR(file_maps)) {
        printk(KERN_WARNING "%s filp_open file:%s error code:%ld.\n", MODULE_TAG, file_r, PTR_ERR(file_maps));
        return 0;
    }

    old_fs = force_uaccess_begin();

    len = vfs_getattr(&file_maps->f_path, &stat, STATX_SIZE, AT_STATX_SYNC_AS_STAT);
    if (len != 0) {
        printk(KERN_WARNING "%s vfs_getattr error.\n", MODULE_TAG);
        goto read_return;
    } else {
        len = stat.size < size ? stat.size : size;
    }

    memset(buff, 0, size);
    ret = kernel_read(file_maps, buff, len, &pos);

read_return:
    force_uaccess_end(old_fs);

    filp_close(file_maps, NULL);
    return ret;
}
