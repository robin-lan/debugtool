
#include <asm/ptrace.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include "kmemmanager.h"
#include "userfile.h"
#include "process.h"
#include "../exedebugtool/main.h"
#include "./kmemprint.h"

#define MODULE_TAG "debugtool:dump_user_content"

enum MapFlag
{
    MapRead = 4,
    MapWrite = 2,
    MapExe = 1
};

struct st_map
{
    unsigned long start;
    unsigned long end;
    unsigned int flags;
    unsigned int pgoff;
    char file[MAX_PATH_LEN];
};

/*
 * Indicate if the VMA is a stack for the given task; for
 * /proc/PID/maps that is the stack of the main task.
 */
static int is_stack(struct vm_area_struct *vma)
{
	/*
	 * We make no effort to guess what a given thread considers to be
	 * its "stack".  It's not even well-defined for programs written
	 * languages like Go.
	 */
	return vma->vm_start <= vma->vm_mm->start_stack &&
		vma->vm_end >= vma->vm_mm->start_stack;
}

static void show_vma_header_prefix(unsigned long start, unsigned long end,
				   vm_flags_t flags, unsigned long long pgoff,
				   dev_t dev, unsigned long ino, struct st_map *map)
{
    map->start = start;
    map->end = end;
    map->flags = 0;
    map->flags |= flags & VM_READ ? MapRead : 0;
    map->flags |= flags & VM_WRITE ? MapWrite: 0;
    map->flags |= flags & VM_EXEC ? MapExe: 0;
    map->pgoff = pgoff;
}

static void get_map_vma(struct vm_area_struct *vma, struct st_map *map)
{
	struct mm_struct *mm = vma->vm_mm;
	struct file *file = vma->vm_file;
	vm_flags_t flags = vma->vm_flags;
	unsigned long ino = 0;
	unsigned long long pgoff = 0;
	unsigned long start, end;
	dev_t dev = 0;
	const char *name = NULL;

	if (file) {
		struct inode *inode = file_inode(vma->vm_file);
		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
		pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
	}

	start = vma->vm_start;
	end = vma->vm_end;
	show_vma_header_prefix(start, end, flags, pgoff, dev, ino, map);

	/*
	 * Print the dentry name for named mappings, and a
	 * special [heap] marker for the heap:
	 */
	if (file) {
        name = d_path(&file->f_path, map->file, MAX_PATH_LEN);
		goto done;
	}

	if (vma->vm_ops && vma->vm_ops->name) {
		name = vma->vm_ops->name(vma);
		if (name)
			goto done;
	}

    if (is_stack(vma)) {
        name = "[stack]";
    }
	if (!name) {
		if (!mm) {
			name = "[vdso]";
			goto done;
		}

		if (vma->vm_start <= mm->brk &&
		    vma->vm_end >= mm->start_brk) {
			name = "[heap]";
			goto done;
		}
	}
done:
    if (name) {
        memmove(map->file, name, strlen(name)+ 1);
    }
}

bool mem_range_available(int target_pid, unsigned long start, unsigned long end)
{
    bool ret = false;
    struct task_struct *tsk;
    struct mm_struct *mm;
    struct vm_area_struct *vma = 0;
    struct st_map *map;

    if (target_pid == 0) {
        tsk = current;
    } else {
        tsk = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    }
    if (NULL == tsk) {
        return ret;
    }

    mm = tsk->mm;
    if (!(mm && mm->mmap)){
        return ret;
    }

    map =  dt_kmalloc(sizeof(struct st_map));
    for (vma = mm->mmap; vma; vma = vma->vm_next){
        memset(map, 0, sizeof(struct st_map));
        get_map_vma(vma, map);
        if ((map->start == start) && (map->end == end)) {
            ret = true;
            break;
        }
    }
    dt_kfree(map);
    return ret;
}

bool mem_addr_available(int target_pid, unsigned long addr, unsigned long *start, unsigned long *end)
{
    bool ret = false;
    struct task_struct *tsk;
    struct mm_struct *mm;
    struct vm_area_struct *vma = 0;
    struct st_map *map;

    if (target_pid == 0) {
        tsk = current;
    } else {
        tsk = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    }
    if (NULL == tsk) {
        return ret;
    }

    mm = tsk->mm;
    if (!(mm && mm->mmap)){
        return ret;
    }

    map =  dt_kmalloc(sizeof(struct st_map));
    for (vma = mm->mmap; vma; vma = vma->vm_next){
        memset(map, 0, sizeof(struct st_map));
        get_map_vma(vma, map);
        if ((map->start < addr) && (map->end > addr)) {
            *start = map->start;
            *end = map->end;
            ret = true;
            break;
        }
    }
    dt_kfree(map);
    return ret;
}

void dump_pid_mem_range_(int target_pid, unsigned long start, unsigned long end, char *dir)
{
    unsigned long status [[gnu::unused]];
    char *dump_file, *buf_read;

    struct task_struct *task = get_target_pid_task(target_pid);
    if (NULL == task) {
        return;
    }

    buf_read = dt_kmalloc(end - start);
    if (NULL == buf_read) {
        return;
    }

    pid_t processid = __task_pid_nr_ns(current, PIDTYPE_TGID, NULL);
    if (target_pid == (int)processid) {
        status = copy_from_user((void *)buf_read, (void *)start, end - start);
    } else {
        access_process_vm(task, start, buf_read, end - start, FOLL_FORCE);
    }

    dump_file = dt_kmalloc_fast_path();
    if (NULL == dump_file) {
        dt_kfree(buf_read);
        return;
    }
	snprintf(dump_file, dt_get_kmalloc_fast_size(), "%s-%010lx-%010lx", dir, start, end);

    write_file(dump_file, buf_read, end - start, O_CREAT|O_RDWR|O_APPEND, 0644);

    dt_kfree_fast_path(dump_file);
    dt_kfree(buf_read);
}

void dump_pid_mem_range(int target_pid, unsigned long start, unsigned long end, char *dir)
{
    bool ret = mem_range_available(target_pid, start, end);
    if (false == ret) {
        return;
    }
    dump_pid_mem_range_(target_pid, start, end, dir);
}

void dump_pid_mem(int target_pid, unsigned long addr, char *dir)
{
    unsigned long start = 0, end = 0;

    bool ret = mem_addr_available(target_pid, addr, &start, &end);
    if (false == ret) {
        return;
    }
    dump_pid_mem_range_(target_pid, start, end, dir);
}

#define REGS_BUFF_SIZE 0x500
void dump_user_regs(char *dir)
{
    char *buf_write = NULL;
    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    char *tmp = dt_kmalloc_fast_path();
    if (NULL == tmp) {
        return;
    }

    buf_write = dt_kmalloc(REGS_BUFF_SIZE);
    if (NULL == buf_write) {
        dt_kfree_fast_path(tmp);
        return;
    }
    memset(buf_write, 0, REGS_BUFF_SIZE); 
    for (int i = 0; i < 30; i+=2) {
        snprintf(tmp, dt_get_kmalloc_fast_size(), " x%d: %010llx    x%d: %010llx\n", i, uregs->regs[i], i+1, uregs->regs[i+1]);
        strcat(buf_write, tmp);
    }
    snprintf(tmp, dt_get_kmalloc_fast_size(), " x%d: %010llx\n", 30, uregs->regs[30]);
    strcat(buf_write, tmp);
    snprintf(tmp, dt_get_kmalloc_fast_size(), " sp: %010llx    pc: %010llx\n", uregs->sp, uregs->pc);
    strcat(buf_write, tmp);

    write_file(dir, buf_write, strlen(buf_write), O_CREAT|O_RDWR|O_APPEND, 0644);

    dt_kfree(buf_write);
    dt_kfree_fast_path(tmp);
}

void dump_user_stack(char *dir)
{
    unsigned long start = 0, end = 0;
    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    pid_t processid= __task_pid_nr_ns(current, PIDTYPE_TGID, NULL);

    bool ret = mem_addr_available(processid, uregs->sp, &start, &end);
    if (false == ret) {
        return;
    }

    dump_pid_mem_range_(processid, start, end, dir);
}

void dump_user_pc_mem_range(char *dir)
{
    unsigned long start = 0, end = 0;
    struct user_pt_regs *uregs = &task_pt_regs(current)->user_regs;
    pid_t processid= __task_pid_nr_ns(current, PIDTYPE_TGID, NULL);

    bool ret = mem_addr_available(processid, uregs->pc, &start, &end);
    if (false == ret) {
        return;
    }
    dump_pid_mem_range_(processid, start, end, dir);
}

#define MAPS_BUFF_SIZE 0x1000
void dump_user_maps(int target_pid, char *dir)
{
    int less_size, len, index = 1;
    struct task_struct *tsk;
    struct mm_struct *mm;
    struct vm_area_struct *vma = 0;
    struct st_map *map;
    char *buff_write, *buff_tmp, *next = NULL;

    if (target_pid == 0) {
        tsk = current;
    } else {
        tsk = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    }
    if (NULL == tsk) {
        return;
    }

    mm = tsk->mm;
    if (!(mm && mm->mmap)){
        return;
    }

    buff_write = dt_kmalloc(MAPS_BUFF_SIZE * index++);
    if (NULL == buff_write) {
        return;
    }
    buff_tmp = dt_kmalloc(MAPS_BUFF_SIZE / 2);
    if (NULL == buff_tmp) {
        goto ret_0;
    }
    map =  dt_kmalloc(sizeof(struct st_map));
    if (NULL == map) {
        goto ret_1;
    }

    next = buff_write;
    less_size = MAPS_BUFF_SIZE * (index - 1) - 1;
    for (vma = mm->mmap; vma; vma = vma->vm_next){
        memset(map, 0, sizeof(struct st_map));
        get_map_vma(vma, map);
        snprintf(buff_tmp, MAPS_BUFF_SIZE / 2, " %010lx - %010lx %d%d%d %s\n",
                map->start, map->end,
                map->flags & MapRead, map->flags & MapWrite, map->flags & MapExe,
                map->file);
        next = sstrcopy(next, less_size, buff_tmp, &less_size);
        if (NULL == next) {
            buff_write = dt_krealloc(buff_write, MAPS_BUFF_SIZE * index++);
            if (NULL == buff_write) {
                goto ret_1;
            }
            len = strlen(buff_write);
            next = len + buff_write;
            less_size = MAPS_BUFF_SIZE * (index - 1) - len - 1;
            next = sstrcopy(next, less_size, buff_tmp, &less_size);
        }
    }

    write_file(dir, buff_write, strlen(buff_write), O_CREAT|O_RDWR|O_APPEND, 0644);
    dt_kfree(map);
ret_1:
    dt_kfree(buff_tmp);
ret_0:
    dt_kfree(buff_write);
}

int dump_index = 0;
void dump_user_content(char *dir)
{
    int index = dump_index;
    dump_index = dump_index + 1;

    char *tmp_dir = dt_kmalloc_fast_path();

    snprintf(tmp_dir, dt_get_kmalloc_fast_size(), "%s-%d-%s.txt", dir, index, "maps");
    dump_user_maps(0, tmp_dir);

    snprintf(tmp_dir, dt_get_kmalloc_fast_size(), "%s-%d-%s.txt", dir, index, "regs");
    dump_user_regs(tmp_dir);

    snprintf(tmp_dir, dt_get_kmalloc_fast_size(), "%s-%d-%s.bin", dir, index, "pc");
    dump_user_pc_mem_range(tmp_dir);

    snprintf(tmp_dir, dt_get_kmalloc_fast_size(), "%s-%d-%s.bin", dir, index, "sp");
    dump_user_stack(tmp_dir);

    dt_kfree_fast_path(tmp_dir);
}
