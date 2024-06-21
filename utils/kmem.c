
#include <linux/slab.h>
#include <linux/mman.h>
#include "./kernel_symbol.h"
#include "./kmem.h"
#include "./kmemmanager.h"

#define MODULE_TAG "debugtool:kmem"

#define pmd_huge(pmd) (pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT))

extern struct util_kernel_symbol kernel_sym;

char __user * kmalloc_user_memory(unsigned long size)
{
    char __user *mm_buf = NULL;
    unsigned long populate = 0;

    down_write(&current->mm->mmap_lock);
    mm_buf = (char __user *)kernel_sym.mem_util.do_mmap(NULL, 0, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, &populate, NULL);
    up_write(&current->mm->mmap_lock);

    if (NULL == mm_buf) {
        printk(KERN_ALERT "[%s] kmalloc_user_memory failed!\n", MODULE_TAG);
    }
    return mm_buf;
}

bool kfree_user_memory(void __user *buf, size_t size)
{
    int error = -1;

    down_write(&current->mm->mmap_lock);
    error = kernel_sym.mem_util.do_munmap(current->mm, (unsigned long)buf, size, NULL);
    up_write(&current->mm->mmap_lock);

    if (error != 0) {
        printk(KERN_ALERT
                "[%s] do_munmap buf:%p, size:%lu, ret:%d error.\n",
                MODULE_TAG, buf, size, error);
    }

    return (error == 0);
}

void copy_userchar2kmalloc(char **str, int *len)
{
    unsigned long status;
    char *tmp = *str;
    long user_len;

    if (0 == *len) {
        *str = NULL;
        return;
    }
    user_len = strnlen_user(*str, *len + 1);
    if (user_len != *len + 1) {
        printk(KERN_ALERT "[%s] copy userchar2kmalloc size error.\n",
               MODULE_TAG);
        *str = NULL;
        *len = 0;
        return;
    }

    *str = dt_kmalloc(*len + 1);
    if (NULL == *str) {
        *len = 0;
        printk(KERN_ALERT "[%s] dt_kmalloc error.\n", MODULE_TAG);
        printk(KERN_ALERT "[%s] copy userchar2kmalloc error.\n", MODULE_TAG);
        return;
    }
    status = copy_from_user(*str, tmp, *len);
    if (0 != status) {
        dt_kfree(*str);
        *str = NULL;
        *len = 0;
        printk(KERN_ALERT "[%s] copy userchar2kmalloc error.\n", MODULE_TAG);
    }
    printk(KERN_INFO "[%s] copy userchar2kmalloc str:%s len:%d.\n", MODULE_TAG,
           *str, *len);
}

struct mm_struct *get_init_mm(unsigned long addr)
{
    struct mm_struct *init_mm;
    struct mm_struct *mm;

    init_mm = kernel_sym.hook_util.init_mm;
    if (is_ttbr0_addr(addr)) {
        /* TTBR0 */
        mm = current->active_mm;
        if (mm == init_mm) {
            printk(KERN_INFO "[%s] [%016lx] user address but active_mm is swapper",
                   MODULE_TAG, addr);
            return NULL;
        }
    } else if (is_ttbr1_addr(addr)) {
        /* TTBR1 */
        mm = init_mm;
    } else {
        printk(KERN_INFO
               "[%s] [%016lx] address between user and kernel address ranges",
               MODULE_TAG, addr);
        return NULL;
    }

    return mm;
}

//bool page_mapping_exist(unsigned long addr, size_t size)
//{
//    pgd_t *pgdp = NULL;
//    p4d_t *p4dp = NULL;
//    pud_t *pudp = NULL;
//    pmd_t *pmdp = NULL;
//    pte_t *ptep = NULL;
//    struct mm_struct *mm;
//    unsigned long end_addr;
//
//
//    mm = get_init_mm(addr);
//    if (!mm) {
//        return false;
//    }
//
//    pgdp = pgd_offset(mm, addr);
//    if (pgd_none(*pgdp) || pgd_bad(*pgdp)) {
//        return false;
//    }
//
//    p4dp = p4d_offset(pgdp, addr);
//    if (p4d_none(*p4dp) || p4d_bad(*p4dp)) {
//        return false;
//    }
//    pudp = pud_offset((p4d_t *)p4dp, addr);
//    if (pud_none(*pudp) || pud_bad(*pudp)) {
//        return false;
//    }
//
//    pmdp = pmd_offset(pudp, addr);
//    if (pmd_none(*pmdp) || pmd_bad(*pmdp)) {
//        return false;
//    }
//
//    // 2MB
//    if (pmd_huge(*pmdp)) {
//        if (!pte_valid(*(pte_t *)pmdp)) {
//            return false;
//        }
//        end_addr = (((addr >> PMD_SHIFT) + 1) << PMD_SHIFT) - 1;
//        goto end;
//    }
//
//    ptep = pte_offset_kernel(pmdp, addr);
//    if (!pte_valid(*ptep)) {
//        return false;
//    }
//    end_addr = (((addr >> PAGE_SHIFT) + 1) << PAGE_SHIFT) - 1;
//
//end:
//    if (end_addr >= addr + size - 1) {
//        return true;
//    }
//
//    return page_mapping_exist(end_addr + 1, size - (end_addr - addr + 1));
//}
//
//bool addr_valid(unsigned long addr, size_t size)
//{
//    int i;
//    for (i = 0; i < size; i++) {
//        if (!virt_addr_valid((void *)addr + i)) {
//            printk(KERN_ALERT "%016lx virt_addr_valid", (unsigned long)((void *)addr + i));
//            return false;
//        }
//    }
//    if (!page_mapping_exist(addr, size)) {
//        return false;
//    }
//
//    return true;
//}

/*
 * Check whether a kernel address is valid (derived from arch/x86/).
 */
int debug_tool_kern_addr_valid(unsigned long addr)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;
	pte_t *ptep, pte;
    struct mm_struct *mm;

	addr = arch_kasan_reset_tag(addr);
	if ((((long)addr) >> VA_BITS) != -1UL)
		return 0;

    mm = get_init_mm(addr);
    if (!mm) {
        return 0;
    }

    pgdp = pgd_offset(mm, addr);
    if (pgd_none(*pgdp) || pgd_bad(*pgdp)) {
        return 0;
    }

	p4dp = p4d_offset(pgdp, addr);
	if (p4d_none(READ_ONCE(*p4dp)))
		return 0;

	pudp = pud_offset(p4dp, addr);
	pud = READ_ONCE(*pudp);
	if (pud_none(pud))
		return 0;

	if (pud_sect(pud))
		return pfn_valid(pud_pfn(pud));

	pmdp = pmd_offset(pudp, addr);
	pmd = READ_ONCE(*pmdp);
	if (pmd_none(pmd))
		return 0;

	if (pmd_sect(pmd))
		return pfn_valid(pmd_pfn(pmd));

	ptep = pte_offset_kernel(pmdp, addr);
	pte = READ_ONCE(*ptep);
	if (pte_none(pte))
		return 0;

	return pfn_valid(pte_pfn(pte));
}

bool addr_valid(unsigned long addr, size_t size)
{
    for (int i = 0; i <= size; i+= 8) {
        if (0 == debug_tool_kern_addr_valid(addr + i)) {
            return false;
        }
    }

    return true;
}

//static pte_t *get_pte(unsigned long addr)
//{
//    pgd_t *pgdp = NULL;
//    p4d_t *p4dp = NULL;
//    pud_t *pudp = NULL;
//    pmd_t *pmdp = NULL;
//    pte_t *ptep = NULL;
//    struct mm_struct *mm;
//
//    mm = get_init_mm(addr);
//    if (!mm) {
//        printk(KERN_ALERT "[%s] failed get mm.\n", MODULE_TAG);
//        return NULL;
//    }
//
//    pgdp = pgd_offset(mm, addr);
//    if (pgd_none(*pgdp) || pgd_bad(*pgdp)) {
//        printk(KERN_ALERT "[%s] failed get pgdp for %p.\n", MODULE_TAG, (void *)addr);
//        return NULL;
//    }
//
//    p4dp = p4d_offset(pgdp, addr);
//    if (p4d_none(*p4dp) || p4d_bad(*p4dp)) {
//        printk(KERN_ALERT "[%s] failed get pd4 for %p.\n", MODULE_TAG, (void *)addr);
//        return NULL;
//    }
//    pudp = pud_offset((p4d_t *)p4dp, addr);
//    if (pud_none(*pudp) || pud_bad(*pudp)) {
//        printk(KERN_ALERT "[%s] failed get pudp for %p.\n", MODULE_TAG, (void *)addr);
//        return NULL;
//    }
//
//    pmdp = pmd_offset(pudp, addr);
//    if (pmd_none(*pmdp) || pmd_bad(*pmdp)) {
//        printk(KERN_ALERT "[%s] failed get pmdp for %p.\n", MODULE_TAG, (void *)addr);
//        return NULL;
//    }
//
//    // 2MB
//    if (pmd_huge(*pmdp)) {
//        if (!pte_valid(*(pte_t *)pmdp)) {
//            printk(KERN_ALERT "[%s] failed get pte for %p.\n", MODULE_TAG, (void *)addr);
//            return NULL;
//        }
//        return (pte_t *)pmdp;
//    }
//
//    ptep = pte_offset_kernel(pmdp, addr);
//    if (!pte_valid(*ptep)) {
//        printk(KERN_ALERT "[%s] failed get pte for %p.\n", MODULE_TAG, (void *)addr);
//        return NULL;
//    }
//
//    return ptep;
//}


static pte_t *get_pte_write_ro(unsigned long addr)
{
    pgd_t *pgdp = NULL;
    p4d_t *p4dp = NULL;
    pud_t *pudp = NULL;
    pmd_t *pmdp = NULL;
    pte_t *ptep = NULL;
    struct mm_struct *mm;

    mm = get_init_mm(addr);
    if (!mm) {
        printk(KERN_ALERT "[%s] failed get mm.\n", MODULE_TAG);
        return NULL;
    }

    pgdp = pgd_offset(mm, addr);
    if (pgd_none(*pgdp)) {
        printk(KERN_ALERT "[%s] failed get pgdp for %p.\n", MODULE_TAG, (void *)addr);
        return NULL;
    }

    p4dp = p4d_offset(pgdp, addr);
    if (p4d_none(*p4dp)) {
        printk(KERN_ALERT "[%s] failed get pd4 for %p.\n", MODULE_TAG, (void *)addr);
        return NULL;
    }
    pudp = pud_offset((p4d_t *)p4dp, addr);
    if (pud_none(*pudp)) {
        printk(KERN_ALERT "[%s] failed get pudp for %p.\n", MODULE_TAG, (void *)addr);
        return NULL;
    }

    pmdp = pmd_offset(pudp, addr);
    if (pmd_none(*pmdp)) {
        printk(KERN_ALERT "[%s] failed get pmdp for %p.\n", MODULE_TAG, (void *)addr);
        return NULL;
    }

    // 2MB
    if (pmd_huge(*pmdp)) {
        if (!pte_valid(*(pte_t *)pmdp)) {
            printk(KERN_ALERT "[%s] failed get pte for %p.\n", MODULE_TAG, (void *)addr);
            return NULL;
        }
        return (pte_t *)pmdp;
    }

    ptep = pte_offset_kernel(pmdp, addr);
    if (!pte_valid(*ptep)) {
        printk(KERN_ALERT "[%s] failed get pte for %p.\n", MODULE_TAG, (void *)addr);
        return NULL;
    }

    return ptep;
}

static inline void set_pte_aatt(struct mm_struct *mm, unsigned long addr,
                                pte_t *ptep, pte_t pte)
{
    //    if (pte_present(pte) && pte_user_exec(pte) && !pte_special(pte))
    if (pte_present(pte) && !pte_special(pte))
        kernel_sym.hook_util.__sync_icache_dcache(pte);

    set_pte(ptep, pte);
}

long write_ro_memory(void *addr, void *source, int size)
{
    pte_t origin_pte, pte, *ptep = NULL;

    int numpages = round_up(size, PAGE_SIZE) / PAGE_SIZE;
    unsigned long start = (unsigned long)addr & PAGE_MASK;
    unsigned long end = PAGE_ALIGN((unsigned long)addr) + numpages * PAGE_SIZE;

    ptep = get_pte_write_ro((unsigned long)addr);
    if (!ptep) {
        printk(KERN_ALERT "[%s] get pte error.\n", MODULE_TAG);
        return -1;
    }
    origin_pte = (pte = *ptep);

    pte = clear_pte_bit(pte, __pgprot(PTE_RDONLY));
    pte = set_pte_bit(pte, __pgprot(PTE_WRITE));

    set_pte_aatt(get_init_mm((unsigned long)addr), (unsigned long)addr, ptep,
                 pte);
    flush_tlb_kernel_range(start, end);

    memcpy(addr, source, size);

    set_pte_aatt(get_init_mm((unsigned long)addr), (unsigned long)addr, ptep,
                 origin_pte);
    flush_tlb_kernel_range(start, end);

    return 0;
}
