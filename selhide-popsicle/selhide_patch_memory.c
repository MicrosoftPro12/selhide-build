// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal arm64 kernel memory patch helper, adapted from KernelSU's
 * hook/arm64/patch_memory.c. Used for rodata function-pointer replacement and
 * for writing KCFI type IDs into our own callback wrappers before installing
 * them.
 */

#ifdef __aarch64__

#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/mm.h>
#include <linux/stop_machine.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/cacheflush.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#include <asm-generic/fixmap.h>

#include "selhide_patch_memory.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
int selhide_read_kernel_nofault(void *dst, const void *src, size_t size)
{
	return (int)probe_kernel_read(dst, src, size);
}

int selhide_write_kernel_nofault(void *dst, const void *src, size_t size)
{
	return (int)probe_kernel_write(dst, src, size);
}

static void selhide_flush_icache(unsigned long start, unsigned long end)
{
	flush_icache_range(start, end);
}

static void selhide_flush_dcache(void *addr, size_t len)
{
	__flush_dcache_area(addr, len);
}
#else
extern void caches_clean_inval_pou(unsigned long start, unsigned long end);

int selhide_read_kernel_nofault(void *dst, const void *src, size_t size)
{
	return (int)copy_from_kernel_nofault(dst, src, size);
}

int selhide_write_kernel_nofault(void *dst, const void *src, size_t size)
{
	return (int)copy_to_kernel_nofault(dst, src, size);
}

static void selhide_flush_icache(unsigned long start, unsigned long end)
{
	caches_clean_inval_pou(start, end);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
static void selhide_flush_dcache(void *addr, size_t len)
{
	__clean_dcache_area_pou(addr, len);
}
#else
static void selhide_flush_dcache(void *addr, size_t len)
{
	dcache_clean_inval_poc((unsigned long)addr, (unsigned long)addr + len);
}
#endif
#endif

static bool selhide_is_vmalloc_or_module_addr(unsigned long addr)
{
#if defined(MODULES_VADDR) && defined(MODULES_END)
	if (addr >= MODULES_VADDR && addr < MODULES_END)
		return true;
#endif
#if defined(VMALLOC_START) && defined(VMALLOC_END)
	if (addr >= VMALLOC_START && addr < VMALLOC_END)
		return true;
#endif
	return false;
}

static unsigned long selhide_phys_from_virt(unsigned long addr, int *err)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct page *page;

	*err = 0;

	/*
	 * Module text lives in the module/vmalloc range. Use the kernel's own
	 * vmalloc walker here so vendor mm_struct layout drift cannot make an
	 * out-of-tree page-table walk dereference the wrong field.
	 */
	if (selhide_is_vmalloc_or_module_addr(addr)) {
		page = vmalloc_to_page((void *)addr);
		if (page)
			return page_to_phys(page) + (addr & ~PAGE_MASK);
	}

	/*
	 * Use the live kernel root page table directly instead of init_mm.
	 * Some vendor trees drift mm_struct layout enough that mm->pgd is
	 * not a safe dereference from an out-of-tree module.
	 */
	pgd = swapper_pg_dir + pgd_index(addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto fail;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		goto fail;
#if defined(p4d_leaf)
	if (p4d_leaf(*p4d))
		return __p4d_to_phys(*p4d) + (addr & ~P4D_MASK);
#endif

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		goto fail;
#if defined(pud_leaf)
	if (pud_leaf(*pud))
		return __pud_to_phys(*pud) + (addr & ~PUD_MASK);
#endif

	pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
	if (pmd_leaf(*pmd))
		return __pmd_to_phys(*pmd) + (addr & ~PMD_MASK);
#endif
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		goto fail;

	pte = pte_offset_kernel(pmd, addr);
	if (!pte || !pte_present(*pte))
		goto fail;

	return __pte_to_phys(*pte) + (addr & ~PAGE_MASK);

fail:
#if defined(CONFIG_ARM64)
	if (virt_addr_valid((void *)addr))
		return virt_to_phys((void *)addr);
	return __pa_symbol((void *)addr);
#endif
	*err = -ENOENT;
	return 0;
}

struct selhide_patch_info {
	void *dst;
	const void *src;
	size_t len;
	atomic_t cpu_count;
	int flags;
	int ret;
};

extern char selhide_patch_text_cb_entry[];

static int selhide_patch_text_nosync(void *dst, const void *src, size_t len,
				     int flags)
{
	unsigned long p = (unsigned long)dst;
	unsigned long phy;
	void *map;
	int phy_err;
	int ret;

	phy = selhide_phys_from_virt(p, &phy_err);
	if (phy_err) {
		pr_err("selhide: patch phys lookup failed dst=%px len=%zu err=%d\n",
		       dst, len, phy_err);
		return phy_err;
	}

	map = (void *)set_fixmap_offset(FIX_TEXT_POKE0, phy);
	ret = selhide_write_kernel_nofault(map, src, len);
	clear_fixmap(FIX_TEXT_POKE0);

	if (!ret) {
		if (flags & SELHIDE_PATCH_FLUSH_ICACHE)
			selhide_flush_icache((uintptr_t)dst,
					     (uintptr_t)dst + len);
		if (flags & SELHIDE_PATCH_FLUSH_DCACHE)
			selhide_flush_dcache(dst, len);
	}

	return ret;
}

int selhide_patch_text_cb_impl(void *arg)
{
	struct selhide_patch_info *info = arg;

	if (atomic_inc_return(&info->cpu_count) == num_online_cpus()) {
		info->ret = selhide_patch_text_nosync(info->dst, info->src,
						      info->len, info->flags);
		atomic_inc(&info->cpu_count);
	} else {
		while (atomic_read(&info->cpu_count) <= num_online_cpus())
			cpu_relax();
		isb();
	}

	return info->ret;
}

int selhide_patch_text(void *dst, const void *src, size_t len, int flags)
{
	struct selhide_patch_info info = {
		.dst = dst,
		.src = src,
		.len = len,
		.cpu_count = ATOMIC_INIT(0),
		.flags = flags,
		.ret = 0,
	};

	return stop_machine((int (*)(void *))(unsigned long)selhide_patch_text_cb_entry,
			    &info, cpu_online_mask);
}

#endif
