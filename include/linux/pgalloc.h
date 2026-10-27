/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PGALLOC_H
#define _LINUX_PGALLOC_H

#include <linux/pgtable.h>
#include <asm/pgalloc.h>

/*
 * {pgd,p4d}_populate_kernel() are defined as macros to allow
 * compile-time optimization based on the configured page table levels.
 * Without this, linking may fail because callers (e.g., KASAN) may rely
 * on calls to these functions being optimized away when passing symbols
 * that exist only for certain page table levels.
 */
#define pgd_populate_kernel(addr, pgd, p4d)				\
	do {								\
		pgd_populate(&init_mm, pgd, p4d);			\
		if (ARCH_PAGE_TABLE_SYNC_MASK & PGTBL_PGD_MODIFIED)	\
			arch_sync_kernel_mappings(addr, addr);		\
	} while (0)

#define p4d_populate_kernel(addr, p4d, pud)				\
	do {								\
		p4d_populate(&init_mm, p4d, pud);			\
		if (ARCH_PAGE_TABLE_SYNC_MASK & PGTBL_P4D_MODIFIED)	\
			arch_sync_kernel_mappings(addr, addr);		\
	} while (0)

#if defined(CONFIG_MMU) && !defined(pmdp_try_populate_kernel)
/**
 * pmdp_try_populate_kernel - point an empty kernel PMD entry at a PTE table
 * @mm: the mm the table belongs to, always &init_mm
 * @pmdp: page middle directory entry
 * @pte: the PTE table to install
 *
 * Install @pte into *@pmdp iff *@pmdp is pmd_none(). Return true on success,
 * false if the entry was already populated. @pte must be fully initialized
 * before the call: on return another CPU may walk it.
 *
 * For special kernel page tables only - never user page tables. The caller
 * must prevent concurrent teardown of @pmdp and must accept that other writers
 * may race. Concurrent clearers must use pmdp_try_clear() so racing writers
 * agree on the outcome.
 *
 * Architectures opt in by providing a cmpxchg-based override, which may be
 * called locklessly from any context, and defining pmdp_try_populate_kernel as
 * an identity macro. The generic version is a plain check and
 * pmd_populate_kernel(), which is only correct when the caller serializes
 * every writer of the entry.
 */
static inline bool pmdp_try_populate_kernel(struct mm_struct *mm, pmd_t *pmdp, pte_t *pte)
{
	pmd_t pmd = pmdp_get(pmdp); /* pmd_none() wants an lvalue on m68k */

	if (!pmd_none(pmd))
		return false;
	smp_wmb(); /* See comment in pmd_install() */
	pmd_populate_kernel(mm, pmdp, pte);
	return true;
}
#endif

#endif /* _LINUX_PGALLOC_H */
