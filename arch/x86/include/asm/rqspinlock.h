/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_RQSPINLOCK_H
#define _ASM_X86_RQSPINLOCK_H

#include <asm/alternative.h>
#include <asm/paravirt.h>
#include <asm/rmwcc.h>

#ifdef CONFIG_PARAVIRT
DECLARE_STATIC_KEY_FALSE(virt_spin_lock_key);

#define resilient_virt_spin_lock_enabled resilient_virt_spin_lock_enabled
static __always_inline bool resilient_virt_spin_lock_enabled(void)
{
       return static_branch_likely(&virt_spin_lock_key);
}

struct rqspinlock;
extern int resilient_tas_spin_lock(struct rqspinlock *lock);

#define resilient_virt_spin_lock resilient_virt_spin_lock
static inline int resilient_virt_spin_lock(struct rqspinlock *lock)
{
	return resilient_tas_spin_lock(lock);
}

#endif /* CONFIG_PARAVIRT */

#define RQ_PENDING_LOOPS	(1 << 9)

#include <asm-generic/rqspinlock.h>

#define rq_fetch_set_pending_acquire rq_fetch_set_pending_acquire
static __always_inline u32 rq_fetch_set_pending_acquire(struct rqspinlock *lock)
{
	u32 val;

	/*
	 * We can't use GEN_BINARY_RMWcc() inside an if() stmt because asm goto
	 * and CONFIG_PROFILE_ALL_BRANCHES=y results in a label inside a
	 * statement expression, which GCC doesn't like.
	 */
	val = GEN_BINARY_RMWcc(LOCK_PREFIX "btsl", lock->val.counter, c,
			       "I", RQ_PENDING_OFFSET) * RQ_PENDING_VAL;
	val |= atomic_read(&lock->val) & ~RQ_PENDING_MASK;

	return val;
}

#endif /* _ASM_X86_RQSPINLOCK_H */
