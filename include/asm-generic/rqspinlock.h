/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Resilient Queued Spin Lock
 *
 * (C) Copyright 2024-2025 Meta Platforms, Inc. and affiliates.
 *
 * Authors: Kumar Kartikeya Dwivedi <memxor@gmail.com>
 */
#ifndef __ASM_GENERIC_RQSPINLOCK_H
#define __ASM_GENERIC_RQSPINLOCK_H

#include <linux/types.h>
#include <linux/build_bug.h>
#include <linux/threads.h>
#include <linux/smp.h>
#include <vdso/time64.h>
#include <linux/percpu.h>

#if CONFIG_NR_CPUS <= (1U << 13)
#define RQ_OWNER_CPU_BITS	13
#define RQ_OWNER_BITS		13
#define RQ_PENDING_OFFSET	15
#define RQ_TAIL_IDX_OFFSET	17
#else
#define RQ_OWNER_CPU_BITS	0
#define RQ_OWNER_BITS		0
#define RQ_PENDING_OFFSET	8
#define RQ_TAIL_IDX_OFFSET	9
#endif

typedef struct rqspinlock {
	union {
		atomic_t val;
#ifdef __LITTLE_ENDIAN
		struct {
			u8	locked;
			u8	owner_pending;
		};
		struct {
			u16	locked_owner_pending;
			u16	tail;
		};
#else
		struct {
			u16	tail;
			u16	locked_owner_pending;
		};
		struct {
			u8	reserved[2];
			u8	owner_pending;
			u8	locked;
		};
#endif
	};
} rqspinlock_t;

/*
 * CONFIG_NR_CPUS <= 8192:
 *     0: locked; 1-13: raw owner CPU; 14: unused; 15: pending;
 *    16: unused; 17-18: tail index + 1; 19-31: raw tail CPU.
 *
 * Unlock clears only the low byte. Upper owner bits remain as residue
 * while unlocked, and acquisition replaces the complete owner code.
 * Pending is independent of the release byte and the tail halfword.
 * A pending owner can hand over with a low-halfword store. A queue head
 * preserves transient pending claims when replacing the owner residue.
 *
 * Larger configurations omit the owner: locked is bit 0, pending bit 8,
 * tail index + 1 bits 9-10, and raw tail CPU bits 11-31. Those helpers use
 * full-word atomic updates to preserve overlapping fields.
 *
 * Index + 1 reserves zero for no tail and admits three queued contexts.
 * An NMI queues only when no other context is queued on the same CPU.
 */
#define RQ_SET_MASK(type)	(((1U << RQ_ ## type ## _BITS) - 1)\
				      << RQ_ ## type ## _OFFSET)
#define RQ_LOCKED_OFFSET	0
#define RQ_LOCKED_BITS		1
#define RQ_LOCKED_MASK		RQ_SET_MASK(LOCKED)
#define RQ_OWNER_OFFSET		1
#define RQ_OWNER_MASK		RQ_SET_MASK(OWNER)
#define RQ_OWNER_RESIDUE_MASK	(RQ_OWNER_MASK & ~0xffU)
#define RQ_PENDING_BITS		1
#define RQ_PENDING_MASK		RQ_SET_MASK(PENDING)
#define RQ_TAIL_IDX_BITS		2
#define RQ_TAIL_IDX_MASK		RQ_SET_MASK(TAIL_IDX)
#define RQ_TAIL_CPU_OFFSET	(RQ_TAIL_IDX_OFFSET + RQ_TAIL_IDX_BITS)
#define RQ_TAIL_CPU_BITS		(32 - RQ_TAIL_CPU_OFFSET)
#define RQ_TAIL_CPU_MASK		RQ_SET_MASK(TAIL_CPU)
#define RQ_TAIL_OFFSET		RQ_TAIL_IDX_OFFSET
#define RQ_TAIL_MASK		(RQ_TAIL_IDX_MASK | RQ_TAIL_CPU_MASK)
#define RQ_TAIL_HALF_OFFSET	16
#define RQ_LOCKED_VAL		(1U << RQ_LOCKED_OFFSET)
#define RQ_PENDING_VAL		(1U << RQ_PENDING_OFFSET)

static_assert(RQ_OWNER_OFFSET + RQ_OWNER_BITS <= RQ_PENDING_OFFSET);
static_assert(!RQ_OWNER_BITS || RQ_OWNER_CPU_BITS == RQ_TAIL_CPU_BITS);
static_assert(CONFIG_NR_CPUS <= (1U << RQ_TAIL_CPU_BITS),
	      "rqspinlock lock word cannot encode this many CPUs");

/*
 * The owner cpu recorded in a lock word, or -1 when owner tracking is disabled.
 * Only meaningful while the locked bit is set in the same word.
 */
static __always_inline int rq_lock_owner(u32 val)
{
	if (!RQ_OWNER_BITS)
		return -1;
	return (val & RQ_OWNER_MASK) >> RQ_OWNER_OFFSET;
}

/*
 * Even though this is same as struct rqspinlock, we need to emit a distinct
 * type in BTF for BPF programs.
 */
struct bpf_res_spin_lock {
	u32 val;
} __aligned(__alignof__(struct rqspinlock));

extern int resilient_tas_spin_lock(rqspinlock_t *lock);
#ifdef CONFIG_QUEUED_SPINLOCKS
extern int resilient_queued_spin_lock_slowpath(rqspinlock_t *lock, u32 val);
#endif

#ifndef resilient_virt_spin_lock_enabled
static __always_inline bool resilient_virt_spin_lock_enabled(void)
{
	return false;
}
#endif

#ifndef resilient_virt_spin_lock
static __always_inline int resilient_virt_spin_lock(rqspinlock_t *lock)
{
	return 0;
}
#endif

/*
 * Default timeout for waiting loops is 0.25 seconds
 */
#define RES_DEF_TIMEOUT (NSEC_PER_SEC / 4)

/*
 * Choose 31 as it makes rqspinlock_held cacheline-aligned.
 */
#define RES_NR_HELD 31

struct rqspinlock_held {
	int cnt;
	/*
	 * This CPU's complete acquisition code, including a nonzero locked byte,
	 * filled in for every possible CPU before rqspinlock users can run.
	 * It shares the cacheline with cnt, which every acquisition increments.
	 * Configurations without an owner field do not read it on acquisition.
	 */
	u32 owner;
	void *locks[RES_NR_HELD];
};

DECLARE_PER_CPU_ALIGNED(struct rqspinlock_held, rqspinlock_held_locks);

/*
 * The lock word value that acquires the lock for the current CPU. Callers
 * run with preemption disabled, so read the per-CPU copy without the
 * preemption guard or debug check; on x86 this is
 * one load from the held-locks cacheline, and on arm64 it reuses the per-CPU
 * base the held-locks update computes.
 */
static __always_inline u32 rq_locked_val(void)
{
	if (!RQ_OWNER_BITS)
		return RQ_LOCKED_VAL;
	return raw_cpu_read(rqspinlock_held_locks.owner);
}

static __always_inline void grab_held_lock_entry(void *lock)
{
	int idx = this_cpu_read(rqspinlock_held_locks.cnt);

	/*
	 * Preemption is disabled. An interrupt using this count before our
	 * store restores it before returning, so idx remains valid. Reserve
	 * the slot before publishing its pointer to a nested context.
	 */
	this_cpu_write(rqspinlock_held_locks.cnt, idx + 1);

	/*
	 * Keep the compiler from publishing the entry before reserving it.
	 * Otherwise an interrupt can reuse our slot and clear it on exit.
	 * Remote readers may still observe a reserved slot before its pointer.
	 */
	barrier();
	if (unlikely(idx >= RES_NR_HELD)) {
		/* Still account for acquisitions beyond the table capacity. */
		return;
	}
	this_cpu_write(rqspinlock_held_locks.locks[idx], lock);
}

/*
 * We simply don't support out-of-order unlocks, and keep the logic simple here.
 * The verifier prevents BPF programs from unlocking out-of-order, and the same
 * holds for in-kernel users.
 *
 * It is possible to run into misdetection scenarios of AA deadlocks on the same
 * CPU, and missed ABBA deadlocks on remote CPUs if this function pops entries
 * out of order (due to lock A, lock B, unlock A, unlock B) pattern. The correct
 * logic to preserve right entries in the table would be to walk the array of
 * held locks and swap and clear out-of-order entries, but that's too
 * complicated and we don't have a compelling use case for out of order unlocking.
 */
static __always_inline void release_held_lock_entry(void)
{
	struct rqspinlock_held *rqh = this_cpu_ptr(&rqspinlock_held_locks);

	if (unlikely(rqh->cnt > RES_NR_HELD))
		goto dec;
	WRITE_ONCE(rqh->locks[rqh->cnt - 1], NULL);
dec:
	/*
	 * Reordering of clearing above with inc and its write in
	 * grab_held_lock_entry that came before us (in same acquisition
	 * attempt) is ok, we either see a valid entry or NULL when it's
	 * visible.
	 *
	 * But this helper is invoked when we unwind upon failing to acquire the
	 * lock. Unlike the unlock path which constitutes a release store after
	 * we clear the entry, we need to emit a write barrier here. Otherwise,
	 * we may have a situation as follows:
	 *
	 * <error> for lock B
	 * release_held_lock_entry
	 *
	 * grab_held_lock_entry
	 * try_cmpxchg_acquire for lock A
	 *
	 * Lack of any ordering means reordering may occur such that dec, inc
	 * are done before entry is overwritten. This permits a remote lock
	 * holder of lock B (which this CPU failed to acquire) to now observe it
	 * as being attempted on this CPU, and may lead to misdetection (if this
	 * CPU holds a lock it is attempting to acquire, leading to false ABBA
	 * diagnosis).
	 *
	 * The case of unlock is treated differently due to NMI reentrancy, see
	 * comments in res_spin_unlock.
	 *
	 * In theory we don't have a problem if the dec and WRITE_ONCE above get
	 * reordered with each other, we either notice an empty NULL entry on
	 * top (if dec succeeds WRITE_ONCE), or a potentially stale entry which
	 * cannot be observed (if dec precedes WRITE_ONCE).
	 *
	 * Emit the write barrier _before_ the dec, this permits dec-inc
	 * reordering but that is harmless as we'd have new entry set to NULL
	 * already, i.e. they cannot precede the NULL store above.
	 */
	smp_wmb();
	this_cpu_dec(rqspinlock_held_locks.cnt);
}

#ifdef CONFIG_QUEUED_SPINLOCKS

/**
 * res_spin_lock - acquire a queued spinlock
 * @lock: Pointer to queued spinlock structure
 *
 * Return:
 * * 0		- Lock was acquired successfully.
 * * -EDEADLK	- Lock acquisition failed because of AA/ABBA deadlock.
 * * -ETIMEDOUT - Lock acquisition failed because of timeout.
 */
static __always_inline int res_spin_lock(rqspinlock_t *lock)
{
	u32 new = rq_locked_val();
	int val = 0;

	/*
	 * Grab the deadlock detection entry before doing the cmpxchg, so that
	 * reentrancy due to NMIs between the succeeding cmpxchg and creation of
	 * held lock entry can correctly detect an acquisition attempt in the
	 * interrupted context.
	 *
	 * cmpxchg lock A
	 * <NMI>
	 * res_spin_lock(A) --> missed AA, leads to timeout
	 * </NMI>
	 * grab_held_lock_entry(A)
	 */
	grab_held_lock_entry(lock);

	/*
	 * Keep the residue observation close to the CAS. The CAS still requires
	 * locked, pending and tail to be clear, and replaces the complete owner.
	 */
	if (RQ_OWNER_BITS)
		val = atomic_read(&lock->val) & RQ_OWNER_RESIDUE_MASK;

	if (likely(atomic_try_cmpxchg_acquire(&lock->val, &val, new)))
		return 0;
	return resilient_queued_spin_lock_slowpath(lock, val);
}

#else

#define res_spin_lock(lock) ({ grab_held_lock_entry(lock); resilient_tas_spin_lock(lock); })

#endif /* CONFIG_QUEUED_SPINLOCKS */

static __always_inline void res_spin_unlock(rqspinlock_t *lock)
{
	struct rqspinlock_held *rqh = this_cpu_ptr(&rqspinlock_held_locks);

	/*
	 * Release the locked byte, preserving pending and the independent tail.
	 * Upper owner bits remain as residue and are ignored while unlocked.
	 * Every acquisition replaces the complete owner and sets the locked byte.
	 * The same release serves the queued and test-and-set paths.
	 *
	 * Perform the smp_store_release before clearing the lock entry so that
	 * NMIs landing in the unlock path can correctly detect AA issues. The
	 * opposite order shown below may lead to missed AA checks:
	 *
	 * WRITE_ONCE(rqh->locks[rqh->cnt - 1], NULL)
	 * <NMI>
	 * res_spin_lock(A) --> missed AA, leads to timeout
	 * </NMI>
	 * smp_store_release(A->locked, 0)
	 */
	smp_store_release(&lock->locked, 0);
	if (likely(rqh->cnt <= RES_NR_HELD))
		WRITE_ONCE(rqh->locks[rqh->cnt - 1], NULL);
	this_cpu_dec(rqspinlock_held_locks.cnt);
}

#define raw_res_spin_lock_init(lock) ({ *(lock) = (rqspinlock_t){0}; })

#define raw_res_spin_lock(lock)                    \
	({                                         \
		int __ret;                         \
		preempt_disable();                 \
		__ret = res_spin_lock(lock);	   \
		if (__ret)                         \
			preempt_enable();          \
		__ret;                             \
	})

#define raw_res_spin_unlock(lock) ({ res_spin_unlock(lock); preempt_enable(); })

#define raw_res_spin_lock_irqsave(lock, flags)    \
	({                                        \
		int __ret;                        \
		local_irq_save(flags);            \
		preempt_disable();                \
		__ret = res_spin_lock(lock);      \
		if (__ret) {                      \
			local_irq_restore(flags); \
			preempt_enable();         \
		}                                 \
		__ret;                            \
	})

#define raw_res_spin_unlock_irqrestore(lock, flags) \
	({                                          \
		res_spin_unlock(lock);              \
		local_irq_restore(flags);           \
		preempt_enable();                   \
	})

#endif /* __ASM_GENERIC_RQSPINLOCK_H */
