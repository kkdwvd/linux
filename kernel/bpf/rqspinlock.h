/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Resilient Queued Spin Lock defines
 *
 * (C) Copyright 2024-2025 Meta Platforms, Inc. and affiliates.
 *
 * Authors: Kumar Kartikeya Dwivedi <memxor@gmail.com>
 */
#ifndef __LINUX_RQSPINLOCK_H
#define __LINUX_RQSPINLOCK_H

#include "../locking/qspinlock.h"
#include <asm-generic/mcs_spinlock.h>

struct res_mcs_spinlock {
	struct mcs_spinlock mcs;
	int next_node_seq;
};

struct rqnode {
	struct res_mcs_spinlock res_mcs;
};

/*
 * try_cmpxchg_tail - Return result of cmpxchg of tail word with a new value
 * @lock: Pointer to queued spinlock structure
 * @tail: The tail to compare against
 * @new_tail: The new queue tail code word
 * Return: Bool to indicate whether the cmpxchg operation succeeded
 *
 * This is used by the head of the wait queue to clean up the queue.
 * Provides relaxed ordering, since observers only rely on initialized
 * state of the node which was made visible through the xchg_tail operation,
 * i.e. through the smp_wmb preceding xchg_tail.
 *
 * We avoid using 16-bit cmpxchg, which is not available on all architectures.
 */
static __always_inline bool try_cmpxchg_tail(struct qspinlock *lock, u32 tail, u32 new_tail)
{
	u32 old, new;

	old = atomic_read(&lock->val);
	do {
		/*
		 * Is the tail part we compare to already stale? Fail.
		 */
		if ((old & _Q_TAIL_MASK) != tail)
			return false;
		/*
		 * Encode latest locked/pending state for new tail.
		 */
		new = (old & _Q_LOCKED_PENDING_MASK) | new_tail;
	} while (!atomic_try_cmpxchg_relaxed(&lock->val, &old, new));

	return true;
}

/*
 * We must be able to distinguish between no-tail, the tail at 0:0,
 * and the sentinel value 1:0, therefore increment the cpu number
 * by two.
 */

static inline __pure u32 encode_tail_rqnode(int cpu, int idx)
{
	u32 tail;

	tail  = (cpu + 2) << _Q_TAIL_CPU_OFFSET;
	tail |= idx << _Q_TAIL_IDX_OFFSET; /* assume < 4 */

	return tail;
}

static inline __pure struct mcs_spinlock *decode_tail_rqnode(u32 tail,
							     struct rqnode __percpu *qnodes)
{
	int cpu = (tail >> _Q_TAIL_CPU_OFFSET) - 1;
	int idx = (tail &  _Q_TAIL_IDX_MASK) >> _Q_TAIL_IDX_OFFSET;

	return per_cpu_ptr(&qnodes[idx].res_mcs.mcs, cpu);
}

#endif /* __LINUX_RQSPINLOCK_H */
