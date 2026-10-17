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

#include <linux/percpu-defs.h>
#include <asm/rqspinlock.h>
#include "../locking/mcs_spinlock.h"

/*
 * Per-CPU queue nodes, one per context that can nest into the slowpath.
 */
#define RQ_MAX_NODES	3
static_assert(RQ_MAX_NODES < (1U << RQ_TAIL_IDX_BITS));

/*
 * The pending bit spinning loop count.
 * This heuristic is used to limit the number of lockword accesses
 * made by atomic_cond_read_relaxed when waiting for the lock to
 * transition out of the "== RQ_PENDING_VAL" state. We don't spin
 * indefinitely because there's no guarantee that we'll make forward
 * progress.
 */
#ifndef RQ_PENDING_LOOPS
#define RQ_PENDING_LOOPS	1
#endif

struct rqnode {
	struct mcs_spinlock mcs;
};

#define RQ_LOCKED_OWNER_MASK	(RQ_LOCKED_MASK | RQ_OWNER_MASK)

#define RQ_LOCKED_PENDING_MASK	(RQ_LOCKED_MASK | RQ_PENDING_MASK)

/*
 * We must be able to distinguish between no-tail and the tail at 0:0,
 * therefore increment the node index by one; store the CPU as is.
 */
static inline __pure u32 rq_encode_tail(int cpu, int idx)
{
	u32 tail;

	tail  = (u32)cpu << RQ_TAIL_CPU_OFFSET;
	tail |= (u32)(idx + 1) << RQ_TAIL_IDX_OFFSET;

	return tail;
}

static inline __pure struct mcs_spinlock *rq_decode_tail(u32 tail,
							  struct rqnode __percpu *rqnodes)
{
	int cpu = (tail & RQ_TAIL_CPU_MASK) >> RQ_TAIL_CPU_OFFSET;
	int idx = ((tail & RQ_TAIL_IDX_MASK) >> RQ_TAIL_IDX_OFFSET) - 1;

	return per_cpu_ptr(&rqnodes[idx].mcs, cpu);
}

static inline __pure
struct mcs_spinlock *rq_grab_mcs_node(struct mcs_spinlock *base, int idx)
{
	return &((struct rqnode *)base + idx)->mcs;
}

/**
 * rq_clear_pending - clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 * @val: Word observed when successfully claiming pending
 *
 * *,1,* -> *,0,*
 *
 * While pending is owned, release can change only the low byte and enqueue only the tail;
 * the upper owner bits cannot change. Restore that saved byte without P.
 */
static __always_inline void rq_clear_pending(rqspinlock_t *lock, u32 val)
{
#if RQ_OWNER_BITS
	WRITE_ONCE(lock->owner_pending, (val & RQ_OWNER_RESIDUE_MASK) >> 8);
#else
	atomic_andnot(RQ_PENDING_VAL, &lock->val);
#endif
}

/**
 * rq_clear_pending_set_locked - take ownership and clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,0 -> *,0,1
 *
 * Lock stealing is not allowed if this function is used.
 */
static __always_inline void rq_clear_pending_set_locked(rqspinlock_t *lock)
{
#if RQ_OWNER_BITS
	WRITE_ONCE(lock->locked_owner_pending, rq_locked_val());
#else
	atomic_add(-RQ_PENDING_VAL + RQ_LOCKED_VAL, &lock->val);
#endif
}

/*
 * rq_xchg_tail - Put in the new queue tail code word & retrieve previous one
 * @lock : Pointer to queued spinlock structure
 * @tail : The new queue tail code word
 * Return: The previous queue tail code word
 *
 * xchg(lock, tail), which heads an address dependency
 *
 * p,*,* -> n,*,* ; prev = xchg(lock, node)
 */
static __always_inline u32 rq_xchg_tail(rqspinlock_t *lock, u32 tail)
{
	/*
	 * The caller orders node initialization before publishing the tail.
	 * Acquire also orders a new first head's locked-field observation
	 * after an earlier queue's cleanup that this exchange observes.
	 */
#if RQ_OWNER_BITS
	return (u32)xchg_acquire(&lock->tail,
				 tail >> RQ_TAIL_HALF_OFFSET) << RQ_TAIL_HALF_OFFSET;
#else
	u32 old = atomic_read(&lock->val), new;

	do {
		new = (old & ~RQ_TAIL_MASK) | tail;
	} while (!atomic_try_cmpxchg_relaxed(&lock->val, &old, new));
	return old;
#endif
}

/*
 * A failed optimistic pending attempt may have set P against an existing
 * queue. Queue heads can change the owner in that interval; undo must keep
 * their current owner bits, rather than restore the claimant's snapshot.
 */
static __always_inline void rq_undo_pending(rqspinlock_t *lock)
{
	atomic_andnot(RQ_PENDING_VAL, &lock->val);
}

#ifndef rq_fetch_set_pending_acquire
static __always_inline u32 rq_fetch_set_pending_acquire(rqspinlock_t *lock)
{
	return atomic_fetch_or_acquire(RQ_PENDING_VAL, &lock->val);
}
#endif

/**
 * rq_set_locked - Set the lock bit and own the lock
 * @lock: Pointer to queued spinlock structure
 * @val: Word observed by the head with locked and pending clear
 *
 * *,*,0 -> *,0,1
 */
static __always_inline void rq_set_locked(rqspinlock_t *lock, u32 val)
{
#if RQ_OWNER_BITS
	u32 new = rq_locked_val();

	/*
	 * The head observed L=P=0 while its tail was present. Nobody can
	 * change the upper owner bits now, but an optimistic pending setter
	 * can transiently set P. Keep that bit until its setter undoes it.
	 * A byte store suffices within one owner group. Crossing groups
	 * replaces the stable residue with an additive RMW that preserves
	 * concurrently changing pending and tail fields.
	 */
	if (likely(!((val ^ new) & RQ_OWNER_RESIDUE_MASK)))
		WRITE_ONCE(lock->locked, new);
	else
		atomic_add(new - (val & RQ_OWNER_RESIDUE_MASK), &lock->val);
#else
	WRITE_ONCE(lock->locked, RQ_LOCKED_VAL);
#endif
}

/**
 * rq_trylock - try to acquire the queued spinlock
 * @lock : Pointer to queued spinlock structure
 * Return: 1 if lock acquired, 0 if failed
 */
static __always_inline int rq_trylock(rqspinlock_t *lock)
{
	int val = atomic_read(&lock->val);

	if (unlikely(val & ~RQ_OWNER_RESIDUE_MASK))
		return 0;

	return likely(atomic_try_cmpxchg_acquire(&lock->val, &val, rq_locked_val()));
}

/*
 * rq_try_cmpxchg_tail - Return result of cmpxchg of tail word with a new value
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
static __always_inline bool rq_try_cmpxchg_tail(rqspinlock_t *lock, u32 tail, u32 new_tail)
{
	u32 old, new;

	old = atomic_read(&lock->val);
	do {
		/*
		 * Is the tail part we compare to already stale? Fail.
		 */
		if ((old & RQ_TAIL_MASK) != tail)
			return false;
		/*
		 * Encode latest locked/pending state for new tail.
		 */
		new = (old & ~RQ_TAIL_MASK) | new_tail;
	} while (!atomic_try_cmpxchg_relaxed(&lock->val, &old, new));

	return true;
}

#endif /* __LINUX_RQSPINLOCK_H */
