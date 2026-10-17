// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Resilient Queued Spin Lock
 *
 * (C) Copyright 2013-2015 Hewlett-Packard Development Company, L.P.
 * (C) Copyright 2013-2014,2018 Red Hat, Inc.
 * (C) Copyright 2015 Intel Corp.
 * (C) Copyright 2015 Hewlett-Packard Enterprise Development LP
 * (C) Copyright 2024-2025 Meta Platforms, Inc. and affiliates.
 *
 * Authors: Waiman Long <longman@redhat.com>
 *          Peter Zijlstra <peterz@infradead.org>
 *          Kumar Kartikeya Dwivedi <memxor@gmail.com>
 */

#include <linux/smp.h>
#include <linux/bug.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/mutex.h>
#include <linux/prefetch.h>
#include <asm/byteorder.h>
#include <trace/events/lock.h>
#include <asm/rqspinlock.h>
#include <linux/timekeeping.h>

/*
 * Include the lock word helpers and statistics code
 */
#ifdef CONFIG_QUEUED_SPINLOCKS
#include "../locking/lock_events.h"
#include "rqspinlock.h"
#endif

/*
 * The basic principle of a queue-based spinlock can best be understood
 * by studying a classic queue-based spinlock implementation called the
 * MCS lock. A copy of the original MCS lock paper ("Algorithms for Scalable
 * Synchronization on Shared-Memory Multiprocessors by Mellor-Crummey and
 * Scott") is available at
 *
 * https://bugzilla.kernel.org/show_bug.cgi?id=206115
 *
 * This queued spinlock implementation is based on the MCS lock, however to
 * make it fit the 4 bytes we assume spinlock_t to be, and preserve its
 * existing API, we must modify it somehow.
 *
 * In particular; where the traditional MCS lock consists of a tail pointer
 * (8 bytes) and needs the next pointer (another 8 bytes) of its own node to
 * unlock the next pending (next->locked), we compress both these: {tail,
 * next->locked} into a single u32 value.
 *
 * Task, softirq, and hardirq contexts need at most three queue nodes per CPU.
 * An NMI only queues if no interrupted context is already queued. Encode the
 * node index plus one in two bits, reserving zero for no tail, and store the
 * raw CPU number beside it. The low byte indicates ownership and is released
 * with a byte store. The remaining low-halfword bits hold the upper owner
 * code and pending; see the layout in asm-generic/rqspinlock.h.
 *
 * We also change the first spinner to spin on the lock bit instead of its
 * node; whereby avoiding the need to carry a node from lock to unlock, and
 * preserving existing lock API. This also makes the unlock code simpler and
 * faster.
 *
 * N.B. The current implementation only supports architectures that allow
 *      atomic operations on smaller 8-bit and 16-bit data types.
 *
 */

struct rqspinlock_timeout {
	u64 timeout_end;
	u64 duration;
	u64 cur;
	u16 spin;
};

#define RES_TIMEOUT_VAL	2

DEFINE_PER_CPU_ALIGNED(struct rqspinlock_held, rqspinlock_held_locks) = {
	.owner = RQ_LOCKED_VAL,
};
EXPORT_SYMBOL_GPL(rqspinlock_held_locks);

#if RQ_OWNER_BITS
/*
 * Fill in each CPU's owner value for the lock word. Per-CPU memory for every
 * possible CPU exists from setup_per_cpu_areas() on, and an early initcall
 * runs before secondary CPUs are brought up and before regular initcalls,
 * including the BPF and locktorture users. Initialize the cache before use:
 * the static initializer supplies CPU0's complete acquisition value.
 */
static int __init rqspinlock_init_owner(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		per_cpu(rqspinlock_held_locks.owner, cpu) = (cpu << RQ_OWNER_OFFSET) | RQ_LOCKED_VAL;
	return 0;
}
early_initcall(rqspinlock_init_owner);
#endif

static bool is_lock_released(rqspinlock_t *lock, u32 mask)
{
	if (!(atomic_read_acquire(&lock->val) & mask & ~RQ_OWNER_RESIDUE_MASK))
		return true;
	return false;
}

static noinline int check_deadlock_AA(rqspinlock_t *lock)
{
	struct rqspinlock_held *rqh = this_cpu_ptr(&rqspinlock_held_locks);
	int cnt = min(RES_NR_HELD, rqh->cnt);

	/*
	 * Return an error if we hold the lock we are attempting to acquire.
	 * We'll iterate over max 32 locks; no need to do is_lock_released.
	 */
	for (int i = 0; i < cnt - 1; i++) {
		if (rqh->locks[i] == lock)
			return -EDEADLK;
	}
	return 0;
}

/*
 * Return -ENOENT if this CPU's table does not contain the target below its
 * current acquisition attempt, 0 if it does but no cycle is found, or
 * -EDEADLK for an ABBA cycle. Never dereference a remote table entry.
 */
static int check_deadlock_ABBA_cpu(rqspinlock_t *lock, int cpu,
				   struct rqspinlock_held *rqh, int rqh_cnt)
{
	struct rqspinlock_held *rqh_cpu = per_cpu_ptr(&rqspinlock_held_locks, cpu);
	int cnt = READ_ONCE(rqh_cpu->cnt);
	void *remote_lock;

	/*
	 * A remote CPU needs a held lock and an acquisition attempt to form a
	 * cycle. Above RES_NR_HELD, its current attempt is absent from the table.
	 */
	if (cpu == smp_processor_id() || cnt < 2 || cnt > RES_NR_HELD)
		return -ENOENT;

	remote_lock = READ_ONCE(rqh_cpu->locks[cnt - 1]);
	if (!remote_lock)
		return -ENOENT;

	/*
	 * The owner snapshot may already be stale. Confirm that this CPU still
	 * lists our target below its top entry, even when it was selected by the
	 * owner field. Missing entries during publication or unwind are
	 * inconclusive; a later check can retry.
	 */
	for (int i = 0; i < cnt - 1; i++) {
		if (READ_ONCE(rqh_cpu->locks[i]) != lock)
			continue;
		for (int j = 0; j < rqh_cnt - 1; j++) {
			if (rqh->locks[j] == remote_lock)
				return -EDEADLK;
		}
		return 0;
	}
	return -ENOENT;
}

/*
 * This focuses on the most common case of ABBA deadlocks (or ABBA involving
 * more locks, which reduce to ABBA). This is not exhaustive, and we rely on
 * timeouts as the final line of defense.
 */
static noinline int check_deadlock_ABBA(rqspinlock_t *lock, u32 mask)
{
	struct rqspinlock_held *rqh = this_cpu_ptr(&rqspinlock_held_locks);
	int rqh_cnt = min(RES_NR_HELD, rqh->cnt);
	int cpu, ret;
	u32 val;

	if (rqh_cnt < 2)
		return 0;

	if (RQ_OWNER_BITS) {
		val = atomic_read_acquire(&lock->val);
		if (!(val & mask & ~RQ_OWNER_RESIDUE_MASK))
			return 0;
		if (val & RQ_LOCKED_MASK) {
			cpu = rq_lock_owner(val);
			if (cpu >= nr_cpu_ids || !cpu_possible(cpu))
				return 0;
			ret = check_deadlock_ABBA_cpu(lock, cpu, rqh, rqh_cnt);
			if (ret == -EDEADLK)
				return ret;
			/*
			 * Pending and tail reservations can belong to interrupted
			 * waiters on other CPUs. If they also block this caller,
			 * the current owner is not the only possible cycle partner.
			 */
			if (!(val & mask & ~(RQ_LOCKED_MASK | RQ_OWNER_MASK)))
				return 0;
		}
	}

	/*
	 * Without an owner field, search every possible CPU. Do the same for
	 * blocking reservations, even if the lock is still owned: a pending
	 * waiter interrupted by an NMI can participate in a cycle without
	 * owning the lock. Held tables include such interrupted attempts, so
	 * the owner field cannot locate that waiter.
	 */
	for_each_possible_cpu(cpu) {
		if (is_lock_released(lock, mask))
			return 0;
		ret = check_deadlock_ABBA_cpu(lock, cpu, rqh, rqh_cnt);
		if (ret != -ENOENT)
			return ret;
	}
	return 0;
}

static noinline int check_timeout(rqspinlock_t *lock, u32 mask,
				  struct rqspinlock_timeout *ts)
{
	u64 prev = ts->cur;
	u64 time;

	if (!ts->timeout_end) {
		if (check_deadlock_AA(lock))
			return -EDEADLK;
		ts->cur = ktime_get_mono_fast_ns();
		ts->timeout_end = ts->cur + ts->duration;
		return 0;
	}

	time = ktime_get_mono_fast_ns();
	if (time > ts->timeout_end)
		return -ETIMEDOUT;

	/*
	 * A millisecond interval passed from last time? Trigger deadlock
	 * checks.
	 */
	if (prev + NSEC_PER_MSEC < time) {
		ts->cur = time;
		return check_deadlock_ABBA(lock, mask);
	}

	return 0;
}

/*
 * Do not amortize with spins when res_smp_cond_load_acquire is defined,
 * as the macro does internal amortization for us.
 */
#ifndef res_smp_cond_load_acquire
#define RES_CHECK_TIMEOUT(ts, ret, mask)                              \
	({                                                            \
		if (!(ts).spin++)                                     \
			(ret) = check_timeout((lock), (mask), &(ts)); \
		(ret);                                                \
	})
#else
#define RES_CHECK_TIMEOUT(ts, ret, mask)			      \
	({ (ret) = check_timeout((lock), (mask), &(ts)); })
#endif

/*
 * Initialize the 'spin' member.
 * Set spin member to 0 to trigger AA/ABBA checks immediately.
 */
#define RES_INIT_TIMEOUT(ts) ({ (ts).spin = 0; })

/*
 * We only need to reset 'timeout_end', 'spin' will just wrap around as necessary.
 * Duration is defined for each spin attempt, so set it here.
 */
#define RES_RESET_TIMEOUT(ts, _duration) ({ (ts).timeout_end = 0; (ts).duration = _duration; })

/*
 * Provide a test-and-set fallback for cases when queued spin lock support is
 * absent from the architecture.
 */
int __lockfunc resilient_tas_spin_lock(rqspinlock_t *lock)
{
	struct rqspinlock_timeout ts;
	int val, ret = 0;

	RES_INIT_TIMEOUT(ts);
	/*
	 * We are either called directly from res_spin_lock after grabbing the
	 * deadlock detection entry when queued spinlocks are disabled, or from
	 * resilient_queued_spin_lock_slowpath after grabbing the deadlock
	 * detection entry. No need to obtain it here.
	 */

	/*
	 * Since the waiting loop's time is dependent on the amount of
	 * contention, a short timeout unlike rqspinlock waiting loops
	 * isn't enough. Choose a second as the timeout value.
	 */
	RES_RESET_TIMEOUT(ts, NSEC_PER_SEC);
retry:
	val = atomic_read(&lock->val);

	if ((val & ~RQ_OWNER_RESIDUE_MASK) || !atomic_try_cmpxchg(&lock->val, &val, rq_locked_val())) {
		if (RES_CHECK_TIMEOUT(ts, ret, ~0u))
			goto out;
		cpu_relax();
		goto retry;
	}

	return 0;
out:
	release_held_lock_entry();
	return ret;
}
EXPORT_SYMBOL_GPL(resilient_tas_spin_lock);

#ifdef CONFIG_QUEUED_SPINLOCKS

/*
 * Per-CPU queue nodes for task, softirq, and hardirq contexts. An NMI can
 * use the first node only when no interrupted context is already queued.
 *
 * Fits within one 64-byte cacheline on a 64-bit architecture.
 */
static DEFINE_PER_CPU_ALIGNED(struct rqnode, rqnodes[RQ_MAX_NODES]);

#ifndef res_smp_cond_load_acquire
#define res_smp_cond_load_acquire(v, c) smp_cond_load_acquire(v, c)
#endif

#define res_atomic_cond_read_acquire(v, c) res_smp_cond_load_acquire(&(v)->counter, (c))

/**
 * resilient_queued_spin_lock_slowpath - acquire the queued spinlock
 * @lock: Pointer to queued spinlock structure
 * @val: Current value of the queued spinlock 32-bit word
 *
 * Return:
 * * 0		- Lock was acquired successfully.
 * * -EDEADLK	- Lock acquisition failed because of AA/ABBA deadlock.
 * * -ETIMEDOUT - Lock acquisition failed because of timeout.
 *
 * (queue tail, pending bit, lock value)
 *
 *              fast     :    slow                                  :    unlock
 *                       :                                          :
 * uncontended  (0,0,0) -:--> (0,0,1) ------------------------------:--> (*,*,0)
 *                       :       | ^--------.------.             /  :
 *                       :       v           \      \            |  :
 * pending               :    (0,1,1) +--> (0,1,0)   \           |  :
 *                       :       | ^--'              |           |  :
 *                       :       v                   |           |  :
 * uncontended           :    (n,x,y) +--> (n,0,0) --'           |  :
 *   queue               :       | ^--'                          |  :
 *                       :       v                               |  :
 * contended             :    (*,x,y) +--> (*,0,0) ---> (*,0,1) -'  :
 *   queue               :         ^--'                             :
 */
int __lockfunc resilient_queued_spin_lock_slowpath(rqspinlock_t *lock, u32 val)
{
	struct mcs_spinlock *prev, *next, *node;
	struct rqspinlock_timeout ts;
	int idx, ret = 0;
	u32 old, tail;

	if (resilient_virt_spin_lock_enabled())
		return resilient_virt_spin_lock(lock);

	RES_INIT_TIMEOUT(ts);

	/*
	 * Wait for in-progress pending->locked hand-overs with a bounded
	 * number of spins so that we guarantee forward progress.
	 *
	 * 0,1,0 -> 0,0,1
	 */
	if ((val & ~RQ_OWNER_RESIDUE_MASK) == RQ_PENDING_VAL) {
		int cnt = RQ_PENDING_LOOPS;
		val = atomic_cond_read_relaxed(&lock->val,
					       ((VAL & ~RQ_OWNER_RESIDUE_MASK) != RQ_PENDING_VAL) || !cnt--);
	}

	/*
	 * If we observe any contention; queue.
	 */
	if (val & ~RQ_LOCKED_OWNER_MASK)
		goto queue;

	/*
	 * Reserve pending optimistically, retaining the baseline admission
	 * path. If a queue appeared, undo only a reservation that we created.
	 */
	val = rq_fetch_set_pending_acquire(lock);
	if (unlikely(val & ~RQ_LOCKED_OWNER_MASK)) {
		if (!(val & RQ_PENDING_MASK))
			rq_undo_pending(lock);
		goto queue;
	}

	/* Deadlock detection entry already held after failing fast path. */

	/*
	 * Pending excludes new owners. If the previous owner is still locked,
	 * acquire-observe its byte release before the plain halfword handover.
	 * The pending helper otherwise supplies the acquisition ordering.
	 */
	if (val & RQ_LOCKED_MASK) {
		RES_RESET_TIMEOUT(ts, RES_DEF_TIMEOUT);
		res_smp_cond_load_acquire(&lock->locked, !VAL ||
					  RES_CHECK_TIMEOUT(ts, ret, RQ_LOCKED_MASK));
	}

	if (ret) {
		/*
		 * We waited for the locked bit to go back to 0, as the pending
		 * waiter, but timed out. We need to clear the pending bit since
		 * we own it. Once a stuck owner has been recovered, the lock
		 * must be restored to a valid state, hence removing the pending
		 * bit is necessary.
		 *
		 * *,1,* -> *,0,*
		 */
		rq_clear_pending(lock, val);
		lockevent_inc(rqspinlock_lock_timeout);
		goto err_release_entry;
	}

	/*
	 * take ownership and clear the pending bit.
	 *
	 * 0,1,0 -> 0,0,1
	 */
	rq_clear_pending_set_locked(lock);
	lockevent_inc(lock_pending);
	return 0;

	/*
	 * End of pending bit optimistic spinning and beginning of MCS
	 * queuing.
	 */
queue:
	/*
	 * Do not queue if we're a waiter and someone is attempting this lock on
	 * the same CPU. In case of NMIs, this prevents long timeouts where we
	 * interrupt the pending waiter, and the owner, that will eventually
	 * signal the head of our queue, both of which are logically but not
	 * physically part of the queue, hence outside the scope of the idx > 0
	 * check above for the trylock fallback.
	 */
	if (check_deadlock_AA(lock)) {
		ret = -EDEADLK;
		goto err_release_entry;
	}

	lockevent_inc(lock_slowpath);
	/* Deadlock detection entry already held after failing fast path. */
	node = this_cpu_ptr(&rqnodes[0].mcs);
	idx = node->count++;
	tail = rq_encode_tail(smp_processor_id(), idx);

	trace_contention_begin(lock, LCB_F_SPIN);

	/*
	 * Three nodes cover task, softirq, and hardirq nesting. An NMI must
	 * not queue behind a context it interrupted, so it uses a node only
	 * when the count was zero. If no node can be used, try once without
	 * queueing and report deadlock on failure. Unlike qspinlock, this
	 * lock can fail instead of spinning unfairly outside the queue.
	 */
	if (unlikely(idx >= RQ_MAX_NODES || (in_nmi() && idx > 0))) {
		lockevent_inc(lock_no_node);
		if (!rq_trylock(lock)) {
			ret = -EDEADLK;
			goto err_release_node;
		}
		goto release;
	}

	node = rq_grab_mcs_node(node, idx);

	/*
	 * Keep counts of non-zero index values:
	 */
	lockevent_cond_inc(lock_use_node2 + idx - 1, idx);

	/*
	 * Ensure that we increment the head node->count before initialising
	 * the actual node. If the compiler is kind enough to reorder these
	 * stores, then an IRQ could overwrite our assignments.
	 */
	barrier();

	node->locked = 0;
	node->next = NULL;

	/*
	 * We touched a (possibly) cold cacheline in the per-cpu queue node;
	 * attempt the trylock once more in the hope someone let go while we
	 * weren't watching.
	 */
	if (rq_trylock(lock))
		goto release;

	/*
	 * Ensure that the initialisation of @node is complete before we
	 * publish the updated tail via rq_xchg_tail() and potentially link
	 * @node into the waitqueue via WRITE_ONCE(prev->next, node) below.
	 */
	smp_wmb();

	/*
	 * Publish the updated tail.
	 * We have already touched the queueing cacheline; don't bother with
	 * pending stuff.
	 *
	 * p,*,* -> n,*,*
	 */
	old = rq_xchg_tail(lock, tail);
	next = NULL;

	/*
	 * if there was a previous node; link it and wait until reaching the
	 * head of the waitqueue.
	 */
	if (old & RQ_TAIL_MASK) {
		int val;

		prev = rq_decode_tail(old, rqnodes);

		/* Link @node into the waitqueue. */
		WRITE_ONCE(prev->next, node);

		val = arch_mcs_spin_lock_contended(&node->locked);
		if (val == RES_TIMEOUT_VAL) {
			ret = -ETIMEDOUT;
			goto waitq_timeout;
		}

		/*
		 * While waiting for the MCS lock, the next pointer may have
		 * been set by another lock waiter. We optimistically load
		 * the next pointer & prefetch the cacheline for writing
		 * to reduce latency in the upcoming MCS unlock operation.
		 */
		next = READ_ONCE(node->next);
		if (next)
			prefetchw(next);
	}

	/*
	 * we're at the head of the waitqueue, wait for the owner & pending to
	 * go away.
	 *
	 * *,x,y -> *,0,0
	 *
	 * this wait loop must use a load-acquire such that we match the
	 * store-release that clears the locked bit and create lock
	 * sequentiality; this is because the rq_set_locked() function below
	 * does not imply a full barrier.
	 *
	 * We use RES_DEF_TIMEOUT * 2 as the duration, as RES_DEF_TIMEOUT is
	 * meant to span maximum allowed time per critical section, and we may
	 * have both the owner of the lock and the pending bit waiter ahead of
	 * us.
	 */
	RES_RESET_TIMEOUT(ts, RES_DEF_TIMEOUT * 2);
	val = res_atomic_cond_read_acquire(&lock->val, !(VAL & RQ_LOCKED_PENDING_MASK) ||
					   RES_CHECK_TIMEOUT(ts, ret, RQ_LOCKED_PENDING_MASK));

	/* Disable queue destruction when we detect deadlocks. */
	if (ret == -EDEADLK) {
		if (!rq_try_cmpxchg_tail(lock, tail, 0)) {
			next = smp_cond_load_relaxed(&node->next, (VAL));
			arch_mcs_spin_unlock_contended(&next->locked);
		}
		goto err_release_node;
	}

waitq_timeout:
	if (ret) {
		/*
		 * If the tail is still pointing to us, then we are the final waiter,
		 * and are responsible for resetting the tail back to 0. Otherwise, if
		 * the cmpxchg operation fails, we signal the next waiter to take exit
		 * and try the same. For a waiter with tail node 'n':
		 *
		 * n,*,* -> 0,*,*
		 *
		 * Tail cleanup preserves locked, owner residue, and pending even
		 * when an optimistic pending setter races with queue teardown.
		 *
		 * We terminate the whole wait queue for two reasons. Firstly,
		 * we eschew per-waiter timeouts with one applied at the head of
		 * the wait queue.  This allows everyone to break out faster
		 * once we've seen the owner / pending waiter not responding for
		 * the timeout duration from the head.  Secondly, it avoids
		 * complicated synchronization, because when not leaving in FIFO
		 * order, prev's next pointer needs to be fixed up etc.
		 */
		if (!rq_try_cmpxchg_tail(lock, tail, 0)) {
			next = smp_cond_load_relaxed(&node->next, VAL);
			WRITE_ONCE(next->locked, RES_TIMEOUT_VAL);
		}
		lockevent_inc(rqspinlock_lock_timeout);
		goto err_release_node;
	}

	/*
	 * claim the lock:
	 *
	 * n,0,0 -> 0,0,1 : lock, uncontended
	 * *,*,0 -> *,*,1 : lock, contended
	 *
	 * If the queue head is the only one in the queue (lock value == tail)
	 * and nobody is pending, clear the tail code and grab the lock.
	 * Otherwise, we only need to grab the lock.
	 */

	if ((val & RQ_TAIL_MASK) == tail) {
		u32 new = rq_locked_val();

		for (;;) {
			if (atomic_try_cmpxchg_relaxed(&lock->val, &val, new))
				goto release; /* No queued successor */
			if ((val & RQ_TAIL_MASK) != tail)
				break;
			/* A pending claimant can abandon before publishing a tail. */
			new = rq_locked_val() | (val & RQ_PENDING_MASK);
		}
	}

	/*
	 * A different tail proves that a successor will publish node->next.
	 * Preserve pending while installing ownership; a racing claimant may
	 * still be undoing its speculative reservation against this queue.
	 */
	rq_set_locked(lock, val);

	/*
	 * contended path; wait for next if not observed yet, release.
	 */
	if (!next)
		next = smp_cond_load_relaxed(&node->next, (VAL));

	arch_mcs_spin_unlock_contended(&next->locked);

release:
	trace_contention_end(lock, 0);

	/*
	 * release the node
	 */
	__this_cpu_dec(rqnodes[0].mcs.count);
	return ret;
err_release_node:
	trace_contention_end(lock, ret);
	__this_cpu_dec(rqnodes[0].mcs.count);
err_release_entry:
	release_held_lock_entry();
	return ret;
}
EXPORT_SYMBOL_GPL(resilient_queued_spin_lock_slowpath);

#endif /* CONFIG_QUEUED_SPINLOCKS */

__bpf_kfunc_start_defs();

static void bpf_prog_report_rqspinlock_violation(const char *str, void *lock, bool irqsave)
{
	struct rqspinlock_held *rqh = this_cpu_ptr(&rqspinlock_held_locks);
	u32 val = atomic_read(&((rqspinlock_t *)lock)->val);
	int owner = rq_lock_owner(val);
	struct bpf_stream_stage ss;
	struct bpf_prog *prog;

	prog = bpf_prog_find_from_stack();
	if (!prog)
		return;
	bpf_stream_stage(ss, prog, BPF_STDERR, ({
		bpf_stream_printk(ss, "ERROR: %s for bpf_res_spin_lock%s\n", str, irqsave ? "_irqsave" : "");
		bpf_stream_printk(ss, "Attempted lock   = 0x%px\n", lock);
		if (!(val & RQ_LOCKED_MASK))
			bpf_stream_printk(ss, "Lock owner CPU   = none\n");
		else if (owner < 0)
			bpf_stream_printk(ss, "Lock owner CPU   = unknown\n");
		else
			bpf_stream_printk(ss, "Lock owner CPU   = %d\n", owner);
		bpf_stream_printk(ss, "Total held locks = %d\n", rqh->cnt);
		for (int i = 0; i < min(RES_NR_HELD, rqh->cnt); i++)
			bpf_stream_printk(ss, "Held lock[%2d] = 0x%px\n", i, rqh->locks[i]);
		bpf_stream_dump_stack(ss);
	}));
}

#define REPORT_STR(ret) ({ (ret) == -ETIMEDOUT ? "Timeout detected" : "AA or ABBA deadlock detected"; })

__bpf_kfunc int bpf_res_spin_lock(struct bpf_res_spin_lock *lock)
{
	int ret;

	BUILD_BUG_ON(sizeof(rqspinlock_t) != sizeof(struct bpf_res_spin_lock));

	preempt_disable();
	ret = res_spin_lock((rqspinlock_t *)lock);
	if (unlikely(ret)) {
		bpf_prog_report_rqspinlock_violation(REPORT_STR(ret), lock, false);
		preempt_enable();
		return ret;
	}
	return 0;
}

__bpf_kfunc void bpf_res_spin_unlock(struct bpf_res_spin_lock *lock)
{
	res_spin_unlock((rqspinlock_t *)lock);
	preempt_enable();
}

__bpf_kfunc int bpf_res_spin_lock_irqsave(struct bpf_res_spin_lock *lock, unsigned long *flags__irq_flag)
{
	u64 *ptr = (u64 *)flags__irq_flag;
	unsigned long flags;
	int ret;

	preempt_disable();
	local_irq_save(flags);
	ret = res_spin_lock((rqspinlock_t *)lock);
	if (unlikely(ret)) {
		bpf_prog_report_rqspinlock_violation(REPORT_STR(ret), lock, true);
		local_irq_restore(flags);
		preempt_enable();
		return ret;
	}
	*ptr = flags;
	return 0;
}

__bpf_kfunc void bpf_res_spin_unlock_irqrestore(struct bpf_res_spin_lock *lock, unsigned long *flags__irq_flag)
{
	u64 *ptr = (u64 *)flags__irq_flag;
	unsigned long flags = *ptr;

	res_spin_unlock((rqspinlock_t *)lock);
	local_irq_restore(flags);
	preempt_enable();
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(rqspinlock_kfunc_ids)
BTF_ID_FLAGS(func, bpf_res_spin_lock, KF_RET_NULL | KF_SPINLOCK_SAFE)
BTF_ID_FLAGS(func, bpf_res_spin_unlock, KF_SPINLOCK_SAFE)
BTF_ID_FLAGS(func, bpf_res_spin_lock_irqsave, KF_RET_NULL | KF_SPINLOCK_SAFE)
BTF_ID_FLAGS(func, bpf_res_spin_unlock_irqrestore, KF_SPINLOCK_SAFE)
BTF_KFUNCS_END(rqspinlock_kfunc_ids)

static const struct btf_kfunc_id_set rqspinlock_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &rqspinlock_kfunc_ids,
};

static __init int rqspinlock_register_kfuncs(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &rqspinlock_kfunc_set);
}
late_initcall(rqspinlock_register_kfuncs);
