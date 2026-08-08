// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/hrtimer.h>
#include <linux/rcupdate_trace.h>
#include <linux/wait.h>

struct bpf_waitq_kern {
	wait_queue_head_t waitq;
	struct rcu_head rcu;
	u32 waiters;
	bool draining;
};

struct bpf_waitq_opaque {
	struct bpf_waitq_kern *waitq;
} __aligned(8);

static void bpf_waitq_free_rcu(struct rcu_head *rcu)
{
	struct bpf_waitq_kern *waitq = container_of(rcu, struct bpf_waitq_kern, rcu);
	unsigned long flags;
	bool free_waitq;

	spin_lock_irqsave(&waitq->waitq.lock, flags);
	waitq->draining = true;
	__wake_up_locked(&waitq->waitq, TASK_NORMAL, 0);
	free_waitq = !waitq->waiters;
	spin_unlock_irqrestore(&waitq->waitq.lock, flags);

	if (free_waitq)
		kfree(waitq);
}

void bpf_waitq_cancel_and_free(void *val)
{
	struct bpf_waitq_opaque *opaque = val;
	struct bpf_waitq_kern *waitq;

	waitq = xchg(&opaque->waitq, NULL);
	if (waitq)
		call_rcu_tasks_trace(&waitq->rcu, bpf_waitq_free_rcu);
}

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_waitq_init(struct bpf_waitq *waitq, void *p__const_map,
			       unsigned int flags)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_map *map = p__const_map;
	struct bpf_waitq_kern *new_waitq;

	BUILD_BUG_ON(sizeof(struct bpf_waitq_opaque) > sizeof(struct bpf_waitq));
	BUILD_BUG_ON(__alignof__(struct bpf_waitq_opaque) != __alignof__(struct bpf_waitq));

	if (flags)
		return -EINVAL;
	if (READ_ONCE(opaque->waitq))
		return -EBUSY;

	new_waitq = bpf_map_kzalloc(map, sizeof(*new_waitq), GFP_KERNEL | __GFP_NOWARN);
	if (!new_waitq)
		return -ENOMEM;
	init_waitqueue_head(&new_waitq->waitq);

	if (cmpxchg(&opaque->waitq, NULL, new_waitq)) {
		kfree(new_waitq);
		return -EBUSY;
	}

	/*
	 * Order publication against the final map user-reference release. Either
	 * release observes the queue or this side observes a zero user count.
	 */
	smp_mb();
	if (!atomic64_read(&map->usercnt)) {
		bpf_waitq_cancel_and_free(opaque);
		return -EPERM;
	}

	return 0;
}

__bpf_kfunc int bpf_waitq_wait(struct bpf_waitq *waitq, const u32 *word,
			       u32 expected, u64 timeout_ns, u64 flags)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_waitq_kern *waitq_kern;
	wait_queue_entry_t entry;
	unsigned long irq_flags;
	bool free_waitq = false;
	int ret = 0;

	if (flags)
		return -EINVAL;
	/* Read with acquire semantics below, which some architectures fault on unaligned. */
	if (!IS_ALIGNED((unsigned long)word, sizeof(*word)))
		return -EINVAL;

	waitq_kern = READ_ONCE(opaque->waitq);
	if (!waitq_kern)
		return -EINVAL;

	/* A waker unlinks the entry, which tells a wakeup from a timeout below. */
	init_wait_entry(&entry, WQ_FLAG_EXCLUSIVE);

	spin_lock_irqsave(&waitq_kern->waitq.lock, irq_flags);
	if (waitq_kern->draining) {
		ret = -ENOENT;
		goto unlock;
	}
	/* Observe the condition update that precedes bpf_waitq_wake(). */
	if (smp_load_acquire(word) != expected) {
		ret = -EAGAIN;
		goto unlock;
	}
	__add_wait_queue_entry_tail(&waitq_kern->waitq, &entry);
	waitq_kern->waiters++;
	set_current_state(TASK_UNINTERRUPTIBLE);
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, irq_flags);

	migrate_enable();
	rcu_read_unlock_trace();

	if (timeout_ns == U64_MAX) {
		schedule();
	} else {
		ktime_t expires = min_t(u64, timeout_ns, KTIME_MAX);

		if (!schedule_hrtimeout(&expires, HRTIMER_MODE_REL))
			ret = -ETIMEDOUT;
	}
	__set_current_state(TASK_RUNNING);

	spin_lock_irqsave(&waitq_kern->waitq.lock, irq_flags);
	/*
	 * An exclusive wakeup that found this entry went to nobody else, so
	 * it is this waiter's even if the timeout fired at the same time.
	 */
	if (list_empty(&entry.entry))
		ret = 0;
	else
		list_del_init(&entry.entry);
	if (!--waitq_kern->waiters && waitq_kern->draining)
		free_waitq = true;
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, irq_flags);

	if (free_waitq)
		kfree(waitq_kern);

	rcu_read_lock_trace();
	migrate_disable();
	return ret;

unlock:
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, irq_flags);
	return ret;
}

__bpf_kfunc int bpf_waitq_wake(struct bpf_waitq *waitq, u32 nr, u64 flags)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_waitq_kern *waitq_kern;
	int nr_exclusive;

	if (flags)
		return -EINVAL;
	if (!nr)
		return 0;

	waitq_kern = READ_ONCE(opaque->waitq);
	if (!waitq_kern)
		return -EINVAL;

	nr_exclusive = nr == U32_MAX ? 0 : min_t(u32, nr, INT_MAX);
	/* Publish BPF-side condition updates before waking a queued waiter. */
	smp_mb();
	return __wake_up(&waitq_kern->waitq, TASK_NORMAL, nr_exclusive, NULL);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_waitq_kfunc_ids)
BTF_ID_FLAGS(func, bpf_waitq_init, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_waitq_wait, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_waitq_wake)
BTF_KFUNCS_END(bpf_waitq_kfunc_ids)

static const struct btf_kfunc_id_set bpf_waitq_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_waitq_kfunc_ids,
};

static int __init bpf_waitq_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_waitq_kfunc_set);
}
late_initcall(bpf_waitq_kfunc_init);
