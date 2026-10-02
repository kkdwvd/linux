// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>
#include <linux/file.h>
#include <linux/hrtimer.h>
#include <linux/kthread.h>
#include <linux/poll.h>
#include <linux/rbtree.h>
#include <linux/rcupdate_trace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/wait.h>

struct bpf_waitq_kern {
	wait_queue_head_t waitq;
	struct rcu_head rcu;
	refcount_t refs;
	u32 sequence;
	bool draining;
	/*
	 * Coroutine frames parked on this queue, see bpf_coro_park_file():
	 * waiting for their event on the list, and ready to be handed back by
	 * bpf_coro_unpark() in the tree, ordered by the priority they were
	 * parked with and then by the order they became ready in. Both are
	 * protected by waitq.lock.
	 */
	struct list_head parked;
	struct rb_root_cached ready;
	u64 ready_seq;
};

/*
 * A parked coroutine frame. The frame itself is the program's allocation
 * from bpf_coro_frame_alloc(); this is the kernel's handle on it while the
 * program has given it up: the wait queue entry on the file it waits for,
 * the node on the owning bpf_waitq's parked list and, once ready, the node
 * in its ready tree.
 */
enum bpf_coro_park_state {
	BPF_CORO_PARK_WAITING,
	BPF_CORO_PARK_READY,
	BPF_CORO_PARK_CANCELLED,
};

struct bpf_coro_park {
	struct list_head node;
	struct rb_node ready_node;
	wait_queue_entry_t wait;
	wait_queue_head_t *whead;
	poll_table pt;
	struct file *file;
	struct bpf_waitq_kern *waitq;
	void *frame;
	u64 prio;	/* lower is handed back first */
	u64 seq;	/* among equal priorities, the order of becoming ready */
	__poll_t events;
	__poll_t revents;
	enum bpf_coro_park_state state;
	bool multi;	/* the file polls more than one wait queue head */
};

struct bpf_waitq_opaque {
	struct bpf_waitq_kern *waitq;
} __aligned(8);

struct bpf_kthread_kern {
	struct task_struct *task;
	struct bpf_map *map;
	struct bpf_prog *prog;
	struct cgroup *cgrp;
	void *callback_fn;
	void *value;
	struct completion initialized;
	struct completion exited;
	spinlock_t lock;
	struct work_struct stop_work;
	struct rcu_head rcu;
	bool start_requested;
	bool stopping;
	bool io_thread;	/* created by create_io_thread() in a user process */
};

struct bpf_kthread_opaque {
	struct bpf_kthread_kern *kthread;
} __aligned(8);

struct bpf_waitq_kern *bpf_waitq_get(struct bpf_waitq *waitq)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_waitq_kern *kern = READ_ONCE(opaque->waitq);

	if (kern)
		refcount_inc(&kern->refs);
	return kern;
}

void bpf_waitq_put(struct bpf_waitq_kern *waitq)
{
	/*
	 * A producer may publish the queue through an RCU-protected pointer
	 * and signal it without holding a reference, so the memory outlives
	 * the last reference by a grace period.
	 */
	if (refcount_dec_and_test(&waitq->refs))
		kfree_rcu(waitq, rcu);
}

int bpf_waitq_signal(struct bpf_waitq_kern *waitq, u32 nr)
{
	unsigned long flags;
	int ret = -ENOENT;

	spin_lock_irqsave(&waitq->waitq.lock, flags);
	if (!waitq->draining) {
		smp_store_release(&waitq->sequence, waitq->sequence + 1);
		__wake_up_locked(&waitq->waitq, TASK_NORMAL,
				 nr == U32_MAX ? 0 : min_t(u32, nr, INT_MAX));
		ret = 0;
	}
	spin_unlock_irqrestore(&waitq->waitq.lock, flags);
	return ret;
}

static void bpf_coro_park_drain(struct bpf_waitq_kern *waitq);

static void bpf_waitq_free_rcu(struct rcu_head *rcu)
{
	struct bpf_waitq_kern *waitq = container_of(rcu, struct bpf_waitq_kern, rcu);
	unsigned long flags;

	spin_lock_irqsave(&waitq->waitq.lock, flags);
	waitq->draining = true;
	__wake_up_locked(&waitq->waitq, TASK_NORMAL, 0);
	spin_unlock_irqrestore(&waitq->waitq.lock, flags);
	bpf_coro_park_drain(waitq);
	bpf_waitq_put(waitq);
}

void bpf_waitq_cancel_and_free(void *val)
{
	struct bpf_waitq_opaque *opaque = val;
	struct bpf_waitq_kern *waitq;

	waitq = xchg(&opaque->waitq, NULL);
	if (waitq)
		call_rcu_tasks_trace(&waitq->rcu, bpf_waitq_free_rcu);
}

static void bpf_kthread_free_rcu(struct rcu_head *rcu)
{
	struct bpf_kthread_kern *kthread = container_of(rcu, struct bpf_kthread_kern, rcu);

	bpf_prog_put(kthread->prog);
	kfree(kthread);
}

static int bpf_kthread_stop_one(struct bpf_kthread_kern *kthread)
{
	struct task_struct *task;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&kthread->lock, flags);
	kthread->stopping = true;
	task = kthread->task;
	spin_unlock_irqrestore(&kthread->lock, flags);

	if (!task) {
		ret = -ENOENT;
	} else if (kthread->io_thread) {
		/*
		 * Not a kthread: it leaves its loop on the stopping flag, so
		 * break any interruptible sleep it is in, a blocking system
		 * call included, and wait for it to run off the end.
		 */
		set_notify_signal(task);
		wait_for_completion(&kthread->exited);
		put_task_struct(task);
		ret = 0;
	} else {
		ret = kthread_stop_put(task);
	}

	spin_lock_irqsave(&kthread->lock, flags);
	kthread->task = NULL;
	spin_unlock_irqrestore(&kthread->lock, flags);
#ifdef CONFIG_CGROUPS
	if (kthread->cgrp) {
		cgroup_put(kthread->cgrp);
		kthread->cgrp = NULL;
	}
#endif

	call_rcu_tasks_trace(&kthread->rcu, bpf_kthread_free_rcu);
	return ret;
}

static void bpf_kthread_stop_work(struct work_struct *work)
{
	struct bpf_kthread_kern *kthread = container_of(work, struct bpf_kthread_kern, stop_work);

	bpf_kthread_stop_one(kthread);
}

static void bpf_kthread_begin_stop(struct bpf_kthread_kern *kthread)
{
	struct task_struct *task = NULL;
	unsigned long flags;

	spin_lock_irqsave(&kthread->lock, flags);
	kthread->stopping = true;
	if (kthread->task) {
		task = kthread->task;
		get_task_struct(task);
	}
	spin_unlock_irqrestore(&kthread->lock, flags);

	if (task) {
		if (kthread->io_thread)
			set_notify_signal(task);
		else
			wake_up_process(task);
		put_task_struct(task);
	}
}

void bpf_kthread_cancel_and_free(void *val)
{
	struct bpf_kthread_opaque *opaque = val;
	struct bpf_kthread_kern *kthread;

	kthread = xchg(&opaque->kthread, NULL);
	if (!kthread)
		return;

	bpf_kthread_begin_stop(kthread);
	schedule_work(&kthread->stop_work);
}

static int bpf_kthread_run(void *data)
{
	struct bpf_kthread_kern *kthread = data;
	bpf_callback_t callback_fn = READ_ONCE(kthread->callback_fn);
	int ret = 0;

	set_current_state(TASK_IDLE);
	complete(&kthread->initialized);
	while (!READ_ONCE(kthread->start_requested) &&
	       !kthread_should_stop() && !READ_ONCE(kthread->stopping)) {
		schedule();
		set_current_state(TASK_IDLE);
	}
	__set_current_state(TASK_RUNNING);

	while (!kthread_should_stop() && !READ_ONCE(kthread->stopping)) {
		void *key;
		u32 idx;

		rcu_read_lock_trace();
		migrate_disable();
		if (READ_ONCE(kthread->stopping)) {
			migrate_enable();
			rcu_read_unlock_trace();
			break;
		}

		key = bpf_map_key_from_value(kthread->map, kthread->value, &idx);
		ret = (int)callback_fn((u64)(long)kthread->map, (u64)(long)key,
				       (u64)(long)kthread->value, 0, 0);

		migrate_enable();
		rcu_read_unlock_trace();
		if (ret)
			break;
		cond_resched();
	}

	return ret;
}

/*
 * The body of a BPF io thread: a thread of the process that created it,
 * sharing its address space, file table and credentials, that never
 * returns to user space. Its loop is the kthread's, except that it ends on
 * the stopping flag or a fatal signal rather than kthread_should_stop(),
 * and that it exits itself, as every thread of a user process must.
 */
static int bpf_kthread_run_io(void *data)
{
	struct bpf_kthread_kern *kthread = data;
	bpf_callback_t callback_fn = READ_ONCE(kthread->callback_fn);
	char comm[TASK_COMM_LEN];
	int ret = 0;

	snprintf(comm, sizeof(comm), "bpf_iothread/%u", kthread->map->id);
	set_task_comm(current, comm);
	complete(&kthread->initialized);

	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (READ_ONCE(kthread->start_requested) || READ_ONCE(kthread->stopping) ||
		    signal_pending(current))
			break;
		schedule();
	}
	__set_current_state(TASK_RUNNING);

	while (!READ_ONCE(kthread->stopping)) {
		void *key;
		u32 idx;

		if (signal_pending(current)) {
			struct ksignal ksig;

			/*
			 * Only SIGKILL and SIGSTOP reach a user worker, and
			 * TIF_NOTIFY_SIGNAL from the stop path. A fatal signal
			 * means the process is going away.
			 */
			if (get_signal(&ksig))
				break;
			continue;
		}

		rcu_read_lock_trace();
		migrate_disable();
		key = bpf_map_key_from_value(kthread->map, kthread->value, &idx);
		ret = (int)callback_fn((u64)(long)kthread->map, (u64)(long)key,
				       (u64)(long)kthread->value, 0, 0);
		migrate_enable();
		rcu_read_unlock_trace();
		if (ret)
			break;
		cond_resched();
	}

	complete(&kthread->exited);
	do_exit(0);
}

/*
 * Whether @kthread is the BPF io thread calling: the kfuncs that act on
 * behalf of the thread's process check this so that no other context can
 * borrow its identity.
 */
bool bpf_kthread_is_current_io(struct bpf_kthread *kthread)
{
	struct bpf_kthread_opaque *opaque = (struct bpf_kthread_opaque *)kthread;
	struct bpf_kthread_kern *kern = READ_ONCE(opaque->kthread);

	return kern && kern->io_thread && READ_ONCE(kern->task) == current;
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
	INIT_LIST_HEAD(&new_waitq->parked);
	new_waitq->ready = RB_ROOT_CACHED;
	refcount_set(&new_waitq->refs, 1);

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

static int __bpf_waitq_wait(struct bpf_waitq *waitq, const u32 *word,
			   u32 expected, u64 timeout_ns, u64 flags)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_waitq_kern *waitq_kern;
	wait_queue_entry_t entry;
	unsigned long irq_flags;
	bool user_task = !(current->flags & PF_KTHREAD);
	int ret = 0;

	if (flags)
		return -EINVAL;

	waitq_kern = READ_ONCE(opaque->waitq);
	if (!waitq_kern)
		return -EINVAL;
	if (!word)
		word = &waitq_kern->sequence;

	init_waitqueue_entry(&entry, current);
	entry.flags |= WQ_FLAG_EXCLUSIVE;

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
	refcount_inc(&waitq_kern->refs);
	/*
	 * A thread of a user process, a BPF io thread included, must wake for
	 * signals: SIGKILL, and for the io thread the stop path's
	 * TIF_NOTIFY_SIGNAL, so it sleeps interruptibly. A kthread has no
	 * signals and sleeps in TASK_IDLE.
	 */
	set_current_state(user_task ? TASK_INTERRUPTIBLE : TASK_IDLE);
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, irq_flags);

	migrate_enable();
	rcu_read_unlock_trace();

	if ((current->flags & PF_KTHREAD) && kthread_should_stop()) {
		__set_current_state(TASK_RUNNING);
		ret = -EINTR;
	} else if (user_task && signal_pending(current)) {
		__set_current_state(TASK_RUNNING);
		ret = -EINTR;
	} else if (timeout_ns == U64_MAX) {
		schedule();
	} else {
		ktime_t expires = ns_to_ktime(timeout_ns);

		if (!schedule_hrtimeout(&expires, HRTIMER_MODE_REL))
			ret = -ETIMEDOUT;
	}
	__set_current_state(TASK_RUNNING);

	spin_lock_irqsave(&waitq_kern->waitq.lock, irq_flags);
	list_del_init(&entry.entry);
	if (waitq_kern->draining)
		ret = -ENOENT;
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, irq_flags);
	bpf_waitq_put(waitq_kern);

	rcu_read_lock_trace();
	migrate_disable();
	return ret;

unlock:
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, irq_flags);
	return ret;
}

__bpf_kfunc int bpf_waitq_wait(struct bpf_waitq *waitq, const u32 *word,
			     u32 expected, u64 timeout_ns, u64 flags)
{
	return __bpf_waitq_wait(waitq, word, expected, timeout_ns, flags);
}

/* Sample before checking readiness, then wait using the sampled sequence. */
__bpf_kfunc u32 bpf_waitq_sequence(struct bpf_waitq *waitq)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_waitq_kern *kern = READ_ONCE(opaque->waitq);

	return kern ? smp_load_acquire(&kern->sequence) : 0;
}

__bpf_kfunc int bpf_waitq_wait_event(struct bpf_waitq *waitq, u32 expected,
				   u64 timeout_ns)
{
	return __bpf_waitq_wait(waitq, NULL, expected, timeout_ns, 0);
}

__bpf_kfunc int bpf_waitq_wake(struct bpf_waitq *waitq, u32 nr, u64 flags)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_waitq_kern *waitq_kern;
	unsigned long irq_flags;

	if (flags)
		return -EINVAL;
	if (!nr)
		return 0;

	waitq_kern = READ_ONCE(opaque->waitq);
	if (!waitq_kern)
		return -EINVAL;

	spin_lock_irqsave(&waitq_kern->waitq.lock, irq_flags);
	smp_store_release(&waitq_kern->sequence, waitq_kern->sequence + 1);
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, irq_flags);
	return __wake_up(&waitq_kern->waitq, TASK_NORMAL,
			 nr == U32_MAX ? 0 : min_t(u32, nr, INT_MAX), NULL);
}

__bpf_kfunc int bpf_kthread_create(struct bpf_kthread *kthread, void *p__const_map,
				   u64 cgroup_id,
				   int (callback_fn)(void *map, int *key, void *value),
				   struct bpf_prog_aux *aux)
{
	struct bpf_kthread_opaque *opaque = (struct bpf_kthread_opaque *)kthread;
	struct bpf_map *map = p__const_map;
	struct bpf_kthread_kern *new_kthread;
	struct bpf_prog *prog;
	struct task_struct *task;
	struct cgroup *cgrp = NULL;
	int err;

	BUILD_BUG_ON(sizeof(struct bpf_kthread_opaque) > sizeof(struct bpf_kthread));
	BUILD_BUG_ON(__alignof__(struct bpf_kthread_opaque) != __alignof__(struct bpf_kthread));

	if (READ_ONCE(opaque->kthread))
		return -EBUSY;

	prog = bpf_prog_inc_not_zero(aux->prog);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	new_kthread = bpf_map_kzalloc(map, sizeof(*new_kthread), GFP_KERNEL | __GFP_NOWARN);
	if (!new_kthread) {
		bpf_prog_put(prog);
		return -ENOMEM;
	}

	new_kthread->map = map;
	new_kthread->prog = prog;
	new_kthread->callback_fn = callback_fn;
	new_kthread->value = (void *)opaque - map->record->kthread_off;
	init_completion(&new_kthread->initialized);
	spin_lock_init(&new_kthread->lock);
	INIT_WORK(&new_kthread->stop_work, bpf_kthread_stop_work);

	if (cgroup_id) {
#ifdef CONFIG_CGROUPS
		cgrp = cgroup_get_from_id(cgroup_id);
		if (IS_ERR(cgrp)) {
			err = PTR_ERR(cgrp);
			goto free_kthread;
		}
		new_kthread->cgrp = cgrp;
#else
		err = -EOPNOTSUPP;
		goto free_kthread;
#endif
	}

	task = kthread_create(bpf_kthread_run, new_kthread, "bpf_kthread/%u", map->id);
	if (IS_ERR(task)) {
		err = PTR_ERR(task);
		goto put_cgroup;
	}
	get_task_struct(task);
	new_kthread->task = task;

	/*
	 * Run the thread up to its park in bpf_kthread_run() before returning.
	 * The generic kthread() prologue that runs first resets the affinity to
	 * the default for the thread's node and only then permits cgroup
	 * migration, so bpf_kthread_bind() and the cgroup attach below take
	 * effect only once it has run.
	 */
	wake_up_process(task);
	wait_for_completion(&new_kthread->initialized);
	if (cgrp) {
		err = cgroup_kthread_attach(cgrp, task);
		if (err)
			goto stop_task;
	}

	if (cmpxchg(&opaque->kthread, NULL, new_kthread)) {
		err = -EBUSY;
		goto stop_task;
	}

	/*
	 * Order publication against the final map user-reference release. Either
	 * release observes the kthread or this side observes a zero user count.
	 */
	smp_mb();
	if (!atomic64_read(&map->usercnt)) {
		bpf_kthread_cancel_and_free(opaque);
		return -EPERM;
	}

	return 0;

stop_task:
	kthread_stop_put(task);
put_cgroup:
	if (cgrp)
		cgroup_put(cgrp);
free_kthread:
	bpf_prog_put(prog);
	kfree(new_kthread);
	return err;
}

/*
 * Create a BPF thread inside the calling process, the way io_uring creates
 * its SQPOLL thread: it shares the address space, file table and
 * credentials of the process, so a callback running on it acts on the
 * process's behalf, see bpf_sys_exec(). Like a kthread it is parked until
 * bpf_kthread_start() and runs the callback until that returns nonzero or
 * bpf_kthread_stop() is called; unlike one it also ends with its process.
 */
__bpf_kfunc int bpf_kthread_create_io(struct bpf_kthread *kthread, void *p__const_map,
				      int (callback_fn)(void *map, int *key, void *value),
				      struct bpf_prog_aux *aux)
{
	struct bpf_kthread_opaque *opaque = (struct bpf_kthread_opaque *)kthread;
	struct bpf_map *map = p__const_map;
	struct bpf_kthread_kern *new_kthread;
	struct bpf_prog *prog;
	struct task_struct *task;
	int err;

	if (READ_ONCE(opaque->kthread))
		return -EBUSY;
	/* Only a user task can be cloned into. */
	if (!current->mm || (current->flags & (PF_KTHREAD | PF_IO_WORKER)))
		return -EINVAL;

	prog = bpf_prog_inc_not_zero(aux->prog);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	new_kthread = bpf_map_kzalloc(map, sizeof(*new_kthread), GFP_KERNEL | __GFP_NOWARN);
	if (!new_kthread) {
		bpf_prog_put(prog);
		return -ENOMEM;
	}

	new_kthread->map = map;
	new_kthread->prog = prog;
	new_kthread->callback_fn = callback_fn;
	new_kthread->value = (void *)opaque - map->record->kthread_off;
	new_kthread->io_thread = true;
	init_completion(&new_kthread->initialized);
	init_completion(&new_kthread->exited);
	spin_lock_init(&new_kthread->lock);
	INIT_WORK(&new_kthread->stop_work, bpf_kthread_stop_work);

	/*
	 * The program runs with migration disabled, and a clone inherits that
	 * state: the thread would never leave it, and the first change of its
	 * affinity would wait forever for it to. Clone with migration enabled,
	 * as the wait queue sleeps do; the Tasks Trace RCU section stays.
	 */
	migrate_enable();
	task = create_io_thread(bpf_kthread_run_io, new_kthread, NUMA_NO_NODE);
	migrate_disable();
	if (IS_ERR(task)) {
		err = PTR_ERR(task);
		goto free_kthread;
	}
	get_task_struct(task);
	new_kthread->task = task;
	wake_up_new_task(task);
	wait_for_completion(&new_kthread->initialized);

	if (cmpxchg(&opaque->kthread, NULL, new_kthread)) {
		err = -EBUSY;
		goto stop_task;
	}

	/* See bpf_kthread_create(). */
	smp_mb();
	if (!atomic64_read(&map->usercnt)) {
		bpf_kthread_cancel_and_free(opaque);
		return -EPERM;
	}

	return 0;

stop_task:
	bpf_kthread_begin_stop(new_kthread);
	wait_for_completion(&new_kthread->exited);
	put_task_struct(task);
free_kthread:
	bpf_prog_put(prog);
	kfree(new_kthread);
	return err;
}

__bpf_kfunc int bpf_kthread_start(struct bpf_kthread *kthread, u64 flags)
{
	struct bpf_kthread_opaque *opaque = (struct bpf_kthread_opaque *)kthread;
	struct bpf_kthread_kern *kthread_kern;
	struct task_struct *task = NULL;
	unsigned long irq_flags;

	if (flags)
		return -EINVAL;

	kthread_kern = READ_ONCE(opaque->kthread);
	if (!kthread_kern)
		return -EINVAL;

	spin_lock_irqsave(&kthread_kern->lock, irq_flags);
	if (!kthread_kern->stopping && kthread_kern->task) {
		kthread_kern->start_requested = true;
		task = kthread_kern->task;
		get_task_struct(task);
	}
	spin_unlock_irqrestore(&kthread_kern->lock, irq_flags);
	if (!task)
		return -ENOENT;

	wake_up_process(task);
	put_task_struct(task);
	return 0;
}

/*
 * Restrict the thread to one CPU. Works before and after bpf_kthread_start():
 * the thread has already run the kthread() prologue that would reset its
 * affinity when bpf_kthread_create() returns, so a parked thread wakes on
 * that CPU and a running one migrates to it. The affinity remains changeable
 * from user space and stays subject to cpusets.
 */
__bpf_kfunc int bpf_kthread_bind(struct bpf_kthread *kthread, u32 cpu)
{
	struct bpf_kthread_opaque *opaque = (struct bpf_kthread_opaque *)kthread;
	struct bpf_kthread_kern *kthread_kern;
	struct task_struct *task = NULL;
	unsigned long irq_flags;
	int ret;

	if (cpu >= nr_cpu_ids || !cpu_possible(cpu))
		return -EINVAL;

	kthread_kern = READ_ONCE(opaque->kthread);
	if (!kthread_kern)
		return -EINVAL;

	spin_lock_irqsave(&kthread_kern->lock, irq_flags);
	if (!kthread_kern->stopping && kthread_kern->task) {
		task = kthread_kern->task;
		get_task_struct(task);
	}
	spin_unlock_irqrestore(&kthread_kern->lock, irq_flags);
	if (!task)
		return -ENOENT;

	ret = set_cpus_allowed_ptr(task, cpumask_of(cpu));
	put_task_struct(task);
	return ret;
}

__bpf_kfunc int bpf_kthread_stop(struct bpf_kthread *kthread, u64 flags)
{
	struct bpf_kthread_opaque *opaque = (struct bpf_kthread_opaque *)kthread;
	struct bpf_kthread_kern *kthread_kern;
	unsigned long irq_flags;

	if (flags)
		return -EINVAL;

	kthread_kern = READ_ONCE(opaque->kthread);
	if (!kthread_kern)
		return -EINVAL;

	spin_lock_irqsave(&kthread_kern->lock, irq_flags);
	if (kthread_kern->task == current) {
		spin_unlock_irqrestore(&kthread_kern->lock, irq_flags);
		return -EDEADLK;
	}
	spin_unlock_irqrestore(&kthread_kern->lock, irq_flags);

	if (cmpxchg(&opaque->kthread, kthread_kern, NULL) != kthread_kern)
		return -ENOENT;

	bpf_kthread_begin_stop(kthread_kern);
	return bpf_kthread_stop_one(kthread_kern);
}

/*
 * Coroutine frames parked on a wait queue.
 *
 * A BPF coroutine that has to wait for a file, say a socket with no data
 * to read, hands its frame to bpf_coro_park_file(): the program gives up
 * the frame and the kernel arms a poll wait on the file. When the file
 * reports the events the frame is moved to the wait queue's ready tree and
 * the queue is signaled like any producer would, so a thread sleeping in
 * bpf_waitq_wait_event() wakes. bpf_coro_unpark() then hands a ready frame
 * back to the program, which resumes the coroutine. The verifier treats an
 * unparked frame's contents as unknown data, as the frame left the program
 * and came back: what the coroutine kept across the wait are plain values.
 *
 * bpf_coro_park_prio() parks a frame ready at once with a priority: the
 * ready tree hands back the lowest priority first and, among equal ones,
 * the first to become ready, so a thread that resumes frames in unpark
 * order runs the scheduling policy whose priorities the program computed,
 * FIFO when they are all the same. A program that yields from a context
 * that cannot sleep, an XDP program handing the rest of a request to a
 * thread say, parks this way: the handle is allocated without sleeping.
 */
static void bpf_coro_park_queue_proc(struct file *file, wait_queue_head_t *whead,
				     poll_table *pt)
{
	struct bpf_coro_park *park = container_of(pt, struct bpf_coro_park, pt);

	/* One wait queue head per file is supported, which every socket has. */
	if (park->whead) {
		park->multi = true;
		return;
	}
	park->whead = whead;
	add_wait_queue(whead, &park->wait);
}

static bool bpf_coro_park_less(struct rb_node *a, const struct rb_node *b)
{
	const struct bpf_coro_park *pa = rb_entry(a, struct bpf_coro_park, ready_node);
	const struct bpf_coro_park *pb = rb_entry(b, struct bpf_coro_park, ready_node);

	if (pa->prio != pb->prio)
		return pa->prio < pb->prio;
	return pa->seq < pb->seq;
}

/* Move @park to the ready tree and signal the queue; the lock is held. */
static void bpf_coro_park_set_ready(struct bpf_coro_park *park, __poll_t revents)
{
	struct bpf_waitq_kern *waitq = park->waitq;

	if (park->state != BPF_CORO_PARK_WAITING)
		return;
	park->state = BPF_CORO_PARK_READY;
	park->revents = revents;
	list_del_init(&park->node);
	park->seq = waitq->ready_seq++;
	rb_add_cached(&park->ready_node, &waitq->ready, bpf_coro_park_less);
	smp_store_release(&waitq->sequence, waitq->sequence + 1);
	__wake_up_locked(&waitq->waitq, TASK_NORMAL, 1);
}

/* Take the first ready frame out of the tree; the lock is held. */
static struct bpf_coro_park *bpf_coro_park_take_ready(struct bpf_waitq_kern *waitq)
{
	struct rb_node *node = rb_first_cached(&waitq->ready);

	if (!node)
		return NULL;
	rb_erase_cached(node, &waitq->ready);
	return rb_entry(node, struct bpf_coro_park, ready_node);
}

static int bpf_coro_park_wake(wait_queue_entry_t *wait, unsigned int mode, int sync, void *key)
{
	struct bpf_coro_park *park = container_of(wait, struct bpf_coro_park, wait);
	struct bpf_waitq_kern *waitq = park->waitq;
	__poll_t revents = key_to_poll(key);
	unsigned long flags;

	if (key && !(revents & park->events))
		return 0;
	/* Single shot: off the file's queue, whose lock the waker holds. */
	list_del_init(&wait->entry);

	spin_lock_irqsave(&waitq->waitq.lock, flags);
	bpf_coro_park_set_ready(park, revents);
	spin_unlock_irqrestore(&waitq->waitq.lock, flags);
	return 0;
}

static void bpf_coro_park_free(struct bpf_coro_park *park)
{
	if (park->whead)
		remove_wait_queue(park->whead, &park->wait);
	if (park->file)
		fput(park->file);
	kfree(park);
}

/* Drop every parked frame: the queue is going away. */
static void bpf_coro_park_drain(struct bpf_waitq_kern *waitq)
{
	struct bpf_coro_park *park;
	unsigned long flags;

	for (;;) {
		spin_lock_irqsave(&waitq->waitq.lock, flags);
		park = list_first_entry_or_null(&waitq->parked, struct bpf_coro_park, node);
		if (park)
			list_del_init(&park->node);
		else
			park = bpf_coro_park_take_ready(waitq);
		if (park)
			park->state = BPF_CORO_PARK_CANCELLED;
		spin_unlock_irqrestore(&waitq->waitq.lock, flags);
		if (!park)
			break;
		kfree_nolock(park->frame);
		bpf_coro_park_free(park);
	}
}

/*
 * Park the coroutine frame @p__coro_frame until @fd reports @events
 * (EPOLLERR and EPOLLHUP are always included), then queue it on @waitq's
 * ready list and signal the queue. The frame is consumed: the program gets
 * it back from bpf_coro_unpark(). A file descriptor that cannot be waited
 * for makes the frame ready at once, so the coroutine retries and sees the
 * error itself. Only a memory allocation failure loses the frame, in which
 * case the call fails and the frame is freed.
 */
__bpf_kfunc int bpf_coro_park_file(void *p__coro_frame, int fd, u32 events,
				   struct bpf_waitq *waitq)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_waitq_kern *waitq_kern;
	struct bpf_coro_park *park;
	unsigned long flags;
	struct file *file;
	__poll_t mask = 0;

	waitq_kern = READ_ONCE(opaque->waitq);
	if (!waitq_kern) {
		kfree_nolock(p__coro_frame);
		return -EINVAL;
	}

	park = kzalloc(sizeof(*park), GFP_KERNEL | __GFP_ACCOUNT);
	if (!park) {
		kfree_nolock(p__coro_frame);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&park->node);
	init_waitqueue_func_entry(&park->wait, bpf_coro_park_wake);
	park->waitq = waitq_kern;
	park->frame = p__coro_frame;
	park->events = (__force __poll_t)events | EPOLLERR | EPOLLHUP;
	park->state = BPF_CORO_PARK_WAITING;
	init_poll_funcptr(&park->pt, bpf_coro_park_queue_proc);
	park->pt._key = park->events;

	spin_lock_irqsave(&waitq_kern->waitq.lock, flags);
	if (waitq_kern->draining) {
		spin_unlock_irqrestore(&waitq_kern->waitq.lock, flags);
		kfree_nolock(p__coro_frame);
		kfree(park);
		return -ENOENT;
	}
	list_add_tail(&park->node, &waitq_kern->parked);
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, flags);

	/* A kthread has no file table; an io thread shares its process's. */
	file = current->files ? fget(fd) : NULL;
	if (file) {
		park->file = file;
		if (file_can_poll(file))
			mask = vfs_poll(file, &park->pt);
		else
			mask = DEFAULT_POLLMASK;
	} else {
		mask = EPOLLNVAL;
	}

	/*
	 * Ready already, or not waitable (no such descriptor, or a file that
	 * polls more than one queue): queue it now. The wait entry may have
	 * been added by the poll above; the state settles the race with a
	 * wake that fires in between, and the entry comes off the file's
	 * queue here or in the wake, whichever the state says did not happen.
	 */
	if (!file || park->multi || (mask & park->events)) {
		spin_lock_irqsave(&waitq_kern->waitq.lock, flags);
		bpf_coro_park_set_ready(park, mask);
		spin_unlock_irqrestore(&waitq_kern->waitq.lock, flags);
		if (park->whead)
			remove_wait_queue(park->whead, &park->wait);
	}
	return 0;
}

/*
 * Park @p__coro_frame on @waitq's ready tree at once with priority @prio: a
 * yield, the frame comes back from a bpf_coro_unpark() once no frame of a
 * lower priority, or of the same one parked earlier, is ready. Callable
 * from any context that runs programs, as the handle is allocated without
 * sleeping.
 */
__bpf_kfunc int bpf_coro_park_prio(void *p__coro_frame, struct bpf_waitq *waitq, u64 prio)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_waitq_kern *waitq_kern;
	struct bpf_coro_park *park;
	unsigned long flags;

	waitq_kern = READ_ONCE(opaque->waitq);
	if (!waitq_kern) {
		kfree_nolock(p__coro_frame);
		return -EINVAL;
	}
	park = kmalloc_nolock(sizeof(*park), __GFP_ZERO | __GFP_ACCOUNT, NUMA_NO_NODE);
	if (!park) {
		kfree_nolock(p__coro_frame);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&park->node);
	park->waitq = waitq_kern;
	park->frame = p__coro_frame;
	park->prio = prio;
	park->state = BPF_CORO_PARK_WAITING;

	spin_lock_irqsave(&waitq_kern->waitq.lock, flags);
	if (waitq_kern->draining) {
		spin_unlock_irqrestore(&waitq_kern->waitq.lock, flags);
		kfree_nolock(p__coro_frame);
		kfree_nolock(park);
		return -ENOENT;
	}
	list_add_tail(&park->node, &waitq_kern->parked);
	bpf_coro_park_set_ready(park, 0);
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, flags);
	return 0;
}

/* Park @p__coro_frame on @waitq's ready tree at once, behind the frames already there. */
__bpf_kfunc int bpf_coro_park(void *p__coro_frame, struct bpf_waitq *waitq)
{
	return bpf_coro_park_prio(p__coro_frame, waitq, 0);
}

/*
 * Hand back a ready frame parked on @waitq as @size__k bytes of frame, or
 * NULL when none is ready. The frame is the program's again, exactly as it
 * gave it up. The verifier lets the program use @size__k bytes of it, so
 * the allocation behind the frame must be at least that large: frames come
 * from bpf_coro_frame_alloc(), whose size the program also chose, and a
 * smaller one on the list is a program bug that drops the frame.
 */
__bpf_kfunc void *bpf_coro_unpark(struct bpf_waitq *waitq, u64 size__k)
{
	struct bpf_waitq_opaque *opaque = (struct bpf_waitq_opaque *)waitq;
	struct bpf_waitq_kern *waitq_kern;
	struct bpf_coro_park *park;
	unsigned long flags;
	void *frame;

	waitq_kern = READ_ONCE(opaque->waitq);
	if (!waitq_kern)
		return NULL;

	spin_lock_irqsave(&waitq_kern->waitq.lock, flags);
	park = bpf_coro_park_take_ready(waitq_kern);
	spin_unlock_irqrestore(&waitq_kern->waitq.lock, flags);
	if (!park)
		return NULL;

	/*
	 * A ready frame had its wait entry taken off the file's queue by the
	 * wake, or by bpf_coro_park_file() when it was ready at once; only the
	 * file reference remains.
	 */
	park->whead = NULL;
	frame = park->frame;
	if (ksize(frame) < size__k) {
		kfree_nolock(frame);
		frame = NULL;
	}
	bpf_coro_park_free(park);
	return frame;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_waitq_kfunc_ids)
BTF_ID_FLAGS(func, bpf_waitq_init)
BTF_ID_FLAGS(func, bpf_waitq_wait, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_waitq_sequence)
BTF_ID_FLAGS(func, bpf_waitq_wait_event, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_waitq_wake)
BTF_ID_FLAGS(func, bpf_kthread_create, KF_SLEEPABLE | KF_IMPLICIT_ARGS)
BTF_ID_FLAGS(func, bpf_kthread_create_io, KF_SLEEPABLE | KF_IMPLICIT_ARGS)
BTF_ID_FLAGS(func, bpf_kthread_start)
BTF_ID_FLAGS(func, bpf_kthread_bind, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kthread_stop, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_coro_park_file, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_coro_park)
BTF_ID_FLAGS(func, bpf_coro_park_prio)
BTF_ID_FLAGS(func, bpf_coro_unpark, KF_ACQUIRE | KF_RET_NULL)
BTF_KFUNCS_END(bpf_waitq_kfunc_ids)

static const struct btf_kfunc_id_set bpf_waitq_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_waitq_kfunc_ids,
};

/*
 * What a program on a packet path may do with a queue a syscall program
 * owns: hand it coroutine frames and signal it. Nothing here sleeps or
 * allocates with a sleeping allocation.
 */
BTF_KFUNCS_START(bpf_waitq_producer_kfunc_ids)
BTF_ID_FLAGS(func, bpf_waitq_sequence)
BTF_ID_FLAGS(func, bpf_waitq_wake)
BTF_ID_FLAGS(func, bpf_coro_park)
BTF_ID_FLAGS(func, bpf_coro_park_prio)
BTF_KFUNCS_END(bpf_waitq_producer_kfunc_ids)

static const struct btf_kfunc_id_set bpf_waitq_producer_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_waitq_producer_kfunc_ids,
};

static int __init bpf_waitq_kfunc_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_waitq_kfunc_set);
	return ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_waitq_producer_kfunc_set);
}
late_initcall(bpf_waitq_kfunc_init);
