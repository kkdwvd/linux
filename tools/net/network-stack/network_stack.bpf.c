// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
/*
 * The network stack's receive processing as a pool of BPF kthreads.
 *
 * Every thread is bound to one CPU and polls the NAPIs the loader has given
 * it, one driver poll per NAPI per pass over its list. Which thread has which
 * NAPIs, and how many threads have any, is decided by the loader, which reads
 * the counters kept here; this file is the loop a thread runs and nothing
 * else.
 *
 * A thread is in one of two phases.
 *
 * Masked: the thread polls with BPF_NAPI_POLL_F_BUSY, so its NAPIs stay
 * scheduled and their interrupts stay masked. While packets keep coming it
 * polls on. Once a pass finds none it spins for spin_ns, then naps nap_ns at
 * a time, both counted from the last packet, and after hold_ns without a
 * packet it gives up the phase. A thread that serves busy queues therefore
 * takes no interrupts at all, and one whose queues go quiet stops costing
 * CPU within hold_ns.
 *
 * Armed: one pass of plain polls lets the drivers complete the NAPIs and
 * unmask their interrupts, and the thread parks. The first schedule of one of
 * its NAPIs wakes it into the masked phase. With hold_ns at zero a thread is
 * always armed, which is threaded NAPI with a thread per CPU.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "network_stack.h"

char LICENSE[] SEC("license") = "GPL";

#define ENOENT		2
#define EAGAIN		11
#define EBUSY		16
#define EINVAL		22
#define ESRCH		3
#define ECANCELED	125
#define ETIMEDOUT	110
#define NSEC_PER_MSEC	1000000ULL
#define LOOP_BOUND	(1 << 23)	/* BPF_MAX_LOOPS */
#define IDLE_PARK_NS	(1000 * NSEC_PER_MSEC)

extern int bpf_task_park(__u64 timeout_ns, __u64 flags) __ksym;
extern int bpf_task_wake(struct task_struct *task, __u64 flags) __ksym;
extern struct task_struct *bpf_kthread_create(int (callback_fn)(__u64 arg), __u64 arg,
					      __u64 flags) __ksym;
extern int bpf_kthread_start(struct task_struct *task, __u64 flags) __ksym;
extern int bpf_kthread_bind(struct task_struct *task, __u32 cpu, __u64 flags) __ksym;
extern int bpf_kthread_attach_cgroup(struct task_struct *task, struct cgroup *cgrp,
				     __u64 flags) __ksym;
extern int bpf_kthread_stop(struct task_struct *task, __u64 flags) __ksym;
extern bool bpf_kthread_should_stop(void) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern struct cgroup *bpf_cgroup_from_id(__u64 cgid) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;
extern int bpf_napi_bind(__u32 napi_id, struct task_struct *task, __u64 flags) __ksym;
extern int bpf_napi_unbind(__u32 napi_id) __ksym;
extern int bpf_napi_poll(__u32 napi_id, __u64 flags) __ksym;

/* Set by the loader, and read by the threads on every pass. */
__u64 hold_ns;		/* stay masked this long after the last packet; 0: never mask */
__u64 spin_ns;		/* of that, spin this long before napping */
__u64 nap_ns;		/* length of a nap with interrupts masked */
/*
 * A thread's callback holds a Tasks Trace RCU read section except while it
 * parks, so a thread that always finds work would hold up every such grace
 * period in the system. It parks for an instant when it has not parked for
 * this long.
 */
__u64 rest_ns;

struct ns_thread threads[NS_MAX_THREADS];
struct ns_napi napis[NS_MAX_NAPIS];

struct thread_slot {
	struct task_struct __kptr *task;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NS_MAX_THREADS);
	__type(key, __u32);
	__type(value, struct thread_slot);
} tasks SEC(".maps");

static __u64 load(__u64 *p)
{
	return *(volatile __u64 *)p;
}

/*
 * One pass over the thread's NAPIs. Adds the packets found to t->pass_work,
 * and sets *more when a NAPI has packets left that no interrupt will announce:
 * its poll used the whole budget, or a plain poll left it scheduled. The count
 * is kept in the thread's slot and not in a register: a sum that grows with
 * every NAPI would be a new state for each, where the verifier does not widen
 * it, and the loop would never converge.
 */
static __always_inline void scan(struct ns_thread *t, __u64 flags, bool *more)
{
	__u32 nr = *(volatile __u32 *)&t->nr_napis;
	int k;

	if (nr > NS_THREAD_NAPIS)
		nr = NS_THREAD_NAPIS;

	bpf_for(k, 0, nr) {
		struct ns_napi *n;
		__u64 t0, t1;
		__u32 slot;
		int ret, w;

		if (k < 0 || k >= NS_THREAD_NAPIS)
			break;
		slot = *(volatile __u32 *)&t->napi[k];
		if (slot >= NS_MAX_NAPIS)
			continue;
		n = &napis[slot];

		t0 = bpf_ktime_get_ns();
		ret = bpf_napi_poll(n->id, flags);
		t1 = bpf_ktime_get_ns();
		if (ret < 0) {
			/* Nothing scheduled, or the thread it moved from is still in it. */
			if (ret == -EAGAIN || ret == -EBUSY)
				continue;
			n->last_err = ret;
			if (ret == -ECANCELED)
				n->cancelled++;
			else if (ret == -ENOENT)
				n->missing++;
			continue;
		}

		w = ret & BPF_NAPI_POLL_WORK_MASK;
		n->polls++;
		/*
		 * With interrupts masked a packet waits for the next poll. t0 can
		 * precede the last poll of a NAPI that just moved from another thread.
		 */
		if (flags && n->last_poll_ns && t0 > n->last_poll_ns &&
		    t0 - n->last_poll_ns > n->gap_max_ns)
			n->gap_max_ns = t0 - n->last_poll_ns;
		n->last_poll_ns = t1;
		if (w) {
			n->pkts += w;
			n->busy_ns += t1 - t0;
			t->pass_work += w;
		}
		if (w >= NS_POLL_BUDGET) {
			n->full++;
			*more = true;
		} else if (!flags && (ret & BPF_NAPI_POLL_MORE)) {
			*more = true;
		}
	}
}

/*
 * A park, which ends the read section the callback runs in if the thread
 * sleeps, see rest_ns. A park that finds a wake pending returns 0 at once, in
 * the section, and one that returns 0 after a sleep looks the same, so only a
 * park that timed out is known to have left it.
 */
static __always_inline int rest(__u64 idx, __u64 timeout_ns)
{
	int ret = bpf_task_park(timeout_ns, 0);

	if (ret == -ETIMEDOUT && idx < NS_MAX_THREADS)
		threads[idx].last_rest_ns = bpf_ktime_get_ns();
	return ret;
}

/*
 * Leave the read section now. Under traffic a wake is pending more often than
 * not, and the first park only consumes it; the thread is about to scan all of
 * its NAPIs anyway.
 */
static __always_inline void breathe(__u64 idx)
{
	int i;

	for (i = 0; i < 4; i++)
		if (rest(idx, 1))
			break;
}

/*
 * The body of a poller thread. The two bounded loops together run for longer
 * than any uptime; a callback cannot loop without a bound.
 */
static int poller(__u64 arg)
{
	__u64 idx = arg;

	if (idx >= NS_MAX_THREADS)
		return -EINVAL;
	threads[idx].armed = 1;
	threads[idx].last_rest_ns = bpf_ktime_get_ns();

	bpf_repeat(LOOP_BOUND) {
		bpf_repeat(LOOP_BOUND) {
			struct ns_thread *t = &threads[idx];
			__u64 hold = load(&hold_ns);
			__u64 flags, now, idle;
			bool more = false;

			if (bpf_kthread_should_stop())
				return 0;

			flags = hold && !t->armed ? BPF_NAPI_POLL_F_BUSY : 0;
			t->pass_work = 0;
			scan(t, flags, &more);
			now = bpf_ktime_get_ns();
			t->scans++;

			if (t->pass_work || more) {
				if (t->pass_work) {
					t->busy_scans++;
					t->last_work_ns = now;
				}
				/* Packets after the interrupts were unmasked: mask again. */
				if (hold)
					t->armed = 0;
				if (now - t->last_rest_ns > load(&rest_ns)) {
					t->rests++;
					breathe(idx);
				}
				continue;
			}

			if (!flags) {
				/*
				 * Every NAPI is complete and its interrupt unmasked.
				 * A schedule since then left a wake pending, so
				 * this returns at once.
				 */
				t->armed = 1;
				t->parks++;
				if (!rest(idx, IDLE_PARK_NS) && idx < NS_MAX_THREADS) {
					threads[idx].wakes++;
					if (hold)
						threads[idx].armed = 0;
				}
				continue;
			}

			idle = now - t->last_work_ns;
			if (idle >= hold) {
				/* The next pass polls without the flag and unmasks. */
				t->armed = 1;
			} else if (idle >= load(&spin_ns)) {
				t->naps++;
				rest(idx, load(&nap_ns));
			} else if (now - t->last_rest_ns > load(&rest_ns)) {
				t->rests++;
				breathe(idx);
			}
		}
	}
	return 0;
}

static struct task_struct *take(__u32 idx)
{
	struct thread_slot *slot;

	slot = bpf_map_lookup_elem(&tasks, &idx);
	if (!slot)
		return NULL;
	return bpf_kptr_xchg(&slot->task, NULL);
}

static void publish(__u32 idx, struct task_struct *task)
{
	struct thread_slot *slot;

	slot = bpf_map_lookup_elem(&tasks, &idx);
	if (slot)
		task = bpf_kptr_xchg(&slot->task, task);
	if (task)
		bpf_task_release(task);
}

/*
 * Create the thread of slot args->thread, in the cgroup args->cgroup_id if
 * that is set, bound to args->cpu, and start it. The cgroup comes first: a
 * cpuset applies its CPUs to a thread that joins.
 */
SEC("syscall")
int ns_thread_create(struct ns_args *args)
{
	struct task_struct *task;
	struct cgroup *cgrp;
	int ret;

	if (args->thread >= NS_MAX_THREADS)
		return -EINVAL;
	task = bpf_kthread_create(poller, args->thread, 0);
	if (!task)
		return -EAGAIN;
	if (args->cgroup_id) {
		cgrp = bpf_cgroup_from_id(args->cgroup_id);
		if (!cgrp) {
			ret = -ENOENT;
			goto stop;
		}
		ret = bpf_kthread_attach_cgroup(task, cgrp, 0);
		bpf_cgroup_release(cgrp);
		if (ret)
			goto stop;
	}
	ret = bpf_kthread_bind(task, args->cpu, 0);
	if (ret)
		goto stop;
	ret = bpf_kthread_start(task, 0);
	if (ret)
		goto stop;
	publish(args->thread, task);
	return 0;
stop:
	bpf_kthread_stop(task, 0);
	bpf_task_release(task);
	return ret;
}

/* Bind args->napi_id to the thread of slot args->thread, or move it there. */
SEC("syscall")
int ns_napi_bind(struct ns_args *args)
{
	struct task_struct *task;
	int ret;

	task = take(args->thread);
	if (!task)
		return -ESRCH;
	ret = bpf_napi_bind(args->napi_id, task, 0);
	publish(args->thread, task);
	return ret;
}

SEC("syscall")
int ns_napi_unbind(struct ns_args *args)
{
	return bpf_napi_unbind(args->napi_id);
}

/* Wake the thread of slot args->thread, to have it read its list again. */
SEC("syscall")
int ns_thread_wake(struct ns_args *args)
{
	struct thread_slot *slot;
	struct task_struct *task;
	__u32 idx = args->thread;
	int ret = -ESRCH;

	slot = bpf_map_lookup_elem(&tasks, &idx);
	if (!slot)
		return -ENOENT;
	bpf_rcu_read_lock();
	task = slot->task;
	if (task)
		ret = bpf_task_wake(task, 0);
	bpf_rcu_read_unlock();
	return ret;
}
