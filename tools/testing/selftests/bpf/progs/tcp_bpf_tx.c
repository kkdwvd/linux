// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include <errno.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define LOOP_BOUND (1 << 23)	/* BPF_MAX_LOOPS */
#define PARK_TIMEOUT_NS (10ULL * 1000 * 1000 * 1000)

struct worker_slot {
	struct task_struct __kptr *task;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct worker_slot);
} workers SEC(".maps");

/* The context of the syscall programs below. */
struct tx_args {
	__u32 queue;
	__u32 pad;
	__u64 flags;
};

__u32 queue;		/* set by the test: the queue the worker serves and sockets join */
__u32 paused;		/* set by the test: the worker parks without polling */
__u32 mode;		/* set by the test: the queue's mode, applied by the worker */
__u32 mode_applied;	/* one plus the mode the worker last set */
__u64 xmits;		/* sockets the worker took off the queue */
int last_ret;		/* what the worker's last poll returned when it found no work */
__u32 assigned;		/* sockets the sockops program assigned to the queue */
int assign_ret;		/* what the last assignment returned */

static __u32 load(__u32 *p)
{
	return *(volatile __u32 *)p;
}

/*
 * The body of the worker thread: transmit what waits on the queue, then park until
 * a sender wakes the thread. The park's timeout is ten seconds, well past what
 * the test waits, so that a lost wake fails the test instead of passing on the
 * timeout. The two bounded loops together outlast the test; a callback cannot
 * loop without a bound.
 */
static int worker(__u64 arg)
{
	int ret;

	bpf_repeat(LOOP_BOUND) {
		bpf_repeat(LOOP_BOUND) {
			if (bpf_kthread_should_stop())
				return 0;
			if (!load(&paused)) {
				__u32 m = load(&mode);

				/* Set, then poll: the order a change of mode needs. */
				if (!bpf_tcp_tx_set_mode(load(&queue), m))
					mode_applied = m + 1;
				ret = bpf_tcp_tx_poll(load(&queue), 64);
				if (ret > 0) {
					__sync_fetch_and_add(&xmits, ret);
					continue;
				}
				last_ret = ret;
			}
			bpf_task_park(PARK_TIMEOUT_NS, 0);
		}
	}
	return -ETIME;
}

static void publish(struct task_struct *task)
{
	struct worker_slot *slot;
	__u32 idx = 0;

	slot = bpf_map_lookup_elem(&workers, &idx);
	if (slot)
		task = bpf_kptr_xchg(&slot->task, task);
	if (task)
		bpf_task_release(task);
}

static struct task_struct *take(void)
{
	struct worker_slot *slot;
	__u32 idx = 0;

	slot = bpf_map_lookup_elem(&workers, &idx);
	if (!slot)
		return NULL;
	return bpf_kptr_xchg(&slot->task, NULL);
}

SEC("syscall")
int create_worker(struct tx_args *args)
{
	struct task_struct *task;
	int ret;

	task = bpf_kthread_create(worker, 0, 0);
	if (!task)
		return -EAGAIN;
	ret = bpf_kthread_start(task, 0);
	if (ret) {
		bpf_kthread_stop(task, 0);
		bpf_task_release(task);
		return ret;
	}
	publish(task);
	return 0;
}

SEC("syscall")
int stop_worker(struct tx_args *args)
{
	struct task_struct *task;
	int ret;

	task = take();
	if (!task)
		return -ESRCH;
	ret = bpf_kthread_stop(task, 0);
	bpf_task_release(task);
	return ret;
}

/* Bind args->queue to the worker. */
SEC("syscall")
int bind_queue(struct tx_args *args)
{
	struct task_struct *task;
	int ret;

	task = take();
	if (!task)
		return -ESRCH;
	ret = bpf_tcp_tx_bind(args->queue, task, args->flags);
	publish(task);
	return ret;
}

/* Bind args->queue to the calling task, which is no BPF kthread. */
SEC("syscall")
int bind_queue_to_current(struct tx_args *args)
{
	return bpf_tcp_tx_bind(args->queue, bpf_get_current_task_btf(), 0);
}

SEC("syscall")
int unbind_queue(struct tx_args *args)
{
	return bpf_tcp_tx_unbind(args->queue);
}

/* Poll args->queue from the calling task, which is not the queue's thread. */
SEC("syscall")
int poll_queue(struct tx_args *args)
{
	return bpf_tcp_tx_poll(args->queue, 64);
}

/* Wake the worker from its park, to have it apply the mode and poll. */
SEC("syscall")
int wake_worker(struct tx_args *args)
{
	struct worker_slot *slot;
	struct task_struct *task;
	__u32 idx = 0;
	int ret = -ESRCH;

	slot = bpf_map_lookup_elem(&workers, &idx);
	if (!slot)
		return -ENOENT;
	bpf_rcu_read_lock();
	task = slot->task;
	if (task)
		ret = bpf_task_wake(task, 0);
	bpf_rcu_read_unlock();
	return ret;
}

/* Set the mode of args->queue to args->flags from a task that is not its thread. */
SEC("syscall")
int set_queue_mode(struct tx_args *args)
{
	return bpf_tcp_tx_set_mode(args->queue, args->flags);
}

/* Assign every connection of the cgroup to the queue once it is established. */
SEC("sockops")
int assign_sock(struct bpf_sock_ops *skops)
{
	struct bpf_sock_ops_kern *kern;

	if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB &&
	    skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
		return 1;
	kern = bpf_cast_to_kern_ctx(skops);
	assign_ret = bpf_tcp_tx_sock_bind(kern, load(&queue));
	__sync_fetch_and_add(&assigned, 1);
	return 1;
}
