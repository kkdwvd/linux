// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include <errno.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define NR_POLLERS 2
#define LOOP_BOUND (1 << 23)	/* BPF_MAX_LOOPS */
#define PARK_TIMEOUT_NS (10ULL * 1000 * 1000 * 1000)
#define BUSY_PARK_NS (1000ULL * 1000)

struct poller_slot {
	struct task_struct __kptr *task;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_POLLERS);
	__type(key, __u32);
	__type(value, struct poller_slot);
} pollers SEC(".maps");

/* The context of the syscall programs below. */
struct napi_args {
	__u32 idx;	/* the poller's slot */
	__u32 napi_id;
	__u64 flags;
};

__u32 napi_id;			/* set by the test: the NAPI the pollers serve */
__u32 paused[NR_POLLERS];	/* set by the test: the poller parks without polling */
__u32 busy[NR_POLLERS];		/* set by the test: the poller keeps the interrupt masked */
__u64 rounds[NR_POLLERS];	/* times the poller went through its loop */
__u64 polls[NR_POLLERS];	/* polls that ran the driver */
__u64 work[NR_POLLERS];		/* packets those polls reported */
int last_err[NR_POLLERS];	/* what the last poll that did not run the driver returned */

static __u32 load(__u32 *p)
{
	return *(volatile __u32 *)p;
}

/*
 * The body of a poller thread: poll the NAPI until the driver completes it,
 * then park until the next schedule wakes the thread. A busy poller never lets
 * the driver complete the NAPI and so gets no wake; it parks for a millisecond
 * between polls instead. The plain park's timeout is ten seconds, well past
 * what a test waits, so that a lost wake fails the test instead of passing on
 * the timeout. The two bounded loops together outlast any test; a callback
 * cannot loop without a bound.
 */
static int poller(__u64 arg)
{
	__u64 idx = arg;
	__u64 flags;
	int ret;

	if (idx >= NR_POLLERS)
		return -EINVAL;

	bpf_repeat(LOOP_BOUND) {
		bpf_repeat(LOOP_BOUND) {
			if (bpf_kthread_should_stop())
				return 0;
			__sync_fetch_and_add(&rounds[idx], 1);
			flags = load(&busy[idx]) ? BPF_NAPI_POLL_F_BUSY : 0;
			if (!load(&paused[idx])) {
				ret = bpf_napi_poll(load(&napi_id), flags);
				if (ret < 0) {
					last_err[idx] = ret;
				} else {
					__sync_fetch_and_add(&polls[idx], 1);
					__sync_fetch_and_add(&work[idx], ret & BPF_NAPI_POLL_WORK_MASK);
					if (!flags && (ret & BPF_NAPI_POLL_MORE))
						continue;
				}
			}
			bpf_task_park(flags ? BUSY_PARK_NS : PARK_TIMEOUT_NS, 0);
		}
	}
	return -ETIME;
}

static void publish(__u32 idx, struct task_struct *task)
{
	struct poller_slot *slot;

	slot = bpf_map_lookup_elem(&pollers, &idx);
	if (slot)
		task = bpf_kptr_xchg(&slot->task, task);
	if (task)
		bpf_task_release(task);
}

static struct task_struct *take(__u32 idx)
{
	struct poller_slot *slot;

	slot = bpf_map_lookup_elem(&pollers, &idx);
	if (!slot)
		return NULL;
	return bpf_kptr_xchg(&slot->task, NULL);
}

SEC("syscall")
int create_poller(struct napi_args *args)
{
	struct task_struct *task;
	int ret;

	task = bpf_kthread_create(poller, args->idx, 0);
	if (!task)
		return -EAGAIN;
	ret = bpf_kthread_start(task, 0);
	if (ret) {
		bpf_kthread_stop(task, 0);
		bpf_task_release(task);
		return ret;
	}
	publish(args->idx, task);
	return 0;
}

SEC("syscall")
int stop_poller(struct napi_args *args)
{
	struct task_struct *task;
	int ret;

	task = take(args->idx);
	if (!task)
		return -ESRCH;
	ret = bpf_kthread_stop(task, 0);
	bpf_task_release(task);
	return ret;
}

/* Wake the poller of slot idx from its park. */
SEC("syscall")
int wake_poller(struct napi_args *args)
{
	struct poller_slot *slot;
	struct task_struct *task;
	__u32 idx = args->idx;
	int ret = -ESRCH;

	slot = bpf_map_lookup_elem(&pollers, &idx);
	if (!slot)
		return -ENOENT;
	bpf_rcu_read_lock();
	task = slot->task;
	if (task)
		ret = bpf_task_wake(task, 0);
	bpf_rcu_read_unlock();
	return ret;
}

/* Bind args->napi_id to the poller of slot idx. */
SEC("syscall")
int bind_napi(struct napi_args *args)
{
	struct task_struct *task;
	int ret;

	task = take(args->idx);
	if (!task)
		return -ESRCH;
	ret = bpf_napi_bind(args->napi_id, task, args->flags);
	publish(args->idx, task);
	return ret;
}

/* Bind args->napi_id to the calling task, which is no BPF kthread. */
SEC("syscall")
int bind_napi_to_current(struct napi_args *args)
{
	return bpf_napi_bind(args->napi_id, bpf_get_current_task_btf(), 0);
}

SEC("syscall")
int unbind_napi(struct napi_args *args)
{
	return bpf_napi_unbind(args->napi_id);
}

SEC("syscall")
int poll_napi(struct napi_args *args)
{
	return bpf_napi_poll(args->napi_id, args->flags);
}

/* Leave args->napi_id to softirq, with a wake after args->flags packets. */
SEC("syscall")
int suspend_napi(struct napi_args *args)
{
	return bpf_napi_suspend(args->napi_id, args->flags);
}

SEC("syscall")
int resume_napi(struct napi_args *args)
{
	return bpf_napi_resume(args->napi_id);
}
