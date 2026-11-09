// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
/*
 * A proactive reclaimer that keeps a buffer of free memory on the host.
 *
 * It is a multi-threaded kswapd with a buffer chosen by the operator: when
 * free memory falls below the low mark, a pool of worker threads reclaims
 * from one target cgroup until free memory is back at the high mark. The
 * kernel picks the pages: reclaim of the target spreads over the cgroups
 * below it in proportion to their LRU lists and honours their memory.low,
 * so the cgroup that must not lose memory is protected by its own setting.
 *
 * The BPF kthreads have two roles:
 *
 *  - The controller wakes every tick, reads the host's free pages, and when
 *    the band calls for it sets the shortfall as the pending work and wakes
 *    the workers. An allocation that wakes kswapd also wakes it early.
 *  - A worker takes chunks of the pending work and reclaims each with one
 *    bpf_proactive_reclaim() call, a single pass of at most 256 KiB, so a
 *    call costs little and the pool reacts within a call.
 *
 * One rule bounds the cost: when the pool's last 100 ms of reclaim work freed
 * less than the floor per millisecond, the target has little cold memory
 * left, so the pool pauses, for twice as long each time this repeats in a
 * row. Judging a window of work rather than a call lets reclaim come back
 * empty while the LRU ages freshly faulted pages, which takes longer than a
 * few calls, and more so with several workers on the same lists.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "reclaim.h"

char LICENSE[] SEC("license") = "GPL";

#define ENOENT		2
#define EAGAIN		11
#define NSEC_PER_MSEC	1000000ULL
#define LOOP_BOUND	(1 << 23)	/* BPF_MAX_LOOPS */
#define IDLE_PARK_NS	(1000 * NSEC_PER_MSEC)

extern int bpf_task_park(__u64 timeout_ns, __u64 flags) __ksym;
extern int bpf_task_wake(struct task_struct *task, __u64 flags) __ksym;
extern struct task_struct *bpf_kthread_create(int (callback_fn)(__u64 arg), __u64 arg,
					      __u64 flags) __ksym;
extern int bpf_kthread_start(struct task_struct *task, __u64 flags) __ksym;
extern int bpf_kthread_attach_cgroup(struct task_struct *task, struct cgroup *cgrp,
				     __u64 flags) __ksym;
extern int bpf_kthread_stop(struct task_struct *task, __u64 flags) __ksym;
extern bool bpf_kthread_should_stop(void) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern struct cgroup *bpf_cgroup_from_id(__u64 cgid) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;
extern struct mem_cgroup *bpf_get_mem_cgroup(struct cgroup_subsys_state *css) __ksym;
extern struct mem_cgroup *bpf_get_root_mem_cgroup(void) __ksym;
extern void bpf_put_mem_cgroup(struct mem_cgroup *memcg) __ksym;
extern long bpf_proactive_reclaim(struct mem_cgroup *memcg, unsigned long size,
				  int swappiness) __ksym;

/* Set by the loader before load. */
const volatile __u64 target_cgid;
const volatile __u64 low_pages;		/* start reclaiming below this many free pages */
const volatile __u64 high_pages;	/* stop at this many */
const volatile __u64 tick_ns = NSEC_PER_MSEC;
const volatile __u32 nr_workers = 4;
const volatile __u64 chunk_bytes = 256 << 10;
const volatile __u64 floor_bytes_per_ms = 32 << 10;
const volatile __u64 window_ns = 100 * NSEC_PER_MSEC;	/* of worker time */
const volatile __s32 swappiness = -1;
const volatile __u64 backoff_min_ns = 100 * NSEC_PER_MSEC;
const volatile __u64 backoff_max_ns = 5000 * NSEC_PER_MSEC;
const volatile __u32 nr_nodes = 1;

struct reclaim_stats stats;
__u64 free_now;		/* free pages at the controller's last pass */
__u32 active;		/* between falling below the low mark and reaching the high mark */
__s64 pending;		/* pages still to reclaim in this pass; workers take from it */
__u64 backoff_ns;	/* the current pause, 0 when the last window paid */
__u64 backoff_until;	/* no new work before this time */
__u64 window_busy;	/* stats.busy_ns and stats.reclaimed when the window began */
__u64 window_bytes;

struct thread_slot {
	struct task_struct __kptr *task;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1 + RECLAIM_MAX_WORKERS);
	__type(key, __u32);
	__type(value, struct thread_slot);
} threads SEC(".maps");

static __u64 load_u64(__u64 *p)
{
	return *(volatile __u64 *)p;
}

/*
 * Free pages, summed over the zones of every node: what the kernel compares
 * with its watermarks. The zones are reached through the root memcg's
 * lruvecs, and indexed by the running kernel's struct zone size.
 */
static __u64 free_pages(struct mem_cgroup *root)
{
	__u64 zones_off = bpf_core_field_offset(struct pglist_data, node_zones);
	__u64 zone_size = bpf_core_type_size(struct zone);
	int nr_zones = bpf_core_enum_value(enum zone_type, __MAX_NR_ZONES);
	int free_idx = bpf_core_enum_value(enum zone_stat_item, NR_FREE_PAGES);
	__u64 free = 0;
	int n, z;

	for (n = 0; n < RECLAIM_MAX_NODES && n < nr_nodes; n++) {
		struct mem_cgroup_per_node *pn = BPF_CORE_READ(root, nodeinfo[n]);
		struct pglist_data *pgdat = pn ? BPF_CORE_READ(pn, lruvec.pgdat) : NULL;

		if (!pgdat)
			continue;
		for (z = 0; z < 8 && z < nr_zones; z++) {
			struct zone *zone = (void *)pgdat + zones_off + z * zone_size;
			long v = BPF_CORE_READ(zone, vm_stat[free_idx].counter);

			if (v > 0)
				free += v;
		}
	}
	return free;
}

static void wake_slot(__u32 idx)
{
	struct thread_slot *slot = bpf_map_lookup_elem(&threads, &idx);
	struct task_struct *task;

	if (!slot)
		return;
	bpf_rcu_read_lock();
	task = slot->task;
	if (task)
		bpf_task_wake(task, 0);
	bpf_rcu_read_unlock();
}

/*
 * Judge the reclaim of the window that just filled: if it freed less than
 * the floor per millisecond of worker time, pause the pool.
 */
static void judge(__u64 now)
{
	__u64 busy = load_u64(&stats.busy_ns), bytes = load_u64(&stats.reclaimed), pause;

	if (busy - window_busy < window_ns)
		return;
	if ((bytes - window_bytes) * NSEC_PER_MSEC >= floor_bytes_per_ms * (busy - window_busy)) {
		backoff_ns = 0;
	} else {
		pause = backoff_ns * 2;
		if (pause < backoff_min_ns)
			pause = backoff_min_ns;
		if (pause > backoff_max_ns)
			pause = backoff_max_ns;
		backoff_ns = pause;
		backoff_until = now + pause;
		pending = 0;
		stats.backoffs++;
	}
	window_busy = busy;
	window_bytes = bytes;
}

/* One pass of the controller: compare free memory with the band, post the work. */
static void control(struct mem_cgroup *root)
{
	__u64 free = free_pages(root), now = bpf_ktime_get_ns();
	__u32 i;

	free_now = free;
	stats.ticks++;
	judge(now);
	if (!active && free < low_pages) {
		active = 1;
		stats.episodes++;
	} else if (active && free >= high_pages) {
		active = 0;
		pending = 0;
	}
	if (!active || now < backoff_until)
		return;
	pending = high_pages - free;
	for (i = 0; i < RECLAIM_MAX_WORKERS && i < nr_workers; i++)
		wake_slot(1 + i);
}

static int controller(__u64 arg)
{
	struct mem_cgroup *root = bpf_get_root_mem_cgroup();
	bool stop = false;

	if (!root)
		return -ENOENT;
	bpf_repeat(LOOP_BOUND) {
		bpf_repeat(LOOP_BOUND) {
			stop = bpf_kthread_should_stop();
			if (stop)
				break;
			control(root);
			bpf_task_park(tick_ns, 0);
		}
		if (stop)
			break;
	}
	bpf_put_mem_cgroup(root);
	return 0;
}


static struct mem_cgroup *target_memcg(void)
{
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;

	cgrp = bpf_cgroup_from_id(target_cgid);
	if (!cgrp)
		return NULL;
	memcg = bpf_get_mem_cgroup(&cgrp->self);
	bpf_cgroup_release(cgrp);
	return memcg;
}

static int worker(__u64 arg)
{
	__s64 chunk_pages = chunk_bytes >> 12;
	struct mem_cgroup *memcg = target_memcg();
	bool stop = false;

	if (!memcg)
		return -ENOENT;
	bpf_repeat(LOOP_BOUND) {
		bpf_repeat(LOOP_BOUND) {
			__u64 t0;
			long ret;

			stop = bpf_kthread_should_stop();
			if (stop)
				break;
			/* Take a chunk; when there is none left, sleep until the controller posts more. */
			if (__sync_fetch_and_add(&pending, -chunk_pages) <= 0) {
				bpf_task_park(IDLE_PARK_NS, 0);
				continue;
			}
			t0 = bpf_ktime_get_ns();
			ret = bpf_proactive_reclaim(memcg, chunk_bytes, swappiness);
			if (ret < 0) {
				__sync_fetch_and_add(&stats.errors, 1);
				continue;
			}
			__sync_fetch_and_add(&stats.calls, 1);
			__sync_fetch_and_add(&stats.reclaimed, ret);
			__sync_fetch_and_add(&stats.busy_ns, bpf_ktime_get_ns() - t0);
		}
		if (stop)
			break;
	}
	bpf_put_mem_cgroup(memcg);
	return 0;
}

/* Publish @task in slot @idx, releasing whatever the slot held. */
static void publish(__u32 idx, struct task_struct *task)
{
	struct thread_slot *slot = bpf_map_lookup_elem(&threads, &idx);

	if (!slot) {
		bpf_task_release(task);
		return;
	}
	task = bpf_kptr_xchg(&slot->task, task);
	if (task)
		bpf_task_release(task);
}

SEC("syscall")
int create_thread(struct reclaim_thread_args *args)
{
	__u64 pool_cgid = args->pool_cgid;
	__u32 idx = args->idx;
	struct task_struct *task;
	struct cgroup *cgrp;
	int ret = 0;

	if (idx > RECLAIM_MAX_WORKERS)
		return -ENOENT;
	if (idx == RECLAIM_CONTROLLER)
		task = bpf_kthread_create(controller, idx, 0);
	else
		task = bpf_kthread_create(worker, idx, 0);
	if (!task)
		return -EAGAIN;
	if (pool_cgid) {
		cgrp = bpf_cgroup_from_id(pool_cgid);
		ret = cgrp ? bpf_kthread_attach_cgroup(task, cgrp, 0) : -ENOENT;
		if (cgrp)
			bpf_cgroup_release(cgrp);
	}
	if (!ret)
		ret = bpf_kthread_start(task, 0);
	if (ret) {
		bpf_kthread_stop(task, 0);
		bpf_task_release(task);
		return ret;
	}
	publish(idx, task);
	return 0;
}

SEC("syscall")
int stop_thread(struct reclaim_thread_args *args)
{
	struct thread_slot *slot;
	struct task_struct *task;
	__u32 idx = args->idx;
	int ret;

	slot = bpf_map_lookup_elem(&threads, &idx);
	if (!slot)
		return -ENOENT;
	task = bpf_kptr_xchg(&slot->task, NULL);
	if (!task)
		return 0;
	ret = bpf_kthread_stop(task, 0);
	bpf_task_release(task);
	return ret;
}

/* An allocation found free memory under the low watermark: look now, not at the next tick. */
SEC("tp_btf/mm_vmscan_wakeup_kswapd")
int BPF_PROG(wakeup_kswapd)
{
	__sync_fetch_and_add(&stats.wakeups, 1);
	wake_slot(RECLAIM_CONTROLLER);
	return 0;
}
