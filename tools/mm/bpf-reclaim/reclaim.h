/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared between the reclaim program and its loader: the configuration the
 * loader fills in, the state the controller keeps per cgroup and per thread,
 * and the counters both sides read. The BPF side gets the kernel types from
 * vmlinux.h, the loader from <linux/bpf.h>.
 */
#ifndef __BPF_RECLAIM_H
#define __BPF_RECLAIM_H

#define BPF_RECLAIM_MAX_THREADS		64
#define BPF_RECLAIM_MAX_CGROUPS		256
#define BPF_RECLAIM_PAGE_SHIFT		12
#define BPF_RECLAIM_PAGE_SIZE		(1ULL << BPF_RECLAIM_PAGE_SHIFT)
/* The kernel's SWAPPINESS_ANON_ONLY from mm/internal.h: reclaim only anon. */
#define BPF_RECLAIM_SWAPPINESS_ANON_ONLY	201

/* The policy, filled in by the loader before the setup program runs. */
struct bpf_reclaim_cfg {
	__u64 root_cgroup_id;	/* the cgroup whose children are managed */
	__u64 interval_ns;	/* controller tick */
	__u64 buffer;		/* bytes of free memory to keep */
	__u64 chunk;		/* bytes a worker claims from a cgroup at a time */
	__u64 floor;		/* bytes of usage never reclaimed below */
	__u32 pool;		/* worker threads */
	__s32 swappiness;	/* -1 for the cgroup's own */
};

/*
 * A managed cgroup, kept in cgroup storage so that it is freed with the
 * cgroup. The controller writes the sample and the quota, the workers claim
 * from the quota and add to the counters.
 */
struct bpf_reclaim_cgroup {
	__u64 quota;		/* bytes left to reclaim this tick */
	__u64 usage;		/* bytes charged at the last tick */
	__u64 headroom;		/* bytes on offer at the last tick */
	__u32 exhausted;	/* a reclaim call found nothing since the last tick */
	__u32 pad;
	/* counters, only added to */
	__u64 reclaimed;	/* bytes the pool reclaimed */
	__u64 calls;		/* bpf_proactive_reclaim() calls */
	__u64 empty;		/* calls that reclaimed nothing */
	__u64 busy_ns;		/* time workers spent in those calls */
	__u64 quota_given;	/* bytes of quota over all ticks */
};

/* A pool worker: sleeps on the pool's wait queue and claims quota. */
struct bpf_reclaim_thread {
	struct bpf_kthread kthread;
	__u32 index;
	__u32 pad;
	__u64 rounds;		/* callback iterations */
	__u64 claims;		/* quota chunks claimed */
	__u64 reclaimed;	/* bytes reclaimed */
	__u64 busy_ns;		/* time spent in reclaim calls */
	__u64 sleeps;
};

/*
 * The workers' wait queue. A map value may hold one wait queue, and the
 * controller's own sits in its value, so the pool's lives apart.
 */
struct bpf_reclaim_pool {
	struct bpf_waitq work;
};

/* The controller thread, its timed sleep, and the global samples. */
struct bpf_reclaim_control {
	struct bpf_kthread kthread;
	struct bpf_waitq tick;
	__u64 last_ns;
	__u64 free;		/* free memory in bytes at the last tick */
	__u64 demand;		/* bytes wanted at the last tick */
	__u32 awake;		/* workers woken at the last tick */
	__u32 nr_cgroups;	/* entries of ids[] */
	__u64 ids[BPF_RECLAIM_MAX_CGROUPS];	/* the managed cgroups at the last tick */
	/* counters */
	__u64 ticks;
	__u64 deficit_ticks;	/* ticks that found free memory below the buffer */
	__u64 free_min;
	__u64 wakeups;		/* worker wakeups requested */
};

#endif /* __BPF_RECLAIM_H */
