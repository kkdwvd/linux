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
#define BPF_RECLAIM_AWAKE_BUCKETS	9
#define BPF_RECLAIM_PAGE_SHIFT		12
#define BPF_RECLAIM_PAGE_SIZE		(1ULL << BPF_RECLAIM_PAGE_SHIFT)
/* The range of a cgroup's coldness estimate; the loader prints it in percent. */
#define BPF_RECLAIM_COLD_MAX		65536
/* The kernel's SWAPPINESS_ANON_ONLY from mm/internal.h: reclaim only anon. */
#define BPF_RECLAIM_SWAPPINESS_ANON_ONLY	201

/* Per-child overrides, keyed by cgroup ID. A field counts only if its bit is set. */
#define BPF_RECLAIM_CHILD_FLOOR		(1 << 0)
#define BPF_RECLAIM_CHILD_WEIGHT	(1 << 1)
#define BPF_RECLAIM_CHILD_TARGET	(1 << 2)
#define BPF_RECLAIM_CHILD_BUDGET	(1 << 3)
#define BPF_RECLAIM_CHILD_EFFICIENCY	(1 << 4)
#define BPF_RECLAIM_CHILD_SWAPPINESS	(1 << 5)
#define BPF_RECLAIM_CHILD_EXCLUDE	(1 << 6)
#define BPF_RECLAIM_WEIGHT_MAX		10000

struct bpf_reclaim_child_cfg {
	__u64 floor;		/* bytes of usage never reclaimed below */
	__u64 weight;		/* importance in the split, 1 to BPF_RECLAIM_WEIGHT_MAX */
	__u64 target_ppm;	/* tolerated stall fraction */
	__u64 cpu_budget_ppm;	/* CPU it may cost per tick */
	__u64 min_efficiency;	/* bytes per CPU-second below which it is expensive */
	__s32 swappiness;	/* -1 for the cgroup's own, or anon only */
	__u32 flags;
};

/* The policy, filled in by the loader before the setup program runs. */
struct bpf_reclaim_cfg {
	__u64 root_cgroup_id;	/* the cgroup whose children are managed */
	__u64 interval_ns;	/* controller tick */
	__u64 lead_ns;		/* how far ahead a drain is met, before it reaches the buffer */
	__u64 buffer;		/* bytes of free memory to keep */
	__u64 max_rate;		/* reclaim cap, bytes per second, 0 for none */
	__u64 probe_ppm;	/* fraction of a child's headroom probed per second below target, 0 off */
	__u64 chunk;		/* bytes a worker claims from a cgroup at a time */
	__u64 floor;		/* bytes of usage never reclaimed below */
	__u64 target_ppm;	/* tolerated stall fraction (PSI some), parts per million */
	__u64 cpu_budget_ppm;	/* CPU a child may cost per tick, parts per million of one CPU */
	__u64 min_efficiency;	/* bytes per CPU-second below which reclaiming a child is expensive */
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
	__u64 asked;		/* bytes of quota the last tick gave it */
	__u64 usage;		/* bytes charged at the last tick */
	__u64 protected;	/* the larger of its floor and its memory.low or memory.min */
	__u64 headroom;		/* bytes on offer at the last tick */
	__u64 weight;		/* its configured importance */
	__u64 target_ppm;	/* its pressure target */
	__u64 share;		/* its weight in this tick's split of the demand */
	__s32 swappiness;	/* the swappiness its reclaim calls use */
	__u32 excluded;		/* configured out of the policy */
	__u64 coldness;		/* estimate that what it holds above the floor is cold */
	__u64 stall_ns;		/* PSI memory some total at the last tick */
	__u64 pressure_ppm;	/* smoothed stall fraction */
	__u64 refaults;		/* workingset refaults, anon and file, at the last tick */
	__u64 refault_rate;	/* smoothed refaults, bytes per second */
	__u64 reclaim_rate;	/* smoothed reclaim by the pool, bytes per second */
	__u64 undone_rate;	/* smoothed regrowth of what the pool took, bytes per second */
	__u64 tick_reclaimed;	/* reclaimed since the last tick */
	__u64 tick_busy_ns;	/* CPU spent on it since the last tick */
	__u64 budget_ns;	/* CPU it may cost this tick */
	__u64 min_efficiency;	/* bytes per CPU-second below which a call ends its chunk */
	__u64 busy_ppm;		/* smoothed CPU spent on it, parts per million of one CPU */
	__u64 efficiency;	/* smoothed bytes reclaimed per CPU-second */
	__u64 scanned;		/* proactive scan count at the last tick */
	__u64 stolen;		/* proactive steal count at the last tick */
	__s64 growth;		/* smoothed allocation net of reclaim and refaults, bytes/s */
	__u32 exhausted;	/* a reclaim call found nothing since the last tick */
	__u32 gated;		/* refaults, pressure or cost kept it out of the last tick */
	__u32 rest;		/* ticks left to sit out after a gate */
	__u32 backoff;		/* ticks the next gate will rest it for */
	__u32 inflight;		/* workers in a reclaim call on it right now */
	__u32 pad;
	/* counters, only added to */
	__u64 reclaimed;	/* bytes the pool reclaimed */
	__u64 calls;		/* bpf_proactive_reclaim() calls */
	__u64 empty;		/* calls that reclaimed nothing */
	__u64 busy_ns;		/* time workers spent in those calls */
	__u64 quota_given;	/* bytes of quota over all ticks */
	__u64 probed;		/* bytes of that quota the probe asked for, beyond the demand */
	__u64 refaults_total;	/* refaults since the policy first saw it */
	__u64 undone_total;	/* bytes the pool took that were back by the next tick */
	__u64 gated_ticks;	/* ticks the gate kept it out */
	__u64 expensive_ticks;	/* ticks the gate closed for cost rather than refaults */
	__u64 budget_hits;	/* times a worker stopped because the CPU budget was spent */
	__u64 slow_calls;	/* calls that ended a chunk for yielding too little per CPU-second */
	__u64 scanned_total;	/* pages the kernel scanned for the pool's reclaim */
	__u64 stolen_total;	/* pages it freed for it */
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
	__s64 drain_rate;	/* smoothed loss of free memory net of reclaim, bytes per second */
	__u64 capacity;		/* smoothed reclaim throughput of one busy worker, bytes per second */
	__u64 pool_busy;	/* workers' busy time at the last tick */
	__u64 pool_reclaimed;	/* workers' reclaimed bytes at the last tick */
	__u64 demand;		/* bytes wanted at the last tick */
	__u32 awake;		/* workers woken at the last tick */
	__u32 nr_cgroups;	/* entries of ids[] */
	__u64 ids[BPF_RECLAIM_MAX_CGROUPS];	/* the managed cgroups at the last tick */
	/* counters */
	__u64 ticks;
	__u64 deficit_ticks;	/* ticks that found free memory below the buffer */
	__u64 lead_ticks;	/* ticks that met a drain before it reached the buffer */
	__u64 free_min;
	__u64 wakeups;		/* worker wakeups requested */
	__u64 reclaimed;	/* bytes reclaimed by the pool, all children */
	__u64 awake_ticks[BPF_RECLAIM_AWAKE_BUCKETS]; /* ticks by workers woken, last bucket and up */
};

#endif /* __BPF_RECLAIM_H */
