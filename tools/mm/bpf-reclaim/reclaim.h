/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef __RECLAIM_H
#define __RECLAIM_H

#define RECLAIM_MAX_WORKERS	64
#define RECLAIM_MAX_NODES	64

/* Thread slots: the controller, then the workers. */
#define RECLAIM_CONTROLLER	0

/* Argument of the create_thread and stop_thread syscall programs. */
struct reclaim_thread_args {
	__u32 idx;			/* slot: RECLAIM_CONTROLLER or 1 + worker */
	__u32 pad;
	__u64 pool_cgid;		/* cgroup to place the thread in, 0 for none */
};

/* Counters the BPF side keeps and the loader prints, all cumulative. */
struct reclaim_stats {
	__u64 ticks;			/* controller passes */
	__u64 episodes;			/* times free memory fell below the low mark */
	__u64 wakeups;			/* controller wakes from the kswapd tracepoint */
	__u64 calls;			/* bpf_proactive_reclaim() calls */
	__u64 reclaimed;		/* bytes those calls reclaimed */
	__u64 busy_ns;			/* time workers spent in those calls */
	__u64 backoffs;			/* pauses: windows of work under the yield floor */
	__u64 errors;			/* calls that returned an error */
};

#endif /* __RECLAIM_H */
