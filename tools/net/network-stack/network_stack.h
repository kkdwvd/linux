/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef __NETWORK_STACK_H
#define __NETWORK_STACK_H

#define NS_MAX_THREADS		256	/* poller threads, one per pool CPU */
#define NS_MAX_NAPIS		256	/* NAPIs of the device */
#define NS_THREAD_NAPIS		32	/* NAPIs one thread can be given */
#define NS_THREAD_TXQS		32	/* TCP xmit queues one thread can be given */
#define NS_MAX_CPUS		1024

/* The budget of one driver poll. A poll that returns it left packets behind. */
#define NS_POLL_BUDGET		64
/* Packets softirq processes for a suspended NAPI before it wakes the thread. */
#define NS_SOFTIRQ_WAKE		64
/* Sockets served per poll of a TCP xmit queue. */
#define NS_TX_BUDGET		64

/*
 * What the loader tells a thread. A thread reads its list on every scan, and
 * the loader changes it while the thread runs: it appends a slot and then
 * raises nr_napis, or overwrites the slot to remove with the last one and
 * then lowers nr_napis. A thread that reads the list in between polls a NAPI
 * twice or one that has just left, which a poll allows.
 */
struct ns_thread {
	__u32 nr_napis;
	__u32 napi[NS_THREAD_NAPIS];	/* slots in the NAPI table */
	/* With --tx: the TCP xmit queues it serves, changed the same way. */
	__u32 nr_txqs;
	__u32 txq[NS_THREAD_TXQS];

	/* The thread's own state, kept here and not in registers. */
	__u32 armed;			/* interrupts are unmasked, the next scan is plain */
	__u32 suspended;		/* its NAPIs are left to softirq */
	__u64 suspend_ns;		/* when they were, or softirq's count was restarted */
	__u64 last_work_ns;		/* end of the last scan that found packets */
	__u64 last_rest_ns;		/* end of the last park */
	__u64 pass_work;		/* packets and sockets the current pass found */

	/* Cumulative counters, written by the thread. */
	__u64 scans;			/* passes over the list */
	__u64 busy_scans;		/* passes that found packets */
	__u64 naps;			/* timed parks with interrupts masked */
	__u64 parks;			/* parks with interrupts unmasked */
	__u64 wakes;			/* such parks that a schedule or the loader ended */
	__u64 rests;			/* parks forced on a thread that never slept */
	__u64 suspends;			/* times it left its NAPIs to softirq */
	__u64 resumes;			/* times it took them back */
	__u64 xmits;			/* sockets whose xmit work it did */
	__u64 xmit_ns;			/* time in polls of xmit queues that found work */
} __attribute__((aligned(64)));

/* One NAPI of the device. The loader sets id; the thread polling it the rest. */
struct ns_napi {
	__u32 id;
	__s32 last_err;			/* the last error other than -EAGAIN and -EBUSY */
	__u64 last_poll_ns;		/* end of the last poll that ran the driver */

	/* Cumulative counters. */
	__u64 polls;			/* polls that ran the driver */
	__u64 pkts;			/* packets they reported */
	__u64 busy_ns;			/* time in polls that found packets */
	__u64 full;			/* polls that used the whole budget */
	__u64 cancelled;		/* polls refused with -ECANCELED: bind again */
	__u64 missing;			/* polls refused with -ENOENT: not bound */
	/* Longest time between two polls with interrupts masked; the loader zeroes it. */
	__u64 gap_max_ns;
} __attribute__((aligned(64)));

/* Argument of the syscall programs. */
struct ns_args {
	__u32 thread;			/* slot of the thread */
	__u32 cpu;			/* create: the CPU to bind the thread to */
	__u32 napi_id;			/* bind, unbind: the NAPI */
	__u32 txq;			/* bind, unbind: the TCP xmit queue */
	__u64 cgroup_id;		/* create: cgroup to place the thread in, 0 for none */
};

#endif /* __NETWORK_STACK_H */
