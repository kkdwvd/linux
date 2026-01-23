// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Timer NMI Concurrency Tester
 *
 * Tests interleaving scenarios between timer operations
 * (start, cancel, cancel_async, callback) in NMI context.
 *
 * Scenarios:
 * 1. Normal: start,        NMI: cancel_async
 * 2. Normal: cancel_async, NMI: start
 * 3. Normal: start,        NMI: (callback executing)
 * 4. Normal: (callback),   NMI: start
 * 5. Normal: cancel_async, NMI: (callback executing)
 * 6. Normal: (callback),   NMI: cancel_async
 * 7. Normal: cancel (sync), NMI: start
 * 8. Normal: cancel (sync), NMI: cancel_async
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_atomic.h"

#define CLOCK_MONOTONIC 1
#define EBUSY 16

/* Timer start flags */
#define BPF_F_TIMER_ABS		(1ULL << 0)
#define BPF_F_TIMER_CPU_PIN	(1ULL << 1)

char _license[] SEC("license") = "GPL";

/* Latency threshold in nanoseconds */
#define LATENCY_THRESH_1MS   1000000ULL
#define LATENCY_THRESH_10MS  10000000ULL
#define LATENCY_THRESH_100MS 100000000ULL

/*
 * Timing statistics for a single operation type
 */
struct op_timing {
	__u64 total_ns;		/* Total time spent */
	__u64 max_ns;		/* Maximum latency observed */
	__u64 count;		/* Number of operations */
	__u64 over_1ms;		/* Count of ops > 1ms */
	__u64 over_10ms;	/* Count of ops > 10ms */
	__u64 over_100ms;	/* Count of ops > 100ms */
};

/*
 * Statistics tracking for timer concurrency tests
 */
struct timer_conctest_stats {
	/* Operation counters - normal context */
	__u64 start_attempts;
	__u64 start_success;
	__u64 start_failure;

	__u64 cancel_attempts;		/* async cancel */
	__u64 cancel_success;
	__u64 cancel_failure;

	__u64 cancel_sync_attempts;	/* sync cancel */
	__u64 cancel_sync_success;
	__u64 cancel_sync_failure;

	/* Callback execution */
	__u64 callback_executions;
	__u64 callback_restarts;

	/* NMI operation counters */
	__u64 nmi_start_attempts;
	__u64 nmi_start_success;
	__u64 nmi_start_failure;

	__u64 nmi_cancel_attempts;
	__u64 nmi_cancel_success;

	/* Interleaving detection */
	__u64 nmi_during_start;		/* NMI hit while in_start=1 */
	__u64 nmi_during_cancel;	/* NMI hit while in_cancel=1 (async) */
	__u64 nmi_during_cancel_sync;	/* NMI hit while in_cancel_sync=1 */
	__u64 nmi_during_callback;	/* NMI hit while in_callback=1 */

	/* General NMI hits */
	__u64 nmi_hits;

	/* Timing statistics */
	struct op_timing start_timing;
	struct op_timing cancel_timing;		/* async cancel */
	struct op_timing cancel_sync_timing;	/* sync cancel */
	struct op_timing callback_timing;
	struct op_timing nmi_start_timing;
	struct op_timing nmi_cancel_timing;
};

/*
 * Per-CPU statistics to avoid contention
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct timer_conctest_stats);
} stats_map SEC(".maps");

/*
 * Timer element for testing
 */
struct timer_elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct timer_elem);
} timer_map SEC(".maps");

/*
 * Global control variables
 */
volatile int enabled = 0;
volatile int nmi_op = 0;		/* 0=start, 1=cancel_async */
volatile int restart_timer = 1;		/* 1=restart from callback */

/* Flags for interleaving detection */
volatile int in_start = 0;
volatile int in_cancel = 0;		/* async cancel */
volatile int in_cancel_sync = 0;	/* sync cancel */
volatile int in_callback = 0;

/*
 * Record timing for an operation
 *
 * Note: max_ns update is racy but acceptable for statistics.
 * We avoid CAS loops since BPF verifier doesn't allow unbounded loops.
 */
static __always_inline void record_timing(struct op_timing *timing, __u64 duration_ns)
{
	__sync_fetch_and_add(&timing->total_ns, duration_ns);
	__sync_fetch_and_add(&timing->count, 1);

	/* Update max - racy but acceptable for stats */
	if (duration_ns > timing->max_ns)
		timing->max_ns = duration_ns;

	/* Count threshold violations */
	if (duration_ns > LATENCY_THRESH_1MS)
		__sync_fetch_and_add(&timing->over_1ms, 1);
	if (duration_ns > LATENCY_THRESH_10MS)
		__sync_fetch_and_add(&timing->over_10ms, 1);
	if (duration_ns > LATENCY_THRESH_100MS)
		__sync_fetch_and_add(&timing->over_100ms, 1);
}

/*
 * Timer callback - runs in softirq context
 *
 * Sets in_callback flag so NMI can detect when callback is executing.
 * Optionally restarts timer immediately to keep callbacks firing.
 */
static int timer_callback(void *map, int *key, struct timer_elem *val)
{
	struct timer_conctest_stats *stats;
	int stats_key = 0;
	__u64 start_time, duration;

	if (!enabled)
		return 0;

	stats = bpf_map_lookup_elem(&stats_map, &stats_key);
	if (!stats)
		return 0;

	start_time = bpf_ktime_get_ns();

	__sync_fetch_and_add(&stats->callback_executions, 1);

	/* Signal that callback is executing */
	in_callback = 1;
	smp_mb();

	/* NMI will naturally interleave - no artificial delay needed */

	/* Clear callback flag before restart */
	in_callback = 0;
	smp_mb();

	/* Record callback timing */
	duration = bpf_ktime_get_ns() - start_time;
	record_timing(&stats->callback_timing, duration);

	/* Restart timer immediately with CPU pinning */
	if (restart_timer) {
		int ret = bpf_timer_start(&val->timer, 0, BPF_F_TIMER_CPU_PIN);
		if (ret == 0)
			__sync_fetch_and_add(&stats->callback_restarts, 1);
	}

	return 0;
}

/*
 * Initialize timer with callback
 */
SEC("syscall")
int init_timer(void *ctx)
{
	struct timer_elem *elem;
	int key = 0;
	int ret;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return -1;

	ret = bpf_timer_init(&elem->timer, &timer_map, CLOCK_MONOTONIC);
	if (ret && ret != -EBUSY)
		return ret;

	ret = bpf_timer_set_callback(&elem->timer, timer_callback);
	if (ret)
		return ret;

	return 0;
}

/*
 * Start timer from normal context
 * Sets in_start flag for NMI interleaving detection
 */
SEC("syscall")
int do_start(void *ctx)
{
	struct timer_conctest_stats *stats;
	struct timer_elem *elem;
	int key = 0;
	int ret;
	__u64 start_time, duration;

	if (!enabled)
		return 0;

	stats = bpf_map_lookup_elem(&stats_map, &key);
	if (!stats)
		return -1;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return -1;

	__sync_fetch_and_add(&stats->start_attempts, 1);

	/* Signal that we're in start operation */
	in_start = 1;
	smp_mb();

	start_time = bpf_ktime_get_ns();
	ret = bpf_timer_start(&elem->timer, 0, BPF_F_TIMER_CPU_PIN);
	duration = bpf_ktime_get_ns() - start_time;

	in_start = 0;
	smp_mb();

	record_timing(&stats->start_timing, duration);

	if (ret == 0)
		__sync_fetch_and_add(&stats->start_success, 1);
	else
		__sync_fetch_and_add(&stats->start_failure, 1);

	return ret;
}

/*
 * Cancel timer from normal context
 * Sets in_cancel flag for NMI interleaving detection
 */
SEC("syscall")
int do_cancel(void *ctx)
{
	struct timer_conctest_stats *stats;
	struct timer_elem *elem;
	int key = 0;
	__u64 start_time, duration;

	if (!enabled)
		return 0;

	stats = bpf_map_lookup_elem(&stats_map, &key);
	if (!stats)
		return -1;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return -1;

	__sync_fetch_and_add(&stats->cancel_attempts, 1);

	/* Signal that we're in cancel operation */
	in_cancel = 1;
	smp_mb();

	start_time = bpf_ktime_get_ns();
	bpf_timer_cancel_async(&elem->timer);
	duration = bpf_ktime_get_ns() - start_time;

	in_cancel = 0;
	smp_mb();

	record_timing(&stats->cancel_timing, duration);

	__sync_fetch_and_add(&stats->cancel_success, 1);

	return 0;
}

/*
 * Synchronous cancel timer from normal context
 * This waits for callback completion if callback is running.
 * Sets in_cancel_sync flag for NMI interleaving detection.
 */
SEC("syscall")
int do_cancel_sync(void *ctx)
{
	struct timer_conctest_stats *stats;
	struct timer_elem *elem;
	int key = 0;
	int ret;
	__u64 start_time, duration;

	if (!enabled)
		return 0;

	stats = bpf_map_lookup_elem(&stats_map, &key);
	if (!stats)
		return -1;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return -1;

	__sync_fetch_and_add(&stats->cancel_sync_attempts, 1);

	/* Signal that we're in sync cancel operation */
	in_cancel_sync = 1;
	smp_mb();

	start_time = bpf_ktime_get_ns();
	ret = bpf_timer_cancel(&elem->timer);
	duration = bpf_ktime_get_ns() - start_time;

	in_cancel_sync = 0;
	smp_mb();

	record_timing(&stats->cancel_sync_timing, duration);

	if (ret >= 0)
		__sync_fetch_and_add(&stats->cancel_sync_success, 1);
	else
		__sync_fetch_and_add(&stats->cancel_sync_failure, 1);

	return ret;
}

/*
 * NMI handler - performs timer operations in NMI context
 *
 * Checks interleaving flags and performs start or cancel_async
 * based on nmi_op configuration.
 */
SEC("perf_event")
int nmi_timer_op(struct bpf_perf_event_data *ctx)
{
	struct timer_conctest_stats *stats;
	struct timer_elem *elem;
	int key = 0;
	int ret;
	__u64 start_time, duration;

	if (!enabled)
		return 0;

	stats = bpf_map_lookup_elem(&stats_map, &key);
	if (!stats)
		return 0;

	elem = bpf_map_lookup_elem(&timer_map, &key);
	if (!elem)
		return 0;

	__sync_fetch_and_add(&stats->nmi_hits, 1);

	/* Detect interleaving with normal context operations */
	if (in_start)
		__sync_fetch_and_add(&stats->nmi_during_start, 1);
	if (in_cancel)
		__sync_fetch_and_add(&stats->nmi_during_cancel, 1);
	if (in_cancel_sync)
		__sync_fetch_and_add(&stats->nmi_during_cancel_sync, 1);
	if (in_callback)
		__sync_fetch_and_add(&stats->nmi_during_callback, 1);

	/* Perform configured NMI operation */
	if (nmi_op == 0) {
		/* NMI: start */
		__sync_fetch_and_add(&stats->nmi_start_attempts, 1);
		start_time = bpf_ktime_get_ns();
		ret = bpf_timer_start(&elem->timer, 0, BPF_F_TIMER_CPU_PIN);
		duration = bpf_ktime_get_ns() - start_time;
		record_timing(&stats->nmi_start_timing, duration);
		if (ret == 0)
			__sync_fetch_and_add(&stats->nmi_start_success, 1);
		else
			__sync_fetch_and_add(&stats->nmi_start_failure, 1);
	} else {
		/* NMI: cancel_async */
		__sync_fetch_and_add(&stats->nmi_cancel_attempts, 1);
		start_time = bpf_ktime_get_ns();
		bpf_timer_cancel_async(&elem->timer);
		duration = bpf_ktime_get_ns() - start_time;
		record_timing(&stats->nmi_cancel_timing, duration);
		__sync_fetch_and_add(&stats->nmi_cancel_success, 1);
	}

	return 0;
}
