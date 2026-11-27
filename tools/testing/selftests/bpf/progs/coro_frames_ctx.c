// SPDX-License-Identifier: GPL-2.0
/*
 * One program whose code allocates and frees frames of one size class in
 * three contexts of a CPU at once: the callback of its timer loops on that in
 * softirq, and the program itself does it where its perf events come, in hard
 * interrupt context for a clock and in NMI for a hardware counter. See
 * prog_tests/coro_frames.c.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

#define CLOCK_MONOTONIC	1

struct elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct elem);
} timers SEC(".maps");

int stop, started;
__u64 rounds, events, no_frame;

static __always_inline void pair(void)
{
	void *frame = bpf_coro_frame_alloc(48, NULL);

	if (frame)
		bpf_coro_frame_free(frame);
	else
		__sync_fetch_and_add(&no_frame, 1);
}

#define TAKE(n)	void *frame##n = bpf_coro_frame_alloc(48, NULL)
#define GIVE(n)	({ if (frame##n) bpf_coro_frame_free(frame##n); })

/* Frames in the cache, so that it is not out of them where it is not taken */
static __noinline void pile(void)
{
	TAKE(0); TAKE(1); TAKE(2); TAKE(3); TAKE(4); TAKE(5); TAKE(6); TAKE(7);

	GIVE(0); GIVE(1); GIVE(2); GIVE(3); GIVE(4); GIVE(5); GIVE(6); GIVE(7);
}

static int loop(void *map, int *key, struct elem *elem)
{
	int i;

	if (!rounds)
		pile();
	bpf_for(i, 0, 4096)
		pair();
	rounds++;
	if (!stop)
		bpf_timer_start(&elem->timer, 1000, BPF_F_TIMER_CPU_PIN);
	return 0;
}

SEC("perf_event")
int event(void *ctx)
{
	struct elem *elem;
	__u32 zero = 0;

	__sync_fetch_and_add(&events, 1);
	pair();
	if (started || stop || bpf_in_nmi())
		return 0;
	/* the first clock event starts the loop */
	elem = bpf_map_lookup_elem(&timers, &zero);
	if (!elem)
		return 0;
	started = 1;
	bpf_timer_init(&elem->timer, &timers, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&elem->timer, loop);
	bpf_timer_start(&elem->timer, 1000, BPF_F_TIMER_CPU_PIN);
	return 0;
}

char _license[] SEC("license") = "GPL";
