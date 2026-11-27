// SPDX-License-Identifier: GPL-2.0
/*
 * A scheduler whose ops.init() arms a timer. The timer is in a map that user
 * space keeps when the scheduler and its struct_ops map are gone, so the
 * callback, a part of the program of ops.init(), goes on to run. Once user
 * space asks for it the callback throws each time: the kernel unwinds a
 * program of a scheduler that is gone, which is none of the next scheduler.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

extern void bpf_throw(u64 cookie) __ksym;

struct elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct elem);
} timers SEC(".maps");

/* What user space still reaches when the skeleton is gone: throw now, and how often it threw */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, u64);
} state SEC(".maps");

UEI_DEFINE(uei);

static int timer_cb(void *map, int *key, struct elem *e)
{
	u32 fail_now = 0, nr_unwound = 1;
	u64 *fail, *nr;

	bpf_timer_start(&e->timer, 5 * 1000 * 1000, 0);
	fail = bpf_map_lookup_elem(&state, &fail_now);
	nr = bpf_map_lookup_elem(&state, &nr_unwound);
	if (fail && nr && *fail) {
		__sync_fetch_and_add(nr, 1);
		bpf_throw(0);
	}
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(stale_unwound_init)
{
	struct elem *e;
	u32 key = 0;

	e = bpf_map_lookup_elem(&timers, &key);
	if (!e)
		return -ENOENT;
	bpf_timer_init(&e->timer, &timers, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&e->timer, timer_cb);
	bpf_timer_start(&e->timer, 5 * 1000 * 1000, 0);
	return 0;
}

void BPF_STRUCT_OPS(stale_unwound_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops stale_unwound_ops = {
	.init		= (void *) stale_unwound_init,
	.exit		= (void *) stale_unwound_exit,
	.name		= "stale_unwound",
};
