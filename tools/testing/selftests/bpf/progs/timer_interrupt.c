// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

#define CLOCK_MONOTONIC		1

int in_interrupt;
int soft_preempt_count;
int soft_in_interrupt;
int soft_in_hardirq;
int hard_preempt_count;
int hard_in_interrupt;
int hard_in_hardirq;
bool soft_fired;
bool hard_fired;
int timer_err;

struct elem {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct elem);
} array SEC(".maps");

static int timer_in_interrupt(void *map, int *key, struct elem *value)
{
	if (*key == 0) {
		soft_preempt_count = get_preempt_count();
		soft_in_interrupt = bpf_in_interrupt();
		soft_in_hardirq = bpf_in_hardirq();
		soft_fired = true;
	} else {
		hard_preempt_count = get_preempt_count();
		hard_in_interrupt = bpf_in_interrupt();
		hard_in_hardirq = bpf_in_hardirq();
		hard_fired = true;
	}
	return 0;
}

static __always_inline int start_timer(int key, __u64 flags)
{
	struct elem *value;
	int err;

	value = bpf_map_lookup_elem(&array, &key);
	if (!value)
		return -1;

	err = bpf_timer_init(&value->t, &array, flags);
	if (err)
		return err;

	err = bpf_timer_set_callback(&value->t, timer_in_interrupt);
	if (err)
		return err;

	return bpf_timer_start(&value->t, 0, BPF_F_TIMER_CPU_PIN);
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test_timer_interrupt)
{
	in_interrupt = bpf_in_interrupt();

	timer_err = start_timer(0, CLOCK_MONOTONIC);
	if (timer_err)
		return 0;

	timer_err = start_timer(1, CLOCK_MONOTONIC | BPF_F_TIMER_HARDIRQ);
	return 0;
}
