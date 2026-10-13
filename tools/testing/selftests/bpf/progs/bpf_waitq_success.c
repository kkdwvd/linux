// SPDX-License-Identifier: GPL-2.0

#include "bpf_experimental.h"

/* Exercise wait queues from syscall programs. */
char _license[] SEC("license") = "GPL";

struct waitq_elem {
	struct bpf_waitq waitq;
	__u32 state;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct waitq_elem);
} waitq_map SEC(".maps");

static __always_inline struct waitq_elem *lookup_elem(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&waitq_map, &key);
}

SEC("syscall")
int init_waitq(void *ctx)
{
	struct waitq_elem *elem = lookup_elem();

	if (!elem)
		return -1;
	return bpf_waitq_init(&elem->waitq, &waitq_map, 0);
}

/* The word holds 0, not 1: the wait returns at once. */
SEC("syscall")
int wait_mismatch(void *ctx)
{
	struct waitq_elem *elem = lookup_elem();

	if (!elem)
		return -1;
	return bpf_waitq_wait(&elem->waitq, &elem->state, 1, 0, 0);
}

/* The word holds 0 and nothing wakes the waiter: it sleeps 1 ms. */
SEC("syscall")
int wait_timeout(void *ctx)
{
	struct waitq_elem *elem = lookup_elem();

	if (!elem)
		return -1;
	return bpf_waitq_wait(&elem->waitq, &elem->state, 0, 1000000, 0);
}

SEC("syscall")
int wait_forever(void *ctx)
{
	struct waitq_elem *elem = lookup_elem();

	if (!elem)
		return -1;
	return bpf_waitq_wait(&elem->waitq, &elem->state, 0, ~0ULL, 0);
}

SEC("syscall")
int wake_one(void *ctx)
{
	struct waitq_elem *elem = lookup_elem();

	if (!elem)
		return -1;
	return bpf_waitq_wake(&elem->waitq, 1, 0);
}

/* A wake between the sample and the wait is not lost: the wait returns -EAGAIN. */
SEC("syscall")
int wait_event_stale(void *ctx)
{
	struct waitq_elem *elem = lookup_elem();
	__u32 seq;

	if (!elem)
		return -1;
	seq = bpf_waitq_sequence(&elem->waitq);
	bpf_waitq_wake(&elem->waitq, 1, 0);
	return bpf_waitq_wait_event(&elem->waitq, seq, 0);
}

SEC("syscall")
int wait_event_timeout(void *ctx)
{
	struct waitq_elem *elem = lookup_elem();

	if (!elem)
		return -1;
	return bpf_waitq_wait_event(&elem->waitq, bpf_waitq_sequence(&elem->waitq), 1000000);
}

SEC("syscall")
int wait_event_forever(void *ctx)
{
	struct waitq_elem *elem = lookup_elem();

	if (!elem)
		return -1;
	return bpf_waitq_wait_event(&elem->waitq, bpf_waitq_sequence(&elem->waitq), ~0ULL);
}
