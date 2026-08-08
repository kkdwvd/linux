// SPDX-License-Identifier: GPL-2.0

#include "bpf_experimental.h"

/* Exercise wait queues from both syscall and BPF kthread contexts. */
char _license[] SEC("license") = "GPL";

struct waitq_elem {
	struct bpf_waitq waitq;
	struct bpf_kthread kthread;
	__u32 state;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct waitq_elem);
} waitq_map SEC(".maps");

__u32 callback_runs[2];
__u32 callback_exits[2];

static int thread_cb(void *map, int *key, void *value)
{
	struct waitq_elem *elem = value;
	int idx = *key;

	if (idx < 0 || idx >= 2)
		return 1;

	__sync_fetch_and_add(&callback_runs[idx], 1);
	if (elem->state == 0) {
		bpf_waitq_wait(&elem->waitq, &elem->state, 0, ~0ULL, 0);
		return 0;
	}

	__sync_fetch_and_add(&callback_exits[idx], 1);
	return 1;
}

static __noinline int start_one(__u32 key)
{
	struct waitq_elem *elem;
	int ret;

	elem = bpf_map_lookup_elem(&waitq_map, &key);
	if (!elem)
		return -1;

	ret = bpf_waitq_init(&elem->waitq, &waitq_map, 0);
	if (ret)
		return ret;
	ret = bpf_kthread_create(&elem->kthread, &waitq_map, thread_cb, 0);
	if (ret)
		return ret;
	return bpf_kthread_start(&elem->kthread, 0);
}

SEC("syscall")
int start_wake_case(void *ctx)
{
	return start_one(0);
}

SEC("syscall")
int start_stop_case(void *ctx)
{
	return start_one(1);
}

SEC("syscall")
int wake_thread(void *ctx)
{
	__u32 key = 0;
	struct waitq_elem *elem;

	elem = bpf_map_lookup_elem(&waitq_map, &key);
	if (!elem)
		return -1;

	elem->state = 1;
	return bpf_waitq_wake(&elem->waitq, 1, 0);
}

SEC("syscall")
int stop_wake_thread(void *ctx)
{
	__u32 key = 0;
	struct waitq_elem *elem;

	elem = bpf_map_lookup_elem(&waitq_map, &key);
	if (!elem)
		return -1;
	return bpf_kthread_stop(&elem->kthread, 0);
}

SEC("syscall")
int wait_mismatch(void *ctx)
{
	__u32 key = 0;
	struct waitq_elem *elem;

	elem = bpf_map_lookup_elem(&waitq_map, &key);
	if (!elem)
		return -1;
	return bpf_waitq_wait(&elem->waitq, &elem->state, 0, 0, 0);
}

SEC("syscall")
int stop_waiting_thread(void *ctx)
{
	__u32 key = 1;
	struct waitq_elem *elem;

	elem = bpf_map_lookup_elem(&waitq_map, &key);
	if (!elem)
		return -1;
	return bpf_kthread_stop(&elem->kthread, 0);
}

SEC("syscall")
int wait_timeout(void *ctx)
{
	__u32 key = 1;
	struct waitq_elem *elem;

	elem = bpf_map_lookup_elem(&waitq_map, &key);
	if (!elem)
		return -1;
	return bpf_waitq_wait(&elem->waitq, &elem->state, 0, 0, 0);
}
