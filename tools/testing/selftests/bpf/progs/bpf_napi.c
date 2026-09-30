// SPDX-License-Identifier: GPL-2.0

#include "bpf_experimental.h"
#include <errno.h>

/* Hand a NAPI to a BPF kthread and poll it the way a NAPI kthread would. */
char _license[] SEC("license") = "GPL";

struct poller {
	struct bpf_kthread kthread;
	struct bpf_waitq waitq;
	__u64 rounds;		/* callback iterations that polled */
	__u64 polls;		/* driver poll calls */
	__u64 work;		/* work units the driver reported */
	__u64 unbound;		/* polls that found the NAPI unbound */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct poller);
} poller_map SEC(".maps");

__u32 napi_id;
__u32 other_napi_id;

static struct poller *get_poller(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&poller_map, &key);
}

static int poll_cb(void *map, int *key, void *value)
{
	struct poller *p = value;
	__u32 seq;
	int ret;

	seq = bpf_waitq_sequence(&p->waitq);

	/* Counters are only added to, never branched on, so the loop converges. */
	ret = bpf_napi_poll(napi_id, 0);
	if (ret >= 0) {
		p->rounds++;
		do {
			p->polls++;
			p->work += ret & BPF_NAPI_POLL_WORK_MASK;
			if (!(ret & BPF_NAPI_POLL_MORE))
				break;
			ret = bpf_napi_poll(napi_id, 0);
		} while (ret >= 0 && can_loop);
	}
	if (ret == -ENOENT) {
		p->unbound++;
		bpf_waitq_wait_event(&p->waitq, seq, 10 * 1000 * 1000ULL);
		return 0;
	}
	bpf_waitq_wait_event(&p->waitq, seq, ~0ULL);
	return 0;
}

SEC("syscall")
int init_waitq(void *ctx)
{
	struct poller *p = get_poller();

	if (!p)
		return -1;
	return bpf_waitq_init(&p->waitq, &poller_map, 0);
}

SEC("syscall")
int bind_napi(void *ctx)
{
	struct poller *p = get_poller();

	if (!p)
		return -1;
	return bpf_napi_bind(napi_id, &p->waitq, 0);
}

SEC("syscall")
int bind_other_napi(void *ctx)
{
	struct poller *p = get_poller();

	if (!p)
		return -1;
	return bpf_napi_bind(other_napi_id, &p->waitq, 0);
}

SEC("syscall")
int bind_bad_flags(void *ctx)
{
	struct poller *p = get_poller();

	if (!p)
		return -1;
	return bpf_napi_bind(napi_id, &p->waitq, 1);
}

SEC("syscall")
int unbind_napi(void *ctx)
{
	return bpf_napi_unbind(napi_id);
}

SEC("syscall")
int poll_napi(void *ctx)
{
	return bpf_napi_poll(napi_id, 0);
}

SEC("syscall")
int poll_busy(void *ctx)
{
	return bpf_napi_poll(napi_id, BPF_NAPI_POLL_F_BUSY);
}

SEC("syscall")
int wake_poller(void *ctx)
{
	struct poller *p = get_poller();

	if (!p)
		return -1;
	return bpf_waitq_wake(&p->waitq, 1, 0);
}

SEC("syscall")
int start_poller(void *ctx)
{
	struct poller *p = get_poller();
	int ret;

	if (!p)
		return -1;
	ret = bpf_kthread_create(&p->kthread, &poller_map, 0, poll_cb);
	if (ret)
		return ret;
	return bpf_kthread_start(&p->kthread, 0);
}

SEC("syscall")
int stop_poller(void *ctx)
{
	struct poller *p = get_poller();

	if (!p)
		return -1;
	return bpf_kthread_stop(&p->kthread, 0);
}
