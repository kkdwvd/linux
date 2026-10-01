// SPDX-License-Identifier: GPL-2.0

#include "bpf_experimental.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

struct elem {
	struct bpf_waitq waitq;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct elem);
} elems SEC(".maps");

static struct elem *elem0(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&elems, &key);
}

SEC("syscall")
__failure __msg("Unreleased reference")
int unpark_leak(void *ctx)
{
	struct elem *e = elem0();
	__u64 *frame;

	if (!e)
		return 0;
	frame = bpf_coro_unpark(&e->waitq, 64);
	if (!frame)
		return 0;
	return frame[0] != 0;
}

SEC("syscall")
__failure __msg("invalid")
int unpark_out_of_bounds(void *ctx)
{
	struct elem *e = elem0();
	__u64 *frame;
	__u64 v;

	if (!e)
		return 0;
	frame = bpf_coro_unpark(&e->waitq, 64);
	if (!frame)
		return 0;
	v = frame[8];
	bpf_coro_frame_free(frame);
	return v != 0;
}

/* An unparked frame's contents are data, not the pointers they may have been. */
SEC("syscall")
__failure __msg("invalid mem access")
int unpark_pointer_lost(void *ctx)
{
	struct elem *e = elem0();
	__u64 *frame;
	__u64 *p;

	if (!e)
		return 0;
	frame = bpf_coro_unpark(&e->waitq, 64);
	if (!frame)
		return 0;
	p = (__u64 *)frame[0];
	bpf_coro_frame_free(frame);
	return *p;
}
