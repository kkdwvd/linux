// SPDX-License-Identifier: GPL-2.0
/* Runtime tests for coroutine frame allocation. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;

char _license[] SEC("license") = "GPL";

SEC("syscall")
int coro_frame_sum(void *ctx)
{
	__u64 *frame = bpf_coro_frame_alloc(64, NULL);
	__u64 sum;

	if (!frame)
		return -1;
	frame[0] = 1;
	frame[1] = 2;
	frame[7] = 39;
	sum = frame[0] + frame[1] + frame[7];
	bpf_coro_frame_free(frame);
	return sum;
}

SEC("syscall")
int coro_frame_odd_size(void *ctx)
{
	__u32 *frame = bpf_coro_frame_alloc(12, NULL);
	__u32 sum;

	if (!frame)
		return -1;
	frame[0] = 1;
	frame[1] = 2;
	frame[2] = 3;
	sum = frame[0] + frame[1] + frame[2];
	bpf_coro_frame_free(frame);
	return sum;
}
