// SPDX-License-Identifier: GPL-2.0
/* Runtime tests for coroutine frame allocation. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

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

/* The id of the frame that bpf_testmod keeps, see bpf_testmod.c */
int kept_id;
/* Set by the continuation of the frame that bpf_testmod keeps */
int kept_ran;

static __noinline __used void coro_frame_resume(void *frame)
{
	bpf_coro_frame_free(frame);
	kept_ran = 1;
}

/* Give bpf_testmod a frame to keep beyond the run of the program */
SEC("syscall")
int coro_frame_keep(void *ctx)
{
	__u64 *slots = bpf_coro_frame_alloc(16, NULL);

	if (!slots)
		return -1;
	slots[0] = (__u64)coro_frame_resume;
	slots[1] = (__u64)coro_frame_resume;
	return bpf_kfunc_coro_keep(kept_id, slots);
}

/* Have the frame that bpf_testmod keeps resumed after this program's run */
SEC("syscall")
int coro_frame_resume_kept(void *ctx)
{
	return bpf_kfunc_coro_resume_kept(kept_id);
}

/* Have bpf_testmod free the frame that it keeps */
SEC("syscall")
int coro_frame_free_kept(void *ctx)
{
	return bpf_kfunc_coro_free_kept(kept_id);
}

/* What became of the resume of the frame that bpf_testmod kept */
SEC("syscall")
int coro_frame_result(void *ctx)
{
	return bpf_kfunc_coro_result(kept_id);
}
