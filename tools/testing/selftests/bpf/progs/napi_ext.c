// SPDX-License-Identifier: GPL-2.0
/*
 * An extension at the step where a NAPI is scheduled, see net/core/napi_bpf.c. The poll is
 * a coroutine by hand: its frame is in the NAPI, the entry defers it to softirq or to the
 * thread of the NAPI, and the kernel resumes the continuation where the NAPI is polled,
 * which calls the driver's poll. See prog_tests/napi_ext.c.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "napi_ext.h"

extern void *bpf_coro_frame_alloc_napi(__u64 size, struct napi_struct *napi) __ksym;
extern void bpf_napi_defer(void *frame, __u32 where) __ksym;
extern void bpf_napi_poll_native(struct napi_struct *napi) __ksym;
extern void bpf_napi_poll_run(struct napi_struct *napi) __ksym;

char _license[] SEC("license") = "GPL";

/* set by the test */
int mode;
int where;
int again_defers;	/* again() defers to 'where' in place of polling */

/* entries by reason, and of those the ones in hard interrupt context */
__u64 entries[3], hardirq;
__u64 deferred, resumed, polled, native, no_frame;
/* the NAPI of the last entry, and how far its frame is behind it */
__u32 napi_id;
__s64 frame_off;

/* The frames of a recursion that began */
unsigned long frames;

/* It calls itself until the stack has no room, which has the kernel unwind the program */
__naked __noinline __used
static unsigned long dives(void)
{
	asm volatile (
		"r1 = %[frames] ll;"
		"r2 = *(u64 *)(r1 + 0);"
		"r2 += 1;"
		"*(u64 *)(r1 + 0) = r2;"
		"*(u64 *)(r10 - 128) = r2;"
		"call dives;"
		"exit;"
		:
		: __imm_addr(frames)
		: __clobber_all
	);
}

/* The continuation: softirq or the thread got to the NAPI. The poll is the end of the frame. */
static __noinline __used void poll_fn(void *frame)
{
	__u64 *f = frame;

	__sync_fetch_and_add(&resumed, 1);
	if (f[3] == MODE_DIVES)
		dives();
	__sync_fetch_and_add(&polled, 1);
	bpf_napi_poll_run((struct napi_struct *)f[2]);
}

static __always_inline void defer(struct napi_struct *napi, int how)
{
	__u64 *f;

	f = bpf_coro_frame_alloc_napi(32, napi);
	if (!f) {
		__sync_fetch_and_add(&no_frame, 1);
		bpf_napi_poll_native(napi);
		return;
	}
	frame_off = (long)f - (long)napi;
	f[0] = (__u64)poll_fn;
	f[1] = 0;
	f[2] = (__u64)napi;
	f[3] = how;
	if (how == MODE_ENTRY_DIVES)
		dives();
	__sync_fetch_and_add(&deferred, 1);
	bpf_napi_defer(f, where);
}

SEC("struct_ops/schedule")
void BPF_PROG(schedule, struct napi_struct *napi, __u32 reason)
{
	if (reason < 3)
		__sync_fetch_and_add(&entries[reason], 1);
	if (bpf_in_hardirq())
		__sync_fetch_and_add(&hardirq, 1);
	napi_id = napi->napi_id;
	if (mode == MODE_NATIVE) {
		__sync_fetch_and_add(&native, 1);
		bpf_napi_poll_native(napi);
		return;
	}
	defer(napi, mode);
}

/* again() of a thread that polls: the frame of a poll that it defers once more */
static __noinline __used void again_fn(void *frame)
{
	__u64 *f = frame;

	__sync_fetch_and_add(&resumed, 1);
	__sync_fetch_and_add(&polled, 1);
	bpf_napi_poll_run((struct napi_struct *)f[2]);
}

SEC("struct_ops/again")
void BPF_PROG(again, struct napi_struct *napi, __u32 reason)
{
	__u64 *f;

	if (reason < 3)
		__sync_fetch_and_add(&entries[reason], 1);
	if (again_defers) {
		f = bpf_coro_frame_alloc_napi(32, napi);
		if (f) {
			f[0] = (__u64)again_fn;
			f[1] = 0;
			f[2] = (__u64)napi;
			__sync_fetch_and_add(&deferred, 1);
			bpf_napi_defer(f, where);
			return;
		}
	}
	__sync_fetch_and_add(&polled, 1);
	bpf_napi_poll_run(napi);
}

SEC(".struct_ops.link")
struct bpf_napi_ops napi_ext = {
	.schedule = (void *)schedule,
	.again = (void *)again,
};
