// SPDX-License-Identifier: GPL-2.0
/*
 * Extensions at the step where a NAPI is scheduled that are not loaded, one struct_ops map
 * each, see prog_tests/napi_ext.c: an entry that keeps its poll or polls itself, a
 * continuation that does not poll or looks at its frame behind the poll, and frames that
 * the kernel could not keep or end.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

extern void *bpf_coro_frame_alloc_napi(__u64 size, struct napi_struct *napi) __ksym;
extern void *bpf_coro_frame_alloc(__u64 size, void *ctx) __ksym;
extern void bpf_coro_frame_free(void *frame) __ksym;
extern void bpf_napi_defer(void *frame, __u32 where) __ksym;
extern void bpf_napi_poll_native(struct napi_struct *napi) __ksym;
extern void bpf_napi_poll_run(struct napi_struct *napi) __ksym;

char _license[] SEC("license") = "GPL";

__u64 sum;

static __noinline __used void poll_fn(void *frame)
{
	__u64 *f = frame;

	bpf_napi_poll_run((struct napi_struct *)f[2]);
}

SEC("struct_ops/again")
void BPF_PROG(again_polls, struct napi_struct *napi, __u32 reason)
{
	bpf_napi_poll_run(napi);
}

SEC("struct_ops/schedule")
void BPF_PROG(schedule_native, struct napi_struct *napi, __u32 reason)
{
	bpf_napi_poll_native(napi);
}

#define EXT(name, sched, ag)						\
	SEC(".struct_ops.link")						\
	struct bpf_napi_ops name = {					\
		.schedule = (void *)sched,				\
		.again = (void *)ag,					\
		.ifindex = 1,						\
	}

/* The entry returns with the poll */
SEC("struct_ops/schedule")
void BPF_PROG(keeps, struct napi_struct *napi, __u32 reason)
{
	sum += napi->napi_id;
}
EXT(ext_keeps, keeps, again_polls);

/* The entry, which runs with interrupts off, calls the driver's poll */
SEC("struct_ops/schedule")
void BPF_PROG(polls, struct napi_struct *napi, __u32 reason)
{
	bpf_napi_poll_run(napi);
}
EXT(ext_polls, polls, again_polls);

/* again() leaves the poll to a step that it is behind */
SEC("struct_ops/again")
void BPF_PROG(again_native, struct napi_struct *napi, __u32 reason)
{
	bpf_napi_poll_native(napi);
}
EXT(ext_again_native, schedule_native, again_native);

static __always_inline __u64 *frame_of(struct napi_struct *napi, void *resume)
{
	__u64 *f = bpf_coro_frame_alloc_napi(32, napi);

	if (!f) {
		bpf_napi_poll_native(napi);
		return NULL;
	}
	f[0] = (__u64)resume;
	f[1] = 0;
	f[2] = (__u64)napi;
	f[3] = 1;
	return f;
}

/* The continuation returns without the poll */
static __noinline __used void no_poll_fn(void *frame)
{
	__u64 *f = frame;

	sum += f[3];
}

SEC("struct_ops/schedule")
void BPF_PROG(cont_keeps, struct napi_struct *napi, __u32 reason)
{
	__u64 *f = frame_of(napi, no_poll_fn);

	if (f)
		bpf_napi_defer(f, BPF_NAPI_SOFTIRQ);
}
EXT(ext_cont_keeps, cont_keeps, again_polls);

/* The continuation looks at its frame behind the poll, in which the NAPI may be scheduled anew */
static __noinline __used void reads_fn(void *frame)
{
	__u64 *f = frame;

	bpf_napi_poll_run((struct napi_struct *)f[2]);
	sum += f[3];
}

SEC("struct_ops/schedule")
void BPF_PROG(cont_reads, struct napi_struct *napi, __u32 reason)
{
	__u64 *f = frame_of(napi, reads_fn);

	if (f)
		bpf_napi_defer(f, BPF_NAPI_SOFTIRQ);
}
EXT(ext_cont_reads, cont_reads, again_polls);

/* A frame that is larger than what a NAPI has for one */
SEC("struct_ops/schedule")
void BPF_PROG(too_big, struct napi_struct *napi, __u32 reason)
{
	__u64 *f = bpf_coro_frame_alloc_napi(64, napi);

	if (f)
		f[0] = 0;
	bpf_napi_poll_native(napi);
}
EXT(ext_too_big, too_big, again_polls);

/* The frame is deferred without its NAPI */
SEC("struct_ops/schedule")
void BPF_PROG(no_host, struct napi_struct *napi, __u32 reason)
{
	__u64 *f = bpf_coro_frame_alloc_napi(32, napi);

	if (!f) {
		bpf_napi_poll_native(napi);
		return;
	}
	f[0] = (__u64)poll_fn;
	f[1] = 0;
	f[2] = 0;
	f[3] = 0;
	bpf_napi_defer(f, BPF_NAPI_SOFTIRQ);
	bpf_napi_poll_native(napi);
}
EXT(ext_no_host, no_host, again_polls);

/* A frame that the kernel would have to call the program for, to end it */
static __noinline __used void holds_fn(void *frame)
{
	__u64 *f = frame;

	bpf_task_release((struct task_struct *)f[3]);
	bpf_napi_poll_run((struct napi_struct *)f[2]);
}

SEC("struct_ops/schedule")
void BPF_PROG(holds, struct napi_struct *napi, __u32 reason)
{
	struct task_struct *task;
	__u64 *f;

	f = bpf_coro_frame_alloc_napi(32, napi);
	if (!f) {
		bpf_napi_poll_native(napi);
		return;
	}
	task = bpf_task_from_pid(1);
	if (!task) {
		bpf_napi_poll_native(napi);
		return;
	}
	f[0] = (__u64)holds_fn;
	f[1] = 0;
	f[2] = (__u64)napi;
	f[3] = (__u64)task;
	bpf_napi_defer(f, BPF_NAPI_SOFTIRQ);
}
EXT(ext_holds, holds, again_polls);

/* A frame from the cache of the program is not in the NAPI for the kernel to keep it there */
SEC("struct_ops/schedule")
void BPF_PROG(cached, struct napi_struct *napi, __u32 reason)
{
	__u64 *f = bpf_coro_frame_alloc(32, NULL);

	if (!f) {
		bpf_napi_poll_native(napi);
		return;
	}
	f[0] = (__u64)poll_fn;
	f[1] = 0;
	f[2] = (__u64)napi;
	f[3] = 0;
	bpf_napi_defer(f, BPF_NAPI_SOFTIRQ);
}
EXT(ext_cached, cached, again_polls);
