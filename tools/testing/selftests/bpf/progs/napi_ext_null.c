// SPDX-License-Identifier: GPL-2.0
/*
 * The null extension at the step where a NAPI is scheduled, and nothing else: every poll is
 * deferred to 'where' and polled by its continuation. And one that is less: its entry leaves
 * every poll to the kernel. With the programs that drive the test NAPI of bpf_testmod, for
 * what the crossing costs and which half of it: see prog_tests/napi_ext.c.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

extern void *bpf_coro_frame_alloc_napi(__u64 size, struct napi_struct *napi) __ksym;
extern void bpf_napi_defer(void *frame, __u32 where) __ksym;
extern void bpf_napi_poll_native(struct napi_struct *napi) __ksym;
extern void bpf_napi_poll_run(struct napi_struct *napi) __ksym;
extern void bpf_napi_poll_at(struct napi_struct *napi, __u32 where) __ksym;

char _license[] SEC("license") = "GPL";

int where;

static __noinline __used void poll_fn(void *frame)
{
	__u64 *f = frame;

	bpf_napi_poll_run((struct napi_struct *)f[2]);
}

SEC("struct_ops/schedule")
void BPF_PROG(schedule, struct napi_struct *napi, __u32 reason)
{
	__u64 *f = bpf_coro_frame_alloc_napi(24, napi);

	if (!f) {
		bpf_napi_poll_native(napi);
		return;
	}
	f[0] = (__u64)poll_fn;
	f[1] = 0;
	f[2] = (__u64)napi;
	bpf_napi_defer(f, where);
}

SEC("struct_ops/again")
void BPF_PROG(again, struct napi_struct *napi, __u32 reason)
{
	bpf_napi_poll_run(napi);
}

SEC(".struct_ops.link")
struct bpf_napi_ops napi_null = {
	.schedule = (void *)schedule,
	.again = (void *)again,
};

/* The entry alone: the kernel's own step for every poll, with no frame and nothing to resume */
SEC("struct_ops/schedule")
void BPF_PROG(schedule_native, struct napi_struct *napi, __u32 reason)
{
	bpf_napi_poll_native(napi);
}

SEC("struct_ops/again")
void BPF_PROG(again_native, struct napi_struct *napi, __u32 reason)
{
	bpf_napi_poll_run(napi);
}

SEC(".struct_ops.link")
struct bpf_napi_ops napi_entry = {
	.schedule = (void *)schedule_native,
	.again = (void *)again_native,
};

/* And one that says where, and leaves the poll there to the kernel: no frame for it */
SEC("struct_ops/schedule")
void BPF_PROG(schedule_at, struct napi_struct *napi, __u32 reason)
{
	bpf_napi_poll_at(napi, where);
}

SEC(".struct_ops.link")
struct bpf_napi_ops napi_at = {
	.schedule = (void *)schedule_at,
	.again = (void *)again,
};

struct test_args {
	__u32 arg;
	__u32 pad;
	__u64 ret;
};

SEC("syscall")
int test_dev(struct test_args *args)
{
	return bpf_kfunc_napi_test_dev(args->arg);
}

SEC("syscall")
int test_id(struct test_args *args)
{
	return bpf_kfunc_napi_test_id();
}

SEC("syscall")
int test_run(struct test_args *args)
{
	args->ret = bpf_kfunc_napi_test_run(args->arg);
	return 0;
}

SEC("syscall")
int test_ctl(struct test_args *args)
{
	args->ret = bpf_kfunc_napi_test_ctl(args->arg);
	return 0;
}
