// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "../test_kmods/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

struct foo {
	int data;
};

__u64 acquired;
__u64 released;
__u32 cancelled;
/* The task the kernel handed test_refcounted a reference to, and how often the unwinder released it. */
__u64 task_ptr;
__u32 task_released;

/* The object the unwinder released: the handle of an object is its pointer. */
SEC("fentry/bpf_unwind_release")
int BPF_PROG(release_hook, struct bpf_resource *res, void *handle, void *flags)
{
	if (res->kind == BPF_RESOURCE_OBJ && (__u64)handle == acquired)
		released = (__u64)handle;
	if (task_ptr && (__u64)handle == task_ptr)
		task_released++;
	return 0;
}

/* The struct_ops was told that its operator was cancelled. */
SEC("fentry/bpf_testmod_ops_cancel")
int BPF_PROG(cancel_hook, const struct bpf_prog *prog)
{
	cancelled++;
	return 0;
}

/* Runs when the struct_ops is attached, and spins until the may_goto cancels it. */
SEC("struct_ops/test_1")
int BPF_PROG(test_1)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	acquired = (__u64)f;
	for (;;)
		cond_break;
	bpf_obj_drop(f);
	return 42;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_cancel = {
	.test_1 = (void *)test_1,
};

/* Loads the task the kernel holds a reference to from ctx: throws holding it when dummy is 0, releases it otherwise. */
static __noinline int release_or_throw(unsigned long long *ctx)
{
	struct task_struct *task = (void *)ctx[1];

	barrier_var(task);
	if (ctx[0] == 0)
		bpf_throw(0);
	bpf_task_release(task);
	return 0;
}

/*
 * The reference the kernel holds for a __ref argument is released once: by
 * the subprog that loads it from ctx, or by the unwinder from the frame that
 * throws holding it, not from the operator's frame as well, which keeps the
 * task live across the call.
 */
SEC("struct_ops/test_refcounted")
int BPF_PROG(test_refcounted, int dummy, struct task_struct *task)
{
	struct task_struct *t = task;

	task_ptr = (__u64)t;
	release_or_throw(ctx);
	return t == NULL;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_ctx_ref = {
	.test_refcounted = (void *)test_refcounted,
};
