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
/*
 * How often the unwinder released the task the kernel handed an operator a
 * reference to: the current task, since the operators run at the attach.
 */
__u32 task_released;

/* The object the unwinder released: the handle of an object is its pointer. */
SEC("fentry/bpf_unwind_release")
int BPF_PROG(release_hook, struct bpf_resource *res, void *handle, void *flags)
{
	if (res->kind == BPF_RESOURCE_OBJ && (__u64)handle == acquired)
		released = (__u64)handle;
	if ((__u64)handle == (__u64)bpf_get_current_task_btf())
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

	release_or_throw(ctx);
	return t == NULL;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_ctx_ref = {
	.test_refcounted = (void *)test_refcounted,
};

/*
 * Throws before touching the argument: the operator holds the reference in
 * the context alone, which nothing live points at by then, so the unwinder
 * releases it from the mirror the entry fills from the context.
 */
SEC("struct_ops/test_refcounted")
int BPF_PROG(test_refcounted_throw_unloaded, int dummy, struct task_struct *task)
{
	bpf_throw(0);
	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_ctx_ref_unloaded = {
	.test_refcounted = (void *)test_refcounted_throw_unloaded,
};

/* Throws with the argument loaded: released from the register that holds it. */
SEC("struct_ops/test_refcounted")
int BPF_PROG(test_refcounted_throw_loaded, int dummy, struct task_struct *task)
{
	acquired = (__u64)task;
	bpf_throw(0);
	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_ctx_ref_loaded = {
	.test_refcounted = (void *)test_refcounted_throw_loaded,
};

static __noinline int throw_with_ctx(unsigned long long *ctx)
{
	if (ctx[0] == 0)
		bpf_throw(0);
	return 0;
}

/*
 * Passes the context to a subprog that throws and releases nothing: the
 * operator's frame lists the argument at the call, through the context or
 * from its mirror, and the subprog, which holds it for the operator, does not.
 */
SEC("struct_ops/test_refcounted")
int BPF_PROG(test_refcounted_callee_throws, int dummy, struct task_struct *task)
{
	throw_with_ctx(ctx);
	bpf_task_release(task);
	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_ctx_ref_callee = {
	.test_refcounted = (void *)test_refcounted_callee_throws,
};
