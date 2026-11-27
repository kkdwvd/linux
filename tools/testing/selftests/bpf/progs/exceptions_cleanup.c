// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

struct foo {
	int data;
	struct bpf_list_node node;
};

/* A choice of the test, read by the program under test. */
__u32 param = 1;

/* The pointer is NULL on one path, the one that is run, and a task on the other at the throw. */
SEC("tc")
__arch_x86_64
__arch_arm64
__success __retval(0xeB9F)
int throw_task_maybe(struct __sk_buff *ctx)
{
	struct task_struct *t = NULL;

	if (!param) {
		t = bpf_task_from_pid(1);
		if (!t)
			return 1;
	}
	if (ctx->len)
		bpf_throw(0xeB9F);
	if (t)
		bpf_task_release(t);
	return 0;
}

static __noinline int throw_unconditionally(void)
{
	bpf_throw(0xeB9F);
	return 0;
}

/* The caller never reads the object again after the call: a hidden slot has it there. */
SEC("tc")
__arch_x86_64
__arch_arm64
__success __retval(0xeB9F)
int throw_obj_dead_caller(struct __sk_buff *ctx)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	return throw_unconditionally();
}

/* GCC puts the call of it last in its function: last insn is not an exit or jmp */
#ifdef __clang__
static __noinline __attribute__((noreturn)) void fail_with(int err)
{
	bpf_throw(err);
	for (;;)
		;
}

int users;

/* The landing pads have run: nothing that the prog acquired is left */
__noinline int all_released(u64 cookie)
{
	return bpf_get_current_task_btf()->rcu_users.refs.counter == users ? cookie : 0;
}

/* The compiler keeps nothing over a call that does not return: the task is in r0 alone */
SEC("tc")
__arch_x86_64
__arch_arm64
__exception_cb(all_released)
__success __retval(3)
int noreturn_callee(struct __sk_buff *ctx)
{
	struct task_struct *cur = bpf_get_current_task_btf(), *t;

	users = cur->rcu_users.refs.counter;
	t = bpf_task_acquire(cur);
	if (!t)
		return 1;
	if (ctx->len)
		fail_with(3);
	bpf_task_release(t);
	return 0;
}
#endif

/* Every frame of the subprog holds an object from the same instruction, and releases its own. */
static __noinline int alloc_recurse_throw(int n)
{
	struct foo *f;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 0;
	if (n)
		alloc_recurse_throw(n - 1);
	else
		bpf_throw(0xeB9F);
	bpf_obj_drop(f);
	return 0;
}

SEC("tc")
__arch_x86_64
__arch_arm64
__success __retval(0xeB9F)
int throw_recursion_holding(struct __sk_buff *ctx)
{
	return alloc_recurse_throw(3);
}

/* The section is entered on one path to the throw only: a hidden slot counts the sections. */
SEC("tc")
__arch_x86_64
__arch_arm64
__success __retval(0xeB9F)
int throw_rcu_some_paths(struct __sk_buff *ctx)
{
	if (param)
		bpf_rcu_read_lock();
	bpf_throw(0xeB9F);
	return 0;
}

char _license[] SEC("license") = "GPL";
