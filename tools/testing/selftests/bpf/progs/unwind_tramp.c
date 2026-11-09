// SPDX-License-Identifier: GPL-2.0
/*
 * Tracing programs on the subprogs of a program the kernel may unwind. The
 * trampoline of anything but fentry stands between the subprog and its BPF
 * caller while the subprog runs, where the unwinder would stop as if the
 * kernel had run the subprog as a callback, so such an attachment is refused
 * where an unwind can pass through the subprog, see bpf_check_attach_target().
 * The targets are the tc programs below with their global subprogs; the
 * tracers are loaded one at a time, each with the subprog it attaches to.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

struct foo {
	int data;
};

__u64 acquired;
__u32 released_cnt;
__u32 subprog_returned;
__u32 fentry_cnt;
__u32 fexit_cnt;

/* Attached for every run: the unwinder releasing the object the program acquired. */
SEC("fentry/bpf_unwind_release")
int BPF_PROG(release_hook, struct bpf_resource *res, void *handle, void *flags)
{
	if (res->kind == BPF_RESOURCE_OBJ && (__u64)handle == acquired)
		released_cnt++;
	return 0;
}

/* Spins until the time slice of the invocation is up, which cancels the program. */
__noinline int global_spin(void)
{
	while (can_loop)
		;
	return 1;
}

/* An unwind from global_spin() passes through a frame of this one. */
__noinline int global_calls_spin(void)
{
	return global_spin() + 1;
}

/* No site of its own: nothing unwinds from a frame of it. */
__noinline int global_leaf(int x)
{
	return x + 1;
}

/* Its only site is the call of global_leaf(), through which nothing unwinds either. */
__noinline int global_calls_leaf(int x)
{
	return global_leaf(x) + 1;
}

__noinline int global_throw(void)
{
	bpf_throw(0);
	return 1;
}

/* Cancelled in global_spin(): the unwinder drops the object, and the call never returns. */
SEC("tc")
int spin_in_subprog(struct __sk_buff *skb)
{
	struct foo *f;
	int ret;

	f = bpf_obj_new(typeof(*f));
	if (!f)
		return 1;
	acquired = (__u64)f;
	ret = global_calls_leaf(skb->len);
	ret += global_calls_spin();
	subprog_returned = 1;
	bpf_obj_drop(f);
	return ret;
}

/* Thrown in global_throw(): the default exception callback returns the cookie. */
SEC("tc")
int throw_in_subprog(struct __sk_buff *skb)
{
	return global_throw() + global_leaf(skb->len);
}

SEC("?fentry/global_spin")
int BPF_PROG(fentry_spin)
{
	fentry_cnt++;
	return 0;
}

SEC("?fexit/global_spin")
int BPF_PROG(fexit_spin, int ret)
{
	fexit_cnt++;
	return 0;
}

SEC("?fexit/global_calls_spin")
int BPF_PROG(fexit_calls_spin, int ret)
{
	fexit_cnt++;
	return 0;
}

SEC("?fexit/global_throw")
int BPF_PROG(fexit_throw, int ret)
{
	fexit_cnt++;
	return 0;
}

SEC("?fexit/global_leaf")
int BPF_PROG(fexit_leaf, int x, int ret)
{
	fexit_cnt++;
	return 0;
}

SEC("?fexit/global_calls_leaf")
int BPF_PROG(fexit_calls_leaf, int x, int ret)
{
	fexit_cnt++;
	return 0;
}
