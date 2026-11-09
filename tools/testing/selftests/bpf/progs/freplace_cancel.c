// SPDX-License-Identifier: GPL-2.0
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
__u64 released;

/* The object the unwinder released: the handle of an object is its pointer. */
SEC("fentry/bpf_unwind_release")
int BPF_PROG(release_hook, struct bpf_resource *res, void *handle, void *flags)
{
	if (res->kind == BPF_RESOURCE_OBJ && (__u64)handle == acquired)
		released = (__u64)handle;
	return 0;
}

/* Holds an object and spins until the may_goto cancels the extension. */
static __always_inline int hold_and_spin(void)
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

/* Replaces the global function of the target: returns into the target's frame. */
SEC("freplace/tc_glob")
int ext_glob(struct __sk_buff *skb)
{
	return hold_and_spin();
}

/* Replaces the target's main program: returns to what ran the target. */
SEC("freplace/tc_main")
int ext_main(struct __sk_buff *skb)
{
	return hold_and_spin();
}
