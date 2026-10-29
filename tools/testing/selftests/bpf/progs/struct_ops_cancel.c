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

/* The object the unwinder released. */
SEC("fentry/bpf_unwind_release")
int BPF_PROG(release_hook, struct bpf_resource *res, void *loc, void *flags)
{
	void *obj;

	if (res->kind != BPF_RESOURCE_OBJ)
		return 0;
	bpf_probe_read_kernel(&obj, sizeof(obj), loc);
	if ((__u64)obj == acquired)
		released = (__u64)obj;
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
