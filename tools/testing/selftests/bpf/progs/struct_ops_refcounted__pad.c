// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

__attribute__((nomerge)) extern void bpf_task_release(struct task_struct *p) __ksym;

/*
 * The task came with the __ref argument: no insn of the prog acquired it. The landing pad of
 * bpf_throw() releases it with the kfunc that its type names.
 */
SEC("struct_ops/test_refcounted")
__arch_x86_64
__arch_arm64
__success
__log_level(2)
__msg("landing pad of bpf_throw at {{[0-9]+}}: ref@{{[0-9]+}}({{[^)]+}}) rcu=0 preempt=0")
__xlated("...")
__xlated("gotol pc+")
__xlated("...")
__xlated("call kernel-function")
__xlated("...")
__xlated("call kernel-function")
int BPF_PROG(refcounted_pad, int dummy, struct task_struct *task)
{
	barrier_var(task);
	if (dummy == 42)
		bpf_throw(0);
	bpf_task_release(task);
	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_refcounted_pad = {
	.test_refcounted = (void *)refcounted_pad,
};
