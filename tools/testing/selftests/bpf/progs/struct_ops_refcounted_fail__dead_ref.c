// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

/* No store follows the argument, so the prog gets no hidden slots, and nothing has its task either */
SEC("struct_ops/test_refcounted")
__arch_x86_64
__arch_arm64
__failure __msg("conflict: no place has the handle on all paths")
int BPF_PROG(refcounted_fail__dead_ref, int dummy, struct task_struct *task)
{
	task = bpf_task_from_pid(1);
	barrier_var(task);
	task = NULL;
	barrier_var(task);
	bpf_throw(0);
	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_dead_ref = {
	.test_refcounted = (void *)refcounted_fail__dead_ref,
};
