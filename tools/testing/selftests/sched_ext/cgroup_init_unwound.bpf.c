// SPDX-License-Identifier: GPL-2.0
/*
 * A scheduler whose ops.cgroup_init() is unwound: it throws. The scheduler has
 * failed at the first cgroup, and the operator is not called for the others.
 * Nor is ops.cgroup_exit(), for a cgroup that the scheduler was told about or
 * for the others.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

extern void bpf_throw(u64 cookie) __ksym;

u64 nr_cgroup_init, nr_cgroup_exit;

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS_SLEEPABLE(cgroup_init_unwound_cgroup_init, struct cgroup *cgrp,
			     struct scx_cgroup_init_args *args)
{
	__sync_fetch_and_add(&nr_cgroup_init, 1);
	bpf_throw(0);
	return 0;
}

void BPF_STRUCT_OPS(cgroup_init_unwound_cgroup_exit, struct cgroup *cgrp)
{
	__sync_fetch_and_add(&nr_cgroup_exit, 1);
}

void BPF_STRUCT_OPS(cgroup_init_unwound_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops cgroup_init_unwound_ops = {
	.cgroup_init	= (void *) cgroup_init_unwound_cgroup_init,
	.cgroup_exit	= (void *) cgroup_init_unwound_cgroup_exit,
	.exit		= (void *) cgroup_init_unwound_exit,
	.name		= "cgroup_init_unwound",
};
