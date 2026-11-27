// SPDX-License-Identifier: GPL-2.0
/*
 * A scheduler that fails while it runs: ops.running() is unwound once user
 * space has asked for it. Its cgroups were initialized before that, and the
 * disable path does not give them back to it: ops.cgroup_exit() is an operator
 * of a scheduler that failed, like any other.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

extern void bpf_throw(u64 cookie) __ksym;

bool fail_now, failed;
u64 nr_cgroup_init, nr_cgroup_exit_failed;

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS_SLEEPABLE(ops_after_failure_cgroup_init, struct cgroup *cgrp,
			     struct scx_cgroup_init_args *args)
{
	__sync_fetch_and_add(&nr_cgroup_init, 1);
	return 0;
}

void BPF_STRUCT_OPS(ops_after_failure_cgroup_exit, struct cgroup *cgrp)
{
	if (failed)
		__sync_fetch_and_add(&nr_cgroup_exit_failed, 1);
}

void BPF_STRUCT_OPS(ops_after_failure_running, struct task_struct *p)
{
	if (fail_now)
		bpf_throw(0);
}

/* scx_claim_exit() has claimed the exit: the error of the unwound operator */
SEC("tp_btf/sched_ext_exit")
int BPF_PROG(exit_claimed, struct scx_sched *sch, u32 kind)
{
	failed = true;
	return 0;
}

void BPF_STRUCT_OPS(ops_after_failure_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops ops_after_failure_ops = {
	.cgroup_init	= (void *) ops_after_failure_cgroup_init,
	.cgroup_exit	= (void *) ops_after_failure_cgroup_exit,
	.running	= (void *) ops_after_failure_running,
	.exit		= (void *) ops_after_failure_exit,
	.name		= "ops_after_failure",
};
