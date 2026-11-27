// SPDX-License-Identifier: GPL-2.0
/*
 * A scheduler that is being unregistered, and whose ops.exit_task() is unwound
 * on the way: it throws once the exit is claimed, which the tracepoint of the
 * claim tells. So the unwound program cannot claim an error. The scheduler has
 * failed all the same, and no operator of it is called after that.
 *
 * User space cannot tell: a task that exits between a flag that it sets and
 * its destroy of the link would be unwound before the exit is claimed, and the
 * scheduler would exit with that error.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

extern void bpf_throw(u64 cookie) __ksym;

bool unloading;
u64 nr_exit_task_unloading;

UEI_DEFINE(uei);

void BPF_STRUCT_OPS(exit_task_unwound_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	if (!unloading)
		return;
	__sync_fetch_and_add(&nr_exit_task_unloading, 1);
	bpf_throw(0);
}

/* scx_claim_exit() has claimed the exit: the unregistration, in this test */
SEC("tp_btf/sched_ext_exit")
int BPF_PROG(exit_claimed, struct scx_sched *sch, u32 kind)
{
	unloading = true;
	return 0;
}

void BPF_STRUCT_OPS(exit_task_unwound_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops exit_task_unwound_ops = {
	.exit_task	= (void *) exit_task_unwound_exit_task,
	.exit		= (void *) exit_task_unwound_exit,
	.name		= "exit_task_unwound",
};
