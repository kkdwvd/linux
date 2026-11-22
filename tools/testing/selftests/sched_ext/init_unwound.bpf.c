// SPDX-License-Identifier: GPL-2.0
/*
 * A scheduler whose ops.init() is unwound: it throws. It returns 0 for that,
 * which is no success: the scheduler has failed, and no operator of it is
 * called after that.
 *
 * The scheduler is told before the exception callback runs, and the callback
 * takes its time. The helper kthread starts to disable the scheduler meanwhile:
 * the error that was claimed is SCX_EXIT_DONE when ops.init() returns, and the
 * enable path still has to see that the scheduler failed.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

#define __exception_cb(name) __attribute__((btf_decl_tag("exception_callback:" #name)))

extern void bpf_throw(u64 cookie) __ksym;

u64 nr_ops_after_init;

UEI_DEFINE(uei);

__noinline int takes_its_time(u64 cookie)
{
	u64 start = bpf_ktime_get_ns();

	/* 100 ms: a wake-up of the helper kthread takes far less */
	while (bpf_ktime_get_ns() - start < 100 * 1000 * 1000)
		;
	return 0;
}

__exception_cb(takes_its_time)
s32 BPF_STRUCT_OPS_SLEEPABLE(init_unwound_init)
{
	bpf_throw(0);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(init_unwound_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	__sync_fetch_and_add(&nr_ops_after_init, 1);
	return 0;
}

void BPF_STRUCT_OPS(init_unwound_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	__sync_fetch_and_add(&nr_ops_after_init, 1);
}

void BPF_STRUCT_OPS(init_unwound_enable, struct task_struct *p)
{
	__sync_fetch_and_add(&nr_ops_after_init, 1);
}

void BPF_STRUCT_OPS(init_unwound_running, struct task_struct *p)
{
	__sync_fetch_and_add(&nr_ops_after_init, 1);
}

void BPF_STRUCT_OPS(init_unwound_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops init_unwound_ops = {
	.init		= (void *) init_unwound_init,
	.init_task	= (void *) init_unwound_init_task,
	.exit_task	= (void *) init_unwound_exit_task,
	.enable		= (void *) init_unwound_enable,
	.running	= (void *) init_unwound_running,
	.exit		= (void *) init_unwound_exit,
	.name		= "init_unwound",
};
