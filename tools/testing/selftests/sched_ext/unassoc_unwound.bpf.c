// SPDX-License-Identifier: GPL-2.0
/*
 * A root scheduler that takes sub-schedulers, and whose ops.running() is a
 * program of two struct_ops maps. Such a program has no scheduler of its own:
 * it could be an operator of the root or of a sub-scheduler. When it is
 * unwound, the root scheduler has failed.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

extern void bpf_throw(u64 cookie) __ksym;

/* a scheduler with ops.sub_attach() is one of the cid form, which has an arena */
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1 << 16);
} arena SEC(".maps");

bool fail_now;

UEI_DEFINE(uei);

void BPF_STRUCT_OPS(unassoc_unwound_running, struct task_struct *p)
{
	/* a program of the scheduler has to refer to the arena */
	asm volatile("" :: "r"(&arena));
	if (fail_now)
		bpf_throw(0);
}

s32 BPF_STRUCT_OPS(unassoc_unwound_sub_attach, struct scx_sub_attach_args *args)
{
	return -EOPNOTSUPP;
}

void BPF_STRUCT_OPS(unassoc_unwound_sub_detach, struct scx_sub_detach_args *args)
{
}

void BPF_STRUCT_OPS(unassoc_unwound_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_CID_DEFINE(unassoc_unwound_ops,
		   .running	= (void *) unassoc_unwound_running,
		   .sub_attach	= (void *) unassoc_unwound_sub_attach,
		   .sub_detach	= (void *) unassoc_unwound_sub_detach,
		   .exit	= (void *) unassoc_unwound_exit,
		   .name	= "unassoc_unwound");

/* Never a scheduler. The attempt to attach it makes ops.running() a program of two maps. */
SCX_OPS_CID_DEFINE(unassoc_unwound_ops2,
		   .running	= (void *) unassoc_unwound_running,
		   .name	= "unassoc_unwound2");
