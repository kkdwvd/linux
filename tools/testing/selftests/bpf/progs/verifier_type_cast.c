// SPDX-License-Identifier: GPL-2.0
/* The type cast instruction, see BPF_TYPE_CAST */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

SEC("raw_tp")
__description("void cast: a scalar becomes memory read at any offset")
__success
int void_cast_reads(void *ctx)
{
	__u64 v = bpf_get_prandom_u32();
	const char *p = bpf_void_cast(v);

	return p[-4096] + p[v] + *(const long *)(p + (1 << 20));
}

SEC("raw_tp")
__description("void cast: a pointer becomes memory read at any offset")
__success
int void_cast_pointer(void *ctx)
{
	const int *p = bpf_void_cast(bpf_get_current_task_btf());

	return p[bpf_get_prandom_u32()];
}

SEC("raw_tp")
__description("type cast: a scalar becomes a struct read through probe loads")
__success
int type_cast_struct(void *ctx)
{
	struct task_struct *task = bpf_type_cast(bpf_get_prandom_u32(), struct task_struct);

	/* a pointer member is an untrusted pointer in turn */
	return task->pid + task->real_parent->pid;
}

SEC("raw_tp")
__description("type cast: a pointer cannot be written through")
__failure __msg("only read is supported")
int type_cast_write(void *ctx)
{
	struct task_struct *task = bpf_type_cast(ctx, struct task_struct);

	task->pid = 0;
	return 0;
}

SEC("raw_tp")
__description("type cast: unknown type ID")
__failure __msg("type_cast insn to unknown BTF type ID 2147483647")
int type_cast_unknown_id(void *ctx)
{
	return *(int *)bpf_type_cast_id(ctx, 0x7fffffff);
}

SEC("raw_tp")
__description("type cast: type ID of a non-struct")
__failure __msg("is not a struct or void")
int type_cast_not_struct(void *ctx)
{
	return *(int *)bpf_type_cast_id(ctx, bpf_core_type_id_kernel(int));
}

SEC("raw_tp")
__description("type cast: type ID must be a constant")
__failure __msg("type_cast insn needs a constant BTF type ID in R1")
int type_cast_var_id(void *ctx)
{
	return *(int *)bpf_type_cast_id(ctx, bpf_get_prandom_u32());
}

SEC("socket")
__description("type cast: privileged only")
__success
__failure_unpriv __msg_unpriv("type_cast insn requires CAP_PERFMON or CAP_SYS_ADMIN")
int type_cast_unpriv(void *ctx)
{
	return *(int *)bpf_void_cast(ctx);
}
