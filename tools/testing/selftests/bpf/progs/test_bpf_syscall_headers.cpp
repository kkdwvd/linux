// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * Compile for architectures with synthetic pt_regs types. Both accesses
 * must retain CO-RE relocations, and the accessor must remain an lvalue.
 */
unsigned long syscall_arg(struct pt_regs *ctx)
{
	return PT_REGS_PARM1_SYSCALL(ctx);
}

const unsigned long *syscall_arg_address(struct pt_regs *ctx)
{
	return &PT_REGS_PARM1_SYSCALL(ctx);
}
