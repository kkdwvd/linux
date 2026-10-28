/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2025 Puranjay Mohan <puranjay@kernel.org> */

#include <linux/linkage.h>
#include <linux/bpf_throw.h>

SYM_FUNC_START(arch_bpf_timed_may_goto)
	/* Allocate stack space and emit frame record */
	stp	x29, x30, [sp, #-(48 + BPF_THROW_REGS_SIZE)]!
	mov     x29, sp

	/*
	 * Save the BPF register file of the may_goto as a struct bpf_throw_regs
	 * at [sp + 16], should the program be cancelled: R0 (x8), R1-R5 (x0-x4),
	 * R6-R9 (x19-x22) and the extra callee-saved registers x23-x28. R0-R5
	 * are restored from here on the normal path, and so are the stack
	 * arguments 6 - 8 (x5-x7), which are saved above the register file.
	 */
	stp	x8, x0, [sp, #16]
	stp	x1, x2, [sp, #32]
	stp	x3, x4, [sp, #48]
	stp	x19, x20, [sp, #64]
	stp	x21, x22, [sp, #80]
	stp	x23, x24, [sp, #96]
	stp	x25, x26, [sp, #112]
	stp	x27, x28, [sp, #128]
	stp	x5, x6, [sp, #(16 + BPF_THROW_REGS_SIZE)]
	str	x7, [sp, #(32 + BPF_THROW_REGS_SIZE)]

	/*
	 * The pointer to count and timestamp was passed in BPF_REG_AX (x9),
	 * pass it as the first argument in x0.
	 */
	mov	x0, x9
	/* The return address into the program identifies the may_goto. */
	mov	x1, x30
	bl	bpf_check_timed_may_goto
#ifdef CONFIG_BPF_SYSCALL
	/* A program past its time is unwound instead of looping on. */
	mov	x1, #BPF_TIMED_MAY_GOTO_CANCEL
	cmp	x0, x1
	b.eq	.Lcancel
#endif
	/* BPF_REG_AX(x9) will be stored into count, so move return value to it. */
	mov	x9, x0

	/* Restore BPF registers R0 - R5 (x8, x0-x4) */
	ldp	x8, x0, [sp, #16]
	ldp	x1, x2, [sp, #32]
	ldp	x3, x4, [sp, #48]
	/* Restore stack arguments 6 - 8 (x5-x7) */
	ldp	x5, x6, [sp, #(16 + BPF_THROW_REGS_SIZE)]
	ldr	x7, [sp, #(32 + BPF_THROW_REGS_SIZE)]

	/* Restore FP and LR */
	ldp	x29, x30, [sp], #(48 + BPF_THROW_REGS_SIZE)

	ret

#ifdef CONFIG_BPF_SYSCALL
.Lcancel:
	/* bpf_throw_unwind(regs, 0, BPF_THROW_CANCEL) does not return. */
	add	x0, sp, #16
	mov	x1, #0
	mov	x2, #BPF_THROW_CANCEL
	bl	bpf_throw_unwind
	brk	#0x1
#endif
SYM_FUNC_END(arch_bpf_timed_may_goto)
