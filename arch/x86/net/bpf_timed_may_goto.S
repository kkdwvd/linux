// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <linux/export.h>
#include <linux/linkage.h>
#include <linux/bpf_throw.h>
#include <asm/nospec-branch.h>

	.code64
	.section .text, "ax"

SYM_FUNC_START(arch_bpf_timed_may_goto)
	ANNOTATE_NOENDBR

	/* Setup frame. */
	pushq %rbp
	movq %rsp, %rbp

	/*
	 * Save r12, then R9..R0 so that [rsp + 8 * i] is r[i]: the register
	 * file of the may_goto, in the layout bpf_throw_unwind() expects, should
	 * the program be cancelled.
	 */
	pushq %r12	/* r[10] */
	pushq %r15	/* R9 */
	pushq %r14	/* R8 */
	pushq %r13	/* R7 */
	pushq %rbx	/* R6 */
	pushq %r8	/* R5 */
	pushq %rcx	/* R4 */
	pushq %rdx	/* R3 */
	pushq %rsi	/* R2 */
	pushq %rdi	/* R1 */
	pushq %rax	/* R0 */

	/*
	 * r10 has the pointer to count and timestamp. JIT added the frame
	 * pointer to the offset. Pass it as first argument, and the return
	 * address into the program, which identifies the may_goto, as second.
	 */
	movq %r10, %rdi
	movq 8(%rbp), %rsi

	/* Emit call depth accounting for call below. */
	CALL_DEPTH_ACCOUNT
	call bpf_check_timed_may_goto

#ifdef CONFIG_BPF_SYSCALL
	cmpq $BPF_TIMED_MAY_GOTO_CANCEL, %rax
	je .Lcancel
#endif

	/* BPF_REG_AX=r10 will be stored into count, so move return value to it. */
	movq %rax, %r10

	/* Restore R0..R9 and r12. */
	popq %rax
	popq %rdi
	popq %rsi
	popq %rdx
	popq %rcx
	popq %r8
	popq %rbx
	popq %r13
	popq %r14
	popq %r15
	popq %r12

	leave
	RET

#ifdef CONFIG_BPF_SYSCALL
.Lcancel:
	/* bpf_throw_unwind(regs, 0, BPF_THROW_CANCEL) does not return. */
	movq %rsp, %rdi
	xorl %esi, %esi
	movl $BPF_THROW_CANCEL, %edx
	CALL_DEPTH_ACCOUNT
	call bpf_throw_unwind
	ud2
#endif
SYM_FUNC_END(arch_bpf_timed_may_goto)
