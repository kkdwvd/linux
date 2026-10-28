/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/linkage.h>
#include <linux/bpf_throw.h>
#include <asm/nospec-branch.h>

	.code64
	.section .text, "ax"

/*
 * Set up a frame and save the BPF register file on the stack as a struct
 * bpf_throw_regs: r12, the callee-saved register no BPF register maps to,
 * then R9..R0, so that [rsp + 8 * i] is r[i].
 */
	.macro	save_bpf_regs
	pushq %rbp
	movq %rsp, %rbp
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
	.endm

/* bpf_throw_unwind(regs, cookie, kind) with the saved register file; it does not return. */
	.macro	throw_unwind cookie, kind
	\cookie
	movq %rsp, %rdi
	movl $\kind, %edx
	CALL_DEPTH_ACCOUNT
	call bpf_throw_unwind
	ud2
	.endm

/*
 * Native entry of the bpf_throw() kfunc. The verifier retargets the call to
 * bpf_throw() here, so the BPF register file of the throw site is still intact
 * on entry; the cookie is R1 of the caller.
 */
SYM_FUNC_START(bpf_throw_entry)
	ANNOTATE_NOENDBR
	save_bpf_regs
	throw_unwind "movq %rdi, %rsi", BPF_THROW_CALL
SYM_FUNC_END(bpf_throw_entry)

/*
 * Entry of a cancellation after the pad of the helper that ran the cancelled
 * callback. The unwinder made it the helper's return address, and the return
 * address of the call in the program, which the callback left in r0, is what
 * the pad returns. Pushing it gives the stack the shape of a call from there:
 * the frame below looks like that of bpf_throw_entry, with the callee-saved
 * registers the helper's epilogue restored, which are all the program has
 * live after a call.
 */
SYM_CODE_START(bpf_cancel_entry)
	UNWIND_HINT_UNDEFINED
	ANNOTATE_NOENDBR
	pushq %rax
	UNWIND_HINT_FUNC
	save_bpf_regs
	throw_unwind "xorl %esi, %esi", BPF_THROW_CANCEL
SYM_CODE_END(bpf_cancel_entry)
