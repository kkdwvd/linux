/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/linkage.h>
#include <linux/bpf_throw.h>
#include <asm/nospec-branch.h>

	.code64
	.section .text, "ax"

/*
 * Native entry of the bpf_throw() kfunc. The verifier retargets the call to
 * bpf_throw() here, so the BPF register file of the throw site is still intact
 * on entry. Capture it on the stack as a struct bpf_throw_regs, along with
 * r12, the callee-saved register no BPF register maps to, and hand it to
 * bpf_throw_unwind(), which never returns.
 */
SYM_FUNC_START(bpf_throw_entry)
	ANNOTATE_NOENDBR

	/* Setup frame. */
	pushq %rbp
	movq %rsp, %rbp

	/* Save r12, then R9..R0 so that [rsp + 8 * i] is r[i]. */
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

	/* bpf_throw_unwind(regs, cookie, BPF_THROW_CALL); the cookie is R1 of the caller. */
	movq %rdi, %rsi
	movq %rsp, %rdi
	movl $BPF_THROW_CALL, %edx

	/* Emit call depth accounting for call below. */
	CALL_DEPTH_ACCOUNT
	call bpf_throw_unwind
	ud2
SYM_FUNC_END(bpf_throw_entry)

/*
 * Entry of a cancellation at an arena page fault in JITed code. The exception
 * table handler leaves the faulting ip in r11, a temporary of the JIT that no
 * BPF register maps to, and returns to the interrupted context with its ip
 * pointing here. That return is an iret, so the stack is the one the program
 * had at the access, and pushing r11 gives it the shape of a call from the
 * faulting instruction: the frame below looks like that of bpf_throw_entry
 * and the unwinder finds the program's frame through the return address, at
 * the exact ip of the access.
 */
SYM_CODE_START(bpf_throw_fault_entry)
	UNWIND_HINT_UNDEFINED
	ANNOTATE_NOENDBR
	pushq %r11
	UNWIND_HINT_FUNC

	/* Setup frame. */
	pushq %rbp
	movq %rsp, %rbp

	/* Save r12, then R9..R0 so that [rsp + 8 * i] is r[i]. */
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

	/* bpf_throw_unwind(regs, 0, BPF_THROW_FAULT) does not return. */
	movq %rsp, %rdi
	xorl %esi, %esi
	movl $BPF_THROW_FAULT, %edx

	/* Emit call depth accounting for call below. */
	CALL_DEPTH_ACCOUNT
	call bpf_throw_unwind
	ud2
SYM_CODE_END(bpf_throw_fault_entry)
