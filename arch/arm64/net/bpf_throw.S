/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/linkage.h>
#include <linux/bpf_throw.h>

/*
 * Push a frame record whose link register is \ra and save the BPF register
 * file of the throw site below it as a struct bpf_throw_regs: r[i] sits at
 * [sp + 16 + 8 * i], with R0 in x8, R1-R5 in x0-x4 and R6-R9 in x19-x22, and
 * the extra callee-saved registers x23..x28 follow at [sp + 96].
 */
	.macro	save_bpf_regs, ra
	stp	x29, \ra, [sp, #-(16 + BPF_THROW_REGS_SIZE)]!
	mov	x29, sp
	stp	x8, x0, [sp, #16]
	stp	x1, x2, [sp, #32]
	stp	x3, x4, [sp, #48]
	stp	x19, x20, [sp, #64]
	stp	x21, x22, [sp, #80]
	stp	x23, x24, [sp, #96]
	stp	x25, x26, [sp, #112]
	stp	x27, x28, [sp, #128]
	.endm

/*
 * Native entry of the bpf_throw() kfunc. The verifier retargets the call to
 * bpf_throw() here, so the BPF register file of the throw site is still intact
 * on entry and x30 is the return address into the program. Capture the file
 * and hand it to bpf_throw_unwind(), which never returns.
 */
SYM_FUNC_START(bpf_throw_entry)
	save_bpf_regs x30
	/* bpf_throw_unwind(regs, cookie, BPF_THROW_CALL); the cookie is R1 of the caller. */
	mov	x1, x0
	add	x0, sp, #16
	mov	x2, #BPF_THROW_CALL
	bl	bpf_throw_unwind
	brk	#0x1
SYM_FUNC_END(bpf_throw_entry)

/*
 * Entry of a cancellation after the pad of the helper that ran the cancelled
 * callback. The unwinder made it the helper's return address, and the return
 * address of the call in the program, which the callback left in r0, is what
 * the pad returns, in x0. The frame record names it as the return address,
 * as if the program had called from there, with the callee-saved registers
 * the helper's epilogue restored, which are all the program has live after
 * a call.
 */
SYM_CODE_START(bpf_cancel_entry)
	save_bpf_regs x0
	/* bpf_throw_unwind(regs, 0, BPF_THROW_CANCEL) does not return. */
	add	x0, sp, #16
	mov	x1, #0
	mov	x2, #BPF_THROW_CANCEL
	bl	bpf_throw_unwind
	brk	#0x1
SYM_CODE_END(bpf_cancel_entry)

/*
 * Entry of a cancellation at an arena page fault in JITed code. The exception
 * table handler leaves the faulting pc in x10, a temporary of the JIT that no
 * BPF register maps to, and returns to the interrupted context with its pc
 * pointing here, on the stack the program had at the access. The frame record
 * names the faulting instruction as the return address, so that the unwinder
 * finds the program's frame at the exact pc of the access.
 */
SYM_CODE_START(bpf_throw_fault_entry)
	save_bpf_regs x10
	/* bpf_throw_unwind(regs, 0, BPF_THROW_FAULT) does not return. */
	add	x0, sp, #16
	mov	x1, #0
	mov	x2, #BPF_THROW_FAULT
	bl	bpf_throw_unwind
	brk	#0x1
SYM_CODE_END(bpf_throw_fault_entry)
