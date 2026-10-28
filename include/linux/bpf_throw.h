/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The interface between the architecture entries of bpf_throw() and the
 * generic unwinder.
 */
#ifndef _LINUX_BPF_THROW_H
#define _LINUX_BPF_THROW_H

/*
 * How control reached bpf_throw_unwind(). The architecture entries are
 * written in assembly and pass the kind as an immediate, so these are
 * macros rather than an enum. The kernel raised every kind but a call.
 */
#define BPF_THROW_CALL		0	/* a call to bpf_throw() */
#define BPF_THROW_FAULT		1	/* an arena fault: the innermost frame is at the faulting insn */
#define BPF_THROW_CANCEL	2	/* a timed may_goto, or the helper that ran a cancelled callback */

/*
 * Returned by bpf_check_timed_may_goto() in place of a loop count when the
 * program is to be cancelled; the slow path then enters bpf_throw_unwind().
 */
#define BPF_TIMED_MAY_GOTO_CANCEL	-1

/*
 * The callee-saved registers of the architecture that no BPF register maps
 * to, which the unwinder restores along with R6..R9 when it discards frames:
 * r12 on x86-64, which holds the arena base, and x23..x28 on arm64, of which
 * x25..x28 are the BPF frame pointer, the tail call count pointer, the
 * private stack pointer and the arena base, while x23 and x24 are left alone
 * by JITed code but may be in use by the C code of the unwinder when it
 * enters the exception callback, whose epilogue never runs.
 */
#if defined(CONFIG_X86_64)
#define BPF_THROW_NR_EXTRA	1
#elif defined(CONFIG_ARM64)
#define BPF_THROW_NR_EXTRA	6
#else
#define BPF_THROW_NR_EXTRA	0
#endif
/* The callee-saved registers the unwinder tracks: R6..R9, then the extra ones. */
#define BPF_THROW_NR_CALLEE_SAVED	(4 + BPF_THROW_NR_EXTRA)
/* The size of struct bpf_throw_regs, for the entries: R0..R9 and the extra ones. */
#define BPF_THROW_REGS_SIZE		(8 * (10 + BPF_THROW_NR_EXTRA))

#ifndef __ASSEMBLER__
#include <linux/build_bug.h>
#include <linux/types.h>
#include <uapi/linux/bpf.h>

/*
 * The register file captured at a throw site: the BPF registers R0..R9, then
 * the extra callee-saved registers of the architecture; from R6 on, indexed
 * like bpf_prog_aux::callee_reg_off.
 */
struct bpf_throw_regs {
	u64 r[BPF_REG_10 + BPF_THROW_NR_EXTRA];
};
static_assert(sizeof(struct bpf_throw_regs) == BPF_THROW_REGS_SIZE);

void bpf_throw_unwind(struct bpf_throw_regs *regs, u64 cookie, unsigned int kind);
/*
 * The native entry of bpf_throw(), on an architecture that has one, the entry
 * a fault at an arena access of JITed code is redirected to, and the entry
 * the helper that ran a cancelled callback returns to, to go on with the
 * cancellation from the call of the helper.
 */
void bpf_throw_entry(void);
void bpf_throw_fault_entry(void);
void bpf_cancel_entry(void);
void *bpf_arch_throw_entry(void);
void *bpf_arch_throw_fault_entry(void);
void *bpf_arch_cancel_entry(void);
/*
 * Where a kernel frame the stack walker passed keeps its return address, given
 * the frame pointer the walker reported for it and the stack pointer it
 * reported for the frame above, and the way to make the JITed frame whose
 * frame pointer is @bp return to @to.
 */
u64 *bpf_arch_ret_slot(u64 bp, u64 next_sp);
void bpf_arch_set_ret_addr(u64 bp, u64 to);
#endif /* __ASSEMBLER__ */

#endif /* _LINUX_BPF_THROW_H */
