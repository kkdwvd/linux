/* SPDX-License-Identifier: GPL-2.0 */
/*
 * What the reclaim program needs beyond vmlinux.h and bpf_helpers.h. The
 * kfunc prototypes come from vmlinux.h, which bpftool generates with them,
 * and the numeric iterator loops from bpf_helpers.h. Only the bounded
 * while-loop guard is missing from both; this is bpf_experimental.h's
 * can_loop, in the form tools/sched_ext carries.
 */
#ifndef __RECLAIM_COMPAT_BPF_H
#define __RECLAIM_COMPAT_BPF_H

/*
 * Hide a variable's value from the compiler, as bpf_misc.h's barrier_var()
 * does, so that a bounds check meant for the verifier is not optimised away.
 */
#define barrier_var(var) asm volatile("" : "+r"(var))

#ifdef __BPF_FEATURE_MAY_GOTO
#define can_loop					\
	({ __label__ l_break, l_continue;		\
	bool ret = true;				\
	asm volatile goto("may_goto %l[l_break]"	\
		      :::: l_break);			\
	goto l_continue;				\
	l_break: ret = false;				\
	l_continue:;					\
	ret;						\
	})
#else
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define can_loop					\
	({ __label__ l_break, l_continue;		\
	bool ret = true;				\
	asm volatile goto("1:.byte 0xe5;		\
		      .byte 0;				\
		      .long ((%l[l_break] - 1b - 8) / 8) & 0xffff;	\
		      .short 0"				\
		      :::: l_break);			\
	goto l_continue;				\
	l_break: ret = false;				\
	l_continue:;					\
	ret;						\
	})
#else
#define can_loop					\
	({ __label__ l_break, l_continue;		\
	bool ret = true;				\
	asm volatile goto("1:.byte 0xe5;		\
		      .byte 0;				\
		      .long (((%l[l_break] - 1b - 8) / 8) & 0xffff) << 16;	\
		      .short 0"				\
		      :::: l_break);			\
	goto l_continue;				\
	l_break: ret = false;				\
	l_continue:;					\
	ret;						\
	})
#endif /* __BYTE_ORDER__ */
#endif /* __BPF_FEATURE_MAY_GOTO */

#endif /* __RECLAIM_COMPAT_BPF_H */
