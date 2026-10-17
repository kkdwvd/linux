/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef __EXCEPTIONS_CLEANUP_H__
#define __EXCEPTIONS_CLEANUP_H__

/* progs/exceptions_cleanup.c: one bit per function that reports it ran. */
#define RAN_FOO3_PREEMPT	0x1
#define RAN_FOO2_RCU		0x2
#define RAN_FOO1V_PREEMPT	0x4
#define RAN_FOO2_DROP		0x8
#define RAN_BUMP		0x10

/* progs/exceptions_cleanup_shapes.c: one bit per landing pad. */
#define RAN_REGS		0x1
#define RAN_WIDE_REC		0x2
#define RAN_RESUME_ALIAS	0x4
#define RAN_NOP_PAD		0x8
#define RAN_VAR_STACK		0x10
#define RAN_GAP_INNER		0x20
#define RAN_GAP_OUTER		0x40
#define RAN_PREC_RESUME		0x80
#define RAN_NO_EXIT_JA		0x100
#define RAN_CALLX		0x200
#define RAN_CALLEE_WRITE	0x400
#define RAN_CALLEE_OFFSET	0x800
#define RAN_GLOBAL_WRITE	0x1000
#define RAN_THROUGH_GLOBAL	0x2000
#define RAN_PAIR_GLOBAL		0x4000
#define RAN_MOVE		0x8000
#define RAN_NO_EXIT_LOOP	0x10000
#define RAN_LAST_CALL		0x20000
#define RAN_NO_TAIL		0x40000
#define RAN_CATCH		0x80000
#define RAN_RETHROW_INNER	0x100000
#define RAN_RETHROW_OUTER	0x200000
#define RAN_SECOND_INNER	0x400000
#define RAN_SECOND_OUTER	0x800000
#define RAN_INERT_CALLER	0x1000000
#define RAN_GOTOX_PAD		0x2000000
#define RAN_EXC_CB_TABLE	0x4000000
#define RAN_THROW_TABLE		0x8000000

#define CLEANUP_REC(begin, end, landing_pad)			\
	".pushsection .bpf_cleanup,\"a\",@progbits;"		\
	".long " begin ";"					\
	".long " end ";"					\
	".long " landing_pad ";"				\
	".popsection;"

/* Set a bit in @pads_ran. */
#define PAD_RAN(bit)						\
	"r1 = %[pads_ran] ll;"					\
	"r2 = *(u64 *)(r1 + 0);"				\
	"r2 |= " bit ";"					\
	"*(u64 *)(r1 + 0) = r2;"

#endif /* __EXCEPTIONS_CLEANUP_H__ */
