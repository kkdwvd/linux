// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/*
 * cancel_goto behind a call of a subprog or behind an access of arena names the pad of that
 * insn. The pads are behind the last insn of their subprog, and the offset of cancel_goto has
 * 32 bits: it is the one insn that the verifier adds there, however much of the program is
 * between it and the pad.
 *
 * The progs hold a record of the ring buffer where they are cancelled, and FILL() puts 2200 or
 * 33000 insns between that point and their pads: the second is more than the 16 bits of a jump
 * count. The pad discards the record, the prog returns the cancel value of its type, and none
 * of the insns in between runs. The runner looks at the ring buffer, and at the insns that the
 * verifier left.
 *
 * The line of the stats, the JITs and the capabilities are those of cancel.c.
 */

char _license[] SEC("license") = "GPL";

/* The verifier doesn't know what is in there */
unsigned long zero;
unsigned long dive;

/* The frames of a recursion that began, and how many times the code behind a point ran */
unsigned long frames;
unsigned long behind;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

/* @var++ in assembly, with r1 and r2 */
#define COUNT(var)				\
	"r1 = %[" #var "] ll;"			\
	"r2 = *(u64 *)(r1 + 0);"		\
	"r2 += 1;"				\
	"*(u64 *)(r1 + 0) = r2;"

/*
 * 2 * @reps insns that take r7 and leave r0. Every other one has a constant: with constant
 * blinding it becomes three, and the pads move that much further away once more.
 */
#define FILL(reps)				\
	".rept " #reps ";"			\
	"r0 = r7;"				\
	"r0 += 1;"				\
	".endr;"

/* for 2200 and for 33000 insns */
#define REPS_2K		1100
#define REPS_33K	16500

/* r0 = a record of the ring buffer or NULL, with r1-r3 */
#define RESERVE					\
	"r1 = %[ringbuf] ll;"			\
	"r2 = 8;"				\
	"r3 = 0;"				\
	"call %[bpf_ringbuf_reserve];"

/* What is behind the point that cancels: discard the record in r6 and return TC_ACT_OK */
#define DISCARD_AND_EXIT			\
	COUNT(behind)				\
	"r1 = r6;"				\
	"r2 = 0;"				\
	"call %[bpf_ringbuf_discard];"		\
	"r0 = 0;"				\
	"exit;"

/* It calls itself until the stack has no room, see cancel.c */
__naked __noinline __used
static unsigned long dives(void)
{
	asm volatile (
		COUNT(frames)
		"*(u64 *)(r10 - 128) = r2;"
		"call dives;"
		COUNT(behind)
		"exit;"
		:
		: __imm_addr(frames),
		  __imm_addr(behind)
		: __clobber_all
	);
}

/* The record is in r6 when dives() is cancelled, and the pad of the call is behind the exit */
#define CALL_PROG(reps)						\
	asm volatile (						\
		RESERVE						\
		"if r0 != 0 goto 1f;"				\
		"r0 = 0;"					\
		"exit;"						\
	"1:"							\
		"r6 = r0;"					\
		"r7 = 0;"					\
		"call dives;"					\
		FILL(reps)					\
		DISCARD_AND_EXIT				\
		:						\
		: __imm(bpf_ringbuf_reserve),			\
		  __imm(bpf_ringbuf_discard),			\
		  __imm_addr(ringbuf),				\
		  __imm_addr(behind)				\
		: __clobber_all					\
	)

SEC("tc")
__description("cancel far: the pad of a call that is more than 2048 insns away")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("call pc+{{[0-9]+}}")
__xlated("cancel_goto pc+{{(2[1-9]|[3-9][0-9])[0-9][0-9]$}}")
__xlated("r0 = r7")
__naked void call_2k(void)
{
	CALL_PROG(REPS_2K);
}

SEC("tc")
__description("cancel far: the pad of a call that is more than 32767 insns away")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 3 padded 3 declined")
__xlated("call pc+{{[0-9]+}}")
__xlated("cancel_goto pc+{{(3[3-9]|[4-9][0-9])[0-9][0-9][0-9]$}}")
__xlated("r0 = r7")
__naked void call_33k(void)
{
	CALL_PROG(REPS_33K);
}

/*
 * No page of the arena is there, so the load faults. The record is in r6, and the pad of the
 * access is where the pad of a call would be.
 */
#define ARENA_PROG(reps)					\
	asm volatile (						\
		"r1 = %[arena] ll;"				\
		RESERVE						\
		"if r0 != 0 goto 1f;"				\
		"r0 = 0;"					\
		"exit;"						\
	"1:"							\
		"r6 = r0;"					\
		"r7 = 0;"					\
		"r8 = 8192;"					\
		"r8 = addr_space_cast(r8, 0, 1);"		\
		"r0 = *(u64 *)(r8 + 0);"			\
		FILL(reps)					\
		DISCARD_AND_EXIT				\
		:						\
		: __imm(bpf_ringbuf_reserve),			\
		  __imm(bpf_ringbuf_discard),			\
		  __imm_addr(arena),				\
		  __imm_addr(ringbuf),				\
		  __imm_addr(behind)				\
		: __clobber_all					\
	)

SEC("tc")
__description("cancel far: the pad of an access of arena that is more than 2048 insns away")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("r0 = *(u64 *)(r8 +0)")
__xlated("cancel_goto pc+{{(2[1-9]|[3-9][0-9])[0-9][0-9]$}}")
__xlated("r0 = r7")
__naked void arena_2k(void)
{
	ARENA_PROG(REPS_2K);
}

SEC("tc")
__description("cancel far: the pad of an access of arena that is more than 32767 insns away")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 1 padded 1 declined")
__xlated("r0 = *(u64 *)(r8 +0)")
__xlated("cancel_goto pc+{{(3[3-9]|[4-9][0-9])[0-9][0-9][0-9]$}}")
__xlated("r0 = r7")
__naked void arena_33k(void)
{
	ARENA_PROG(REPS_33K);
}

/* The load faults, like the one of ARENA_PROG(), and the frame holds nothing */
__naked __noinline __used
static unsigned long faults(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
		"r1 = 8192;"
		"r1 = addr_space_cast(r1, 0, 1);"
		"r0 = *(u64 *)(r1 + 0);"
		"exit;"
		:
		: __imm_addr(arena)
		: __clobber_all
	);
}

/*
 * A raw tracepoint prog with 64 bytes of stack has a private stack. On x86-64 its frame
 * pointer is in r9, which the JIT saves around a call. The return to the pad has to restore
 * r9 as well, so behind such a call cancel_goto is code: a return jumps over it, and the
 * cancel_exit of the callee returns into it, where it pops r9 and jumps to the pad. A tracing
 * prog cannot recurse, so the callee is cancelled by a load that faults.
 */
#define PRIV_STACK_PROG(reps)					\
	asm volatile (						\
		"r7 = 0;"					\
		"*(u64 *)(r10 - 64) = r7;"			\
		RESERVE						\
		"if r0 != 0 goto 1f;"				\
		"r0 = 0;"					\
		"exit;"						\
	"1:"							\
		"r6 = r0;"					\
		"call faults;"					\
		FILL(reps)					\
		DISCARD_AND_EXIT				\
		:						\
		: __imm(bpf_ringbuf_reserve),			\
		  __imm(bpf_ringbuf_discard),			\
		  __imm_addr(ringbuf),				\
		  __imm_addr(behind)				\
		: __clobber_all					\
	)

SEC("raw_tp")
__description("cancel far: the pad of a call in a frame with a private stack")
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 2 padded 2 declined")
__xlated("call pc+{{[0-9]+}}")
__xlated("cancel_goto pc+{{(3[3-9]|[4-9][0-9])[0-9][0-9][0-9]$}}")
__xlated("r0 = r7")
__arch_arm64
__arch_x86_64
__jited("	movq	%rax, %rbx")
__jited("	pushq	%r9")
__jited("	callq	0x{{.*}}")
__jited("	popq	%r9")
__jited("	jmp	L{{[0-9]+}}")
__jited("	popq	%r9")
__jited("	jmp	L{{[0-9]+}}")
__jited("L{{[0-9]+}}:	movq	%r13, %rax")
__naked void priv_stack_33k(void)
{
	PRIV_STACK_PROG(REPS_33K);
}

/* r1: whether to dive first. r0 = a record or NULL: the frame returns with it. */
__naked __noinline __used
static unsigned long gets_record(void)
{
	asm volatile (
		"if r1 == 0 goto 1f;"
		"call dives;"
	"1:"
		RESERVE
		"exit;"
		:
		: __imm(bpf_ringbuf_reserve),
		  __imm_addr(ringbuf)
		: __clobber_all
	);
}

/*
 * One of the two paths to the call of dives() holds a record: the one that gets_record() returned
 * with. The frame has a drop flag for it, which is set behind the call of gets_record(): behind
 * its cancel_goto, where only a call that returns gets to. Both calls have their pads behind the
 * exit. The pad of the first one runs when gets_record() dives, and releases nothing.
 */
#define FLAG_PROG(reps)						\
	asm volatile (						\
		"r7 = 0;"					\
		"r1 = %[zero] ll;"				\
		"r1 = *(u64 *)(r1 + 0);"			\
		"if r1 != 0 goto 2f;"				\
		"r1 = %[dive] ll;"				\
		"r1 = *(u64 *)(r1 + 0);"			\
		"call gets_record;"				\
		"if r0 != 0 goto 1f;"				\
		"r0 = 0;"					\
		"exit;"						\
	"1:"							\
		"r6 = r0;"					\
		"r7 = 1;"					\
		"goto 3f;"					\
	"2:"							\
		"r6 = 0;"					\
	"3:"							\
		"call dives;"					\
		FILL(reps)					\
		COUNT(behind)					\
		"if r7 == 0 goto 4f;"				\
		"r1 = r6;"					\
		"r2 = 0;"					\
		"call %[bpf_ringbuf_discard];"			\
	"4:"							\
		"r0 = 0;"					\
		"exit;"						\
		:						\
		: __imm(bpf_ringbuf_discard),			\
		  __imm_addr(zero),				\
		  __imm_addr(dive),				\
		  __imm_addr(behind)				\
		: __clobber_all					\
	)

SEC("tc")
__description("cancel far: a drop flag behind a call whose pad is more than 2048 insns away")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 5 padded 5 declined")
__xlated("call pc+{{[0-9]+}}")
__xlated("cancel_goto pc+{{(2[1-9]|[3-9][0-9])[0-9][0-9]$}}")
__naked void flag_2k(void)
{
	FLAG_PROG(REPS_2K);
}

SEC("tc")
__description("cancel far: a drop flag behind a call whose pad is more than 32767 insns away")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 5 padded 5 declined")
__xlated("call pc+{{[0-9]+}}")
__xlated("cancel_goto pc+{{(3[3-9]|[4-9][0-9])[0-9][0-9][0-9]$}}")
__naked void flag_33k(void)
{
	FLAG_PROG(REPS_33K);
}

/*
 * unwind_goto and unwind_exit as raw insns, like in verifier_unwind.c. struct bpf_insn of
 * vmlinux.h is relocatable, and what inline asm takes for a constant is not: hence a copy of
 * it, with BPF_JMP | BPF_JCOND and BPF_JMP | BPF_EXIT for the opcodes.
 */
struct raw_insn {
	__u8 code;
	__u8 dst_reg:4;
	__u8 src_reg:4;
	__s16 off;
	__s32 imm;
};

#define unwind_goto(off) ".8byte %[insn_unwind_goto_" #off "];"
#define unwind_exit ".8byte %[insn_unwind_exit];"

#define __imm_unwind_goto(_off) \
	__imm_insn(insn_unwind_goto_##_off, \
		   ((struct raw_insn) { .code = 0xe5, .src_reg = BPF_UNWIND_GOTO, .off = _off }))
#define __imm_unwind_exit \
	__imm_insn(insn_unwind_exit, \
		   ((struct raw_insn) { .code = 0x95, .src_reg = BPF_UNWIND_EXIT }))

/* r1 == 0: unwinds with r0 = 5. Otherwise it dives until the prog is cancelled. */
__naked __noinline __used
static unsigned long unwinds_or_dives(void)
{
	asm volatile (
		"if r1 != 0 goto 1f;"
		"r0 = 5;"
		unwind_exit
	"1:"
		"call dives;"
		"exit;"
		:
		: __imm_unwind_exit
		: __clobber_all
	);
}

/*
 * The call has the unwind_goto of the prog behind it, and cancel_goto behind that. The JITs
 * look for both directly behind the call. The patches turn the 8200 divisions into 32800
 * insns, too far for the 16 bits of unwind_goto: the jumps that get to its landing pad go
 * behind cancel_goto, which is no code.
 *
 * The record is in r6. When the callee is cancelled the pad of the verifier discards it, and
 * when the callee unwinds the landing pad of the prog does, and returns 7.
 */
SEC("tc")
__description("cancel far: unwind_goto in front of cancel_goto that patches push out of range")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __log_level(4)
__msg("cancel sites 4 padded 4 declined")
__xlated("call pc+{{[0-9]+}}")
__xlated("unwind_goto pc+2")
__xlated("cancel_goto pc+{{(3[2-9]|[4-9][0-9])[0-9][0-9][0-9]$}}")
__xlated("goto pc+1")
__xlated("gotol pc+{{(3[2-9]|[4-9][0-9])[0-9][0-9][0-9]$}}")
__xlated("r7 = 1")
__naked void unwind_far(void)
{
	asm volatile (
		RESERVE
		"if r0 != 0 goto 1f;"
		"r0 = 0;"
		"exit;"
	"1:"
		"r6 = r0;"
		"r1 = %[dive] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"r8 = r1;"
		"call unwinds_or_dives;"
		unwind_goto(8211)
		"r7 = 1;"
		".rept 8200; r7 /= r8; .endr;"
		DISCARD_AND_EXIT
		/* the landing pad of the prog */
		"r1 = r6;"
		"r2 = 0;"
		"call %[bpf_ringbuf_discard];"
		"r0 = 7;"
		"exit;"
		:
		: __imm(bpf_ringbuf_reserve),
		  __imm(bpf_ringbuf_discard),
		  __imm_addr(ringbuf),
		  __imm_addr(dive),
		  __imm_addr(behind),
		  __imm_unwind_goto(8211)
		: __clobber_all
	);
}

/* The ring buffer takes a record and hands it to the consumer */
SEC("tc")
int ringbuf_submit(struct __sk_buff *skb)
{
	long *rec;

	rec = bpf_ringbuf_reserve(&ringbuf, sizeof(*rec), 0);
	if (!rec)
		return 0;
	*rec = 1;
	bpf_ringbuf_submit(rec, 0);
	return 0;
}
