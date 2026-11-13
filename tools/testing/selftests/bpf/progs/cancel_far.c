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
 * 33000 insns between that point and their pads: more than BPF_GUARD_NEAR, from where on
 * may_goto takes gotol to get to a pad, and more than the 16 bits of a jump count. The pad
 * discards the record, the prog returns the cancel value of its type, and none of the insns in
 * between runs. The runner looks at the ring buffer, and at the insns that the verifier left.
 *
 * The line of the stats, the JITs and the capabilities are those of cancel.c.
 */

char _license[] SEC("license") = "GPL";

/* The frames of a recursion that began, and how many times the code behind a point ran */
unsigned long frames;
unsigned long behind;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

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
