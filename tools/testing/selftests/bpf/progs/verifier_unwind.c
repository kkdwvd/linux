// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

/*
 * llvm lowers unwinding to two insns:
 *   invoke foo unwind pad    call foo; unwind_goto pad
 *   resume                   unwind_exit
 * The tests spell them out as raw insns, so they don't depend on llvm version.
 * The argument of unwind_goto() is the number of insns to skip.
 */
#define unwind_goto(off) ".8byte %[insn_unwind_goto_" #off "];"
#define unwind_exit ".8byte %[insn_unwind_exit];"

#define __imm_unwind_goto(off) \
	__imm_insn(insn_unwind_goto_##off, \
		   BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, off, 0))
#define __imm_unwind_exit \
	__imm_insn(insn_unwind_exit, \
		   BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0))

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern void bpf_throw(__u64 cookie) __ksym;
extern void __bpf_trap(void) __ksym;
struct task_struct {};
extern struct task_struct *bpf_task_from_pid(int pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} prog_array SEC(".maps");

struct timer_elem {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct timer_elem);
} timer_map SEC(".maps");

/* The verifier doesn't know what is in there */
unsigned long zero;
unsigned long one = 1;

/*
 * The verifier follows a static subprog, so it knows which way it leaves when
 * it knows the argument. To have both ways at run time the tests pass skb->len,
 * which is 64, or skb->len - 64.
 *
 * r1 == 0: returns 7, otherwise unwinds with r0 = 5
 */
__naked __noinline __used
static unsigned long may_unwind(void)
{
	asm volatile (
		"if r1 != 0 goto 1f;"
		"r0 = 7;"
		"exit;"
	"1:"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

/* The patches of the divisions push the pad out of the 16-bit range */
#define FAR_PAD(name, sub)					\
__naked void name(void)						\
{								\
	asm volatile (						\
		"r6 = *(u32 *)(r1 + 0);"			\
		"r1 = r6;"					\
		"r1 -= " #sub ";"				\
		"call may_unwind;"				\
		unwind_goto(8202)				\
		"r7 = 1;"					\
		".rept 8200; r7 /= r6; .endr;"			\
		"exit;"						\
		"r0 += 100;"					\
		"exit;"						\
		:						\
		: __imm_unwind_goto(8202)			\
		: __clobber_all);				\
}

SEC("tc")
__arch_x86_64 __arch_arm64
__success __retval(7)
__load_if_JITed()
FAR_PAD(far_pad_returns, 64)

SEC("tc")
__arch_x86_64 __arch_arm64
__success __retval(105)
__load_if_JITed()
FAR_PAD(far_pad_unwinds, 0)

/* owns nothing: its pad only carries on */
__naked __noinline __used
static unsigned long passes_on(void)
{
	asm volatile (
		"call may_unwind;"
		unwind_goto(2)
		"r0 += 1;"
		"exit;"
		unwind_exit
		:
		: __imm_unwind_goto(2),
		  __imm_unwind_exit
	);
}

__naked __noinline __used
static unsigned long always_unwinds(void)
{
	asm volatile (
		"r0 = 5;"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

__naked __noinline __used
static unsigned long never_unwinds(void)
{
	asm volatile (
		"r0 = 7;"
		"exit;"
	);
}

/* Both can unwind. This one returns 7. */
__naked __noinline __used
unsigned long global_returns(void)
{
	asm volatile (
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 != 0 goto 1f;"
		"r0 = 7;"
		"exit;"
	"1:"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(zero),
		  __imm_unwind_exit
	);
}

/* This one unwinds with r0 = 5 */
__naked __noinline __used
unsigned long global_unwinds(void)
{
	asm volatile (
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 != 0 goto 1f;"
		"r0 = 7;"
		"exit;"
	"1:"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(one),
		  __imm_unwind_exit
	);
}

SEC("tc")
__description("unwind: the callee returns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int callee_returns(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"r1 -= 64;"
		"call may_unwind;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_unwind_goto(1)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: the callee unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(42)
__naked int callee_unwinds(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"call may_unwind;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_unwind_goto(1)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: return through two frames")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(8)
__naked int two_frames_return(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"r1 -= 64;"
		"call passes_on;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_unwind_goto(1)
		: __clobber_all
	);
}

/* unwind_exit returns r0 like exit does */
SEC("tc")
__description("unwind: unwind through two frames, r0 reaches the pad")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(15)
__naked int two_frames_unwind(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"call passes_on;"
		unwind_goto(1)
		"exit;"
		"r0 += 10;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_unwind_goto(1)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: r6-r9 and the stack are intact in the pad")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(1111)
__naked int pad_sees_callee_saved(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"r6 = 1;"
		"r7 = 10;"
		"r8 = 100;"
		"r9 = 400;"
		"*(u64 *)(r10 - 8) = 600;"
		"call passes_on;"
		unwind_goto(2)
		"r0 = 0;"
		"exit;"
		"r0 = r6;"
		"r0 += r7;"
		"r0 += r8;"
		"r0 += r9;"
		"r1 = *(u64 *)(r10 - 8);"
		"r0 += r1;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_unwind_goto(2)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: r1-r5 are not readable in the pad")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("R3 !read_ok")
__naked int pad_reads_r3(void)
{
	asm volatile (
		"r3 = 0;"
		"call always_unwinds;"
		unwind_goto(1)
		"exit;"
		"r0 = r3;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: unwind_exit of the main prog is exit")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(3)
__naked int main_prog_unwinds(void)
{
	asm volatile (
		"r0 = 3;"
		unwind_exit
		:
		: __imm_unwind_exit
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: unwind_exit of the main prog needs r0")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("R0 !read_ok")
__naked int main_prog_unwinds_no_r0(void)
{
	asm volatile (
		unwind_exit
		:
		: __imm_unwind_exit
		: __clobber_all
	);
}

/*
 * What follows unwind_goto is dead code. unwind_exit still has to find the pad,
 * and the cpu predicts that the callee returns: there is a trap for that.
 */
SEC("tc")
__description("unwind: the callee never returns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(42)
__xlated("0: call pc+4")
__xlated("1: unwind_goto pc+1")
__xlated("2: goto pc-1")
__xlated("3: r0 = 42")
__xlated("4: exit")
__naked int callee_never_returns(void)
{
	asm volatile (
		"call always_unwinds;"
		unwind_goto(2)
		"r0 = 1;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(2)
		: __clobber_all
	);
}

/* The pad is dead code and goes away together with unwind_goto */
SEC("tc")
__description("unwind: the callee never unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__xlated("0: call pc+1")
__xlated("1: exit")
__xlated("2: r0 = 7")
__xlated("3: exit")
__naked int callee_never_unwinds(void)
{
	asm volatile (
		"call never_unwinds;"
		unwind_goto(1)
		"exit;"
		"r0 = *(u64 *)(r0 + 0);"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: the pad drops what the frame owns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(42)
__naked int pad_unlocks(void)
{
	asm volatile (
		"r6 = *(u32 *)(r1 + %[len]);"
		"call %[bpf_rcu_read_lock];"
		"r1 = r6;"
		"call may_unwind;"
		unwind_goto(3)
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock),
		  __imm_unwind_goto(3)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: the pad is checked like any other code")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("in main prog cannot be used inside bpf_rcu_read_lock-ed region")
__naked int pad_does_not_unlock(void)
{
	asm volatile (
		"r6 = *(u32 *)(r1 + %[len]);"
		"call %[bpf_rcu_read_lock];"
		"r1 = r6;"
		"call may_unwind;"
		unwind_goto(3)
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock),
		  __imm_unwind_goto(3)
		: __clobber_all
	);
}

/* Leaves either way with the same registers */
__naked __noinline __used
static unsigned long same_regs(void)
{
	asm volatile (
		"r0 = 0;"
		"if r1 != 0 goto 1f;"
		"exit;"
	"1:"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

/*
 * After the call the two states differ only in the way the callee left.
 * The second one must not be pruned, or nobody looks at the pad.
 */
SEC("tc")
__description("unwind: the way the callee left is a part of the state")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("R0 invalid mem access 'scalar'")
__flag(BPF_F_TEST_STATE_FREQ)
__naked int no_pruning_after_the_call(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"call same_regs;"
		unwind_goto(1)
		"exit;"
		"r0 = *(u64 *)(r0 + 0);"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_unwind_goto(1)
		: __clobber_all
	);
}

/* 1, 5, 9 .. in r1 are kept apart up to the jump that tests them. What unwinds leaves before. */
__naked __noinline __used
static unsigned long passes_on_then_tests_arg(void)
{
	asm volatile (
		"r6 = r1;"
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"call may_unwind;"
		unwind_goto(4)
		"if r6 == 3 goto 1f;"
		"r0 = 0;"
	"1:"
		"r0 = 7;"
		"exit;"
		unwind_exit
		:
		: __imm_addr(zero),
		  __imm_unwind_goto(4),
		  __imm_unwind_exit
	);
}

#define CALL(arg)				\
	"r1 = " #arg ";"			\
	"call passes_on_then_tests_arg;"	\
	unwind_goto(1)				\
	"goto +2;"				\
	"r0 = 42;"				\
	"exit;"
#define CALL8(a, b, c, d, e, f, g, h) \
	CALL(a) CALL(b) CALL(c) CALL(d) CALL(e) CALL(f) CALL(g) CALL(h)

/*
 * The same unwound state comes out of the subprog for each call, before the state of the call
 * meets those of the calls before it. Each call gets it twice at most: 14 states per call, 450 in
 * all. If each call gets all copies there are 1411.
 */
SEC("socket")
__description("unwind: what unwinds out of a subprog gets to each of 32 calls once")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(0) __log_level(4)
__msg("total_states {{[0-9][0-9][0-9]}} peak_states")
__naked int unwinds_to_32_calls(void)
{
	asm volatile (
		CALL8(1, 5, 9, 13, 17, 21, 25, 29)
		CALL8(33, 37, 41, 45, 49, 53, 57, 61)
		CALL8(65, 69, 73, 77, 81, 85, 89, 93)
		CALL8(97, 101, 105, 109, 113, 117, 121, 125)
		"r0 = 0;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

/* Returns ctx, or unwinds with a number in r0 */
__naked __noinline __used
static unsigned long ctx_or_unwind(void)
{
	asm volatile (
		"r2 = *(u32 *)(r1 + %[len]);"
		"if r2 > 100 goto 1f;"
		"r0 = r1;"
		"exit;"
	"1:"
		"r0 = 0;"
		unwind_exit
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_unwind_exit
	);
}

/*
 * unwind_exit changes its return address, so the cpu mispredicts the return and
 * runs what follows unwind_goto with r0 of unwind_exit. No speculative state is
 * verified there: the insns need CAP_PERFMON.
 */
SEC("socket")
__description("unwind: unwind_exit and unwind_goto need CAP_PERFMON")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(50) /* 64 without the ethernet header */
__failure_unpriv __msg_unpriv("CAP_PERFMON is required to unwind")
__caps_unpriv(CAP_BPF)
__naked int speculative_fall_through(void)
{
	asm volatile (
		"call ctx_or_unwind;"
		unwind_goto(2)
		"r0 = *(u32 *)(r0 + %[len]);"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_unwind_goto(2)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: a global subprog returns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int calls_global_returns(void)
{
	asm volatile (
		"call global_returns;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: a global subprog unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(15)
__naked int calls_global_unwinds(void)
{
	asm volatile (
		"call global_unwinds;"
		unwind_goto(1)
		"exit;"
		"r0 += 10;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

/*
 * The callers of a global subprog take what comes out of it for a number, also when it unwinds
 * and also when it returns nothing: unwind_exit needs a number in r0 there. The exit insn of the
 * same subprogs leaves r0 unwritten, which a subprog that returns nothing may do.
 *
 * This one leaves a pointer to its stack in r0 when it unwinds.
 */
__naked __noinline __used
void global_void_unwinds_with_ptr(void)
{
	asm volatile (
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = r10;"
		unwind_exit
		:
		: __imm_addr(one),
		  __imm_unwind_exit
	);
}

SEC("tc")
__description("unwind: unwind_exit of a global subprog that returns nothing needs a number in r0")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("At subprogram exit the register R0 is not a scalar value (fp)")
__naked int global_void_unwinds_ptr(void)
{
	asm volatile (
		"call global_void_unwinds_with_ptr;"
		unwind_goto(2)
		"r0 = 0;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(2)
		: __clobber_all
	);
}

/* Nor a pointer that a callee left there, which its pad passes on with unwind_exit of its own */
__naked __noinline __used
static unsigned long unwinds_with_ptr(void)
{
	asm volatile (
		"r0 = %[one] ll;"
		unwind_exit
		:
		: __imm_addr(one),
		  __imm_unwind_exit
	);
}

__naked __noinline __used
void global_void_passes_ptr_on(void)
{
	asm volatile (
		"call unwinds_with_ptr;"
		unwind_goto(1)
		"exit;"
		unwind_exit
		:
		: __imm_unwind_goto(1),
		  __imm_unwind_exit
	);
}

SEC("tc")
__description("unwind: a pad in a global subprog that returns nothing cannot pass a pointer on")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("At subprogram exit the register R0 is not a scalar value (map_value)")
__naked int global_void_passes_ptr(void)
{
	asm volatile (
		"call global_void_passes_ptr_on;"
		unwind_goto(2)
		"r0 = 0;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(2)
		: __clobber_all
	);
}

/* Nor a register that it has not written */
__naked __noinline __used
void global_void_unwinds_without_r0(void)
{
	asm volatile (
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 != 0 goto 1f;"
		"exit;"
	"1:"
		unwind_exit
		:
		: __imm_addr(one),
		  __imm_unwind_exit
	);
}

SEC("tc")
__description("unwind: unwind_exit of a global subprog that returns nothing needs r0")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("R0 !read_ok")
__naked int global_void_unwinds_no_r0(void)
{
	asm volatile (
		"call global_void_unwinds_without_r0;"
		unwind_goto(2)
		"r0 = 0;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(2)
		: __clobber_all
	);
}

/* The verifier doesn't look inside */
SEC("tc")
__description("unwind: the pad of a call of a global subprog is always checked")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("R0 invalid mem access 'scalar'")
__naked int global_pad_is_checked(void)
{
	asm volatile (
		"call global_returns;"
		unwind_goto(1)
		"exit;"
		"r0 = *(u64 *)(r0 + 0);"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

/*
 * GLOBAL SUBPROGS THAT NEVER RETURN. The verifier does not look into a global subprog at its
 * call. It knows which subprogs have no path from their first insn to an exit, see
 * bpf_compute_might_return(), and it does not go on behind a call of one: what follows the call
 * is dead code, as it is behind a call of always_unwinds().
 *
 * In each of these progs what follows the call reads through r0, which is a number behind the call
 * of a global subprog: the prog loads only if the verifier does not go on there. A subprog that
 * has a way to return, however unlikely, makes the same prog fail.
 */
#define BEHIND_CALL(name, callee)				\
__naked int name(void)						\
{								\
	asm volatile (						\
		"call " #callee ";"				\
		unwind_goto(2)					\
		"r0 = *(u64 *)(r0 + 0);"			\
		"exit;"						\
		"r0 += 10;"					\
		"exit;"						\
		:						\
		: __imm_unwind_goto(2)				\
		: __clobber_all);				\
}

#define NEVER_RETURNS						\
	__arch_x86_64 __arch_arm64				\
	__load_if_JITed()					\
	__success

#define MIGHT_RETURN						\
	__arch_x86_64 __arch_arm64				\
	__load_if_JITed()					\
	__failure __msg("R0 invalid mem access 'scalar'")

__naked __noinline __used
unsigned long global_always_unwinds(void)
{
	asm volatile (
		"r0 = 5;"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

/* A trap stands where the cpu predicts that the call returns, and the pad gets r0 of unwind_exit */
SEC("tc")
__description("unwind: a global subprog never returns")
NEVER_RETURNS __retval(15)
__xlated("0: call pc+4")
__xlated("1: unwind_goto pc+1")
__xlated("2: goto pc-1")
__xlated("3: r0 += 10")
__xlated("4: exit")
BEHIND_CALL(global_never_returns, global_always_unwinds)

/* Its exit stands behind a jump that is never taken: that edge is gone from the graph */
__naked __noinline __used
unsigned long global_exit_is_folded(void)
{
	asm volatile (
		"r1 = 0;"
		"if r1 != 0 goto 1f;"
		"r0 = 5;"
		unwind_exit
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm_unwind_exit
	);
}

SEC("tc")
__description("unwind: a global subprog whose exit a jump on a constant skips never returns")
NEVER_RETURNS __retval(15)
BEHIND_CALL(global_folded_never_returns, global_exit_is_folded)

/*
 * A path ends at a call of __bpf_trap(), which the verifier rejects when it gets there. It does
 * not get there here: the first jump leaves r1 <= 5, and the second one is always taken then.
 * The edge to the trap stays in the graph, no constant decides that jump.
 */
__naked __noinline __used
unsigned long global_trap_is_dead(void)
{
	asm volatile (
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 > 5 goto 1f;"
		"if r1 < 7 goto 1f;"
		"call __bpf_trap;"
		"exit;"
	"1:"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(one),
		  __imm_unwind_exit
	);
}

SEC("tc")
__description("unwind: a global subprog whose other path ends in __bpf_trap() never returns")
NEVER_RETURNS __retval(15)
BEHIND_CALL(global_trap_never_returns, global_trap_is_dead)

/* A state gets to this trap. The summary is none the wiser: the prog is rejected for the trap. */
__naked __noinline __used
unsigned long global_traps(void)
{
	asm volatile (
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 1f;"
		"call __bpf_trap;"
	"1:"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(zero),
		  __imm_unwind_exit
	);
}

SEC("tc")
__description("unwind: a global subprog that gets to __bpf_trap() is rejected there")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__failure __msg("unexpected __bpf_trap() due to uninitialized variable?")
BEHIND_CALL(global_trap_is_rejected, global_traps)

/*
 * Its exit stands behind the call of itself. A path gets to the exit only if that call returns, so
 * no path does. The recursion ends when the stack is used up, and the kernel unwinds the prog. What
 * follows the call is dead code, in the subprog and in the prog.
 */
__naked __noinline __used
unsigned long global_calls_itself(void)
{
	asm volatile (
		"r6 = 0;"
		"call global_calls_itself;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: a global subprog that calls itself in front of its exit never returns")
NEVER_RETURNS __retval(2)
__xlated("...")
__xlated("call pc+4")
__xlated("kgoto pc+1")
__xlated("goto pc-1")
__xlated("r0 = 2")
__xlated("exit")
__xlated("...")
__xlated("r6 = 0")
__xlated("call pc-")
__xlated("kgoto pc+1")
__xlated("goto pc-1")
__xlated("r0 = 2")
__xlated("r2 = 0")
__xlated("kexit")
__naked int global_recursion_never_returns(void)
{
	asm volatile (
		"call global_calls_itself;"
		"r0 = *(u64 *)(r0 + 0);"
		"exit;"
		::: __clobber_all
	);
}

/* Two that call each other in front of their exits: neither returns */
__naked __noinline __used
unsigned long global_calls_other(void);

__naked __noinline __used
unsigned long global_calls_one(void)
{
	asm volatile (
		"r6 = 0;"
		"call global_calls_other;"
		"exit;"
	);
}

__naked __noinline __used
unsigned long global_calls_other(void)
{
	asm volatile (
		"r6 = 0;"
		"call global_calls_one;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: two global subprogs that call each other in front of their exits never return")
NEVER_RETURNS __retval(2)
BEHIND_CALL(global_cycle_never_returns, global_calls_one)

/*
 * A static subprog that only calls what never returns does not return either, and so on up: the
 * exit of each of them stands behind such a call. What unwind_exit left gets through the static
 * frame, and out of the global one comes the value of the kernel, TC_ACT_SHOT.
 */
__naked __noinline __used
static unsigned long calls_global_always_unwinds(void)
{
	asm volatile (
		"call global_always_unwinds;"
		"exit;"
	);
}

__naked __noinline __used
unsigned long global_calls_static_never_returns(void)
{
	asm volatile (
		"call calls_global_always_unwinds;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: a global subprog whose exit is behind calls that never return never returns")
NEVER_RETURNS __retval(12)
BEHIND_CALL(global_chain_never_returns, global_calls_static_never_returns)

/*
 * It has no unwind_exit, and the kernel unwinds it on every path: in a loop that nothing ends when
 * the tests run it, or at bpf_throw(), which is where its paths end. The exit is there because a
 * subprog cannot end in a call.
 */
__naked __noinline __used
unsigned long global_spins_or_throws(void)
{
	asm volatile (
		"r2 = %[one] ll;"
	"1:"
		"r1 = *(u64 *)(r2 + 0);"
		"if r1 != 0 goto 1b;"
		"r1 = 0;"
		"call %[bpf_throw];"
		"exit;"
		:
		: __imm_addr(one),
		  __imm(bpf_throw)
	);
}

SEC("tc")
__description("unwind: a global subprog that the kernel unwinds on every path never returns")
NEVER_RETURNS __retval(2)
BEHIND_CALL(global_kunwinds_never_returns, global_spins_or_throws)

/*
 * THE WAYS TO RETURN. Each of these subprogs unwinds when the tests run it, and each has a path to
 * an exit that the verifier cannot rule out before it looks at the states: what follows a call
 * of it is verified. global_unwinds() has a plain exit behind a jump on a variable.
 */
SEC("tc")
__description("unwind: a global subprog with an exit behind a jump might return")
MIGHT_RETURN
BEHIND_CALL(global_exit_might_return, global_unwinds)

/*
 * No state gets to this exit: the first jump leaves r1 <= 5, and the second one is always taken
 * then. That is known to the main pass only. For the summary the edge is there.
 */
__naked __noinline __used
unsigned long global_exit_is_dead(void)
{
	asm volatile (
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 > 5 goto 1f;"
		"if r1 < 7 goto 1f;"
		"r0 = 0;"
		"exit;"
	"1:"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(one),
		  __imm_unwind_exit
	);
}

SEC("tc")
__description("unwind: a global subprog with an exit that only ranges rule out might return")
MIGHT_RETURN
BEHIND_CALL(global_dead_exit_might_return, global_exit_is_dead)

/*
 * A tail call that is taken leaves the subprog like exit does, and so does ld_abs or ld_ind that
 * fails. These three static subprogs have no exit insn: the hidden exit is their one way to
 * return. Each global subprog only calls one of them, and has its exit behind that call.
 */
__naked __noinline __used
static unsigned long tail_calls_or_unwinds(void)
{
	asm volatile (
		"r2 = %[prog_array] ll;"
		"r3 = 0;"
		"call %[bpf_tail_call];"
		"r0 = 5;"
		unwind_exit
		:
		: __imm(bpf_tail_call),
		  __imm_addr(prog_array),
		  __imm_unwind_exit
	);
}

__noinline unsigned long global_tail_calls_or_unwinds(struct __sk_buff *skb)
{
	return tail_calls_or_unwinds();
}

SEC("tc")
__description("unwind: a global subprog that returns by a tail call only might return")
MIGHT_RETURN
BEHIND_CALL(global_tail_call_might_return, global_tail_calls_or_unwinds)

/* The packet is shorter than that */
__naked __noinline __used
static unsigned long ld_abs_or_unwinds(void)
{
	asm volatile (
		"r6 = r1;"
		"r0 = *(u8 *)skb[1000];"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

__noinline unsigned long global_ld_abs_or_unwinds(struct __sk_buff *skb)
{
	return ld_abs_or_unwinds();
}

SEC("tc")
__description("unwind: a global subprog that returns by ld_abs only might return")
MIGHT_RETURN
BEHIND_CALL(global_ld_abs_might_return, global_ld_abs_or_unwinds)

__naked __noinline __used
static unsigned long ld_ind_or_unwinds(void)
{
	asm volatile (
		"r6 = r1;"
		"r7 = %[zero] ll;"
		"r7 = *(u64 *)(r7 + 0);"
		"r0 = *(u8 *)skb[r7];"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(zero),
		  __imm_unwind_exit
	);
}

__noinline unsigned long global_ld_ind_or_unwinds(struct __sk_buff *skb)
{
	return ld_ind_or_unwinds();
}

SEC("tc")
__description("unwind: a global subprog that returns by ld_ind only might return")
MIGHT_RETURN
BEHIND_CALL(global_ld_ind_might_return, global_ld_ind_or_unwinds)

/*
 * ld_abs leaves the static subprog with r0 = 0, the global one returns that, and the prog goes
 * on at run time. So the insn behind unwind_goto has to be the code of the prog. A trap there,
 * which is what follows a call that never returns, would spin when the call returns: this test
 * looks at the insns and runs nothing. prog_tests/unwind_attach.c runs the prog, once it has seen
 * the same.
 */
SEC("tc")
__description("unwind: a global subprog returns by ld_abs")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success
__xlated("0: call pc+")
__xlated("1: unwind_goto pc+")
__xlated("2: r0 += 7")
__xlated("3: exit")
__naked int global_ld_abs_returns(void)
{
	asm volatile (
		"call global_ld_abs_or_unwinds;"
		unwind_goto(2)
		"r0 += 7;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(2)
		: __clobber_all
	);
}

/* may_goto of the prog jumps to the exit, in a function that the kernel cannot unwind */
__naked __noinline __used
unsigned long global_may_goto_exits(void)
{
	asm volatile (
	"1:"
		"may_goto 2f;"
		"goto 1b;"
	"2:"
		"r0 = 0;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: a global subprog whose may_goto jumps to an exit might return")
MIGHT_RETURN
BEHIND_CALL(global_may_goto_might_return, global_may_goto_exits)

/* The callee of callx is not known to the summary: callx returns, whatever it calls here */
__naked __noinline __used
unsigned long global_callx_then_exit(void)
{
	asm volatile (
		"r6 = %[always_unwinds] ll;"
		"callx r6;"
		"exit;"
		:
		: __imm_addr(always_unwinds)
	);
}

SEC("tc")
__description("unwind: a global subprog with an exit behind callx might return")
MIGHT_RETURN
BEHIND_CALL(global_callx_might_return, global_callx_then_exit)

/* What comes back to the call of always_unwinds() goes to its pad, and the pad returns */
__naked __noinline __used
unsigned long global_pad_exits(void)
{
	asm volatile (
		"call always_unwinds;"
		unwind_goto(1)
		unwind_exit
		"r0 = 0;"
		"exit;"
		:
		: __imm_unwind_goto(1),
		  __imm_unwind_exit
	);
}

SEC("tc")
__description("unwind: a global subprog whose pad of a call that never returns exits might return")
MIGHT_RETURN
BEHIND_CALL(global_pad_might_return, global_pad_exits)

/* The exit is behind a call of a subprog that might return */
__naked __noinline __used
unsigned long global_calls_global_unwinds(void)
{
	asm volatile (
		"call global_unwinds;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: a global subprog with an exit behind a call that might return might return")
MIGHT_RETURN
BEHIND_CALL(global_call_might_return, global_calls_global_unwinds)

/* A recursion with a way out */
__naked __noinline __used
unsigned long global_recursion_with_exit(void)
{
	asm volatile (
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 1f;"
		"call global_recursion_with_exit;"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(zero)
	);
}

SEC("tc")
__description("unwind: a global subprog that calls itself and has another exit might return")
MIGHT_RETURN
BEHIND_CALL(global_recursion_might_return, global_recursion_with_exit)

/*
 * Two that call each other, of which one has a way out: both might return. The first has its exit
 * behind the call of the second, so it returns if the second does.
 */
__naked __noinline __used
unsigned long global_returns_or_calls_back(void);

__naked __noinline __used
unsigned long global_exit_behind_cycle(void)
{
	asm volatile (
		"call global_returns_or_calls_back;"
		"exit;"
	);
}

__naked __noinline __used
unsigned long global_returns_or_calls_back(void)
{
	asm volatile (
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 1f;"
		"call global_exit_behind_cycle;"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(zero)
	);
}

SEC("tc")
__description("unwind: a global subprog in a cycle of calls that has a way out might return")
MIGHT_RETURN
BEHIND_CALL(global_cycle_might_return, global_exit_behind_cycle)

/*
 * The call returns at run time: the second subprog returns 0, then the first, and the prog goes
 * on. No trap behind the call here either, and prog_tests/unwind_attach.c runs the prog. The
 * kernel can unwind the cycle, when its stack is used up: kgoto stands behind the call.
 */
SEC("tc")
__description("unwind: a global subprog returns out of a cycle of calls")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success
__xlated("...")
__xlated("{{[0-9]+}}: call pc+5")
__xlated("{{[0-9]+}}: kgoto pc+2")
__xlated("{{[0-9]+}}: r0 += 7")
__xlated("{{[0-9]+}}: exit")
__naked int global_cycle_returns(void)
{
	asm volatile (
		"call global_exit_behind_cycle;"
		unwind_goto(2)
		"r0 += 7;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(2)
		: __clobber_all
	);
}

/*
 * The summary walks a callee ahead of its callers, and no subprog returns until a walk shows it. In
 * a cycle of calls some callee comes ahead of a caller that it calls back. Here the prog gets into
 * the cycle through global_out_or_round(), which has the way out, so global_goes_round() is walked
 * first: its exit is behind the call of a subprog that is not known to return yet, and only a
 * second round of walks finds that it returns. The insn that reads through r0 stands behind the
 * call of global_goes_round(), in the other subprog: it is verified only if that call returns.
 */
__naked __noinline __used
unsigned long global_goes_round(void);

__naked __noinline __used
unsigned long global_out_or_round(void)
{
	asm volatile (
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 1f;"
		"call global_goes_round;"
		"r0 = *(u64 *)(r0 + 0);"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(zero)
	);
}

__naked __noinline __used
unsigned long global_goes_round(void)
{
	asm volatile (
		"call global_out_or_round;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: a global subprog that returns if its caller in a cycle does might return")
MIGHT_RETURN
__naked int global_round_might_return(void)
{
	asm volatile (
		"call global_out_or_round;"
		"exit;"
		::: __clobber_all
	);
}

/* The same with the two subprogs defined the other way around */
__naked __noinline __used
unsigned long global_out_or_round_2(void);

__naked __noinline __used
unsigned long global_goes_round_2(void)
{
	asm volatile (
		"call global_out_or_round_2;"
		"exit;"
	);
}

__naked __noinline __used
unsigned long global_out_or_round_2(void)
{
	asm volatile (
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 == 0 goto 1f;"
		"call global_goes_round_2;"
		"r0 = *(u64 *)(r0 + 0);"
	"1:"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(zero)
	);
}

SEC("tc")
__description("unwind: a global subprog that returns if its caller in a cycle does, defined first, might return")
MIGHT_RETURN
__naked int global_round_might_return_2(void)
{
	asm volatile (
		"call global_out_or_round_2;"
		"exit;"
		::: __clobber_all
	);
}

/* gotox is its one way to the exit: the walk follows the jump table of the subprog */
__naked __noinline __used
unsigned long global_gotox_exits(void)
{
	asm volatile ("						\
	.pushsection .jumptables,\"\",@progbits;		\
jt0_%=:								\
	.quad ret0_%= - .text;					\
	.size jt0_%=, 8;					\
	.global jt0_%=;						\
	.popsection;						\
								\
	r0 = jt0_%= ll;						\
	r0 = *(u64 *)(r0 + 0);					\
	.8byte %[gotox_r0];					\
ret0_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm_insn(gotox_r0, BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_0, 0, 0, 0))
	);
}

SEC("tc")
__description("unwind: a global subprog that gets to its exit by gotox only might return")
MIGHT_RETURN
BEHIND_CALL(global_gotox_might_return, global_gotox_exits)

/*
 * It returns 0 through its jump table, and the prog goes on: no trap behind the call here either.
 * prog_tests/unwind_attach.c runs it. Nothing unwinds the subprog, so unwind_goto of the prog and
 * its landing pad are gone.
 */
SEC("tc")
__description("unwind: a global subprog returns by gotox")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success
__xlated("0: call pc+2")
__xlated("1: r0 += 7")
__xlated("2: exit")
__naked int global_gotox_returns(void)
{
	asm volatile (
		"call global_gotox_exits;"
		unwind_goto(2)
		"r0 += 7;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(2)
		: __clobber_all
	);
}

/*
 * The landing pad of a call of a subprog that never returns releases what the frame holds. What
 * follows the call is dead code that reads nothing of it, here an exit. No frame runs that insn,
 * so for liveness it reads what the pad may read, as a call of bpf_throw() does: r6 is a place of
 * the task, and the frame needs no hidden slot. The verifier adds unwind_goto, and the pad ends the
 * prog with TC_ACT_SHOT.
 */
SEC("tc")
__description("unwind: a reference in r6 at a call of a subprog that never returns needs no hidden slot")
NEVER_RETURNS __retval(2)
__log_level(2)
__msg("landing pad of call at 6 for unwind_exit: ref@1(r6) rcu=0 preempt=0")
__not_msg("has hidden slots")
__naked int task_at_call_never_returns(void)
{
	asm volatile (
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"if r0 != 0 goto 1f;"
		"r0 = 7;"
		"exit;"
	"1:"
		"r6 = r0;"
		"call global_always_unwinds;"
		"exit;"
		:
		: __imm(bpf_task_from_pid)
		: __clobber_all
	);
}

/*
 * Here a jump goes to the insn behind the call, from the path that has released the task: that
 * insn is code of the normal path, which does not read r6, and its liveness is that of the code.
 * The task has no place behind the call, and the frame keeps it in a hidden slot.
 */
SEC("tc")
__description("unwind: a reference in r6 at a call that never returns in front of live code has a hidden slot")
NEVER_RETURNS __retval(2)
__log_level(2)
__msg("func#0 has hidden slots for: refs")
__naked int task_at_call_in_front_of_live_code(void)
{
	asm volatile (
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"if r0 == 0 goto 2f;"
		"r6 = r0;"
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 != 0 goto 1f;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"goto 2f;"
	"1:"
		"call global_always_unwinds;"
	"2:"
		"r0 = 7;"
		"exit;"
		:
		: __imm(bpf_task_from_pid),
		  __imm(bpf_task_release),
		  __imm_addr(one)
		: __clobber_all
	);
}

/* It returns nothing. When it unwinds it leaves with r0 = 5. */
__naked __noinline __used
void global_void_unwinds(void)
{
	asm volatile (
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"if r1 != 0 goto 1f;"
		"exit;"
	"1:"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_addr(one),
		  __imm_unwind_exit
	);
}

/* What unwind_exit left in r0 reaches the pad, also out of a subprog that returns nothing */
SEC("tc")
__description("unwind: a global subprog that returns nothing unwinds, r0 reaches the pad")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(15)
__naked int calls_global_void_unwinds(void)
{
	asm volatile (
		"call global_void_unwinds;"
		unwind_goto(2)
		"r0 = 0;"
		"exit;"
		"r0 += 10;"
		"exit;"
		:
		: __imm_unwind_goto(2)
		: __clobber_all
	);
}

/* To the caller it is a number */
SEC("tc")
__description("unwind: r0 is a number in the pad of a call of a global subprog that returns nothing")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("R0 invalid mem access 'scalar'")
__naked int global_void_pad_is_checked(void)
{
	asm volatile (
		"call global_void_unwinds;"
		unwind_goto(2)
		"r0 = 0;"
		"exit;"
		"r0 = *(u64 *)(r0 + 0);"
		"exit;"
		:
		: __imm_unwind_goto(2)
		: __clobber_all
	);
}

/*
 * A subprog that returns nothing and never returns, see global_always_unwinds(), and the pad right
 * behind its call, where a compiler puts it: only what unwind_exit left gets there, and r0 is a
 * number.
 */
__naked __noinline __used
void global_void_always_unwinds(void)
{
	asm volatile (
		"r0 = 5;"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

SEC("tc")
__description("unwind: the pad follows the call of a global subprog that returns nothing and never returns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(15)
__naked int pad_follows_global_void_never_returns(void)
{
	asm volatile (
		"call global_void_always_unwinds;"
		unwind_goto(0)
		"r0 += 10;"
		"exit;"
		:
		: __imm_unwind_goto(0)
		: __clobber_all
	);
}

/*
 * The same for a stack slot: nothing reads fp-8 behind the call, but the stack of the frame is
 * live there too, so the slot is a place of the task. The pad loads the task from it and releases
 * it once, and the prog gets no insn for a hidden slot.
 */
SEC("tc")
__description("unwind: a reference in the stack at a call of a subprog that never returns needs no hidden slot")
NEVER_RETURNS __retval(2)
__log_level(2)
__msg("landing pad of call at 6 for unwind_exit: ref@1(*fp-8) rcu=0 preempt=0")
__not_msg("has hidden slots")
__xlated("5: *(u64 *)(r10 -8) = r0")
__xlated("6: call pc+6")
__xlated("7: unwind_goto pc+1")
__xlated("8: goto pc-1")
__xlated("9: r1 = *(u64 *)(r10 -8)")
__xlated("10: call kernel-function")
__xlated("11: r0 = 2")
__xlated("12: exit")
__naked int task_in_stack_at_call_never_returns(void)
{
	asm volatile (
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"if r0 != 0 goto 1f;"
		"r0 = 7;"
		"exit;"
	"1:"
		"*(u64 *)(r10 - 8) = r0;"
		"call global_always_unwinds;"
		"exit;"
		:
		: __imm(bpf_task_from_pid)
		: __clobber_all
	);
}

/*
 * The rule does not ask whether the callee is global. The verifier follows always_unwinds() and
 * knows from that that nothing comes back, but what is live behind the call is decided before
 * that, by the summary.
 */
SEC("tc")
__description("unwind: a reference in r6 at a call of a static subprog that never returns needs no hidden slot")
NEVER_RETURNS __retval(2)
__log_level(2)
__msg("landing pad of call at 6 for unwind_exit: ref@1(r6) rcu=0 preempt=0")
__not_msg("has hidden slots")
__naked int task_at_static_call_never_returns(void)
{
	asm volatile (
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"if r0 != 0 goto 1f;"
		"r0 = 7;"
		"exit;"
	"1:"
		"r6 = r0;"
		"call always_unwinds;"
		"exit;"
		:
		: __imm(bpf_task_from_pid)
		: __clobber_all
	);
}

__naked __noinline __used
unsigned long global_never_unwinds(void)
{
	asm volatile (
		"r0 = 7;"
		"exit;"
	);
}

SEC("tc")
__description("unwind: a global subprog that cannot unwind")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int calls_global_never_unwinds(void)
{
	asm volatile (
		"call global_never_unwinds;"
		"exit;"
		::: __clobber_all
	);
}

/*
 * The verifier gets to the pad from the first call only, with r6 = 1. The second
 * unwind_goto stays, since the pad is not dead code.
 */
SEC("tc")
__description("unwind: a pad shared with a call of a subprog that cannot unwind")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int shared_pad(void)
{
	asm volatile (
		"r6 = 1;"
		"call global_returns;"
		unwind_goto(4)
		"r6 = 2;"
		"call global_never_unwinds;"
		unwind_goto(1)
		"exit;"
		"r0 = r6;"
		"exit;"
		:
		: __imm_unwind_goto(4),
		  __imm_unwind_goto(1)
		: __clobber_all
	);
}

/* The verifier adds it, and a landing pad that ends the prog with TC_ACT_SHOT */
SEC("tc")
__description("unwind: no unwind_goto after a call of a global subprog")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__xlated("0: call pc+4")
__xlated("1: unwind_goto pc+1")
__xlated("2: exit")
__xlated("3: r0 = 2")
__xlated("4: exit")
__naked int global_no_unwind_goto(void)
{
	asm volatile (
		"call global_returns;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("unwind: no unwind_goto after a call of a static subprog")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2)
__naked int static_no_unwind_goto(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"call may_unwind;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len))
		: __clobber_all
	);
}

/* In more RCU sections than a landing pad that the verifier could add leaves */
SEC("tc")
__description("unwind: no unwind_goto after a call, and no landing pad will do")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__failure __msg("landing pad of call at 9 for unwind_exit: conflict: too much is held")
__naked int static_no_landing_pad(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"call always_unwinds;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock)
		: __clobber_all
	);
}

/* The verifier sees that it doesn't get to unwind_exit */
SEC("tc")
__description("unwind: no unwind_goto is fine when the callee doesn't unwind")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int static_does_not_get_there(void)
{
	asm volatile (
		"r1 = 0;"
		"call may_unwind;"
		"exit;"
		::: __clobber_all
	);
}

SEC("tc")
__description("unwind: callx, the callee returns")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int callx_returns(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"r1 -= 64;"
		"r6 = %[may_unwind] ll;"
		"callx r6;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_addr(may_unwind),
		  __imm_unwind_goto(1)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: callx, the callee unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(42)
__naked int callx_unwinds(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"r6 = %[may_unwind] ll;"
		"callx r6;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_addr(may_unwind),
		  __imm_unwind_goto(1)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: unwind_goto after a plain insn")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("unwind_goto at insn 1 doesn't follow a call of a subprog")
__naked int unwind_goto_after_mov(void)
{
	asm volatile (
		"r0 = 0;"
		unwind_goto(0)
		"exit;"
		:
		: __imm_unwind_goto(0)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: unwind_goto is the first insn")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("unwind_goto at insn 0 doesn't follow a call of a subprog")
__naked int unwind_goto_first(void)
{
	asm volatile (
		unwind_goto(0)
		"r0 = 0;"
		"exit;"
		:
		: __imm_unwind_goto(0)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: unwind_goto after a call of a helper")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("unwind_goto at insn 1 doesn't follow a call of a subprog")
__naked int unwind_goto_after_helper(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		unwind_goto(0)
		"exit;"
		:
		: __imm(bpf_get_prandom_u32),
		  __imm_unwind_goto(0)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: unwind_goto after a call of a kfunc")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("unwind_goto at insn 1 doesn't follow a call of a subprog")
__naked int unwind_goto_after_kfunc(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		unwind_goto(0)
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_rcu_read_lock),
		  __imm(bpf_rcu_read_unlock),
		  __imm_unwind_goto(0)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: jump to unwind_goto")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("jump to unwind_goto at insn 3")
__naked int jump_to_unwind_goto(void)
{
	asm volatile (
		"r0 = 0;"
		"if r1 != 0 goto 1f;"
		"call never_unwinds;"
	"1:"
		unwind_goto(0)
		"exit;"
		:
		: __imm_unwind_goto(0)
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: reserved fields of unwind_goto")
__failure __msg("invalid may_goto imm 1")
__naked int unwind_goto_reserved(void)
{
	asm volatile (
		"call never_unwinds;"
		".8byte %[bad];"
		"exit;"
		:
		: __imm_insn(bad, BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, 0, 1))
		: __clobber_all
	);
}

/* 32 bits for the offset are for unwind_goto that the verifier adds */
SEC("tc")
__description("unwind: unwind_goto of the prog has 16 bits for the offset")
__failure __msg("unknown opcode e6")
__naked int unwind_goto_imm(void)
{
	asm volatile (
		"call never_unwinds;"
		".8byte %[bad];"
		"exit;"
		:
		: __imm_insn(bad, BPF_RAW_INSN(BPF_JMP32 | BPF_JCOND, 0, BPF_UNWIND_GOTO, 0, 0))
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: unknown kind of jcond")
__failure __msg("invalid may_goto imm 0")
__naked int jcond_unknown(void)
{
	asm volatile (
		"call never_unwinds;"
		".8byte %[bad];"
		"exit;"
		:
		: __imm_insn(bad, BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO + 1, 0, 0))
		: __clobber_all
	);
}

SEC("tc")
__description("unwind: unknown kind of exit")
__failure __msg("BPF_EXIT uses reserved fields")
__naked int exit_unknown(void)
{
	asm volatile (
		"r0 = 0;"
		".8byte %[bad];"
		:
		: __imm_insn(bad, BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT + 1, 0, 0))
		: __clobber_all
	);
}

/* r1 is the index: unwinds in the second iteration */
__naked __noinline __used
static unsigned long cb_unwinds(void)
{
	asm volatile (
		"r0 = 0;"
		"if r1 != 0 goto 1f;"
		"exit;"
	"1:"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

/* bpf_loop() has a pad for it, and the verifier adds the one after the call */
SEC("tc")
__description("unwind: callback unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(2)
__naked int callback_unwinds(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[cb_unwinds];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm_ptr(cb_unwinds),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

__naked __noinline __used
static unsigned long async_cb_unwinds(void)
{
	asm volatile (
		"r0 = 0;"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

/* The kernel calls it. It's the top frame like the main prog: unwind_exit is exit. */
SEC("tc")
__description("unwind: async callback unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(0)
int async_callback_unwinds(void *ctx)
{
	struct timer_elem *val;
	int key = 0;

	val = bpf_map_lookup_elem(&timer_map, &key);
	if (!val)
		return 0;

	bpf_timer_init(&val->t, &timer_map, 0);
	bpf_timer_set_callback(&val->t, (void *)async_cb_unwinds);
	bpf_timer_start(&val->t, 0, 0);
	return 0;
}

/* Not naked: the argument has to have a name in BTF */
__noinline int exception_cb_unwinds(__u64 cookie)
{
	if (cookie)
		asm volatile ("r0 = 7;" unwind_exit :: __imm_unwind_exit : "r0");
	return 0;
}

SEC("tc")
__description("unwind: exception callback unwinds")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__attribute__((btf_decl_tag("exception_callback:exception_cb_unwinds")))
__success __retval(7)
int exception_callback_unwinds(struct __sk_buff *skb)
{
	bpf_throw(skb->len);
	return 0;
}

__noinline int exception_cb_spins_lsm(__u64 cookie)
{
	while (*(volatile unsigned long *)&one)
		;
	return -13;
}

/* It returns in place of the main prog, so it ends like the main prog when its time slice is over */
SEC("lsm/file_mprotect")
__description("unwind: a loop in the exception callback on an LSM hook ends the prog with -EPERM")
__arch_x86_64 __arch_arm64 __load_if_JITed()
__attribute__((btf_decl_tag("exception_callback:exception_cb_spins_lsm")))
__success
__xlated("r0 = -1")
__xlated("exit")
int exception_callback_spins_lsm(void *ctx)
{
	bpf_throw(0);
	return 0;
}

/* What it calls can unwind as long as it doesn't let it out */
__naked __noinline __used
static unsigned long cb_catches(void)
{
	asm volatile (
		"call may_unwind;"
		unwind_goto(0)
		"r0 = 0;"
		"exit;"
		:
		: __imm_unwind_goto(0)
	);
}

SEC("tc")
__description("unwind: callback catches")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(3)
__naked int callback_catches(void)
{
	asm volatile (
		"r1 = 3;"
		"r2 = %[cb_catches];"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"exit;"
		:
		: __imm_ptr(cb_catches),
		  __imm(bpf_loop)
		: __clobber_common
	);
}

/* Both leave the subprog like exit does */
__naked __noinline __used
static unsigned long does_tail_call(void)
{
	asm volatile (
		"r6 = *(u32 *)(r1 + %[len]);"
		"r2 = %[prog_array] ll;"
		"r3 = 0;"
		"call %[bpf_tail_call];"
		"r0 = 7;"
		"if r6 == 64 goto 1f;"
		unwind_exit
	"1:"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm(bpf_tail_call),
		  __imm_addr(prog_array),
		  __imm_unwind_exit
	);
}

SEC("tc")
__description("unwind: tail call in a subprog that can unwind")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int tail_call_in_subprog(void)
{
	asm volatile (
		"call does_tail_call;"
		unwind_goto(1)
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(1)
		: __clobber_all
	);
}

/* The packet is shorter than that: ld_abs leaves the subprog with r0 = 0 */
__naked __noinline __used
static unsigned long does_ld_abs(void)
{
	asm volatile (
		"r6 = r1;"
		"r0 = *(u8 *)skb[1000];"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

SEC("tc")
__description("unwind: ld_abs in a subprog that can unwind")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__success __retval(7)
__naked int ld_abs_in_subprog(void)
{
	asm volatile (
		"call does_ld_abs;"
		unwind_goto(2)
		"r0 += 7;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_unwind_goto(2)
		: __clobber_all
	);
}

/* It reads through a pointer to the stack of the main prog: verified in the frames of its callers */
__naked __noinline __used
static unsigned long unwinds_with_0_or_5(void)
{
	asm volatile (
		"r6 = *(u64 *)(r1 + 0);"
		"call %[bpf_get_prandom_u32];"
		"if r0 == 0 goto +2;"
		"r0 = 5;"
		unwind_exit
		"r0 = 0;"
		unwind_exit
		:
		: __imm(bpf_get_prandom_u32),
		  __imm_unwind_exit
		: __clobber_all
	);
}

/* No unwind_goto: the verifier adds it, and a landing pad that passes on what unwind_exit left */
__naked __noinline __used
static unsigned long calls_unwinds_with_0_or_5(void)
{
	asm volatile ("call unwinds_with_0_or_5; r0 = 1; exit;" ::: __clobber_all);
}

/*
 * Two unwound states that differ in what unwind_exit left alone meet where no insn of the prog
 * reads r0, behind the call in the frame in between. r0 stays apart all the same: the pad of the
 * prog reads it, and takes 5 for a pointer.
 */
SEC("tc")
__description("unwind: two values of unwind_exit through a plain call, the pad of the prog expects 0")
__arch_x86_64
__arch_arm64
__load_if_JITed()
__failure __msg("R1 invalid mem access 'scalar'")
__naked int two_values_through_plain_call(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = r10;"
		"r1 += -8;"
		"call calls_unwinds_with_0_or_5;"
		unwind_goto(2)
		"r0 = 1;"
		"exit;"
		"if r0 == 0 goto +2;"
		"r1 = 0;"
		"r0 = *(u64 *)(r1 + 0);"
		"r0 = 2;"
		"exit;"
		:
		: __imm_unwind_goto(2)
		: __clobber_all
	);
}

/*
 * JITs don't emit anything for unwind_goto. It's an extable entry, where
 * unwind_exit looks its return address up.
 * With KASAN x86-64 JIT wraps a load in pushes, a call and pops. 'r2 = 0x1234'
 * is where the patterns start, so that they don't take that call for the one
 * of the subprog.
 */
SEC("tc")
__description("unwind: jit")
__success __retval(42)
__load_if_JITed()
__arch_x86_64
__jited("	movl	$0x1234, %esi")
__jited("...") /* call depth accounting */
__jited("	callq	0x{{.*}}")
__jited("	movl	$0x7, %eax")
__jited("...")
__jited("	movl	$0x5, %eax")
__jited("	pushq	%rax")
__jited("	pushq	%rsi")
__jited("	movq	0x8(%rbp), %rdi")
__jited("...") /* call depth accounting */
__jited("	callq	0x{{.*}}")
__jited("	movq	%rax, 0x8(%rbp)")
__jited("	popq	%rsi")
__jited("	popq	%rax")
__arch_arm64
__jited("	mov	x1, #0x1234")
__jited("	bl	{{.*}}")
__jited("	mov	x8, x0")
__jited("	mov	x8, #0x7")
__jited("...")
__jited("	mov	x8, #0x5")
__jited("	stp	x8, x1, [sp, #-0x10]!")
__jited("	ldr	x0, [x29, #0x8]")
__jited("...")
__jited("	mov	x10, x0")
__jited("	ldp	x8, x1, [sp], #0x10")
__jited("...")
__jited("	add	x30, x30, x10")
__jited("	ret")
__naked int jit(void)
{
	asm volatile (
		"r1 = *(u32 *)(r1 + %[len]);"
		"r2 = 0x1234;"
		"call may_unwind;"
		unwind_goto(2)
		"r0 = 7;"
		"exit;"
		"r0 = 42;"
		"exit;"
		:
		: __imm_const(len, offsetof(struct __sk_buff, len)),
		  __imm_unwind_goto(2)
		: __clobber_all
	);
}

/* r1 == 0: returns 7, otherwise unwinds with r0 = 5 */
__naked __noinline __used
static unsigned long may_unwind_big_stack(void)
{
	asm volatile (
		"*(u64 *)(r10 - 200) = r1;"
		"if r1 != 0 goto 1f;"
		"r0 = 7;"
		"exit;"
	"1:"
		"r0 = 5;"
		unwind_exit
		:
		: __imm_unwind_exit
	);
}

/*
 * x86-64 keeps the pointer to the private stack in r9 and saves it around a call.
 * The value that is read back in the pad is there only when r9 is restored: on the way of
 * unwind_exit a landing behind the last insn of the prog does that. What returns goes on with
 * the exit that follows the call.
 */
SEC("raw_tp")
__description("unwind: private stack, the callee unwinds")
__success __retval(47)
__load_if_JITed()
__arch_x86_64
__jited("	movl	$0x1234, %esi") /* past the load, see above */
__jited("	pushq	%r9")
__jited("...") /* call depth accounting */
__jited("	callq	0x{{.*}}")
__jited("	popq	%r9")
__jited("L{{.*}}:	leave")
__jited("...")
__jited("	popq	%r9")
__jited("	jmp	L{{.*}}")
__arch_arm64
__naked int private_stack_unwinds(void)
{
	asm volatile (
		"*(u64 *)(r10 - 200) = 42;"
		"r1 = %[one] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"r2 = 0x1234;"
		"call may_unwind_big_stack;"
		unwind_goto(1)
		"exit;"
		"r1 = *(u64 *)(r10 - 200);"
		"r0 += r1;"
		"exit;"
		:
		: __imm_addr(one),
		  __imm_unwind_goto(1)
		: __clobber_all
	);
}

SEC("raw_tp")
__description("unwind: private stack, the callee returns")
__success __retval(49)
__load_if_JITed()
__arch_x86_64
__arch_arm64
__naked int private_stack_returns(void)
{
	asm volatile (
		"*(u64 *)(r10 - 200) = 42;"
		"r1 = %[zero] ll;"
		"r1 = *(u64 *)(r1 + 0);"
		"call may_unwind_big_stack;"
		unwind_goto(3)
		"r1 = *(u64 *)(r10 - 200);"
		"r0 += r1;"
		"exit;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(zero),
		  __imm_unwind_goto(3)
		: __clobber_all
	);
}

/*
 * BTF FUNC records are not generated for kfuncs referenced
 * from inline assembly. These records are necessary for
 * libbpf to link the program. The function below is a hack
 * to ensure that BTF FUNC records are generated.
 */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	bpf_task_release(bpf_task_from_pid(1));
	__bpf_trap();
	bpf_throw(0);
}

char _license[] SEC("license") = "GPL";
