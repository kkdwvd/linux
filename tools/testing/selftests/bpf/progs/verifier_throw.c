// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

/* bpf_throw() unwinds the prog through landing pads. The cookie goes to the top frame in r0. */
#define unwind_goto(off) ".8byte %[insn_unwind_goto_" #off "];"
#define unwind_exit ".8byte %[insn_unwind_exit];"

#define __imm_unwind_goto(off) \
	__imm_insn(insn_unwind_goto_##off, \
		   BPF_RAW_INSN(BPF_JMP | BPF_JCOND, 0, BPF_UNWIND_GOTO, off, 0))
#define __imm_unwind_exit \
	__imm_insn(insn_unwind_exit, \
		   BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, BPF_UNWIND_EXIT, 0, 0))
#define __exception_cb(name) __attribute__((btf_decl_tag("exception_callback:" #name)))

extern void bpf_throw(__u64 cookie) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
struct task_struct {};
extern struct task_struct *bpf_task_from_pid(int pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;
extern int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end) __ksym;

/* kfuncs that only asm calls need BTF */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
}

/* The verifier doesn't know what is in there */
unsigned long one = 1;

/* @reg = a task, which has to be released */
#define ACQUIRE_TASK(reg)				\
		"r1 = 1;"				\
		"call %[bpf_task_from_pid];"		\
		"if r0 != 0 goto +1;"			\
		"exit;"					\
		#reg " = r0;"

/* if (one) bpf_throw(cookie); */
#define THROW(cookie)					\
		"r1 = %[one] ll;"			\
		"r1 = *(u64 *)(r1 + 0);"		\
		"if r1 == 0 goto +2;"			\
		"r1 = " #cookie ";"			\
		"call %[bpf_throw];"

/* The landing pad has no call: the cookie needs no place in the stack */
SEC("tc")
__description("throw: nothing is held")
__arch_x86_64 __arch_arm64
__success __retval(7)
__xlated("3: if r1 == 0x0 goto pc+2")
__xlated("4: r1 = 7")
__xlated("5: gotol pc+2")
__xlated("6: r0 = 1")
__xlated("7: exit")
__xlated("8: r0 = r1")
__xlated("9: exit")
__naked void nothing_is_held(void)
{
	asm volatile (
	THROW(7)
		"r0 = 1;"
		"exit;"
		:: __imm_addr(one), __imm(bpf_throw)
		: __clobber_all);
}

/* Nothing follows bpf_throw(). It reads the stack of its frame all the same. */
SEC("tc")
__description("throw: the task is in a stack slot alone")
__arch_x86_64 __arch_arm64
__success __retval(7)
__naked void task_in_a_spill_alone(void)
{
	asm volatile (
	ACQUIRE_TASK(r0)
		"*(u64 *)(r10 - 8) = r0;"
		"r0 = 0;"
		"r1 = 7;"
		"call %[bpf_throw];"
		"exit;"
		:: __imm(bpf_task_from_pid), __imm(bpf_throw)
		: __clobber_all);
}

__naked __noinline __used
static unsigned long leaf_holds_task(void)
{
	asm volatile (
	ACQUIRE_TASK(r6)
	THROW(7)
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = 1;"
		"exit;"
		:: __imm_addr(one), __imm(bpf_throw),
		   __imm(bpf_task_from_pid), __imm(bpf_task_release)
		: __clobber_all);
}

__naked __noinline __used
static unsigned long mid_holds_task(void)
{
	asm volatile (
	ACQUIRE_TASK(r6)
		"call leaf_holds_task;"
		"r1 = r6;"
		"call %[bpf_task_release];"
		"r0 = 2;"
		"exit;"
		:: __imm(bpf_task_from_pid), __imm(bpf_task_release)
		: __clobber_all);
}

__noinline int adds_one(__u64 cookie)
{
	return cookie + 1;
}

/* A release is a call: each pad keeps the value in a hidden word. The last calls the callback. */
SEC("tc")
__description("throw: three frames hold something, the exception callback gets the cookie")
__arch_x86_64 __arch_arm64
__success __retval(8)
__exception_cb(adds_one)
/* main */
__xlated("...")
__xlated("call pc+")
__xlated("kgoto pc+")
__xlated("...")
__xlated("exit")
__xlated("*(u64 *)(r10 -8) = r0")
__xlated("call kernel-function")
__xlated("r1 = *(u64 *)(r10 -8)")
__xlated("call pc+")
__xlated("exit")
/* mid */
__xlated("...")
__xlated("kgoto pc+")
__xlated("...")
__xlated("exit")
__xlated("*(u64 *)(r10 -8) = r0")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = *(u64 *)(r10 -8)")
__xlated("r2 = 0")
__xlated("kexit")
/* leaf */
__xlated("...")
__xlated("r1 = 7")
__xlated("gotol pc+")
__xlated("...")
__xlated("exit")
__xlated("*(u64 *)(r10 -8) = r1")
__xlated("r1 = r6")
__xlated("call kernel-function")
__xlated("r0 = *(u64 *)(r10 -8)")
__xlated("r2 = 0")
__xlated("kexit")
__naked void three_frames(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call mid_holds_task;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 3;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

static __noinline __used int makes_iter(struct bpf_iter_num *it)
{
	return bpf_iter_num_new(it, 0, 10);
}

/*
 * One path makes an iterator, the other one acquires a task and drops the pointer: each holds one
 * reference where they meet. A landing pad that trusts a hidden slot would destroy 0xdead0000.
 */
#define NO_SLOT_FOR(name, desc, make, on_both_paths, where_they_meet)					\
SEC("tc")												\
__description("throw: no place has the task, " desc)							\
__arch_x86_64 __arch_arm64										\
__failure __msg("landing pad of bpf_throw at {{[0-9]+}}: conflict: no place has the handle on all paths") \
__naked void name(void)											\
{													\
	asm volatile (											\
		"r6 = %[one] ll;"									\
		"r6 = *(u64 *)(r6 + 0);"								\
		"r8 = 0xdead0000 ll;"									\
		"if r6 == 0 goto 1f;"									\
		"r1 = r10;"										\
		"r1 += -8;"										\
		"r2 = 0;"										\
		"r3 = 10;"										\
		"call " make ";"									\
		on_both_paths										\
		"goto 2f;"										\
	"1:"												\
		"r1 = 1;"										\
		"call %[bpf_task_from_pid];"								\
		"*(u64 *)(r10 - 8) = r0;"								\
		on_both_paths										\
	"2:"												\
		"r0 = 0;"										\
		"r6 = 0;"										\
		where_they_meet										\
		"r1 = 7;"										\
		"call %[bpf_throw];"									\
		"exit;"											\
		:: __imm_addr(one), __imm(bpf_task_from_pid), __imm(bpf_iter_num_new), __imm(bpf_throw)	\
		: __clobber_all);									\
}

#define OVERWRITE "*(u64 *)(r10 - 8) = r8;"
NO_SLOT_FOR(iter_or_dead_task, "an iterator is overwritten", "%[bpf_iter_num_new]", "", OVERWRITE)
NO_SLOT_FOR(iter_or_dead_spill, "an iterator and the spill are overwritten", "%[bpf_iter_num_new]", OVERWRITE, "")
NO_SLOT_FOR(iter_by_callee_or_dead_task, "a callee made the iterator", "makes_iter", "", OVERWRITE)

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} sockmap SEC(".maps");

/* No store follows the lookup, so the function gets no slots */
SEC("tc")
__description("throw: no place has the task, nor a socket out of a sockmap")
__arch_x86_64 __arch_arm64
__failure __msg("landing pad of bpf_throw at {{[0-9]+}}: conflict: no place has the handle on all paths")
__naked void sockmap_and_task_dead(void)
{
	asm volatile (
		"r6 = 0;"
		"*(u32 *)(r10 - 4) = r6;"
		"r1 = %[sockmap] ll;"
		"r2 = r10;"
		"r2 += -4;"
		"call %[bpf_map_lookup_elem];"
		"r1 = 1;"
		"call %[bpf_task_from_pid];"
		"r0 = 0;"
		"r1 = 0;"
		"call %[bpf_throw];"
		"exit;"
		:: __imm_addr(sockmap), __imm(bpf_map_lookup_elem), __imm(bpf_task_from_pid), __imm(bpf_throw)
		: __clobber_all);
}

static __noinline __used int always_throws(void)
{
	bpf_throw(7);
	return 0;
}

static __noinline void throws_then_releases(struct task_struct *task)
{
	if (one)
		bpf_throw(7);
	bpf_task_release(task);
}

/* The caller has no place for the task after the call. The message names the call. */
SEC("tc")
__description("throw: the callee releases what it was handed and throws first")
__arch_x86_64 __arch_arm64
__failure __msg("landing pad of call at {{[0-9]+}}: conflict: no place has the handle on all paths")
int callee_releases(void *ctx)
{
	struct task_struct *task = bpf_task_from_pid(1);

	if (task)
		throws_then_releases(task);
	return 1;
}

/* r0 of the state that comes back to the call is the cookie, not what r0 was in front of it */
SEC("tc")
__description("throw: r0 is a constant in front of the helper whose callback throws")
__arch_x86_64 __arch_arm64
__success __retval(7)
__naked void const_r0_before_helper(void)
{
	asm volatile (
		"r0 = 1;"
		"r1 = 1;"
		"r2 = %[always_throws] ll;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		"r0 = 1;"
		"exit;"
		:: __imm_addr(always_throws), __imm(bpf_loop)
		: __clobber_all);
}

int cb_runs;

__noinline int throws_again(__u64 cookie)
{
	cb_runs++;
	bpf_throw(cookie + cb_runs);
	return 0;
}

/* What unwinds out of the exception callback ends the prog: the callback is not called again */
SEC("tc")
__description("throw: the exception callback throws")
__arch_x86_64 __arch_arm64
__success __retval(7)
__exception_cb(throws_again)
int exception_cb_throws(void *ctx)
{
	if (one)
		bpf_throw(6);
	return 1;
}

__noinline int adds_forty(__u64 cookie)
{
	return cookie + 40;
}

/*
 * The pad of a guard calls the exception callback too, in a prog that never throws. Nothing in
 * this prog needs a JIT: the callback leaves with exit, so its call is followed by the exit of the
 * pad and not by unwind_goto, which only a JIT knows. The loop ends when its guard fires.
 */
SEC("tc")
__description("throw: no bpf_throw(), the guard of a loop calls the exception callback")
__success __retval(42)
__exception_cb(adds_forty)
__xlated("r1 = 2")
__xlated("call pc+")
__xlated("exit")
int guard_calls_exception_cb(void *ctx)
{
	while (*(volatile unsigned long *)&one)
		;
	return 1;
}

__noinline int leaves_with_unwind_exit(__u64 cookie)
{
	if (cookie)
		asm volatile ("r0 = 9;" unwind_exit :: __imm_unwind_exit : "r0");
	return 0;
}

/*
 * unwind_exit of the exception callback looks for the pad of its return address, which is in the
 * pad that called it. unwind_goto +0 behind the call is that entry: it gets to the exit of the pad.
 */
SEC("tc")
__description("throw: the exception callback leaves with unwind_exit")
__arch_x86_64 __arch_arm64
__success __retval(9)
__exception_cb(leaves_with_unwind_exit)
__xlated("call pc+")
__xlated("unwind_goto pc+0")
__xlated("exit")
int exception_cb_unwind_exits(void *ctx)
{
	if (one)
		bpf_throw(6);
	return 1;
}

static int throws_12345(__u32 i, void *ctx)
{
	bpf_throw(12345);
	return 0;
}

__noinline int loops(__u64 cookie)
{
	bpf_loop(1, throws_12345, NULL, 0);
	return 0;
}

/* No callback gets that cookie: it is checked like the value at the exit of the main prog */
SEC("lsm/task_setnice")
__description("throw: below the exception callback the cookie is what the prog returns")
__arch_x86_64 __arch_arm64
__failure __msg("At program exit the register R1 has smin=12345 smax=12345 should have been in [-4095, 0]")
__exception_cb(loops)
int cookie_below_exception_cb(void *ctx)
{
	bpf_throw(0);
	return 0;
}

#ifdef CAN_USE_CALLX

/* r2 = always_throws, out of a table of functions */
#define FROM_TABLE						\
		".pushsection .rodata,\"a\",@progbits;"		\
		".balign 8;"					\
		"tbl_%=: .quad always_throws;"			\
		".type tbl_%=, @object;"			\
		".size tbl_%=, .-tbl_%=;"			\
		".popsection;"					\
		"r2 = tbl_%= ll;"				\
		"r2 = *(u64 *)(r2 + 0);"

__noinline int loops_over_table(__u64 cookie)
{
	asm volatile (
	FROM_TABLE
		"r1 = 1;"
		"r3 = 0;"
		"r4 = 0;"
		"call %[bpf_loop];"
		:: __imm(bpf_loop)
		: __clobber_all);
	return 0;
}

/* Only the main pass finds the callback of bpf_loop(). libbpf fills tables for progs with callx. */
SEC("fentry/bpf_check")
__description("throw: below the exception callback, in a callback from a table of functions")
__arch_x86_64 __arch_arm64
__failure __msg("exception cb gets to always_throws(), whose address is taken elsewhere")
__exception_cb(loops_over_table)
__naked void cookie_from_table_below_exception_cb(void)
{
	asm volatile (
	FROM_TABLE
		"callx r2;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}
#endif

/* It reads through a pointer to the stack of the main prog: verified in the frames of its callers */
__naked __noinline __used
static unsigned long throws_0_or_5(void)
{
	asm volatile (
		"r6 = *(u64 *)(r1 + 0);"
		"call %[bpf_get_prandom_u32];"
		"if r0 == 0 goto +2;"
		"r1 = 5;"
		"call %[bpf_throw];"
		"r1 = 0;"
		"call %[bpf_throw];"
		"exit;"
		:: __imm(bpf_get_prandom_u32), __imm(bpf_throw)
		: __clobber_all);
}

__naked __noinline __used
static unsigned long calls_throws_0_or_5(void)
{
	asm volatile ("call throws_0_or_5; r0 = 1; exit;" ::: __clobber_all);
}

/*
 * Two unwound states that differ in the cookie alone meet where no insn of the prog reads r0. The
 * landing pad of the prog would take a cookie of 5 for a pointer, but bpf_throw() does not get
 * there: the kernel unwinds past it. See verifier_unwind.c for the same with unwind_exit.
 */
SEC("tc")
__description("throw: two cookies through a plain call, the pad of the prog is not entered")
__arch_x86_64 __arch_arm64
__success
__naked void two_cookies(void)
{
	asm volatile (
		"r1 = 0;"
		"*(u64 *)(r10 - 8) = r1;"
		"r1 = r10;"
		"r1 += -8;"
		"call calls_throws_0_or_5;"
		unwind_goto(2)
		"r0 = 1;"
		"exit;"
		"if r0 == 0 goto +2;"
		"r1 = 0;"
		"r0 = *(u64 *)(r1 + 0);"
		"r0 = 2;"
		"exit;"
		:: __imm_unwind_goto(2)
		: __clobber_all);
}

__naked __noinline __used
static unsigned long unwinds_with_64(void)
{
	asm volatile ("r0 = 64;" unwind_exit :: __imm_unwind_exit : __clobber_all);
}

/* In a prog that throws 'r0 = x; unwind_exit' is bpf_throw(x): the top frame returns x */
SEC("fentry/bpf_check")
__description("throw: unwind_exit of the prog with a value that the prog may not return")
__arch_x86_64 __arch_arm64
__failure __msg("At program exit the register R0 has smin=64 smax=64 should")
__naked void unwind_exit_out_of_range(void)
{
	asm volatile (
		"call unwinds_with_64;"
		"r1 = 0;"
		"call %[bpf_throw];"
		"exit;"
		:: __imm(bpf_throw)
		: __clobber_all);
}

__naked __noinline __used
static unsigned long unwinds_with_pointer(void)
{
	asm volatile ("r0 = %[one] ll;" unwind_exit
		      :: __imm_addr(one), __imm_unwind_exit : __clobber_all);
}

/* The landing pad would pass the pointer on, and the prog would return it */
SEC("tc")
__description("throw: unwind_exit of the prog with a pointer")
__arch_x86_64 __arch_arm64
__failure
__msg("landing pad of call at 0 for unwind_exit: conflict: the value of unwind_exit is not a number")
__naked void unwind_exit_with_pointer(void)
{
	asm volatile (
		"call unwinds_with_pointer;"
		"r1 = 0;"
		"call %[bpf_throw];"
		"exit;"
		:: __imm(bpf_throw)
		: __clobber_all);
}

/* The landing pad has a call, so the cookie needs 8 bytes of a stack that the prog uses up */
SEC("tc")
__description("throw: no room in the stack for the cookie")
__arch_x86_64 __arch_arm64
__failure __msg("landing pad of call at {{[0-9]+}}: conflict: no room in the stack for the value")
__naked void no_room_for_cookie(void)
{
	asm volatile (
		"*(u64 *)(r10 - 2048) = 1;"
		"call %[bpf_rcu_read_lock];"
		"call always_throws;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

int again;

static __noinline int depth(int n)
{
	if (n >= 100)
		bpf_throw(0);
	return n > 0 ? (depth(n - 1) + 1) & 255 : 0;
}

static __noinline int depth_to(int n, long *out)
{
	*out = depth(n);
	return 0;
}

/* bpf_throw() does not read R2-R5: the pointer that is left over in r2 is no argument of depth() */
SEC("tc")
__description("throw: in a recursive subprog, a pointer to the stack is left over in r2")
__arch_x86_64 __arch_arm64
__success __retval(7)
int recursion_throws(struct __sk_buff *skb)
{
	long x = 0;

	depth_to(again + 7, &x);
	return x;
}

/* A global function that throws */
__naked __noinline __used
unsigned long global_throws(void)
{
	asm volatile (
		"r1 = 0;"
		"call %[bpf_throw];"
		"r0 = 0;"
		"exit;"
		:: __imm(bpf_throw) : __clobber_all);
}

/* Returns 5. If r1 * r1 is not r2 it calls the global function that throws first. One exit. */
__naked __noinline __used
static unsigned long throws_unless_square(void)
{
	asm volatile (
		"r3 = r1;"
		"r3 *= r1;"
		"if r3 == r2 goto 1f;"
		"call global_throws;"
	"1:	r0 = 5;"
		"exit;"
		::: __clobber_all);
}

/*
 * No call gets to the global function: 2 * 2 is 4 and 3 * 3 is 9. The two calls joined do, and
 * the prog is in more sections than a landing pad leaves. Where the global function throws is
 * not seen from its callers: the call of it is where their frame is left, and the jump that skips
 * the call is what has to be kept apart.
 */
SEC("tc")
__description("throw: two calls that skip a global function that throws, only their join gets to it")
__arch_x86_64 __arch_arm64
__success __retval(10)
__naked void global_throw_only_in_join(void)
{
	asm volatile (
		".rept 9;"
		"call %[bpf_rcu_read_lock];"
		".endr;"
		"r1 = 2;"
		"r2 = 4;"
		"call throws_unless_square;"
		"r6 = r0;"
		"r1 = 3;"
		"r2 = 9;"
		"call throws_unless_square;"
		"r6 += r0;"
		".rept 9;"
		"call %[bpf_rcu_read_unlock];"
		".endr;"
		"r0 = r6;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

/* The global function is called in an RCU section and throws: the caller leaves the section */
SEC("tc")
__description("throw: a global function that throws is called in an RCU section")
__arch_x86_64 __arch_arm64
__success __retval(0)
__naked void global_throws_in_section(void)
{
	asm volatile (
		"call %[bpf_rcu_read_lock];"
		"call global_throws;"
		"call %[bpf_rcu_read_unlock];"
		"r0 = 1;"
		"exit;"
		:: __imm(bpf_rcu_read_lock), __imm(bpf_rcu_read_unlock)
		: __clobber_all);
}

__noinline int large_cb(__u64 cookie)
{
	asm volatile ("*(u64 *)(r10 - 1104) = 1;" ::: "memory");
	return cookie + 1;
}

/* The landing pad calls the exception callback: its frame is on top of the frame of the main prog */
SEC("tc")
__description("throw: the main prog and the exception callback are too deep together")
__arch_x86_64 __arch_arm64
__failure __msg("combined stack size of 2 calls is 2208. Too large")
__exception_cb(large_cb)
int main_and_cb_too_deep(void *ctx)
{
	asm volatile ("*(u64 *)(r10 - 1104) = 1;" ::: "memory");
	if (one)
		bpf_throw(5);
	return 1;
}

char _license[] SEC("license") = "GPL";
