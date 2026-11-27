// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "../test_kmods/bpf_testmod.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

#define CLOCK_MONOTONIC 1

struct elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 7);
	__type(key, int);
	__type(value, struct elem);
} timers SEC(".maps");

/* The pad that ends the invocation tells the struct_ops. The cookie waits in the stack. */
SEC("struct_ops")
int BPF_PROG(test_1, struct st_ops_args *args)
{
	if (args->a)
		bpf_throw(5);
	return 7;
}

__noinline __used static int throws_5_if(u64 a)
{
	if (a)
		bpf_throw(5);
	return 7;
}

/* BPF_JMP | BPF_JCOND with BPF_UNWIND_GOTO in src_reg, and BPF_JMP | BPF_EXIT with BPF_UNWIND_EXIT */
#define unwind_goto(label) ".8byte ((((" #label " - .) / 8 - 1) & 0xffff) << 16) | 0x10e5;"
#define unwind_exit ".8byte 0x1095;"

/*
 * The call has a landing pad of the prog that only resumes: the kernel enters it, and the code
 * that stands in for its unwind_exit ends the invocation. That code tells the struct_ops, once.
 */
SEC("struct_ops")
int BPF_PROG(test_1_pad, struct st_ops_args *args)
{
	register long a asm("r1") = args->a;
	register long ret asm("r0");

	asm volatile (
		"call throws_5_if;"
		unwind_goto(1f)
		"goto 2f;"
	"1:"
		unwind_exit
	"2:"
		: "=r"(ret) : "r"(a) : "r2", "r3", "r4", "r5");
	return ret;
}

__noinline int throws_again(u64 cookie)
{
	bpf_throw(cookie + 1);
	return 0;
}

/*
 * The pad of the prog tells the struct_ops and calls the exception callback. What unwinds out of
 * that ends the same invocation: it is not told a second time.
 */
SEC("struct_ops")
__attribute__((btf_decl_tag("exception_callback:throws_again")))
int test_1_exception_cb(unsigned long long *ctx)
{
	struct st_ops_args *args = (void *)ctx[0];

	if (args->a)
		bpf_throw(5);
	return 7;
}

static int timer_cb(void *map, int *key, struct elem *e)
{
	bpf_throw(0);
	return 0;
}

/*
 * The address of the callback waits in a register over a call, so it is not seen in advance that
 * only bpf_timer_set_callback() gets it: the callback is expected to have callers in the prog,
 * and its pad ends in kexit. The kernel alone calls it: kexit finds no landing pad at the return
 * address of the frame, and tells the struct_ops. The pad does not: once.
 */
SEC("struct_ops")
int BPF_PROG(test_1_timer, struct st_ops_args *args)
{
	int (*cb)(void *map, int *key, struct elem *e) = timer_cb;
	struct elem *e;
	int key = 0;

	e = bpf_map_lookup_elem(&timers, &key);
	if (!e)
		return 1;
	barrier_var(cb);
	if (bpf_timer_init(&e->timer, &timers, CLOCK_MONOTONIC))
		return 2;
	if (bpf_timer_set_callback(&e->timer, cb))
		return 3;
	if (bpf_timer_start(&e->timer, 0, 0))
		return 4;
	return 7;
}

/* Not inlined: the call of the prog and the kernel get to the same function */
static __noinline int called_and_timer_cb(void *map, int *key, struct elem *e)
{
	bpf_throw(8);
	return 0;
}

/*
 * A timer callback that the prog calls as a function as well. It has one pad for both, which ends
 * in kexit. Called by the prog, that goes to the pad of the call, and the pad that ends the
 * invocation tells the struct_ops. Called by the kernel, it finds no landing pad, and tells.
 */
SEC("struct_ops")
int BPF_PROG(test_1_timer_called, struct st_ops_args *args)
{
	struct elem *e;
	int key = 1;

	e = bpf_map_lookup_elem(&timers, &key);
	if (!e)
		return 1;
	if (args->a)
		return called_and_timer_cb(&timers, &key, e);
	if (bpf_timer_init(&e->timer, &timers, CLOCK_MONOTONIC))
		return 2;
	if (bpf_timer_set_callback(&e->timer, called_and_timer_cb))
		return 3;
	if (bpf_timer_start(&e->timer, 0, 0))
		return 4;
	return 7;
}

/* A recursion without an end: the kernel unwinds it when the stack has no room for one more frame */
__naked __noinline __used
static unsigned long goes_down(void)
{
	asm volatile (
		"r1 = 0;"
		"call goes_down;"
		"exit;"
		::: __clobber_all);
}

/* How many times the callback got to its second frame */
int second_frames;

/*
 * A timer callback that calls itself: r1 is the map when the kernel calls it, and 0 when it does.
 * In its second frame it goes down a recursion that the kernel unwinds, with kexit. That takes
 * both frames of the callback, through the pad of its call of itself, and the first one returns
 * to the kernel: there the struct_ops is told.
 */
__naked __noinline __used
static int recursive_timer_cb(void *map, int *key, struct elem *e)
{
	asm volatile (
		"if r1 == 0 goto 1f;"
		"r1 = 0;"
		"call recursive_timer_cb;"
		"exit;"
	"1:"
		"r1 = %[second_frames] ll;"
		"r2 = *(u32 *)(r1 + 0);"
		"r2 += 1;"
		"*(u32 *)(r1 + 0) = r2;"
		"call goes_down;"
		"exit;"
		:
		: __imm_addr(second_frames)
		: __clobber_all);
}

SEC("struct_ops")
int BPF_PROG(test_1_timer_recursive, struct st_ops_args *args)
{
	struct elem *e;
	int key = 2;

	e = bpf_map_lookup_elem(&timers, &key);
	if (!e)
		return 1;
	if (bpf_timer_init(&e->timer, &timers, CLOCK_MONOTONIC))
		return 2;
	if (bpf_timer_set_callback(&e->timer, recursive_timer_cb))
		return 3;
	if (bpf_timer_start(&e->timer, 0, 0))
		return 4;
	return 7;
}

__noinline __used static int throws_0(void)
{
	bpf_throw(0);
	return 0;
}

/* How many times the landing pad of the callback below ran */
int cb_pad_runs;

/*
 * A timer callback with a landing pad of its own that only resumes. The kernel unwinds what it
 * calls and enters the pad. The code that stands in for unwind_exit of the pad leaves the frame
 * with kexit, which finds no landing pad where the frame returns to: the kernel called it, and
 * the struct_ops is told there, once. No pad of the callback tells.
 */
__naked __noinline __used
static int timer_cb_with_pad(void *map, int *key, struct elem *e)
{
	asm volatile (
		"call throws_0;"
		unwind_goto(1f)
		"r0 = 0;"
		"exit;"
	"1:"
		"r1 = %[cb_pad_runs] ll;"
		"r2 = *(u32 *)(r1 + 0);"
		"r2 += 1;"
		"*(u32 *)(r1 + 0) = r2;"
		unwind_exit
		:
		: __imm_addr(cb_pad_runs)
		: __clobber_all);
}

SEC("struct_ops")
int BPF_PROG(test_1_timer_pad, struct st_ops_args *args)
{
	struct elem *e;
	int key = 3;

	e = bpf_map_lookup_elem(&timers, &key);
	if (!e)
		return 1;
	if (bpf_timer_init(&e->timer, &timers, CLOCK_MONOTONIC))
		return 2;
	if (bpf_timer_set_callback(&e->timer, timer_cb_with_pad))
		return 3;
	if (bpf_timer_start(&e->timer, 0, 0))
		return 4;
	return 7;
}

/*
 * Who is told about an unwind of the prog's own, see bpf_prog_unwound_to_kernel(): a struct_ops is
 * told where a landing pad that the verifier emitted ends the invocation, and not where
 * unwind_exit of the prog does.
 *
 * A frame that the kernel called and that leaves with unwind_exit of the prog was not stopped by
 * the kernel: it ends as with exit, and nobody is told. In the operator the insn is exit. In the
 * callback of a timer it finds no landing pad and returns to the kernel.
 */
SEC("struct_ops")
__naked int test_1_unwinds(void)
{
	asm volatile (
		"r0 = 9;"
		unwind_exit
		::: __clobber_all);
}

__naked __noinline __used
static int unwinds_by_itself(void)
{
	asm volatile (
		"r0 = 9;"
		unwind_exit
		::: __clobber_all);
}

/*
 * unwind_exit of a function that the frame calls, with no unwind_goto at the call: a pad of the
 * verifier ends the invocation there, with 0, and a pad that ends an invocation tells the
 * struct_ops whatever its site is. This pins that half of the rule.
 */
SEC("struct_ops")
__naked int test_1_callee_unwinds(void)
{
	asm volatile (
		"call unwinds_by_itself;"
		"r0 = 7;"
		"exit;"
		::: __clobber_all);
}

/* How many times the two callbacks below ran */
int own_unwinds;

#define COUNT_OWN_UNWINDS			\
		"r1 = %[own_unwinds] ll;"	\
		"r2 = *(u32 *)(r1 + 0);"	\
		"r2 += 1;"			\
		"*(u32 *)(r1 + 0) = r2;"

/* unwind_exit of the callback finds no landing pad where the kernel called: nobody is told */
__naked __noinline __used
static int timer_cb_unwinds(void *map, int *key, struct elem *e)
{
	asm volatile (
	COUNT_OWN_UNWINDS
		"r0 = 0;"
		unwind_exit
		:
		: __imm_addr(own_unwinds)
		: __clobber_all);
}

/*
 * Only the kernel calls it, and its pad of the verifier ends the invocation with exit. That pad
 * tells, as the one of the operator above does.
 */
__naked __noinline __used
static int timer_cb_callee_unwinds(void *map, int *key, struct elem *e)
{
	asm volatile (
	COUNT_OWN_UNWINDS
		"call unwinds_by_itself;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(own_unwinds)
		: __clobber_all);
}

#define ARMS_TIMER(name, nr, cb)						\
SEC("struct_ops")								\
int BPF_PROG(name, struct st_ops_args *args)					\
{										\
	struct elem *e;								\
	int key = nr;								\
										\
	e = bpf_map_lookup_elem(&timers, &key);					\
	if (!e)									\
		return 1;							\
	if (bpf_timer_init(&e->timer, &timers, CLOCK_MONOTONIC))		\
		return 2;							\
	if (bpf_timer_set_callback(&e->timer, cb))				\
		return 3;							\
	if (bpf_timer_start(&e->timer, 0, 0))					\
		return 4;							\
	return 7;								\
}

ARMS_TIMER(test_1_timer_unwinds, 4, timer_cb_unwinds)
ARMS_TIMER(test_1_timer_callee_unwinds, 5, timer_cb_callee_unwinds)

/*
 * The same callback, but the prog calls it as a function as well: it can leave unwound, and its
 * pad of the verifier ends in unwind_exit. Called by the kernel that finds no landing pad, and
 * nobody is told: no pad has ended the invocation. Called by the operator it comes back to a call
 * without unwind_goto, and the pad of the operator ends the invocation and tells.
 */
__naked __noinline __used
static int called_timer_cb_callee_unwinds(void *map, int *key, struct elem *e)
{
	asm volatile (
	COUNT_OWN_UNWINDS
		"call unwinds_by_itself;"
		"r0 = 0;"
		"exit;"
		:
		: __imm_addr(own_unwinds)
		: __clobber_all);
}

SEC("struct_ops")
int BPF_PROG(test_1_called_timer_callee_unwinds, struct st_ops_args *args)
{
	struct elem *e;
	int key = 6;

	e = bpf_map_lookup_elem(&timers, &key);
	if (!e)
		return 1;
	if (args->a)
		return called_timer_cb_callee_unwinds(&timers, &key, e);
	if (bpf_timer_init(&e->timer, &timers, CLOCK_MONOTONIC))
		return 2;
	if (bpf_timer_set_callback(&e->timer, called_timer_cb_callee_unwinds))
		return 3;
	if (bpf_timer_start(&e->timer, 0, 0))
		return 4;
	return 7;
}

/*
 * What test_1(ctx[0]) of the struct_ops map ctx[1] returns, and in the upper half how many calls
 * of ->unwound() that made
 */
SEC("syscall")
int call_test_1(__u64 *ctx)
{
	struct st_ops_args args = { .a = ctx[0] };
	int cnt = bpf_kfunc_multi_st_ops_unwound_cnt();
	int ret = bpf_kfunc_multi_st_ops_test_1(&args, ctx[1]);

	return (bpf_kfunc_multi_st_ops_unwound_cnt() - cnt) << 16 | ret;
}

/* How many invocations were unwound so far */
SEC("syscall")
int unwound_cnt(void *ctx)
{
	return bpf_kfunc_multi_st_ops_unwound_cnt();
}

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_map = {
	.test_1 = (void *)test_1,
};

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_pad = {
	.test_1 = (void *)test_1_pad,
};

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_exception_cb = {
	.test_1 = (void *)test_1_exception_cb,
};

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_timer = {
	.test_1 = (void *)test_1_timer,
};

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_timer_called = {
	.test_1 = (void *)test_1_timer_called,
};

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_timer_recursive = {
	.test_1 = (void *)test_1_timer_recursive,
};

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_timer_pad = {
	.test_1 = (void *)test_1_timer_pad,
};

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_unwinds = {
	.test_1 = (void *)test_1_unwinds,
};

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_callee_unwinds = {
	.test_1 = (void *)test_1_callee_unwinds,
};

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_timer_unwinds = {
	.test_1 = (void *)test_1_timer_unwinds,
};

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_timer_callee_unwinds = {
	.test_1 = (void *)test_1_timer_callee_unwinds,
};

SEC(".struct_ops.link")
struct bpf_testmod_multi_st_ops st_ops_called_timer_callee_unwinds = {
	.test_1 = (void *)test_1_called_timer_callee_unwinds,
};
